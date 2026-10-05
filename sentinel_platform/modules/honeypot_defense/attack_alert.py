"""attack_alert —— 攻击告警（防御型蜜罐 + 入侵检测）。

职责：
  - 部署诱饵服务（假备份文件、弱密码管理后台、假 API 等）
  - 检测 Web 攻击（SQL 注入、XSS、目录遍历、文件包含等）
  - 检测后渗透行为（Webshell 上传、反弹 Shell、提权尝试等）
  - 攻击者溯源（IP、指纹、行为分析、时区推断）
  - 实时告警和攻击报告生成

检测能力：
  - Web 攻击检测：
    - SQL 注入尝试（参数中的 SQL 语句）
    - XSS 攻击（<script>、onerror 等）
    - 目录遍历（../../../etc/passwd）
    - 文件包含（?file=、?page= 等）
    - 命令注入（; whoami、| cat /etc/passwd）
    - 敏感路径访问（/backup.zip、/admin、/.git/config）
    - 异常 User-Agent（扫描器特征）
    - 暴力破解（短时间多次登录失败）

  - 后渗透检测：
    - Webshell 上传尝试（.php、.jsp、.aspx 上传）
    - Webshell 行为（eval、assert、exec 等函数调用）
    - 反弹 Shell（nc、bash -i、python -c 等）
    - 提权尝试（sudo、su、chmod +s 等）
    - 内网探测（扫描内网 IP 段）
    - 数据窃取（大量数据下载）

攻击者溯源：
  - IP 地理定位（MaxMind GeoIP2）
  - TLS 指纹（JA3/JA4）
  - HTTP/2 指纹
  - User-Agent 解析
  - 请求头顺序和特征
  - 时区分析（根据访问时间推测作息规律）
  - ASN 归属（ISP、云服务商）
  - 威胁情报查询（已知恶意 IP）

对外接口：
  - deploy_traps() - 部署诱饵服务
  - detect_attack(request) - 检测单次请求是否为攻击
  - trace_attacker(attacker_ip) - 溯源攻击者
  - list_attacks(filters) - 列出攻击记录
  - generate_attack_report(attack_id) - 生成攻击报告

数据模型：
  - ATTACK_ALERT 集合：记录所有检测到的攻击
  - ATTACKER_PROFILE 集合：攻击者画像（IP 聚合）
  - TRAP_ACCESS 集合：诱饵访问记录

使用场景：
  - 工作台 → 攻击告警页面
  - 实时监控系统被攻击情况
  - 自动溯源攻击者
  - 生成安全事件报告
"""
from __future__ import annotations

import os
import time
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote
from collections import defaultdict

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections, get_registry, ROLE
from . import _waf_rules as _WAF

logger = get_logger()


# ============================================================================
# 攻击检测规则
# ============================================================================

class AttackDetector:
    """攻击检测器（OWASP CRS 衍生规则集 + 异常评分 + 行为分析）。
    规则集移到 _waf_rules 模块（成熟正则，覆盖变体，可热更新迭代），本类只做评分编排。"""

    # 规则集引用 _waf_rules（编译好的正则；更新规则改那个文件，走热更新到达存量）
    SQL_INJECTION_PATTERNS = _WAF.SQLI_PATTERNS
    XSS_PATTERNS = _WAF.XSS_PATTERNS
    PATH_TRAVERSAL_PATTERNS = _WAF.TRAVERSAL_PATTERNS
    COMMAND_INJECTION_PATTERNS = _WAF.RCE_PATTERNS
    SENSITIVE_PATH_PATTERNS = _WAF.SENSITIVE_PATH_PATTERNS
    SCANNER_USER_AGENTS = _WAF.SCANNER_UA_KEYWORDS
    WEBSHELL_PATTERNS = _WAF.WEBSHELL_PATTERNS

    # 异常评分阈值（对标 OWASP CRS 默认 5）：单请求各特征命中累加，总分 ≥ 此值才判为攻击请求。
    # 单个弱信号（仅扫描器 UA=2 / 仅 4xx=1）分不够，不误报；强特征（SQLi/RCE=5）单独即触发。
    ANOMALY_THRESHOLD = 5
    # 各特征评分权重（借 CRS 思想：payload 强特征高分，行为/上下文弱信号低分，叠加才定性）
    SCORE_SQLI = 5
    SCORE_RCE = 5          # 命令注入
    SCORE_TRAVERSAL = 5
    SCORE_XSS = 5          # XSS 也是明确攻击 payload（CRS 里同为 critical），单独命中即应触发
    SCORE_WEBSHELL = 5
    SCORE_SENSITIVE_PATH = 3   # 敏感路径探测（仅 4xx 计分，见下）
    SCORE_SCANNER_UA = 2       # 扫描器 UA（弱信号，单独不足以定性）
    SCORE_4XX = 1              # 4xx 响应（弱信号）

    def detect_scored(self, request_data: Dict[str, Any]):
        """检测单请求（OWASP CRS 式异常评分）。返回 (info_or_None, raw_score)：
        raw_score=各特征加权累加的原始分（含未达阈值的探测信号，供漏桶累积用）；
        总分 ≥ 阈值 → info 为攻击详情 dict，否则 info=None。

        参数: request_data = {method, path, query, headers, body, source_ip, status, timestamp}
        返回: 攻击检测结果 dict（含 attack_type/severity/description/evidence/confidence/score），
              总分不足阈值 → None（不误报正常请求）。

        设计（解决误报根因）：
        - payload 强特征（SQLi/RCE/遍历/XSS/webshell）打任何接口都计分——攻击者打我们真实接口也抓。
        - 敏感路径/扫描器 UA 是弱信号，仅在 4xx（探测不存在路径）时计分，且需与其他特征叠加过阈值；
          正常操作（2xx + 无 payload）总分 0，不进桶不告警（治 /api/console 轮询、curl 验证误报）。
        """
        path = request_data.get("path", "")
        query = request_data.get("query", "")
        body = request_data.get("body", "")
        headers = request_data.get("headers", {})
        user_agent = headers.get("User-Agent", "")
        status = int(request_data.get("status", 0) or 0)
        is_4xx = 400 <= status < 500

        suspicious_content = f"{path} {query} {body}"
        score = 0
        hits = []          # [(type, severity, evidence, weight)]

        # ① SQL 注入（强特征，任何响应码都计）
        for pat in self.SQL_INJECTION_PATTERNS:
            m = pat.search(suspicious_content)
            if m:
                score += self.SCORE_SQLI
                hits.append(("SQL Injection", "high", m.group(0), self.SCORE_SQLI))
                break
        # ② 命令注入
        for pat in self.COMMAND_INJECTION_PATTERNS:
            m = pat.search(suspicious_content)
            if m:
                score += self.SCORE_RCE
                hits.append(("Command Injection", "high", m.group(0), self.SCORE_RCE))
                break
        # ③ 目录遍历
        for pat in self.PATH_TRAVERSAL_PATTERNS:
            m = pat.search(suspicious_content)
            if m:
                score += self.SCORE_TRAVERSAL
                hits.append(("Path Traversal", "high", path, self.SCORE_TRAVERSAL))
                break
        # ④ XSS
        for pat in self.XSS_PATTERNS:
            m = pat.search(suspicious_content)
            if m:
                score += self.SCORE_XSS
                hits.append(("XSS", "medium", m.group(0), self.SCORE_XSS))
                break
        # ⑤ Webshell 上传（文件上传 + webshell 文件名特征）
        if "filename=" in body or "Content-Disposition" in str(headers):
            for pat in self.WEBSHELL_PATTERNS:
                if pat.search(body):
                    score += self.SCORE_WEBSHELL
                    hits.append(("Webshell Upload", "high", body[:200], self.SCORE_WEBSHELL))
                    break
        # ⑥ 敏感路径探测（不限响应码）：正则匹配的是平台明确不存在的敏感路径（/.git、/wp-admin、
        #    /phpmyadmin、webshell 文件等），正常用户/平台自身绝不会访问 → 命中即探测信号。
        #    **注意 SPA 特性**：本平台 nginx try_files 对任何不存在路径 fallback 返 200（非 404），
        #    故不能靠 4xx 判定探测——敏感路径命中本身就是强信号，与响应码无关。
        for pat in self.SENSITIVE_PATH_PATTERNS:
            if pat.search(path):
                score += self.SCORE_SENSITIVE_PATH
                hits.append(("Sensitive Path Access", "medium", path, self.SCORE_SENSITIVE_PATH))
                break
        # ⑦ 扫描器 UA（弱信号）
        for scanner in self.SCANNER_USER_AGENTS:
            if scanner.lower() in user_agent.lower():
                score += self.SCORE_SCANNER_UA
                hits.append(("Scanner", "low", user_agent, self.SCORE_SCANNER_UA))
                break
        # ⑧ 4xx 弱信号（探测/爆破常伴大量 4xx）
        if is_4xx:
            score += self.SCORE_4XX

        # 总分不足阈值 → 不算"攻击请求"（返 None），但把原始 score 一并返回供漏桶用探测分累积
        if score < self.ANOMALY_THRESHOLD:
            return None, score

        # 定性：取命中特征里权重最高的作为主攻击类型（CRS 里最严重的决定归类）
        if hits:
            hits.sort(key=lambda h: h[3], reverse=True)
            atype, severity, evidence, _ = hits[0]
        else:
            atype, severity, evidence = "Suspicious Probe", "low", path
        info = {
            "attack_type": atype,
            "severity": severity,
            "description": "异常评分 {} (阈值 {})，命中: {}".format(
                score, self.ANOMALY_THRESHOLD, "、".join(h[0] for h in hits) or "4xx累积"),
            "evidence": evidence,
            "confidence": min(0.5 + score * 0.08, 0.99),   # 分越高置信越高
            "score": score,
        }
        return info, score

    def detect(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """兼容入口（端点手动检测用）：只返回攻击 info（未达阈值返 None）。"""
        info, _ = self.detect_scored(request_data)
        return info


# ============================================================================
# 攻击者溯源
# ============================================================================

def trace_attacker(ip: str) -> Dict[str, Any]:
    """溯源攻击者（IP 地理定位 + 指纹分析 + 威胁情报）。

    参数:
        ip: 攻击者 IP

    返回:
        {
            "ip": str,
            "country": str,
            "city": str,
            "isp": str,
            "asn": str,
            "timezone": str,
            "is_proxy": bool,
            "is_vpn": bool,
            "threat_level": "high" | "medium" | "low",
            "attack_history": int,  # 历史攻击次数
            "first_seen": float,
            "last_seen": float
        }
    """
    coll = get_repo().collection(Collections.ATTACK_ALERT)

    # 查询该 IP 的历史攻击记录（聚合条，含 hit_count）
    history = list(coll.find({"source_ip": ip}).sort("timestamp", -1).limit(200))

    geo = _geo_lookup(ip)   # 真实 GeoIP（内网/查不到则降级，见函数内）

    if not history:
        return {
            "ip": ip, "attack_history": 0, "first_seen": 0, "last_seen": 0,
            "threat_level": "low", "is_proxy": False, "is_vpn": False,
            "timezone": "Unknown", "attack_types": [], **geo,
        }

    # 真实攻击次数 = Σhit_count（聚合条各自的命中数），而非聚合记录条数
    attack_count = sum(int(h.get("hit_count", 1) or 1) for h in history)
    first_seen = min(h.get("first_seen", h.get("timestamp", 0)) or 0 for h in history)
    last_seen = max(h.get("timestamp", 0) or 0 for h in history)
    attack_types = sorted({h.get("attack_type", "") for h in history if h.get("attack_type")})

    # 威胁等级：按真实命中次数 + 攻击类型多样性综合评估
    if attack_count >= 100 or len(attack_types) >= 4:
        threat_level = "high"
    elif attack_count >= 10 or len(attack_types) >= 2:
        threat_level = "medium"
    else:
        threat_level = "low"

    return {
        "ip": ip,
        "threat_level": threat_level,
        "attack_history": attack_count,
        "attack_types": attack_types,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "is_proxy": False,        # 保留字段（威胁情报 API 未接，暂 False，前端已容错显示）
        "is_vpn": False,
        "timezone": geo.get("timezone", "Unknown"),
        **geo,                    # country/city/isp/asn（真实 GeoIP，见 _geo_lookup）
    }


# GeoIP 解析器单例（惰性开库，进程内复用；复用 kernel/recon/enrich 的 GeoLite2 能力，不造轮子）
_geo_resolver = None


def _geo_lookup(ip: str) -> Dict[str, Any]:
    """真实 GeoIP 地理定位（复用 recon/enrich 的 GeoIPResolver + external/geolite2 库）。
    内网/保留地址直接标注，公网 IP 查 GeoLite2-City（国家/城市）+ ASN（ISP/自治域）。
    库缺失/查不到 → country/isp 等降级为 Unknown（不报错）。"""
    out = {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}
    if not ip:
        return out
    # 内网/保留地址识别（GeoIP 库对私网无数据，直接标注）
    try:
        import ipaddress
        ipobj = ipaddress.ip_address(ip)
        if ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local:
            out.update({"country": "内网/保留地址", "city": "局域网",
                        "isp": "内网", "asn": "-"})
            return out
    except Exception:
        pass
    # 公网 IP：查 GeoLite2
    try:
        global _geo_resolver
        if _geo_resolver is None:
            from sentinel_platform.modules.kernel.recon.enrich import GeoIPResolver
            _geo_resolver = GeoIPResolver()
        city = _geo_resolver.city(ip) or {}
        asn = _geo_resolver.asn(ip) or {}
        if city.get("country"):
            out["country"] = city["country"]
        if city.get("city"):
            out["city"] = city["city"]
        if asn.get("org"):
            out["isp"] = asn["org"]
        if asn.get("number") is not None:
            out["asn"] = "AS{}".format(asn["number"])
    except Exception as exc:
        logger.debug("geo_lookup degraded: %s", exc)
    return out


# ============================================================================
# 攻击记录管理
# ============================================================================

def record_attack(request_data: Dict[str, Any], attack_info: Dict[str, Any]) -> str:
    """记录攻击事件。

    参数:
        request_data: 请求数据
        attack_info: 攻击检测结果

    返回:
        攻击记录 ID
    """
    coll = get_repo().collection(Collections.ATTACK_ALERT)

    doc = {
        "_id": f"attack_{int(time.time() * 1000)}_{request_data.get('source_ip', '')}",
        "source_ip": request_data.get("source_ip", ""),
        "attack_type": attack_info.get("attack_type", "Unknown"),
        "severity": attack_info.get("severity", "low"),
        "description": attack_info.get("description", ""),
        "evidence": attack_info.get("evidence", ""),
        "confidence": attack_info.get("confidence", 0.0),
        "request": {
            "method": request_data.get("method", ""),
            "path": request_data.get("path", ""),
            "query": request_data.get("query", ""),
            "headers": request_data.get("headers", {}),
            "body": request_data.get("body", "")[:500],  # 只保存前 500 字符
        },
        "timestamp": request_data.get("timestamp", time.time()),
        "traced": False,  # 是否已溯源
    }

    try:
        coll.insert_one(doc)
        logger.info(f"记录攻击事件: {doc['_id']} - {attack_info.get('attack_type')}")
        return doc["_id"]
    except Exception as exc:
        logger.error(f"记录攻击事件失败: {exc}", exc_info=True)
        return ""


def list_attacks(page: int = 1, size: int = 20, filters: Optional[Dict[str, Any]] = None,
                 sort_order: str = "desc") -> Dict[str, Any]:
    """列出攻击记录。

    参数:
        page: 页码
        size: 每页数量
        filters: 筛选条件 {attack_type, severity, source_ip, start_time, end_time}
        sort_order: 按最近时间(timestamp)排序方向，desc=新→旧(默认)/asc=旧→新（前端点击"最近时间"列切换）

    返回:
        {"items": [...], "total": int, "page": int, "size": int}
    """
    coll = get_repo().collection(Collections.ATTACK_ALERT)

    query = {}
    if filters:
        if filters.get("attack_type"):
            query["attack_type"] = filters["attack_type"]
        if filters.get("severity"):
            query["severity"] = filters["severity"]
        if filters.get("source_ip"):
            query["source_ip"] = filters["source_ip"]
        if filters.get("start_time") or filters.get("end_time"):
            query["timestamp"] = {}
            if filters.get("start_time"):
                query["timestamp"]["$gte"] = filters["start_time"]
            if filters.get("end_time"):
                query["timestamp"]["$lte"] = filters["end_time"]

    total = coll.count_documents(query)
    direction = 1 if str(sort_order).lower() == "asc" else -1   # 默认 desc（新→旧）
    items = list(coll.find(query).sort("timestamp", direction).skip((page - 1) * size).limit(size))

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size
    }


def get_attack_stats() -> Dict[str, Any]:
    """获取攻击统计信息。

    返回:
        {
            "total_attacks": int,
            "today_attacks": int,
            "by_type": {attack_type: count},
            "by_severity": {severity: count},
            "top_attackers": [{ip, count}],
            "recent_attacks": [...]
        }
    """
    coll = get_repo().collection(Collections.ATTACK_ALERT)

    # 统计口径：记录是聚合条（一条含 hit_count 次真实命中）。累计攻击=Σhit_count（真实请求次数），
    # 而非聚合记录数——否则扫描器打几百次只显 8，与直觉不符（用户反馈"累计攻击只有8"）。
    def _sum_hits(match=None):
        pipe = ([{"$match": match}] if match else []) + [
            {"$group": {"_id": None, "n": {"$sum": {"$ifNull": ["$hit_count", 1]}}}}]
        r = list(coll.aggregate(pipe))
        return int(r[0]["n"]) if r else 0

    total_attacks = _sum_hits()
    today_start = time.time() - 86400
    today_attacks = _sum_hits({"timestamp": {"$gte": today_start}})

    # 按类型统计（累加 hit_count）
    type_pipeline = [
        {"$group": {"_id": "$attack_type", "count": {"$sum": {"$ifNull": ["$hit_count", 1]}}}},
        {"$sort": {"count": -1}}
    ]
    by_type = {item["_id"]: item["count"] for item in coll.aggregate(type_pipeline)}

    # 按严重程度统计（累加 hit_count）
    severity_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": {"$ifNull": ["$hit_count", 1]}}}}
    ]
    by_severity = {item["_id"]: item["count"] for item in coll.aggregate(severity_pipeline)}

    # Top 攻击者（累加 hit_count）
    attacker_pipeline = [
        {"$group": {"_id": "$source_ip", "count": {"$sum": {"$ifNull": ["$hit_count", 1]}}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    top_attackers = [{"ip": item["_id"], "count": item["count"]} for item in coll.aggregate(attacker_pipeline)]

    # 最近攻击
    recent_attacks = list(coll.find().sort("timestamp", -1).limit(10))

    return {
        "total_attacks": total_attacks,
        "today_attacks": today_attacks,
        "by_type": by_type,
        "by_severity": by_severity,
        "top_attackers": top_attackers,
        "recent_attacks": recent_attacks
    }


# ============================================================================
# 方案 B'：nginx 日志流分析（docker logs -f 读 nginx stdout → 解析 → 检测 → 聚合落库）
# ============================================================================

# nginx combined 日志格式：
# IP - - [10/Sep/2026:16:34:35 +0800] "GET /path?q=x HTTP/1.1" 200 130 "referer" "UA" "-"
_NGINX_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) [^"]*" '
    r'(?P<status>\d+) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


def parse_nginx_log_line(line: str) -> Optional[Dict[str, Any]]:
    """解析一条 nginx combined 日志行 → request_data（喂给 AttackDetector）。
    解析失败返 None（非请求行/格式不符，跳过）。"""
    m = _NGINX_LINE_RE.match(line.strip())
    if not m:
        return None
    uri = m.group("uri") or "/"
    path, _, query = uri.partition("?")
    try:
        dpath = unquote(path)
    except Exception:
        dpath = path
    return {
        "method": m.group("method"),
        "path": dpath,
        "query": unquote(query) if query else "",
        "headers": {"User-Agent": m.group("ua") or ""},
        "body": "",
        "source_ip": m.group("ip"),
        "status": int(m.group("status") or 0),
        "timestamp": time.time(),
    }


# 聚合去重窗口：同 (IP + attack_type) 在窗口内不重复插入新行，只累加 hit_count（防扫描器刷屏撑爆库）。
_AGG_WINDOW_SEC = 600      # 10 分钟窗口
_local_agg_seen: Dict[str, float] = {}   # 进程内快查（减少 DB 命中）；权威仍是 DB upsert


# —— 攻击告警推送（需求5）：同 IP 5 分钟内不重复推 ——
# 攻击监控靠 MongoDB 单例锁（_try_acquire_lock），跨 worker 只有一个进程真跑并调 record_attack_agg，
# 故进程内 dict[ip]->last_push_ts 去重是安全的（无多 worker 分裂问题）。
_ATTACK_PUSH_TTL = 300                       # 5 分钟
_attack_push_seen: Dict[str, float] = {}     # ip -> 上次推送时间戳


def _attack_alert_enabled() -> bool:
    """攻击告警推送开关（默认开）：复用 api_keys 飞书渠道 attack_alert_notify 字段。
    只有显式 False 才算关（存量未存该字段 get_key 返 "" → 按默认开，用 is not False 判定）。"""
    try:
        keys = get_registry().get("api_keys_service")
        if keys and hasattr(keys, "get_key"):
            cfg = keys.get_key("feishu") or {}
            return cfg.get("attack_alert_notify", True) is not False
    except Exception as exc:
        logger.debug("attack alert switch degraded: %s", exc)
    return True


def _notify_attack(doc: Dict[str, Any]) -> None:
    """推送攻击告警（攻击者 IP + 详情），经 ROLE.NOTIFY；同 IP 5 分钟去重 + 开关控制，缺失降级不崩。"""
    if not _attack_alert_enabled():
        return
    ip = doc.get("source_ip", "") or "unknown"
    now = time.time()
    last = _attack_push_seen.get(ip, 0)
    if now - last < _ATTACK_PUSH_TTL:
        return                                # 同 IP 5 分钟内已推过，跳过
    svc = get_registry().get(ROLE.NOTIFY)
    if not svc:
        return
    _attack_push_seen[ip] = now
    if len(_attack_push_seen) > 500:          # 防内存增长，清过期项
        for k in [k for k, t in _attack_push_seen.items() if now - t > _ATTACK_PUSH_TTL]:
            _attack_push_seen.pop(k, None)
    try:
        lines = [
            "🚨 检测到攻击行为",
            "攻击者 IP：{}".format(ip),
            "攻击类型：{}".format(doc.get("attack_type", "Unknown")),
            "严重程度：{}".format(doc.get("severity", "low")),
            "命中次数：{}".format(doc.get("hit_count", 1)),
            "最近路径：{}".format(doc.get("last_path", "") or "-"),
        ]
        desc = doc.get("description", "")
        if desc:
            lines.append("描述：{}".format(desc))
        svc.notify("\n".join(lines), title="攻击告警", level="error")
    except Exception as exc:
        logger.debug("attack notify failed: %s", exc)


def record_attack_agg(request_data: Dict[str, Any], attack_info: Dict[str, Any]) -> str:
    """聚合去重落库：同 IP+攻击类型 在窗口内 upsert 累加 hit_count（首次插入，之后累加）。
    治扫描器几千请求刷几千告警——一次扫描聚合成一条（带命中计数 + 最近样本路径）。"""
    coll = get_repo().collection(Collections.ATTACK_ALERT)
    ip = request_data.get("source_ip", "")
    atype = attack_info.get("attack_type", "Unknown")
    now = time.time()
    win = int(now // _AGG_WINDOW_SEC)                 # 窗口编号（同窗口聚合，跨窗口新起一条）
    agg_id = f"agg_{win}_{atype}_{ip}".replace(" ", "_")

    try:
        coll.update_one(
            {"_id": agg_id},
            {
                "$setOnInsert": {
                    "source_ip": ip,
                    "attack_type": atype,
                    "severity": attack_info.get("severity", "low"),
                    "description": attack_info.get("description", ""),
                    "confidence": attack_info.get("confidence", 0.0),
                    "first_seen": now,
                    "traced": False,
                },
                "$set": {
                    "evidence": attack_info.get("evidence", ""),   # 最近一次命中样本
                    "last_path": request_data.get("path", ""),
                    "timestamp": now,                              # 最近命中时间（列表按此排序）
                    "request": {
                        "method": request_data.get("method", ""),
                        "path": request_data.get("path", ""),
                        "query": request_data.get("query", "")[:200],
                        "headers": request_data.get("headers", {}),
                        "body": "",
                    },
                },
                "$inc": {"hit_count": 1},                          # 累计命中次数
            },
            upsert=True,
        )
        # 攻击告警推送（需求5）：同 IP 5 分钟去重 + 开关控制，best-effort 不影响落库
        _notify_attack({
            "source_ip": ip, "attack_type": atype,
            "severity": attack_info.get("severity", "low"),
            "description": attack_info.get("description", ""),
            "hit_count": attack_info.get("hit_count", 1),
            "last_path": request_data.get("path", ""),
        })
        return agg_id
    except Exception as exc:
        logger.error(f"聚合记录攻击失败: {exc}", exc_info=True)
        return ""


# ── CrowdSec 式漏桶（Leaky Bucket）：行为层检测 + 自动封禁触发信号 ──
# 每个 IP 一个桶，"攻击请求"往桶里丢一滴，桶按 LEAK_RATE 匀速漏。短时密集攻击 → 桶超容量 → 溢出。
# 优于滑窗计数：自然区分"持续密集攻击"(溢出)和"偶发"(漏干)，慢速扫描不误触发、快速爆破立即溢出。
# 桶溢出 = ①产生行为告警 ②触发自动封禁。参数默认 容量5 / 每10秒漏1（≈短时5次攻击溢出）。
BUCKET_CAPACITY = 5           # 桶容量：攒到这么多滴未漏完 → 溢出
BUCKET_LEAK_RATE = 0.1        # 漏速：每秒漏 0.1 滴（= 每 10 秒漏 1 滴）
_buckets: Dict[str, Dict[str, float]] = {}   # ip -> {level, last_ts}（进程内；监控单例，无多worker分裂）


def _bucket_add(ip: str, now: float, drops: float = 1.0) -> bool:
    """往 IP 漏桶加 drops 滴（先按时间漏水再加）。返回本次是否溢出（≥容量）。"""
    b = _buckets.get(ip)
    if b is None:
        b = {"level": 0.0, "last_ts": now}
        _buckets[ip] = b
    elapsed = max(0.0, now - b["last_ts"])
    b["level"] = max(0.0, b["level"] - elapsed * BUCKET_LEAK_RATE)   # 先漏
    b["last_ts"] = now
    b["level"] += drops                                             # 再加
    if b["level"] >= BUCKET_CAPACITY:
        b["level"] = 0.0        # 溢出后清空重新蓄，避免持续溢出刷屏（下一轮攒满再触发）
        return True
    return False


_NGINX_CONTAINER = "docker-nginx-1"   # VM/生产 compose 默认命名（同 _updater._safe_restart_worker 口径）
_monitor_started = False
_LOCK_ID = "attack_alert_monitor"     # MongoDB 单例锁（跨 gunicorn 多 worker 只跑一个监控）
_LOCK_TTL = 45                        # 锁有效期（秒）；持有者每 15s 续期，进程死后 45s 锁过期可被接管


def _try_acquire_lock(owner: str) -> bool:
    """抢占/续期监控单例锁。返回是否持有（本进程是唯一监控者）。
    机制：锁文档带 expire_at；抢占条件=不存在 或 已过期 或 自己持有。多 worker 竞争只一个成功。
    锁存独立集合（_locks），不污染 ATTACK_ALERT 的攻击记录查询/统计。"""
    try:
        coll = get_repo().collection("attack_alert_locks")
        now = time.time()
        r = coll.update_one(
            {"_id": _LOCK_ID,
             "$or": [{"owner": owner}, {"expire_at": {"$lt": now}}]},
            {"$set": {"owner": owner, "expire_at": now + _LOCK_TTL, "kind": "_lock"}},
            upsert=False,
        )
        if r.modified_count or r.matched_count:
            return True
        # 文档不存在→尝试插入（首个抢占者）；并发下唯一 _id 保证只一个成功
        try:
            coll.insert_one({"_id": _LOCK_ID, "owner": owner,
                             "expire_at": now + _LOCK_TTL, "kind": "_lock"})
            return True
        except Exception:
            return False
    except Exception:
        return False


def _monitor_loop(owner: str):
    """后台线程：轮询 docker logs --since 拉 nginx 增量日志，逐行解析→检测→聚合落库。
    方案 B'：不改 nginx.conf/compose，纯代码热更；依赖 web 容器已挂载的 /var/run/docker.sock。
    **用轮询而非 -f**：docker logs -f（follow 流）在本环境 daemon 读日志文件写入中间态会崩
    （'invalid character \\x00'），改每 poll_interval 秒拉一次 --since（非 follow，稳定）。
    单例：靠 MongoDB 锁保证多 gunicorn worker 只一个真跑（抢不到的等待接管）。
    去重：拉取窗口有重叠防漏，靠「已处理行指纹集」保证同一条日志只处理一次（防爆破计数重复累加）。"""
    import subprocess
    detector = AttackDetector()
    poll_interval = 5              # 每 5s 拉一次
    tail_n = 400                   # 每次拉最近 N 行（--tail 在本环境稳定，--since/-f 均失效见踩坑注释）
    seen_lines: dict = {}          # 行指纹 -> 处理时间；防重叠重复处理（尤其爆破计数）
    logged_start = False
    while True:
        # 抢锁：抢不到=别的 worker 在监控，本 worker 静默等待（随时准备接管挂掉的持有者）
        if not _try_acquire_lock(owner):
            time.sleep(30)
            continue
        if not logged_start:
            logger.info("attack_alert 日志监控已启动（轮询 docker logs --tail %d %s，%ss/次）", tail_n, _NGINX_CONTAINER, poll_interval)
            logged_start = True
        try:
            # **用 --tail 而非 --since/-f**：本环境 docker daemon 的 --since（时区错乱恒返 0 行）
            # 与 -f（follow 流遇日志写入中间态崩 '\x00'）均不可靠，只有 --tail（按行数）稳定。
            # 每次拉最近 tail_n 行，靠 seen_lines 行指纹去重跳过已处理的（含时间戳，同一行只处理一次）。
            r = subprocess.run(
                ["docker", "logs", "--tail", str(tail_n), _NGINX_CONTAINER],
                capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=15,
            )
            nowp = time.time()
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                # 行去重：同一条原始日志行（含时间戳）只处理一次（重叠窗口会重复拉到）
                fp = hash(line)
                if fp in seen_lines:
                    continue
                seen_lines[fp] = nowp
                rd = parse_nginx_log_line(line)
                if not rd:
                    continue
                ip = rd.get("source_ip", "")
                # 内网/保留地址（docker 网关 172.x、宿主/局域网 192.168.x、环回）：平台自身基础设施
                # 与可信运维访问，绝非公网攻击者 → 不检测、不进桶、不封禁（治 curl/内部调用误报 +
                # 自动封禁 docker 网关自锁事故）。白名单 IP 同样跳过（用户维护）。
                if is_internal_ip(ip) or is_whitelisted(ip):
                    continue
                # ① 单请求 CRS 异常评分（返回 info(达攻击阈值) 或 None，raw_score=原始分含未达阈值的探测信号）
                info, raw_score = detector.detect_scored(rd)
                if info:
                    record_attack_agg(rd, info)
                # ② 进 IP 漏桶：达攻击阈值滴 2 滴（强特征快溢出）；未达阈值但有探测分（敏感路径+3，
                #    或扫描器UA+4xx=3，如 dirsearch 狂扫敏感路径/爆破探测）滴 1 滴——累积必溢出，抓"扫描行为"。
                #    **阈值 3 而非 2**：单独一个扫描器 UA（+2）在正常 2xx 请求上不进桶——curl / python-requests /
                #    go-http-client / wget 都命中 SCANNER_UA_KEYWORDS，正常内部/客户端调用不该被当扫描累积
                #    （对齐 detect_scored 文档"2xx + 无 payload 总分不进桶"的设计，治 curl 验证误报根因）。
                #    真扫描器一定伴随敏感路径命中或大量 4xx，raw_score≥3 仍会进桶，不漏抓。
                drops = 0.0
                if info:
                    drops = 2.0
                elif raw_score >= 3:      # 有探测嫌疑（敏感路径命中/扫描器UA+4xx/多个弱信号叠加）
                    drops = 1.0
                if drops and _bucket_add(ip, nowp, drops):
                    # ③ 桶溢出 = 持续密集攻击/扫描确认 → 行为告警 + 自动封禁
                    overflow = {
                        "attack_type": "Sustained Attack",
                        "severity": "high",
                        "description": "IP 漏桶溢出（短时密集攻击/扫描），已自动封禁",
                        "evidence": "最近: {} {}".format(rd.get("method", ""), rd.get("path", "")),
                        "confidence": 0.95,
                    }
                    record_attack_agg(rd, overflow)
                    auto_ban_ip(ip, reason="漏桶溢出（短时密集攻击自动封禁）")
            # 清理指纹集（保留最近 60s，防无限增长；比 since 窗口大即可）
            cutoff = nowp - 60
            for k in [k for k, v in seen_lines.items() if v < cutoff]:
                seen_lines.pop(k, None)
        except Exception as exc:
            logger.debug("attack_alert 日志轮询异常: %s", exc)
        time.sleep(poll_interval)


def start_monitor() -> bool:
    """启动日志监控后台线程（幂等，进程内只起一个；跨进程/多 worker 靠 MongoDB 锁保证只一个真跑）。
    须在挂载了 docker.sock 的进程调用（web 容器）——docker CLI/sock 不可用则降级不启动，返 False。
    每个 gunicorn worker 都会调它并起线程，但只有抢到 MongoDB 锁的那个真正读日志，其余空转等待接管。"""
    global _monitor_started
    if _monitor_started:
        return True
    import shutil
    if not shutil.which("docker") or not os.path.exists("/var/run/docker.sock"):
        logger.warning("attack_alert 日志监控未启动：无 docker CLI 或 docker.sock（非 docker 部署/未挂 sock 降级）")
        return False
    import threading
    # owner 唯一标识：主机名+PID+线程，用于 MongoDB 锁归属判定
    owner = "{}:{}".format(os.uname().nodename if hasattr(os, "uname") else "host", os.getpid())
    t = threading.Thread(target=_monitor_loop, args=(owner,), name="attack-alert-monitor", daemon=True)
    t.start()
    _monitor_started = True
    logger.info("attack_alert 日志监控线程已派发（owner=%s，抢锁后真跑）", owner)
    return True


# ============================================================================
# 封禁 / 白名单（CrowdSec 式「决策层」，与检测分离）
# ============================================================================

AUTO_BAN_TTL = 24 * 3600      # 自动封禁默认时长：24 小时后自动解封（手动封禁可设永久）
_wl_cache = {"ips": set(), "ts": 0.0}   # 白名单进程内缓存（5s TTL，减少每条日志查库）


def is_internal_ip(ip: str) -> bool:
    """源 IP 是否为内网/保留地址（RFC1918 私网 / 环回 / 链路本地）。

    这类 IP 只会是平台自身基础设施（docker 网桥网关 172.x、宿主/局域网网关 192.168.x）
    或可信运维内网访问，绝非公网攻击者。检测/漏桶/封禁一律跳过——否则把平台自身流量、
    运维访问、内部服务调用（curl / python-requests / go-http-client 等客户端）误判为攻击，
    甚至自动封禁 docker 网关导致所有经反代的流量被 403 锁死（实测事故根因）。
    与 _geo_lookup 对私网标注「内网/保留地址」的口径保持一致。

    部署注意：若平台前置了「私网地址的反向代理/负载均衡」，nginx 必须配 real_ip 让检测拿到
    真实公网客户端 IP，否则内网段一律视为可信（本设计宁可对内网漏报，也不自锁基础设施）。
    """
    if not ip:
        return False
    try:
        import ipaddress
        o = ipaddress.ip_address(ip)
        return bool(o.is_private or o.is_loopback or o.is_link_local)
    except Exception:
        return False


def is_whitelisted(ip: str) -> bool:
    """IP 是否在白名单（用户维护）。带 5s 进程内缓存（监控每条日志都查，避免频繁打库）。"""
    if not ip:
        return False
    now = time.time()
    if now - _wl_cache["ts"] > 5:
        try:
            coll = get_repo().collection(Collections.ATTACK_WHITELIST)
            _wl_cache["ips"] = {d["_id"] for d in coll.find({}, {"_id": 1})}
            _wl_cache["ts"] = now
        except Exception:
            pass
    return ip in _wl_cache["ips"]


def is_banned(ip: str) -> bool:
    """IP 是否处于封禁中（未过期）。供 Flask 网关 before_request 调用拦截。
    内网/保留地址直接放行：即便库里残留旧的误封记录（本次修复前自动封的 docker 网关等），
    网关侧也不再拦截，彻底根治「基础设施被误封→经反代流量全 403」的自锁。"""
    if not ip or is_internal_ip(ip):
        return False
    try:
        coll = get_repo().collection(Collections.ATTACK_BANLIST)
        doc = coll.find_one({"_id": ip})
        if not doc:
            return False
        exp = doc.get("expire_at")
        if exp and exp < time.time():      # 已过期 → 惰性删除，视为未封
            coll.delete_one({"_id": ip})
            return False
        return True
    except Exception:
        return False


def auto_ban_ip(ip: str, reason: str = "") -> bool:
    """自动封禁（漏桶溢出触发）。内网/保留地址与白名单 IP 不封；默认 24h 后自动解封。幂等 upsert。
    内网兜底：封禁 docker 网关（172.x）会锁死所有经反代的流量（自锁事故），故基础设施 IP 绝不自动封。"""
    if not ip or is_internal_ip(ip) or is_whitelisted(ip):
        return False
    try:
        now = time.time()
        get_repo().collection(Collections.ATTACK_BANLIST).update_one(
            {"_id": ip},
            {"$setOnInsert": {"ban_type": "auto", "banned_at": now, "operator": "system"},
             "$set": {"reason": reason or "自动封禁", "expire_at": now + AUTO_BAN_TTL}},
            upsert=True)
        logger.warning("attack_alert 自动封禁 IP=%s reason=%s", ip, reason)
        return True
    except Exception as exc:
        logger.error("auto_ban_ip 失败: %s", exc)
        return False


def ban_ip(ip: str, operator: str = "", reason: str = "", permanent: bool = True) -> Dict[str, Any]:
    """手动封禁。permanent=True 永久（expire_at=None），否则默认 24h。"""
    if not ip:
        return {"error": "ip 必填"}
    try:
        now = time.time()
        doc = {"ban_type": "manual", "banned_at": now, "operator": operator or "manual",
               "reason": reason or "手动封禁", "expire_at": None if permanent else now + AUTO_BAN_TTL}
        get_repo().collection(Collections.ATTACK_BANLIST).update_one(
            {"_id": ip}, {"$set": doc}, upsert=True)
        logger.warning("attack_alert 手动封禁 IP=%s by=%s", ip, operator)
        return {"ok": True, "ip": ip}
    except Exception as exc:
        return {"error": str(exc)[:120]}


def unban_ip(ip: str) -> Dict[str, Any]:
    """手动解封（删封禁记录）。"""
    try:
        get_repo().collection(Collections.ATTACK_BANLIST).delete_one({"_id": ip})
        _buckets.pop(ip, None)          # 顺带清空该 IP 漏桶，避免解封后残留水位又秒溢出
        logger.info("attack_alert 解封 IP=%s", ip)
        return {"ok": True, "ip": ip}
    except Exception as exc:
        return {"error": str(exc)[:120]}


def list_bans(page: int = 1, size: int = 50) -> Dict[str, Any]:
    """列出当前封禁 IP（惰性剔除已过期的）。"""
    try:
        coll = get_repo().collection(Collections.ATTACK_BANLIST)
        now = time.time()
        coll.delete_many({"expire_at": {"$ne": None, "$lt": now}})   # 清过期
        total = coll.count_documents({})
        items = list(coll.find({}).sort("banned_at", -1).skip((page - 1) * size).limit(size))
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        return {"items": [], "total": 0, "error": str(exc)[:120]}


def add_whitelist(ip: str, operator: str = "", note: str = "") -> Dict[str, Any]:
    """加白名单（用户手动输入 / 攻击记录一键加白）。加白同时解除该 IP 现有封禁。"""
    if not ip:
        return {"error": "ip 必填"}
    try:
        get_repo().collection(Collections.ATTACK_WHITELIST).update_one(
            {"_id": ip},
            {"$set": {"operator": operator or "manual", "note": note, "added_at": time.time()}},
            upsert=True)
        _wl_cache["ts"] = 0.0                     # 失效缓存，下次即时生效
        unban_ip(ip)                              # 白名单优先：解除现有封禁
        logger.info("attack_alert 加白名单 IP=%s by=%s", ip, operator)
        return {"ok": True, "ip": ip}
    except Exception as exc:
        return {"error": str(exc)[:120]}


def del_whitelist(ip: str) -> Dict[str, Any]:
    """移出白名单。"""
    try:
        get_repo().collection(Collections.ATTACK_WHITELIST).delete_one({"_id": ip})
        _wl_cache["ts"] = 0.0
        return {"ok": True, "ip": ip}
    except Exception as exc:
        return {"error": str(exc)[:120]}


def list_whitelist(page: int = 1, size: int = 100) -> Dict[str, Any]:
    """列出白名单。"""
    try:
        coll = get_repo().collection(Collections.ATTACK_WHITELIST)
        total = coll.count_documents({})
        items = list(coll.find({}).sort("added_at", -1).skip((page - 1) * size).limit(size))
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        return {"items": [], "total": 0, "error": str(exc)[:120]}


