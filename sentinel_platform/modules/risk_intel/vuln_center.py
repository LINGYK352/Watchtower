"""risk_intel/vuln_center —— 漏洞中心（实现 FINDING / FindingService）。

三来源漏洞统一治理：AI 渗透（intel_finding）+ 哨兵 PoC（vuln）+ Nuclei（nuclei_result）混排。
核心能力：
  - 证据强制：verified 仅在工具实抓「请求 + 正向响应」（confirmed）时为真，否则降 lead（治假验证）。
  - CVSS 3.1 定级 + triage 校准（信息型/指纹型降级，向量硬闸防误降真漏洞）——见 `_cvss.py`。
  - 三来源混排查询/标记/统计（供漏洞中心前端页），四状态（已验证/线索/未处理/误报，默认藏误报）。
  - 出洞推送：verified 漏洞经 registry 调 NOTIFY（缺失降级，不硬 import notify 模块）。

迁移来源：app/services/finding.py + utils/cvss.py + finding_template.py（逻辑规格，净室重写）。
**签名对齐冻结契约**（INTERFACES §二 FINDING）：
  - `record_finding(finding: dict) -> dict{ok,id?,dup}`：单条登记（幂等 norm_target+norm_type）；
    finding 传 `md_text` 时切换为「批量解析报告 md 登记」（session 收尾用，返回聚合摘要）。
  - `is_identify_poc(plg_name, vul_name) -> bool`：纯判定，识别类 PoC（指纹）不入漏洞库。
查询/标记/统计（list_unified_findings/mark_unified/finding_stat 等）非 Protocol 方法，
作 Impl 扩展方法 + 模块级函数供 `router/endpoints/risk_intel.py` 调。不放 HTTP 路由。

bson.ObjectId 惰性 import（对齐 core/db.py 惰性 pymongo 范式）——单测走 fake repo + 字符串 _id
不触发；真实部署 Linux 有 pymongo（wheel 已入 vendor/wheels）。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import get_registry, ROLE, Collections
from . import _cvss

logger = get_logger()

COLL = Collections.INTEL_FINDING

# 证据强制：能证明漏洞真实存在的"验证类"工具（真发包/真跑 PoC，产出请求+响应）。
VERIFY_TOOLS = {"http_request", "run_nuclei", "run_npoc"}
# 三来源混排可选值（poc=PoC 插件命中，nuclei=nuclei 扫描，ai=AI 渗透已验证）
UNIFIED_SOURCES = ("ai", "poc", "nuclei")
# 漏洞处理状态合法值：""(未处理)/ submitted(已提交)/ false_positive(误报)
HANDLE_STATUSES = ("", "submitted", "false_positive")

def _host_of(url_or_target: str) -> str:
    """从 URL/target 提取 host（去 scheme/port/path），用于宽松匹配 finding 与工具调用。"""
    s = (url_or_target or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("@")[-1].split(":")[0]
    return s


def _norm_target_for_dedup(target: str) -> str:
    """漏洞 target 归一化（去重键用）：去 scheme（协议无关）、剥 www、去 query/fragment、去末尾斜杠；
    保留 path（不同路径是不同漏洞点）与端口（不同端口常是不同服务）。"""
    s = (target or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("#")[0].split("?")[0]
    host_seg = s.split("/", 1)[0]
    if host_seg.startswith("www.") and host_seg.split(":")[0].count(".") >= 2:
        s = s[4:]
    return s.rstrip("/")


def _norm_vuln_type(vuln_type: str) -> str:
    """漏洞类型归一化（去重键用）：吸收 AI 措辞微差（空白/标点/大小写/常见分类前缀）。"""
    s = (vuln_type or "").strip().lower()
    s = re.sub(r"^(信息泄露|敏感信息泄露|漏洞|风险|缺陷|配置缺陷)[\s\-:：]+", "", s)
    s = re.sub(r"[\s\-_:：、,，.。()（）\[\]【】]+", "", s)
    return s


def _result_obj(res: Any) -> Dict[str, Any]:
    """tool_log 里的 result 是 dispatch 返回的 JSON 字符串，解析回 dict；失败返回 {}。"""
    if isinstance(res, dict):
        return res
    if isinstance(res, str):
        try:
            return json.loads(res)
        except Exception:
            return {}
    return {}


def _positive_signal(tool_name: str, result: Any) -> str:
    """判一次验证工具调用响应是否「正向」：positive / negative / unknown。只做客观信号判断。"""
    r = _result_obj(result)
    if r.get("error"):
        return "negative"
    if tool_name == "http_request":
        if r.get("partial"):
            return "unknown"               # §1.1：读取超时/中断/部分响应一律保留 lead，不当证据
        sc = r.get("status_code")
        if sc is None or not isinstance(sc, int):
            return "unknown"
        if 400 <= sc <= 404 or sc == 429:
            return "negative"
        if sc >= 500:                      # 5xx=WAF/代理/后端崩，不能证明漏洞存在（旧坑：503 误判 verified）
            return "unknown"
        if r.get("body_skipped"):
            return "unknown"               # 大文件/二进制未读 body：能访问 ≠ 拿到敏感内容
        body = r.get("body") or ""
        if len((body or "").strip()) < 50:
            return "unknown"               # 空响应/极短默认页不算证据
        return "positive"
    if tool_name in ("run_nuclei", "run_npoc"):
        try:
            return "positive" if int(r.get("count", 0)) > 0 else "negative"
        except (TypeError, ValueError):
            return "unknown"
    return "unknown"


def match_evidence(finding: Dict[str, Any], tool_log: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """为一条 finding 在 tool_log 里找支撑它的验证工具调用（证据强制核心）。

    匹配：VERIFY_TOOLS + 调用 url 归一化端点（host+path）**精确相等**命中 finding.target 端点
    （父路径不挂子路径，防 /api 误挂 /api/user/list）。
    返回 (evidence_level, evidence)：confirmed(有正向证据)/attempted(打过但否定)/none。
    """
    if not tool_log:
        return "none", []
    fhost = _host_of(finding.get("target", ""))
    if not fhost:
        return "none", []
    fnorm = _norm_target_for_dedup(finding.get("target", ""))

    def _endpoint_match(cand: str) -> bool:
        if _host_of(cand) != fhost:
            return False
        return fnorm == _norm_target_for_dedup(cand)

    hits: List[Dict[str, Any]] = []
    any_attempt = False
    for t in tool_log:
        name = t.get("name") or t.get("tool") or ""
        if name not in VERIFY_TOOLS:
            continue
        args = t.get("arguments") or t.get("input") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        cand = args.get("url") or args.get("target") or ""
        if not _endpoint_match(cand):
            continue
        any_attempt = True
        raw = t.get("result") or t.get("output")
        signal = _positive_signal(name, raw)
        if signal == "positive":
            hits.append({
                "tool": name, "arguments": args,
                "result": raw[:4000] if isinstance(raw, str) else raw,
                "signal": signal,
            })
    if hits:
        return "confirmed", hits[:5]
    if any_attempt:
        return "attempted", []
    return "none", []


# ---------------- 报告 md 解析（AI 会话收尾批量登记用） ----------------

_HEADER_RE = re.compile(r"^###\s+(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*$", re.M)
_TARGET_RE = re.compile(r"^-\s*目标[:：]\s*(.+?)\s*$", re.M)
_IMPACT_RE = re.compile(r"^-\s*危害[:：]\s*(.+?)\s*$", re.M)
_VERIFY_RE = re.compile(r"^-\s*验证方式[:：]\s*(.+?)\s*$", re.M)
_KEYRESP_RE = re.compile(r"^-\s*关键响应[:：]\s*(.+?)\s*$", re.M)

_SEVERITY_MAP = {
    "critical": "critical", "严重": "critical", "高危": "high", "high": "high",
    "中危": "medium", "medium": "medium", "低危": "low", "low": "low",
    "信息": "info", "info": "info", "informational": "info",
}


def _norm_severity(s: str) -> str:
    return _SEVERITY_MAP.get((s or "").strip().lower(), (s or "").strip() or "unknown")


def _grade(mid_field: str, vuln_type: str = "", impact: str = "") -> Tuple[str, Optional[float], str, str, str]:
    """解析标题第二段 → (cvss_vector, cvss_score, cvss_severity, calibrated_severity, basis)。
    第二段是 CVSS 3.1 向量 → 代码算分（权威）；旧格式文字等级 → cvss 留空走文字归一化（标 legacy）。"""
    raw = (mid_field or "").strip()
    if _cvss.is_valid_vector(raw):
        score, sev = _cvss.score_from_vector(raw)
        vec = raw if raw.upper().startswith("CVSS:") else "CVSS:3.1/" + raw
        cal_sev, basis = _cvss.calibrate_severity(sev, score, vuln_type, impact, vector=vec)
        return vec, score, sev, cal_sev, basis
    sev = _norm_severity(raw)
    cal_sev, basis = _cvss.calibrate_severity(sev, None, vuln_type, impact)
    return "", None, sev, cal_sev, basis


def parse_findings_md(md_text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """从渗透报告 md 的 `## 漏洞` 板块解析漏洞条目。返回 (findings, errors)。
    解析容错铁律：抓不到的标 parse_error 不静默丢（格式漂移要看得见）。"""
    if not md_text:
        return [], []
    m = re.search(r"^##\s*漏洞\s*$(.*?)(?=^##\s|\Z)", md_text, re.M | re.S)
    section = m.group(1) if m else md_text

    findings: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    all_h3 = re.findall(r"^###\s+.+$", section, re.M)
    headers = list(_HEADER_RE.finditer(section))
    matched_lines = {h.group(0) for h in headers}
    for line in all_h3:
        if line.strip() not in matched_lines and not _HEADER_RE.match(line.strip()):
            errors.append({"block": line[:120], "reason": "### 标题非三段式(时间|等级|类型)，解析跳过"})
    if not headers:
        return [], errors
    for i, h in enumerate(headers):
        start = h.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(section)
        body = section[start:end]
        time_s, sev_s, type_s = h.group(1), h.group(2), h.group(3)
        tgt = _TARGET_RE.search(body)
        code = re.search(r"```(?:\w+)?\n(.*?)```", body, re.S)
        poc_s = code.group(1).strip() if code else ""
        if tgt:
            target_s = tgt.group(1).strip()
        else:
            url_m = re.search(r"https?://[^\s'\"`)]+", poc_s)
            if url_m:
                target_s = url_m.group(0)
                errors.append({"block": h.group(0)[:120],
                               "reason": "缺 - 目标: 行(已从 PoC 的 URL 兜底提取，该漏洞已保留)"})
            else:
                errors.append({"block": h.group(0)[:120],
                               "reason": "缺 - 目标: 行且 PoC 无 URL，无法定位目标，跳过"})
                continue
        imp = _IMPACT_RE.search(body)
        impact_s = imp.group(1).strip() if imp else ""
        vm = _VERIFY_RE.search(body)
        kr = _KEYRESP_RE.search(body)
        cvss_vec, cvss_score, severity, cal_severity, cal_basis = _grade(sev_s, type_s, impact_s)
        if not cvss_vec:
            errors.append({"block": h.group(0)[:120],
                           "reason": "定级第二段非 CVSS 3.1 向量(已按文字等级兜底，标 legacy)"})
        findings.append({
            "time": time_s.strip(), "cvss_vector": cvss_vec, "cvss_score": cvss_score,
            "severity": cal_severity,              # 最终 triage 等级（校准后，展示/统计用）
            "cvss_severity": severity,             # CVSS base 原始等级（留痕，可审计）
            "severity_basis": cal_basis, "grade_legacy": not bool(cvss_vec),
            "vuln_type": type_s.strip(), "target": target_s, "impact": impact_s,
            "verify_method": vm.group(1).strip() if vm else "",
            "key_response": kr.group(1).strip() if kr else "", "poc": poc_s,
        })
    return findings, errors


def is_identify_poc(plg_name: str = "", vul_name: str = "") -> bool:
    """判断一条哨兵 PoC 命中是否属于「纯识别类」（指纹/服务发现，非漏洞，不进漏洞中心）。
    判定：① plugin_name 以 _identify 结尾（大小写不敏感）；② 或 vul_name 以"发现"开头且不含"漏洞"。"""
    pn = (plg_name or "").strip()
    vn = (vul_name or "").strip()
    if pn.lower().endswith("_identify"):
        return True
    if vn.startswith("发现") and "漏洞" not in vn:
        return True
    return False


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0, "unknown": 0, "": 0}

# 规范等级集（用于 min_severity 阈值计算；不含 unknown/none/"" 等哨兵值）。
_CANON_SEV = ("critical", "high", "medium", "low", "info")


def _below_severities(min_sev: Optional[str]) -> List[str]:
    """求「低于阈值」的规范等级名列表（min_severity 过滤用）。

    只列规范集内低于阈值的等级（min='low' → ['info']；min='medium' → ['info','low']）。
    **刻意不含 unknown/none/'' 及缺失字段**——用 $nin 排除时，字段缺失或值为 unknown 的
    PoC/Nuclei 命中不会被误杀（守「误藏真漏洞」比「多显 info」更危险的取舍）。
    min 非法/为空 → 返回 []（不过滤）。
    """
    m = (min_sev or "").strip().lower()
    if m not in _CANON_SEV:
        return []
    thr = _SEV_RANK[m]
    return [s for s in _CANON_SEV if _SEV_RANK[s] < thr]


# 合法推送阈值档（注意：不能用 `in _SEV_RANK` 判——那含 ""/unknown/none 会让空配置被当有效阈值→阈值=0→全推）
_VALID_MIN_SEV = ("critical", "high", "medium", "low", "info")


def _min_severity() -> str:
    """出洞推送阈值（api_keys.feishu.min_severity），默认 medium。库不可用/未配降级 medium。"""
    try:
        doc = get_repo().collection(Collections.API_KEYS).find_one({"name": "default"}) or {}
        v = ((doc.get("feishu") or {}) or {}).get("min_severity", "")
        return v if v in _VALID_MIN_SEV else "medium"
    except Exception:
        return "medium"


def _notify_vuln(vuln_type: str, target: str, severity: str, cvss_score: Any = None, unit: str = "") -> None:
    """出洞推送：**只推已验证漏洞**（调用方保证），severity 达阈值才推。经 registry 调 NOTIFY，
    取不到（未注册）优雅降级——不硬 import notify 模块（守强解耦）。"""
    if _SEV_RANK.get((severity or "").lower(), 0) < _SEV_RANK.get(_min_severity(), 2):
        return
    svc = get_registry().get(ROLE.NOTIFY)
    if not svc:
        return                              # NOTIFY 未注册：降级静默
    lines = ["类型: {}".format(vuln_type), "目标: {}".format(target), "等级: {}".format(severity)]
    if cvss_score:
        lines.append("CVSS: {}".format(cvss_score))
    if unit:
        lines.append("单位: {}".format(unit))
    lines.append("时间: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")))
    try:
        svc.notify("\n".join(lines), title="漏洞告警 [{}]".format(str(severity).upper()),
                   level=severity, channel="feishu")
    except Exception as exc:
        logger.debug("vuln_center: notify failed: %s", exc)


def _try_upgrade_lead(coll, existed: Dict[str, Any], ev_level: str,
                      evidence: List[Dict[str, Any]], now: str) -> str:
    """同 key 已存记录时：旧 lead + 新 confirmed → 升级（不无脑 skip）。只升不降。
    返回 "upgraded"（需补推送）/ "kept"（无需动）。"""
    if ev_level != "confirmed":
        return "kept"
    if existed.get("verified") and existed.get("status") == "finding":
        return "kept"
    coll.update_one({"_id": existed["_id"]}, {"$set": {
        "verified": True, "evidence_level": "confirmed", "evidence": evidence,
        "status": "finding", "update_date": now, "upgraded_from_lead": True,
    }})
    return "upgraded"


class FindingServiceImpl:
    """FINDING 实现。满足 contracts.FindingService（结构化子类型，无需继承）。"""

    def is_identify_poc(self, plg_name: str = "", vul_name: str = "") -> bool:
        return is_identify_poc(plg_name, vul_name)

    def parse_findings_md(self, md_text: str) -> List[Dict[str, Any]]:
        """解析报告 md 的漏洞列表(供引擎 _report_quality_score 按漏洞数×等级选 best_content)。
        只返 findings 列表(丢弃 errors)。解析失败返空。"""
        try:
            findings, _errors = parse_findings_md(md_text)
            return findings or []
        except Exception:
            return []

    def record_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """登记一条 AI 渗透漏洞（幂等 norm_target+norm_type）。证据强制：无实抓正向证据 → status=lead 降级。

        finding 关键字段：target(必填)/vuln_type(必填)/cvss_vector/impact/poc/verify_method/key_response/
                          tool_log(证据核对用)/session_id/asset_key/subdomain/unit。
        **批量模式**：finding 含 `md_text` 时，解析报告 md 逐条登记（AI 会话收尾用），返回聚合摘要
                     `{ok, ingested, leads, skipped, errors}`；tool_log/session_id/asset_key/subdomain/unit
                     作为公共上下文透传给每条。
        单条返回：`{ok, id?, dup, verified, evidence_level, severity}`。内部捕获异常不抛。
        """
        if not isinstance(finding, dict):
            return {"ok": False, "dup": False, "error": "finding 必须是 dict"}
        if "md_text" in finding:
            return self._ingest_md(finding)
        return self._record_one(finding)

    def _record_one(self, finding: Dict[str, Any], tool_log: Optional[List] = None,
                    ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = ctx or {}
        vuln_type = str(finding.get("vuln_type") or "").strip()
        target = str(finding.get("target") or "").strip()
        if not vuln_type or not target:
            return {"ok": False, "dup": False, "error": "vuln_type 与 target 必填"}
        tool_log = tool_log if tool_log is not None else (finding.get("tool_log") or [])
        impact = finding.get("impact", "")
        cvss_vec_in = finding.get("cvss_vector", "")
        cvss_vec, cvss_score, severity, cal_severity, cal_basis = _grade(cvss_vec_in, vuln_type, impact)
        ev_level, evidence = match_evidence({"target": target}, tool_log)
        verified = (ev_level == "confirmed")
        norm_target = _norm_target_for_dedup(target)
        norm_type = _norm_vuln_type(vuln_type)
        unit = finding.get("unit", "") or ctx.get("unit", "")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            coll = get_repo().collection(COLL)
            key = {"norm_target": norm_target, "norm_type": norm_type}
            existed = coll.find_one(key)
            if existed:
                act = _try_upgrade_lead(coll, existed, ev_level, evidence, now)
                if act == "upgraded":
                    _notify_vuln(vuln_type, target, cal_severity,
                                 cvss_score, existed.get("unit", "") or unit)
                    return {"ok": True, "id": str(existed["_id"]), "dup": False, "upgraded": True,
                            "verified": True, "evidence_level": "confirmed"}
                return {"ok": True, "id": str(existed["_id"]), "dup": True, "verified": bool(existed.get("verified"))}
            doc = {
                "time": finding.get("time", now), "cvss_vector": cvss_vec, "cvss_score": cvss_score,
                "severity": cal_severity, "cvss_severity": severity, "severity_basis": cal_basis,
                "grade_legacy": not bool(cvss_vec), "vuln_type": vuln_type, "target": target,
                "impact": impact, "poc": finding.get("poc", ""),
                "verify_method": finding.get("verify_method", ""), "key_response": finding.get("key_response", ""),
                "source": "ai", "session_id": str(finding.get("session_id") or ctx.get("session_id") or ""),
                "norm_target": norm_target, "norm_type": norm_type,
                "asset_key": finding.get("asset_key", "") or ctx.get("asset_key", ""),
                "subdomain": finding.get("subdomain", "") or ctx.get("subdomain", ""),
                "unit": unit, "verified": verified, "evidence_level": ev_level, "evidence": evidence,
                "status": "finding" if verified else "lead", "save_date": now, "update_date": now,
            }
            res = coll.insert_one(doc)
            if verified:
                _notify_vuln(vuln_type, target, cal_severity, cvss_score, unit)   # 只推已验证
            return {"ok": True, "id": str(getattr(res, "inserted_id", "")), "dup": False,
                    "verified": verified, "evidence_level": ev_level, "severity": cal_severity}
        except Exception as exc:
            logger.debug("vuln_center: record_finding failed: %s", exc)
            return {"ok": False, "dup": False, "error": str(exc)}

    def _ingest_md(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """批量：解析报告 md 逐条登记（幂等）。公共上下文（tool_log/session_id/unit 等）透传每条。"""
        md_text = finding.get("md_text") or ""
        tool_log = finding.get("tool_log") or []
        ctx = {k: finding.get(k, "") for k in ("session_id", "asset_key", "subdomain", "unit")}
        parsed, errors = parse_findings_md(md_text)
        ingested = leads = skipped = 0
        for f in parsed:
            r = self._record_one(f, tool_log=tool_log, ctx=ctx)
            if not r.get("ok"):
                continue
            if r.get("dup"):
                skipped += 1
            elif r.get("verified") or r.get("upgraded"):
                ingested += 1
            else:
                leads += 1
        if errors:
            logger.warning("vuln_center ingest md 有 %d 个漏洞块解析失败(格式漂移): %s",
                           len(errors), errors[:3])
        return {"ok": True, "ingested": ingested, "leads": leads, "skipped": skipped,
                "errors": errors, "findings": parsed}

def _oid(v: Any):
    """字符串 → bson.ObjectId（惰性 import，对齐 core/db.py 惰性 pymongo）。

    无 bson（如无 pymongo 的开发/测试机）时回退返回原值——真实部署 Linux 有 pymongo，
    ObjectId 生效；测试用 fake repo 存字符串 _id，回退原值即可匹配。仅在 v 为空时返 None。
    """
    if v in (None, ""):
        return None
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v                       # 无 bson：回退原值（测试/无 pymongo 环境）
    except Exception:
        return v                       # 非法 ObjectId 回退原值（对齐平台约定；生产真库对字符串查不到，效果一致）


def _norm_unified(doc: Dict[str, Any], source: str) -> Dict[str, Any]:
    """把一条原始漏洞文档归一成混排列表行（只取公共字段，详情另拉）。"""
    base = {
        "_id": str(doc.get("_id", "")), "source": source,
        "save_date": doc.get("save_date", ""), "task_id": doc.get("task_id", ""),
        "task_name": "",
        "session_id": str(doc.get("session_id", "")) if source == "ai" else "",
        "handle_status": doc.get("handle_status", "") or "",
        "handle_by": doc.get("handle_by", "") or "", "handle_at": doc.get("handle_at", "") or "",
    }
    if source == "ai":
        _sev = (doc.get("severity") or "unknown").lower()
        _chain = (doc.get("chain_severity") or "").lower()
        _eff = _chain if _SEV_RANK.get(_chain, 0) > _SEV_RANK.get(_sev, 0) else _sev
        base.update({
            "name": doc.get("vuln_type", "") or "未分类", "target": doc.get("target", ""),
            "severity": _eff, "base_severity": _sev, "chain_severity": _chain,
            "chain_title": doc.get("chain_title", ""), "verified": bool(doc.get("verified")),
            "unit": doc.get("unit", ""), "cvss_score": doc.get("cvss_score"),
            "cvss_severity": doc.get("cvss_severity", ""), "severity_basis": doc.get("severity_basis", ""),
        })
    elif source == "nuclei":
        base.update({
            "name": doc.get("vuln_name", "") or doc.get("template_id", "") or "nuclei",
            "target": doc.get("vuln_url", "") or doc.get("target", ""),
            "severity": (doc.get("vuln_severity") or "unknown").lower(),
            "verified": True, "unit": "", "cvss_score": None,
        })
    else:  # poc（vuln 集合，NPoC 插件命中，无 severity 字段）
        base.update({
            "name": doc.get("vul_name", "") or doc.get("plg_name", "") or "PoC",
            "target": doc.get("target", ""),
            "severity": (doc.get("vuln_severity") or doc.get("severity") or "unknown").lower(),
            "verified": True, "unit": "", "cvss_score": None,
        })
    return base


def _attach_task_names(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """为当前页漏洞行批量回填 task_name（四级目录第一级）。poc/nuclei 经 task_id；ai 经 session→source_task_id 两跳。"""
    if not rows:
        return rows
    repo = get_repo()
    sess_ids = {r["session_id"] for r in rows if r.get("source") == "ai" and r.get("session_id")}
    sess2task: Dict[str, str] = {}
    if sess_ids:
        oids = [o for o in (_oid(s) for s in sess_ids) if o is not None]
        if oids:
            for s in repo.collection(Collections.PENTEST_SESSION).find(
                    {"_id": {"$in": oids}}, {"source_task_id": 1}):
                sess2task[str(s["_id"])] = s.get("source_task_id", "") or ""
    task_ids = set()
    for r in rows:
        tid = sess2task.get(r.get("session_id", ""), "") if r.get("source") == "ai" else (r.get("task_id", "") or "")
        if tid:
            task_ids.add(tid)
    task2name: Dict[str, str] = {}
    if task_ids:
        oids = [o for o in (_oid(t) for t in task_ids) if o is not None]
        if oids:
            for t in repo.collection(Collections.TASK).find({"_id": {"$in": oids}}, {"name": 1}):
                task2name[str(t["_id"])] = t.get("name", "") or ""
    for r in rows:
        tid = sess2task.get(r.get("session_id", ""), "") if r.get("source") == "ai" else (r.get("task_id", "") or "")
        r["task_name"] = task2name.get(tid, "")
    return rows


_POC_EXCLUDE_IDENTIFY = {"$nor": [{"plg_name": {"$regex": "_identify$", "$options": "i"}},
                                  {"vul_name": {"$regex": "^发现(?!.*漏洞)"}}]}


def _apply_handle_date(q: Dict[str, Any], handle_status: Optional[str],
                       date_from: Optional[str], date_to: Optional[str]) -> Dict[str, Any]:
    """处理状态 + 时间范围过滤注入（列表/计数同口径）。未指定 handle_status 时默认藏误报。"""
    if not handle_status:
        q["handle_status"] = {"$ne": "false_positive"}
    elif handle_status == "unhandled":
        q["handle_status"] = {"$in": [None, ""]}
    else:
        q["handle_status"] = handle_status
    if date_from or date_to:
        rng: Dict[str, Any] = {}
        if date_from:
            rng["$gte"] = str(date_from)
        if date_to:
            dt = str(date_to)
            rng["$lte"] = dt + " 23:59:59" if len(dt) <= 10 else dt
        q["save_date"] = rng
    return q


def list_unified_findings(unit=None, severity=None, source=None, keyword=None, verified=None,
                          page=1, size=20, include_leads=False, handle_status=None,
                          date_from=None, date_to=None, min_severity=None) -> Dict[str, Any]:
    """三来源混排列表（vuln + nuclei_result + intel_finding），按 save_date 倒序 + 分页。
    漏洞中心只放真漏洞：未显式要线索时 AI 来源锁 verified=True。返回 {items, total}。

    severity=精确等级过滤（单选）；min_severity=最低等级阈值（默认前端传 low，隐藏 info 噪声）。
    两者可叠加；severity 精确命中时 min_severity 自然被 severity 收窄，无冲突。"""
    page = max(1, int(page or 1))
    size = max(1, int(size or 20))
    if verified is None and not include_leads:
        verified = True
    sources = [source] if source in UNIFIED_SOURCES else list(UNIFIED_SOURCES)
    if unit and source not in ("poc", "nuclei"):
        sources = [s for s in sources if s == "ai"]
    kw = (keyword or "").strip()
    below = _below_severities(min_severity)
    fetch_n = page * size
    repo = get_repo()

    def _collect(coll_name: str, src: str, extra_q: Dict[str, Any]) -> List[Dict[str, Any]]:
        q = dict(extra_q)
        field = {"ai": "severity", "nuclei": "vuln_severity"}.get(src, "vuln_severity")
        if severity:
            q[field] = severity.lower()
        elif below:                            # min_severity：排除低于阈值的规范等级（$nin 不误杀缺失字段）
            q[field] = {"$nin": below}
        _apply_handle_date(q, handle_status, date_from, date_to)
        return [_norm_unified(d, src) for d in repo.collection(coll_name).find(q).sort("_id", -1).limit(fetch_n)]

    merged: List[Dict[str, Any]] = []
    for src in sources:
        if src == "ai":
            aq: Dict[str, Any] = {"source": "ai"}
            if unit:
                aq["unit"] = {"$regex": re.escape(unit.strip()), "$options": "i"}
            if verified is not None:
                aq["verified"] = bool(verified)
            merged += _collect(COLL, "ai", aq)
        elif src == "nuclei":
            merged += _collect(Collections.NUCLEI_RESULT, "nuclei", {})
        elif src == "poc":
            merged += _collect(Collections.VULN, "poc", dict(_POC_EXCLUDE_IDENTIFY))

    if kw:
        terms = [t for t in kw.lower().split() if t]
        def _hit(r):
            blob = "{} {} {}".format(r.get("name", "") or "", r.get("target", "") or "",
                                     r.get("unit", "") or "").lower()
            return all(t in blob for t in terms)
        merged = [r for r in merged if _hit(r)]

    merged.sort(key=lambda r: r.get("save_date") or "", reverse=True)
    page_rows = merged[(page - 1) * size: page * size]
    _attach_task_names(page_rows)
    total = len(merged) if kw else _unified_count(sources, unit, severity, source, verified,
                                                  handle_status, date_from, date_to, min_severity)
    return {"items": page_rows, "total": total}


def _unified_count(sources, unit, severity, source, verified, handle_status=None,
                   date_from=None, date_to=None, min_severity=None) -> int:
    repo = get_repo()
    below = _below_severities(min_severity)

    def _sev_clause(field: str, q: Dict[str, Any]) -> None:
        if severity:
            q[field] = severity.lower()
        elif below:
            q[field] = {"$nin": below}

    total = 0
    for src in sources:
        if src == "ai":
            q: Dict[str, Any] = {"source": "ai"}
            if unit:
                q["unit"] = {"$regex": re.escape(unit.strip()), "$options": "i"}
            if verified is not None:
                q["verified"] = bool(verified)
            _sev_clause("severity", q)
            total += repo.collection(COLL).count_documents(
                _apply_handle_date(q, handle_status, date_from, date_to))
        elif src == "nuclei":
            q = {}
            _sev_clause("vuln_severity", q)
            total += repo.collection(Collections.NUCLEI_RESULT).count_documents(
                _apply_handle_date(q, handle_status, date_from, date_to))
        elif src == "poc":
            q = dict(_POC_EXCLUDE_IDENTIFY)
            _sev_clause("vuln_severity", q)
            total += repo.collection(Collections.VULN).count_documents(
                _apply_handle_date(q, handle_status, date_from, date_to))
    return total


_SRC_COLL = {"ai": COLL, "poc": Collections.VULN, "nuclei": Collections.NUCLEI_RESULT}


def unified_detail(source: str, _id: str) -> Optional[Dict[str, Any]]:
    """按来源拉单条漏洞完整记录（详情取全字段：AI 的 CVSS/证据、PoC/nuclei 原字段）。"""
    coll_name = _SRC_COLL.get(source)
    if not coll_name:
        return None
    oid = _oid(_id)
    if oid is None:
        return None
    try:
        doc = get_repo().collection(coll_name).find_one({"_id": oid})
    except Exception:
        return None
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    doc["source"] = source
    return doc


def delete_unified(source: str, ids: List[str]) -> int:
    """漏洞中心批量删除：按来源删对应集合的多条记录。返回删除条数。"""
    coll_name = _SRC_COLL.get(source)
    if not coll_name or not ids:
        return 0
    oids = [o for o in (_oid(i) for i in ids) if o is not None]
    if not oids:
        return 0
    try:
        return get_repo().collection(coll_name).delete_many({"_id": {"$in": oids}}).deleted_count
    except Exception as exc:
        logger.debug("vuln_center: delete_unified failed: %s", exc)
        return 0


def mark_unified(source: str, ids: List[str], handle_status: str, handle_by: str = "") -> int:
    """漏洞中心批量标记处理状态（""重置/submitted/false_positive）。记 handle_by/handle_at 审计。返回更新条数。"""
    coll_name = _SRC_COLL.get(source)
    if not coll_name or not ids:
        return 0
    if handle_status not in HANDLE_STATUSES:
        raise ValueError("非法 handle_status: {}".format(handle_status))
    oids = [o for o in (_oid(i) for i in ids) if o is not None]
    if not oids:
        return 0
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    set_fields = {"handle_status": handle_status, "update_date": now}
    set_fields["handle_by"] = handle_by or "" if handle_status else ""
    set_fields["handle_at"] = now if handle_status else ""
    try:
        return get_repo().collection(coll_name).update_many(
            {"_id": {"$in": oids}}, {"$set": set_fields}).modified_count
    except Exception as exc:
        logger.debug("vuln_center: mark_unified failed: %s", exc)
        return 0


def finding_stat(unit=None) -> Dict[str, Any]:
    """漏洞统计：AI 渗透（intel_finding）已验证 vs 线索分开计 + 哨兵扫描（vuln/nuclei）合计。"""
    repo = get_repo()
    fq: Dict[str, Any] = {"source": "ai"}
    if unit:
        fq["unit"] = unit
    try:
        fcoll = repo.collection(COLL)
        ai_verified = fcoll.count_documents(dict(fq, verified=True))
        ai_leads = fcoll.count_documents(dict(fq, verified=False))
        by_sev: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for d in fcoll.find(dict(fq, verified=True)):
            _sv = (d.get("severity", "unknown") or "unknown").lower()
            _cs = (d.get("chain_severity", "") or "").lower()
            eff = _cs if _SEV_RANK.get(_cs, 0) > _SEV_RANK.get(_sv, 0) else _sv
            by_sev[eff] = by_sev.get(eff, 0) + 1
            vt = d.get("vuln_type", "未分类")
            by_type[vt] = by_type.get(vt, 0) + 1
        # poc/nuclei 是系统扫描来源，无 unit 维度（unit 是情报归集层才有）。
        # 修 bug：原 `if not unit` 使按单位筛选时 poc/nuclei 统计恒 0，而列表(list_unified_findings)
        # 对 poc/nuclei 忽略 unit 全量显示 → 统计与列表口径不一致，用户见"系统扫描=0/合计对不上"。
        # 现统一口径：poc/nuclei 恒全量计（与列表一致）；unit_scoped 标记告知前端该口径，避免误解。
        poc_total = (repo.collection(Collections.VULN).count_documents(dict(_POC_EXCLUDE_IDENTIFY))
                     + repo.collection(Collections.NUCLEI_RESULT).count_documents({}))
        return {
            "ai": {"total": ai_verified, "verified": ai_verified, "leads": ai_leads,
                   "by_severity": by_sev, "by_type": by_type},
            "poc": {"total": poc_total, "unit_scoped": False},
            "combined_total": ai_verified + poc_total, "unit": unit or "",
        }
    except Exception as exc:
        logger.debug("vuln_center: finding_stat failed: %s", exc)
        return {"ai": {"total": 0, "verified": 0, "leads": 0, "by_severity": {}, "by_type": {}},
                "poc": {"total": 0}, "combined_total": 0, "unit": unit or ""}


# —— Impl 扩展方法（供 router 经 registry 调查询/标记/统计；Protocol 只含 record_finding/is_identify_poc）——
FindingServiceImpl.list_unified_findings = staticmethod(list_unified_findings)
FindingServiceImpl.unified_detail = staticmethod(unified_detail)
FindingServiceImpl.delete_unified = staticmethod(delete_unified)
FindingServiceImpl.mark_unified = staticmethod(mark_unified)
FindingServiceImpl.finding_stat = staticmethod(finding_stat)


# —— 进程级单例 + registry 接入 ——
_service = FindingServiceImpl()


def get_service() -> FindingServiceImpl:
    return _service








