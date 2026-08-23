"""task_plan/policy —— 策略配置（扫描策略 CRUD + 展开为任务 options）。

策略是「扫描/AI 渗透怎么打」的配置中心：域名/IP/站点扫描项、PoC/弱口令插件清单、
资产收集模式、AI 渗透模式与三轨代理出口等。task_create 下发任务时选一个策略，
经 `get_options_by_policy_id` 展开成 `task.options`，被内核扫描（orchestration）与
扫描完自动派发（asset_intel.auto_collect）消费。

**无 ROLE**（纯配置叶子）：经 registry 以字符串键 `"policy_service"` 注册（照
dashboard/api_keys 先例），router `endpoints/task_plan.py` + task_create 取用。不放 HTTP 路由。

**禁止硬限制参数（铁律）**：port_parallelism / port_min_rate / host_timeout / port_custom 等
是策略的**缺省值**，用户可自由改写，本叶子只做**语法校验**（端口格式合法），绝不夹上下限、
不砍用户设定值；list 分页 size 缺省 10 仅是不传时的默认，传入多大都透传不砍。

迁移来源：app/helpers/policy.py（get_options_by_policy_id）+ app/routes/policy.py（CRUD + schema）。
净室重写：旧代码用 flask_restx model 承载默认值，这里改为纯 dict 常量（叶子不依赖 flask/路由）。
bson.ObjectId 惰性 import（对齐 core/db 惰性 pymongo）：无 bson 环境回退原字符串 id，单测可跑。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections
from sentinel_platform.core import models

logger = get_logger()

# —— 配置默认值（净室重写自旧 flask_restx model 的 default/example）——
# 这些是**缺省值**，不是限制；用户提交的值原样透传（守禁止硬限制参数）。
DOMAIN_CONFIG_DEFAULT = {
    "domain_brute": True, "domain_brute_type": "big", "alt_dns": True,
    "arl_search": True, "dns_query_plugin": False,
    # 自定义字典（空=用内置默认 dicts/domain_2w.txt / dnsserver.txt；填多行文本则覆盖，禁硬限制）
    "subdomain_dict": "", "resolvers_custom": "",
}
IP_CONFIG_DEFAULT = {
    "port_scan": True, "port_scan_type": "test", "service_detection": False,
    "os_detection": False, "ssl_cert": False, "skip_scan_cdn_ip": True,
    "port_custom": "80,443", "host_timeout_type": "default", "host_timeout": 900,
    "port_parallelism": 32, "port_min_rate": 60, "exclude_ports": "",
}
SITE_CONFIG_DEFAULT = {
    "site_identify": False, "site_capture": False, "search_engines": False,
    "site_spider": False, "nuclei_scan": False, "web_info_hunter": False,
}
SCOPE_CONFIG_DEFAULT = {"scope_id": ""}

_COLLECT_MODES = ("single", "multi_brute", "multi_passive")
# 四档渗透模式（强度轻→重），与 ai_config.PENTEST_MODES 单一事实源对齐。
# 净室自包含（叶子间零 import，见 MODULES 铁律），故此处手抄——ai_config 增减模式时同步本行。
_PENTEST_MODES = ("detect", "conservative", "src", "redteam")
_EGRESS_PREFS = ("smart", "proxy", "direct")
_DEDUP_LEVELS = (1, 2, 3)
_SCOPE_DRIFT_LEVELS = (1, 2, 3)


def _oid(v: Any):
    """字符串 → bson.ObjectId（惰性 import）；无 bson 回退原值（测试/离线），空返 None。"""
    if v in (None, ""):
        return None
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v
    except Exception:
        return v          # 非法 ObjectId 回退原值（对齐平台约定；生产真 ObjectId 库对字符串查不到，效果一致）


# —— 归一化（净室，自包含，不 import 别的叶子）——
def _norm_collect_mode(v: str) -> str:
    v = (v or "multi_brute").lower()
    return v if v in _COLLECT_MODES else "multi_brute"


def _norm_pentest_mode(v: str) -> str:
    v = (v or "src").lower()
    return v if v in _PENTEST_MODES else "src"


def _norm_egress_pref(v: str) -> str:
    """AI 攻击出口归一 smart/proxy/direct（兼容旧 follow→smart / on→proxy / off→direct）。"""
    v = (v or "smart").lower()
    if v in _EGRESS_PREFS:
        return v
    return {"follow": "smart", "on": "proxy", "off": "direct"}.get(v, "smart")


_EGRESS_MODES = ("direct", "global", "rule", "smart")


def _norm_egress(egress: Any, legacy_val: str = "", legacy_kind: str = "") -> Dict[str, Any]:
    """出口归一成 4模式 {mode, rule_id}（2026-08 代理重构）。
    优先用新字段 egress={mode, rule_id}；否则从旧字段迁移：
      legacy_kind='scan'：scan_proxy(proxy/direct) → proxy→global / direct→direct
      legacy_kind='pentest'：pentest_proxy(smart/proxy/direct/follow/on/off) → smart/global/direct
    mode 非法回退 smart(pentest)/direct(scan)。rule_id 仅 mode=rule 时有意义。"""
    if isinstance(egress, dict) and egress.get("mode"):
        m = str(egress.get("mode", "")).lower()
        if m in _EGRESS_MODES:
            return {"mode": m, "rule_id": str(egress.get("rule_id", "") or "")}
    # 旧字段迁移
    lv = (legacy_val or "").lower()
    if legacy_kind == "scan":
        return {"mode": "global" if lv == "proxy" else "direct", "rule_id": ""}
    # pentest: smart/proxy/direct(+follow/on/off)
    m = {"proxy": "global", "on": "global", "off": "direct", "follow": "smart",
         "direct": "direct", "smart": "smart", "global": "global", "rule": "rule"}.get(lv, "smart")
    return {"mode": m, "rule_id": ""}


def _norm_dedup_level(v: Any) -> int:
    """去重策略级别归一：1=不去重 2=保守(默认) 3=激进。"""
    try:
        v = int(v)
    except (TypeError, ValueError):
        v = 2
    return v if v in _DEDUP_LEVELS else 2


def _norm_scope_drift_level(v: Any) -> int:
    """scope偏移级别归一：1=零偏移 2=轻度(默认) 3=中度。"""
    try:
        v = int(v)
    except (TypeError, ValueError):
        v = 2
    return v if v in _SCOPE_DRIFT_LEVELS else 2


# —— 端口语法校验（格式合法 + 端口号 0-65535）——
def build_port_custom(port_custom: str):
    """解析自定义端口串为列表；非法项返回该项字符串（调用方据此报错）。"""
    port_list: List[str] = []
    for item in (port_custom or "").split(","):
        item = item.strip()
        if not item:
            continue
        if not re.match(r"^[\d\-]+$", item):
            return item
        # 校验端口号范围 0-65535
        parts = item.split("-")
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return item
        if any(n < 0 or n > 65535 for n in nums):
            return item
        if len(parts) == 2 and nums[0] > nums[1]:
            return item
        port_list.append(item)
    return port_list


def is_valid_exclude_ports(exclude_ports: str) -> bool:
    """校验 nmap 排除端口范围格式（0-65535，start<=end）。"""
    if not re.fullmatch(r"(\d+(-\d+)?,?)+", exclude_ports or ""):
        return False
    for part in exclude_ports.split(","):
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
            except ValueError:
                return False
            if start > end or not (0 <= start <= 65535) or not (0 <= end <= 65535):
                return False
        else:
            if not (0 <= int(part) <= 65535):
                return False
    return True


def _validate_plugin_config(config: List[Dict[str, Any]]):
    """校验 poc/brute 插件清单：插件必须在 poc 集合存在，去重。返回归一列表或错误字符串。"""
    seen = set()
    out: List[Dict[str, Any]] = []
    for item in config or []:
        name = str(item.get("plugin_name", "") or "")
        if not name or name in seen:
            continue
        info = get_repo().collection(Collections.POC).find_one({"plugin_name": name})
        if not info:
            return "没有找到 {} 插件".format(name)
        seen.add(name)
        out.append({"plugin_name": name, "vul_name": info.get("vul_name", ""),
                    "enable": bool(item.get("enable", False))})
    return out


def _merged(default: Dict[str, Any], override: Any) -> Dict[str, Any]:
    """默认值 + 用户覆盖（用户值透传不砍，守禁止硬限制参数）。"""
    d = dict(default)
    if isinstance(override, dict):
        d.update(override)
    return d


class PolicyServiceImpl:
    """策略配置能力（无 ROLE，字符串键 policy_service 注册）。"""

    def list_policies(self, name: Optional[str] = None, page: int = 1, size: int = 10) -> Dict[str, Any]:
        """策略列表（可按名称模糊 + 分页）。size 缺省 10 仅默认，传入多大都透传不砍（无硬限制）。"""
        try:
            page = max(1, int(page or 1))
            size = max(1, int(size or 10))
        except (TypeError, ValueError):
            page, size = 1, 10
        q: Dict[str, Any] = {}
        if name:
            q["name"] = {"$regex": re.escape(str(name).strip()), "$options": "i"}
        try:
            coll = get_repo().collection(Collections.POLICY)
            total = coll.count_documents(q)
            items = []
            for d in coll.find(q).sort("_id", -1).skip((page - 1) * size).limit(size):
                d["_id"] = str(d["_id"])
                items.append(d)
            return {"items": items, "total": total, "page": page, "size": size}
        except Exception as exc:
            logger.debug("policy: list failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "size": size}

    def add_policy(self, name: str, policy: Dict[str, Any], desc: str = "") -> Dict[str, Any]:
        """新建策略。校验插件存在/端口语法；归一模式/代理三轨。返回 {ok, policy_id?} 或 {ok:False,error}。"""
        name = str(name or "").strip()
        if not name:
            return {"ok": False, "error": "name 必填"}
        if not isinstance(policy, dict):
            return {"ok": False, "error": "policy 必须是对象"}

        ip_config = _merged(IP_CONFIG_DEFAULT, policy.get("ip_config"))
        if ip_config.get("port_scan_type") == "custom":
            parsed = build_port_custom(ip_config.get("port_custom", "80,443"))
            if isinstance(parsed, str):
                return {"ok": False, "error": "自定义端口非法: {}".format(parsed)}
            ip_config["port_custom"] = ",".join(parsed)
        if ip_config.get("exclude_ports") and not is_valid_exclude_ports(ip_config["exclude_ports"]):
            return {"ok": False, "error": "排除端口格式非法: {}".format(ip_config["exclude_ports"])}

        poc_config = _validate_plugin_config(policy.get("poc_config") or [])
        if isinstance(poc_config, str):
            return {"ok": False, "error": poc_config}
        brute_config = _validate_plugin_config(policy.get("brute_config") or [])
        if isinstance(brute_config, str):
            return {"ok": False, "error": brute_config}

        item = {
            "name": name,
            "policy": {
                "domain_config": _merged(DOMAIN_CONFIG_DEFAULT, policy.get("domain_config")),
                "ip_config": ip_config,
                "site_config": _merged(SITE_CONFIG_DEFAULT, policy.get("site_config")),
                "poc_config": poc_config, "brute_config": brute_config,
                "file_leak": bool(policy.get("file_leak", False)),
                "fileleak_dict": str(policy.get("fileleak_dict", "") or ""),
                "npoc_service_detection": bool(policy.get("npoc_service_detection", False)),
                "collect_mode": _norm_collect_mode(policy.get("collect_mode", "multi_brute")),
                "auto_pentest": bool(policy.get("auto_pentest", False)),
                "pentest_mode": _norm_pentest_mode(policy.get("pentest_mode", "src")),
                # 代理出口 4模式（2026-08 重构，废旧 scan_proxy/pentest_proxy/proxy_source）：
                # {mode: direct/global/rule/smart, rule_id}。存量策略读旧字段自动迁移。
                "scan_egress": _norm_egress(policy.get("scan_egress"),
                                            policy.get("scan_proxy", "direct"), "scan"),
                "pentest_egress": _norm_egress(policy.get("pentest_egress"),
                                               policy.get("pentest_proxy", "smart"), "pentest"),
                "scope_config": _merged(SCOPE_CONFIG_DEFAULT, policy.get("scope_config")),
                "dedup_level": _norm_dedup_level(policy.get("dedup_level", 2)),
                "scope_drift_level": _norm_scope_drift_level(policy.get("scope_drift_level", 2)),
                "intel_enabled": bool(policy.get("intel_enabled", True)),
            },
            "desc": str(desc or ""),
            "update_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            res = get_repo().collection(Collections.POLICY).insert_one(item)
            return {"ok": True, "policy_id": str(getattr(res, "inserted_id", ""))}
        except Exception as exc:
            logger.debug("policy: add failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    def edit_policy(self, policy_id: str, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """编辑策略（深合并允许字段 + 重新校验插件）。返回 {ok, data?} 或 {ok:False,error}。"""
        oid = _oid(policy_id)
        if oid is None:
            return {"ok": False, "error": "policy_id 非法"}
        if not isinstance(policy_data, dict) or not policy_data:
            return {"ok": False, "error": "policy_data 为空"}
        try:
            coll = get_repo().collection(Collections.POLICY)
            item = coll.find_one({"_id": oid})
            if not item:
                return {"ok": False, "error": "策略不存在"}
            allow = {"name", "desc", "policy"}
            for k in list(policy_data.keys()):
                if k in allow:
                    if k == "policy" and isinstance(item.get("policy"), dict) and isinstance(policy_data[k], dict):
                        item["policy"].update(policy_data[k])
                    else:
                        item[k] = policy_data[k]
            pol = item.get("policy", {})
            if isinstance(pol, dict):
                for cfg_key in ("poc_config", "brute_config"):
                    if cfg_key in pol:
                        validated = _validate_plugin_config(pol.get(cfg_key) or [])
                        if isinstance(validated, str):
                            return {"ok": False, "error": validated}
                        pol[cfg_key] = validated
            item["update_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
            coll.update_one({"_id": oid}, {"$set": item})
            item["_id"] = str(item["_id"])
            return {"ok": True, "data": item}
        except Exception as exc:
            logger.debug("policy: edit failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    def delete_policy(self, ids: List[str]) -> Dict[str, Any]:
        """批量删除策略。返回 {ok, deleted}。"""
        if not ids or not isinstance(ids, list):
            return {"ok": False, "error": "policy_id(非空数组) 必填", "deleted": 0}
        oids = [o for o in (_oid(i) for i in ids) if o is not None]
        if not oids:
            return {"ok": True, "deleted": 0}
        try:
            n = get_repo().collection(Collections.POLICY).delete_many({"_id": {"$in": oids}}).deleted_count
            return {"ok": True, "deleted": n}
        except Exception as exc:
            logger.debug("policy: delete failed: %s", exc)
            return {"ok": False, "error": str(exc), "deleted": 0}

    def get_options_by_policy_id(self, policy_id: str, task_tag: str = "") -> Dict[str, Any]:
        """把策略展开成扫描任务 options（供 task_create/orchestration/auto_collect 消费）。

        资产发现任务（task_tag==TaskTag.TASK）才带 domain/ip 配置；其余（监控等）只带 site + 顶层项。
        无该策略返回 {}（消费方降级）。这是 policy 叶子被别的模块调的核心跨模块方法。
        """
        oid = _oid(policy_id)
        if oid is None:
            return {}
        try:
            data = get_repo().collection(Collections.POLICY).find_one({"_id": oid})
        except Exception as exc:
            logger.debug("policy: get_options failed: %s", exc)
            return {}
        if not data:
            return {}
        policy = dict(data.get("policy") or {})
        options: Dict[str, Any] = {"policy_name": data.get("name", "")}
        domain_config = policy.pop("domain_config", {})
        ip_config = policy.pop("ip_config", {})
        site_config = policy.pop("site_config", {})
        scope_config = policy.pop("scope_config", None)
        if isinstance(scope_config, dict) and scope_config.get("scope_id"):
            options["related_scope_id"] = scope_config["scope_id"]
        if task_tag == models.TaskTag.TASK:      # 仅资产发现任务需要域名/IP 配置
            options.update(domain_config or {})
            options.update(ip_config or {})
        options.update(site_config or {})
        options.update(policy)                    # 顶层项（file_leak/collect_mode/auto_pentest/三轨代理等）
        return options


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = PolicyServiceImpl()


def get_service() -> PolicyServiceImpl:
    return _service

