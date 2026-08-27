"""risk_intel/asset_intel —— 资产情报归集中心（实现 INTEL / IntelService）。

扫描后把 site 结果归一成资产实例（intel_asset，站点级去重）+ 系统身份（intel_system）；
对应前端 pages/intel/IntelCenter.vue（归集后 intel_asset 有数据即可用，不孤岛）。

契约（冻结，见 INTERFACES.md §二 INTEL）——本模块对外经 registry 暴露：
  collect_from_task(task_id) -> dict          手动归集：site→intel_asset（按 asset_key 幂等）
  auto_collect_after_scan(task_id) -> dict     扫完钩子：归集 + 按 task.options.auto_pentest 经 PENTEST_DISPATCH 派发

叶子另提供（供 router endpoints 调，非 ROLE）：stat / list_* / match_asset / build_pentest_context / resolve_icp。
消费：`SYSTEM_TAGS`（kernel，系统命名/标签）、`PENTEST_DISPATCH`（ai_pentest 未建→只归集不派发降级）、
`ext_source`（ICP 备案查询，未建→unit 留空降级）。负责集合：intel_asset / intel_system / intel_code / intel_report。

**去重铁律**（踩坑：绝不用 system_id/指纹哈希做资产去重→跨单位误聚漏渗整单位）：资产去重键=
`normalize_asset_key`（站点级 scheme://host:port，剥 www，补默认端口），物理唯一标识，非推断聚类。
迁移来源：intel_center.py。依赖：仅 stdlib（hashlib/urllib）+ bson(guard)。**无新增 vendor，默认本地库**。
不放 HTTP 路由。**禁硬限制参数**：list size<=0 全量。
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_logger, models
from sentinel_platform.contracts import Collections, get_registry

logger = get_logger()

_DEFAULT_PORT = {"http": 80, "https": 443}

def _oid(_id: str):
    try:
        from bson import ObjectId
        return ObjectId(_id)
    except Exception:
        return _id


def normalize_asset_key(site: str) -> str:
    """站点 URL → 资产实例唯一 key: scheme://host:port（**去重铁律：物理唯一标识**）。
    不含 path（同站不同页归一到一条）；补默认端口；host 小写；剥前导 www.（剥后仍 ≥1 点才剥）。"""
    if not site:
        return ""
    site = site.strip()
    if "://" not in site:
        site = "http://" + site
    parts = urlsplit(site)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
    try:
        port = parts.port or _DEFAULT_PORT.get(scheme, 80)
    except ValueError:
        port = _DEFAULT_PORT.get(scheme, 80)
    return "{}://{}:{}".format(scheme, host, port)


def normalize_system_key(finger_names: List[str], title: str = "", version: str = "") -> str:
    """系统身份 key = 指纹名集合+标题+版本 归一哈希（同系统不同版本视为不同身份）。"""
    names = sorted({(n or "").strip().lower() for n in (finger_names or []) if n})
    title = (title or "").strip().lower()
    version = (version or "").strip().lower()
    if not names and not title:
        return ""
    return hashlib.sha1(("|".join(names) + "#" + title + "#" + version).encode("utf-8")).hexdigest()


def _finger_names(site_item: Dict[str, Any]) -> List[str]:
    out = []
    for f in site_item.get("finger", []) or []:
        nm = f.get("name") if isinstance(f, dict) else None
        if nm:
            out.append(nm)
    return out


def _finger_version(site_item: Dict[str, Any]) -> str:
    for f in site_item.get("finger", []) or []:
        if isinstance(f, dict) and (f.get("version") or "").strip():
            return f["version"].strip()
    return ""


def _fld_of(hostname: str) -> str:
    """粗取主域（末两段；净室轻量，不引 tld 库）。IP/单段原样返回。"""
    h = (hostname or "").strip().lower().split(":")[0]
    if not h or h.replace(".", "").isdigit():
        return h
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def _system_tags_svc():
    """取 SYSTEM_TAGS 服务（经 registry，**不 import kernel 内部**，守解耦）。未注册返回 None。"""
    from sentinel_platform.contracts import ROLE
    return get_registry().get(ROLE.SYSTEM_TAGS)


def _pick_sys_name(finger_names: List[str], title: str = "") -> str:
    """系统主名：经 registry 调 SYSTEM_TAGS.pick_system_name；未注册降级取首个指纹/标题。"""
    svc = _system_tags_svc()
    if svc and hasattr(svc, "pick_system_name"):
        try:
            nm = svc.pick_system_name({"finger": [{"name": n} for n in finger_names], "title": title})
            if nm:
                return nm
        except Exception:
            pass
    return (finger_names[0] if finger_names else (title or "").strip()) or "未知系统"


def _extract_tags(finger_names: List[str], title: str = "") -> List[str]:
    """标签：经 registry 调 SYSTEM_TAGS.extract_tags（Protocol 返 str 列表）；未注册降级 []。
    仅走冻结 Protocol，不 import kernel 内部（typed 标签相似度借鉴由 kernel 自己读 intel_system 算）。"""
    svc = _system_tags_svc()
    if svc and hasattr(svc, "extract_tags"):
        try:
            return svc.extract_tags({"finger": [{"name": n} for n in finger_names], "title": title})
        except Exception:
            return []
    return []


def _gather_recon(site_item: Dict[str, Any], task_id: str) -> Dict[str, Any]:
    """聚合该站点的侦察发现（端口/漏洞/泄露/密钥/端点/证书 计数 + 明细），供前端展示 + 价值信号。
    净室轻量版：按 host/task_id 从各集合取计数，异常降级空。"""
    host = ""
    try:
        host = (urlsplit(site_item.get("site", "") or site_item.get("url", "")).hostname or site_item.get("hostname", "") or "").lower()
    except Exception:
        host = site_item.get("hostname", "") or ""
    repo = get_repo()

    def _cnt(coll_name: str, query: Dict[str, Any]) -> int:
        try:
            return repo.collection(coll_name).count_documents(query)
        except Exception:
            return 0

    port_info = site_item.get("port_info") or []
    vuln_cnt = _cnt(Collections.VULN, {"task_id": task_id}) + _cnt(Collections.NUCLEI_RESULT, {"task_id": task_id})
    leak_cnt = _cnt(Collections.FILELEAK, {"task_id": task_id})
    secret_cnt = 0
    try:
        secret_cnt = repo.collection(Collections.WIH).count_documents(
            {"task_id": task_id, "record_type": {"$in": ["secret", "key", "token"]}})
    except Exception:
        secret_cnt = 0
    summary = {
        "port_cnt": len(port_info),
        "vuln_cnt": vuln_cnt,
        "leak_cnt": leak_cnt,
        "secret_cnt": secret_cnt,
    }
    return {"host": host, "ports": port_info, "summary": summary}


def _merge_recon(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> Dict[str, Any]:
    """二次归集叠加：新发现并入历史（计数取大值，不丢上次成果，铁律二）。"""
    if not old:
        return new
    os_, ns_ = old.get("summary", {}) or {}, new.get("summary", {}) or {}
    merged_summary = {k: max(os_.get(k, 0), ns_.get(k, 0)) for k in set(os_) | set(ns_)}
    out = dict(new)
    out["summary"] = merged_summary
    # 端口并集（按 port_id 去重）
    seen, ports = set(), []
    for p in (old.get("ports") or []) + (new.get("ports") or []):
        pid = p.get("port_id") if isinstance(p, dict) else p
        if pid not in seen:
            seen.add(pid)
            ports.append(p)
    out["ports"] = ports
    return out


def upsert_system(finger_names, title="", version="", asset_key="", unit="") -> str:
    """按系统身份 key upsert intel_system，把资产并入 instance_keys。返回 system_id（无有效身份返 ""）。
    系统名/标签经 SYSTEM_TAGS（registry）。写 intel_system（本叶子负责该集合）。"""
    sys_key = normalize_system_key(finger_names, title=title, version=version)
    if not sys_key:
        return ""
    name = _pick_sys_name(finger_names, title)
    if version:
        name = "{} {}".format(name, version)
    tags = _extract_tags(finger_names, title)
    now = models_now()
    try:
        coll = get_repo().collection(Collections.INTEL_SYSTEM)
        existed = coll.find_one({"key": sys_key})
        if existed:
            upd: Dict[str, Any] = {"$set": {"update_date": now}}
            ats: Dict[str, Any] = {}
            if asset_key:
                ats["instance_keys"] = asset_key
            if unit:
                ats["units"] = unit
            if ats:
                upd["$addToSet"] = ats
            if tags and not existed.get("tags"):
                upd["$set"]["tags"] = tags
            if name and name != existed.get("name"):
                upd["$set"]["name"] = name
            coll.update_one({"_id": existed["_id"]}, upd)
            return str(existed["_id"])
        doc = {
            "key": sys_key, "name": name,
            "finger_names": sorted({n for n in finger_names if n}),
            "title": title, "version": version, "tags": tags,
            "instance_keys": [asset_key] if asset_key else [],
            "units": [unit] if unit else [],
            "attack_surface": [], "known_vulns": [], "common_leaks": [],
            "success_paths": [], "code_id": "", "save_date": now, "update_date": now,
        }
        return str(coll.insert_one(doc).inserted_id)
    except Exception as exc:
        logger.debug("upsert_system degraded: %s", exc)
        return ""


def models_now() -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _fallback_unit(task_name: str, target: str) -> str:
    """无单位名且收集不到时的默认单位名：`任务名_目标名`，其中 `.` 用 `_` 代替。
    任务名/目标名缺失时降级用另一个；都空则返回空（调用方兜底）。单位视图据此展示。"""
    tn = (task_name or "").strip().replace(".", "_")
    tg = (target or "").strip().replace(".", "_")
    if tn and tg:
        return "{}_{}".format(tn, tg)
    return tn or tg


def upsert_asset(site_item: Dict[str, Any], unit: str = "", task_id: str = "",
                 task_name: str = "", unit_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """单条 site → intel_asset upsert（按 asset_key 幂等）。返回 {asset_key, system_id, is_new}。
    归集不查 ICP（挪到写报告，见迁移注）；无人工 unit 时按 fld 查 unit_map 定单位。"""
    # 站点 URL 字段兼容：新 recon pipeline 的 httpx 写 SiteRec.url；旧 ARL/FOFA 导入写 site。两者都认。
    asset_key = normalize_asset_key(site_item.get("site", "") or site_item.get("url", ""))
    if not asset_key:
        return {"asset_key": "", "system_id": "", "is_new": False}
    finger_names = _finger_names(site_item)
    title = site_item.get("title", "") or ""
    version = _finger_version(site_item)
    hostname = site_item.get("hostname", "") or ""
    fld = site_item.get("fld", "") or _fld_of(hostname)
    if not unit and unit_map and fld:
        unit = unit_map.get(fld, "") or ""
    # 无单位名且收集不到（ICP/unit_map 都空）→ 回退"任务名_目标名"（. 换 _），保证单位视图不落"无单位"
    if not unit:
        unit = _fallback_unit(task_name, hostname or asset_key)

    now = models_now()
    try:
        coll = get_repo().collection(Collections.INTEL_ASSET)
        existed = coll.find_one({"key": asset_key})
    except Exception as exc:
        logger.debug("upsert_asset read degraded: %s", exc)
        existed = None
        coll = None
    if coll is None:
        return {"asset_key": asset_key, "system_id": "", "is_new": False}

    recon = _gather_recon(site_item, task_id)
    if existed:
        recon = _merge_recon(existed.get("recon"), recon)
    system_id = upsert_system(finger_names, title=title, version=version, asset_key=asset_key, unit=unit)

    snapshot = {
        "site": site_item.get("site", "") or site_item.get("url", ""), "hostname": hostname, "subdomain": hostname, "fld": fld,
        "ip": site_item.get("ip", ""), "title": title, "status": site_item.get("status", 0),
        "http_server": site_item.get("http_server", ""), "finger_names": finger_names,
        "system_name": _pick_sys_name(finger_names, title), "system_id": system_id, "recon": recon,
    }
    if existed:
        set_data = {"update_date": now}
        set_data.update(snapshot)
        merged = sorted({n for n in (list(existed.get("finger_names", []) or []) + finger_names) if n})
        set_data["finger_names"] = merged
        set_data["system_name"] = _pick_sys_name(merged, title)
        if unit and not existed.get("unit"):
            set_data["unit"] = unit
        if task_id:
            set_data["source_task_id"] = task_id
        set_data["collect_count"] = existed.get("collect_count", 1) + 1
        set_data["last_collect_date"] = now
        coll.update_one({"_id": existed["_id"]}, {"$set": set_data})
        return {"asset_key": asset_key, "system_id": system_id, "is_new": False}
    doc = {
        "key": asset_key, "unit": unit, "source_task_id": task_id, "source_task_name": task_name,
        "pentest_status": "none", "report_id": "", "collect_count": 1, "last_collect_date": now,
        "save_date": now, "update_date": now,
    }
    doc.update(snapshot)
    try:
        coll.insert_one(doc)
    except Exception as exc:
        logger.debug("upsert_asset insert degraded: %s", exc)
        return {"asset_key": asset_key, "system_id": system_id, "is_new": False}
    return {"asset_key": asset_key, "system_id": system_id, "is_new": True}


# ========== INTEL 契约 ==========

def collect_from_task(task_id: str) -> Dict[str, Any]:
    """从任务 site 结果归集资产（幂等：按 asset_key 归并）。契约返回摘要 dict。"""
    if not task_id:
        return {"error": "task_id 必填"}
    try:
        repo = get_repo()
        task = repo.collection(Collections.TASK).find_one({"_id": _oid(task_id)})
        task_name = (task or {}).get("name", "")
        src = (task or {}).get("source", {}) or {}
        unit = (src.get("unit") if isinstance(src, dict) else "") or ""
        unit_map = (task or {}).get("unit_map", {}) or {}
        total, new_cnt, sys_ids, asset_keys = 0, 0, set(), []
        for site_item in repo.collection(Collections.SITE).find({"task_id": task_id}):
            total += 1
            ret = upsert_asset(site_item, unit=unit, task_id=task_id, task_name=task_name, unit_map=unit_map)
            if ret["is_new"]:
                new_cnt += 1
            if ret["system_id"]:
                sys_ids.add(ret["system_id"])
            if ret.get("asset_key"):
                asset_keys.append(ret["asset_key"])
        return {"task_id": task_id, "site_total": total, "new_asset": new_cnt,
                "system_cnt": len(sys_ids), "asset_keys": asset_keys}
    except Exception as exc:
        logger.debug("collect_from_task degraded: %s", exc)
        return {"error": str(exc), "task_id": task_id, "site_total": 0, "new_asset": 0,
                "system_cnt": 0, "asset_keys": []}


def _parse_mission_intel(options: Dict[str, Any]) -> List[Dict[str, Any]]:
    """把 task.options.mission_intel_raw（前端 JSON 字符串 [{match:{unit,target},text}]）解析成 list。
    兼容已是 list 的情形。解析失败/空 → []（治断链：旧代码存 raw 但派发读 mission_intel 键不匹配）。"""
    raw = options.get("mission_intel_raw") or options.get("mission_intel")
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        import json as _json
        data = _json.loads(raw) if isinstance(raw, str) else []
        return data if isinstance(data, list) else []
    except Exception:
        return []


def auto_collect_after_scan(task_id: str) -> Dict[str, Any]:
    """扫完钩子：归集 + 按 task.options.auto_pentest 经 PENTEST_DISPATCH 派发。
    PENTEST_DISPATCH（ai_pentest）未注册时**只归集不派发降级**（不孤岛靠归集本身可用）。
    归集 0 资产但 auto_pentest=True 且有明确目标时，直接用目标创建资产并派发（支持"只渗透不扫描"）。"""
    collected = collect_from_task(task_id)
    dispatched = None
    skipped = None
    try:
        task = get_repo().collection(Collections.TASK).find_one({"_id": _oid(task_id)})
        options = ((task or {}).get("options", {}) or {})
        _keys = collected.get("asset_keys") or []
        task_type = (task or {}).get("type", "") or ""
        if bool(options.get("auto_pentest", False)) and not _keys:
            # 归集 0 资产但有明确目标 → 直接用目标创建资产再派发（"只渗透不扫描"场景，仅 domain/ip 适用）。
            # unit/fofa 类型的 target 不是可访问 host（unit=中文单位名、fofa=display 文案），
            # 绝不能拼 http:// 当 site 归集——否则造出 http://单位名 垃圾资产、派发假目标。
            # 遵守 _unit_handler 的 honest degrade 契约（"反查不到不伪造"）：这两类归集 0 就跳过派发。
            target = (task or {}).get("target", "").strip()
            if task_type in ("unit", "fofa"):
                skipped = "本任务（{}）归集 0 资产，目标非可访问 host，honest degrade 不伪造资产".format(task_type)
            elif target:
                _keys = _ensure_target_as_asset(target, task_id, task or {})
            if not _keys and not skipped:
                skipped = "本任务归集 0 资产且目标无法转为资产，跳过派发"
        if bool(options.get("auto_pentest", False)) and _keys:
            dispatcher = get_registry().get(_pentest_role())
            if dispatcher and hasattr(dispatcher, "batch_create_from_assets"):
                # 代理出口 4模式（2026-08）：优先新 pentest_egress{mode,rule_id}，回退旧 pentest_proxy/proxy_source。
                _peg = options.get("pentest_egress") or {}
                _pmode = (_peg.get("mode") if isinstance(_peg, dict) else "") or options.get("pentest_proxy") or "smart"
                _prid = (_peg.get("rule_id") if isinstance(_peg, dict) else "") or ""
                dispatched = dispatcher.batch_create_from_assets(
                    asset_keys=_keys,
                    auto_start=True, skip_pentested=True,
                    mode=options.get("pentest_mode") or "src",
                    egress_proxy=_pmode, proxy_source=_prid or options.get("proxy_source") or "subscription",
                    whitelist=options.get("pentest_whitelist") or [],
                    mission_intel=_parse_mission_intel(options),
                    dedup_level=int(options.get("dedup_level", 2) or 2),
                    scope_drift_level=int(options.get("scope_drift_level", 2) or 2),
                    intel_enabled=bool(options.get("intel_enabled", True)),
                    provider_id=options.get("pentest_provider_id") or "",   # 锁定 AI 模型透传到会话
                    source_task_id=str(task_id))
            else:
                skipped = "PENTEST_DISPATCH 未就绪（ai_pentest 未建），只归集不派发"
    except Exception as exc:
        logger.debug("auto_collect dispatch degraded: %s", exc)
        skipped = "派发降级: {}".format(exc)
    out: Dict[str, Any] = {"collected": collected, "dispatched": dispatched}
    if skipped:
        out["skipped"] = skipped
    return out


# 合法 host 校验：域名（含点、仅字母数字/连字符/点，末段是字母）或 IPv4（可带 :port）。
# 拒绝中文单位名、含空格/=/引号 的 FOFA 语句等非 host 串，防它们被拼成 http:// 归集为垃圾资产。
_HOST_RE = re.compile(r"^(?:https?://)?"
                      r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"   # 域名
                      r"|(?:\d{1,3}\.){3}\d{1,3})"                                              # 或 IPv4
                      r"(?::\d{1,5})?(?:/.*)?$")


def _is_valid_host(t: str) -> bool:
    """判断字符串是否为可访问 host（合法域名或 IPv4，可带 scheme/port/path）。
    只有它才能被拼 http:// 当 site 归集。unit(中文单位名)/fofa(查询语句)非 host，返回 False。"""
    return bool(_HOST_RE.match((t or "").strip()))


def _ensure_target_as_asset(target: str, task_id: str, task: Dict[str, Any]) -> List[str]:
    """将任务目标直接注册为资产（支持"只渗透不扫描"：策略关了扫描但开了 auto_pentest）。
    为每个目标构造最小 site 文档并调 upsert_asset，返回 asset_keys。
    双保险（主守卫在 auto_collect_after_scan 按 type 排除 unit/fofa）：这里再按 host 格式过滤，
    非合法 host（中文单位名/FOFA 语句/含空格等）一律跳过不归集，防未来新增任务类型再踩坑。"""
    targets = [t.strip() for t in re.split(r"[,;\n\r]+", target) if t.strip()]
    keys = []
    src = (task.get("source", {}) or {})
    unit = (src.get("unit") if isinstance(src, dict) else "") or ""
    task_name = task.get("name", "")
    for t in targets:
        if not _is_valid_host(t):
            logger.info("_ensure_target_as_asset: 目标 %r 非合法 host，跳过（不伪造资产）", t[:60])
            continue
        # 构造 site URL：域名/IP 加 http:// 前缀（已带 scheme 则原样）
        if re.match(r"^https?://", t, re.I):
            site_url = t
        else:
            site_url = "http://{}".format(t)
        site_doc = {"site": site_url, "hostname": t.split("//")[-1].split("/")[0].split(":")[0],
                    "title": "", "status": 0, "task_id": str(task_id)}
        ret = upsert_asset(site_doc, unit=unit, task_id=str(task_id), task_name=task_name)
        if ret.get("asset_key"):
            keys.append(ret["asset_key"])
    return keys


def _pentest_role() -> str:
    from sentinel_platform.contracts import ROLE
    return ROLE.PENTEST_DISPATCH


# ========== 叶子非 ROLE 能力（供 router / 前端）==========

def stat() -> Dict[str, Any]:
    """情报中心总览统计（对齐前端 IntelStat）。读库失败降级零值。"""
    try:
        repo = get_repo()
        a = repo.collection(Collections.INTEL_ASSET)
        return {
            "asset_total": a.count_documents({}),
            "asset_pentested": a.count_documents({"pentest_status": "done"}),
            "system_total": repo.collection(Collections.INTEL_SYSTEM).count_documents({}),
            "code_total": repo.collection(Collections.INTEL_CODE).count_documents({}),
            "code_audited": repo.collection(Collections.INTEL_CODE).count_documents({"audit_status": "done"}),
            "report_total": repo.collection(Collections.INTEL_REPORT).count_documents({}),
            "asset_with_vuln": a.count_documents({"recon.summary.vuln_cnt": {"$gt": 0}}),
            "asset_with_leak": a.count_documents({"recon.summary.leak_cnt": {"$gt": 0}}),
            "asset_with_secret": a.count_documents({"recon.summary.secret_cnt": {"$gt": 0}}),
        }
    except Exception:
        return {k: 0 for k in ("asset_total", "asset_pentested", "system_total", "code_total",
                               "code_audited", "report_total", "asset_with_vuln",
                               "asset_with_leak", "asset_with_secret")}


_INTEL_COLLS = {
    "intel_asset": Collections.INTEL_ASSET, "intel_system": Collections.INTEL_SYSTEM,
    "intel_code": Collections.INTEL_CODE, "intel_report": Collections.INTEL_REPORT,
}


def list_collection(collection: str, page: int = 1, size: int = 10, **filters: Any) -> Dict[str, Any]:
    """情报集合分页查询（intel_asset/system/code/report）。**禁硬限制**：size<=0 返全量。"""
    name = _INTEL_COLLS.get(collection)
    if not name:
        return {"items": [], "total": 0, "page": 1, "size": size, "error": "未知集合"}
    import re
    q: Dict[str, Any] = {}
    for f in ("unit", "system_id", "pentest_status", "asset_key"):
        if filters.get(f):
            q[f] = filters[f]
    if filters.get("keyword"):
        kw = {"$regex": re.escape(filters["keyword"]), "$options": "i"}
        q["$or"] = [{"key": kw}, {"system_name": kw}, {"hostname": kw}, {"name": kw}]
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 10
    try:
        coll = get_repo().collection(name)
        total = coll.count_documents(q)
        cur = coll.find(q).sort("_id", -1)
        if size and size > 0:
            cur = cur.skip((page - 1) * size).limit(size)
        items = []
        for d in cur:
            d["_id"] = str(d.get("_id", ""))
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        logger.debug("list_collection degraded: %s", exc)
        return {"items": [], "total": 0, "page": page, "size": size}


def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    """渗透报告详情（intel_report 单条）。找不到返 None（#4：前端点报告查看，原无此端点→404）。"""
    rid = (report_id or "").strip()
    if not rid:
        return None
    try:
        d = get_repo().collection(Collections.INTEL_REPORT).find_one({"_id": _oid(rid)})
        if not d:
            return None
        d["_id"] = str(d.get("_id", ""))
        return d
    except Exception as exc:
        logger.debug("get_report %s degraded: %s", rid, exc)
        return None


def delete_records(collection: str, ids: List[str]) -> Dict[str, Any]:
    """批量删除情报集合记录（#5：前端点选删除，原无 delete 端点/能力→404）。
    collection 必须在白名单 _INTEL_COLLS；ids 必须非空（禁空条件全表删，同 batch 派发铁律）。"""
    name = _INTEL_COLLS.get(collection)
    if not name:
        return {"error": "未知集合: {}".format(collection), "deleted": 0}
    ids = [str(x).strip() for x in (ids or []) if str(x).strip()]
    if not ids:
        return {"error": "_id(非空数组) 必填，拒绝空条件删除", "deleted": 0}
    try:
        oids = [_oid(x) for x in ids]
        r = get_repo().collection(name).delete_many({"_id": {"$in": oids}})
        return {"deleted": int(getattr(r, "deleted_count", 0) or 0)}
    except Exception as exc:
        logger.debug("delete_records %s degraded: %s", collection, exc)
        return {"error": str(exc), "deleted": 0}


def match_asset(site: str) -> Optional[Dict[str, Any]]:
    """渗透前去重：给定 URL 查资产实例是否已存在/已渗透。返回资产 dict 或 None。"""
    asset_key = normalize_asset_key(site)
    if not asset_key:
        return None
    try:
        item = get_repo().collection(Collections.INTEL_ASSET).find_one({"key": asset_key})
        if not item:
            return None
        item["_id"] = str(item["_id"])
        return item
    except Exception:
        return None


def build_pentest_context(asset_key: str) -> Dict[str, Any]:
    """AI 渗透前高价值情报档案；完整明细由专用工具按指针读取，避免开局上下文爆炸。"""
    try:
        repo = get_repo()
        asset = repo.collection(Collections.INTEL_ASSET).find_one({"key": asset_key})
    except Exception:
        asset = None
    if not asset:
        return {"identity": {"asset_key": asset_key}, "attack_surface": {}, "history": {}, "pointers": {}}
    recon = asset.get("recon", {}) or {}
    task_id = asset.get("source_task_id", "")
    host = asset.get("hostname", "")

    def _samples(name: str, query: Dict[str, Any], fields: Dict[str, int], limit: int = 20) -> List[Dict[str, Any]]:
        try:
            rows = []
            for d in repo.collection(name).find(query, fields).limit(limit):
                d.pop("_id", None)
                rows.append(d)
            return rows
        except Exception:
            return []

    target_rx = {"$regex": _re.escape(host)} if host else None
    scoped = {"task_id": task_id} if task_id else {}
    urls = _samples(Collections.URL, dict(scoped), {"url": 1, "site": 1, "status_code": 1, "source": 1})
    wih_q = dict(scoped)
    if host:
        wih_q["$or"] = [{"site": target_rx}, {"content": target_rx}]
    wih = _samples(Collections.WIH, wih_q, {"record_type": 1, "content": 1, "site": 1})
    leaks_q = dict(scoped)
    if host:
        leaks_q["$or"] = [{"site": target_rx}, {"url": target_rx}]
    leaks = _samples(Collections.FILELEAK, leaks_q, {"site": 1, "url": 1, "status_code": 1})
    # 攻击面已知漏洞：与漏洞中心口径一致（含 lead 待验证，非只 verified），否则"漏洞中心有洞会话台不显示"。
    # 匹配放宽：asset_key 精确 OR target/site 命中本资产 host（历史 finding 可能未落 asset_key 或键不一致）。
    fq: Dict[str, Any] = {"asset_key": asset_key}
    if host:
        fq = {"$or": [{"asset_key": asset_key}, {"target": target_rx}, {"site": target_rx}]}
    # known_findings 保留 _id + 标记 source="ai"：供会话台左侧"已确认漏洞"点击 → 调
    # vuln_center.unified_detail("ai", _id) 拉完整详情（证据/CVSS/PoC/key_response）。
    # 不复用 _samples（它 pop 掉 _id），这里单独查并把 _id 转成字符串带出。
    findings = []
    try:
        for d in repo.collection(Collections.INTEL_FINDING).find(
                fq, {"vuln_type": 1, "target": 1, "severity": 1, "evidence_level": 1,
                     "status": 1, "verified": 1, "title": 1}).limit(20):
            d["_id"] = str(d.get("_id", ""))
            d["source"] = "ai"
            findings.append(d)
    except Exception:
        findings = []
    return {
        "identity": {"asset_key": asset_key, "hostname": host, "fld": asset.get("fld", ""),
                     "unit": asset.get("unit", ""), "system_name": asset.get("system_name", ""),
                     "system_id": asset.get("system_id", "")},
        "attack_surface": {"ports": recon.get("ports", []), "summary": recon.get("summary", {}),
                           "url_samples": urls, "wih_samples": wih, "fileleak_samples": leaks},
        "known_findings": findings,
        "history": {"pentest_status": asset.get("pentest_status", "none"),
                    "report_id": asset.get("report_id", "")},
        "pointers": {"task_id": task_id, "unit": asset.get("unit", ""),
                     "system_id": asset.get("system_id", ""), "asset_key": asset_key},
    }


def resolve_icp(domain: str) -> Dict[str, Any]:
    """域名 → 备案单位（经 ext_source，未建降级空 unit）。写报告时按需查。"""
    out = {"domain": domain, "unit": "", "icp_no": "", "source": "", "updated": 0}
    svc = get_registry().get("ext_source_service")
    if svc and hasattr(svc, "icp_query"):
        try:
            r = svc.icp_query(domain) or {}
            out.update({"unit": r.get("unit", ""), "icp_no": r.get("icp_no", ""), "source": r.get("source", "")})
        except Exception:
            pass
    return out


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0, "": 0}


def save_pentest_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """AI 渗透会话收尾:写一篇 intel_report（往期报告，供三层情报联动第二层「往期借鉴」）。

    从 intel_finding 按 session_id 派生 vuln_index/max_severity（会话漏洞已由实时 report_finding
    + 末尾 md 补遗登记）。幂等:同 source_session 已有则更新（会话续跑不重复建报告）。
    report 需含 session_id;可选 unit/asset_key/source_task_id/site/content/system_name/title。
    无 session_id → 返回 {error} 不抛。
    """
    session_id = str(report.get("session_id") or "").strip()
    if not session_id:
        return {"error": "session_id 必填"}
    try:
        finds = list(get_repo().collection(Collections.INTEL_FINDING).find({"session_id": session_id}))
        vuln_index = [str(f.get("_id")) for f in finds]
        max_sev, max_rank = "", -1
        for f in finds:
            sv = (f.get("severity") or "").lower()
            if _SEV_RANK.get(sv, 0) > max_rank:
                max_rank, max_sev = _SEV_RANK.get(sv, 0), sv
        now = models_now()
        site = report.get("site", "") or report.get("asset_key", "")
        doc = {
            "source_session": session_id,
            "source_task_id": str(report.get("source_task_id", "") or ""),
            "unit": report.get("unit", ""), "asset_key": report.get("asset_key", ""),
            "title": report.get("title", "") or "AI 渗透报告 {}".format(site),
            "system_name": report.get("system_name", ""),
            "max_severity": max_sev, "vuln_index": vuln_index,
            "content": report.get("content", ""), "update_date": now,
        }
        rcoll = get_repo().collection(Collections.INTEL_REPORT)
        existed = rcoll.find_one({"source_session": session_id})
        if existed:
            rcoll.update_one({"_id": existed["_id"]}, {"$set": doc})
            _mark_asset_pentested(report.get("asset_key", ""), str(existed["_id"]))
            return {"ok": True, "report_id": str(existed["_id"]), "vuln_count": len(vuln_index), "updated": True}
        doc["save_date"] = now
        rid = rcoll.insert_one(doc).inserted_id
        # 回填资产 pentest_status=done + report_id（治流式多触发重复派发：done 后 skip_pentested 生效）
        _mark_asset_pentested(report.get("asset_key", ""), str(rid))
        return {"ok": True, "report_id": str(rid), "vuln_count": len(vuln_index), "updated": False}
    except Exception as exc:
        logger.debug("save_pentest_report degraded: %s", exc)
        return {"error": str(exc)}


# ========== 轴二：同系统跨单位打法借鉴（intel_system.success_paths）==========
# key=system_id（非资产 key）。铁律一：跨单位打法是待验证假设，返回脱敏（物理标识→{TARGET}/凭证打码）
# + 显式提示须本目标自证。只搬方法不搬赃物。
import re as _re

_CRED_HINT = _re.compile(r"(?i)(cookie|token|session|authorization|password|passwd|pwd|secret|api[_-]?key)\b\s*[:=]\s*\S+")


def _desensitize_path(text: str, instance_hosts: List[str]) -> str:
    """脱敏跨单位打法：本系统各实例 host → {TARGET}，凭证键值打码。只搬方法不搬赃物。"""
    if not text:
        return ""
    out = str(text)
    for h in sorted({h for h in (instance_hosts or []) if h}, key=len, reverse=True):
        try:
            out = _re.sub(_re.escape(h), "{TARGET}", out, flags=_re.IGNORECASE)
        except Exception:
            pass
    out = _CRED_HINT.sub(lambda m: "{}=<REDACTED>".format(m.group(1)), out)
    return out


def _system_hosts(sysdoc: Dict[str, Any]) -> List[str]:
    hosts = []
    for k in (sysdoc.get("instance_keys") or []):
        try:
            h = urlsplit(k).hostname or ""
            if h:
                hosts.append(h)
        except Exception:
            pass
    return hosts


# ========== 指纹分层打法库（intel_playbook，核心链路 §6.2）==========
# 两级目录：Layer1 单组件 / Layer2 组件组合。推荐分 = 层级基础分 + 有效分 + title辅助。
# 有效分：出高危+5 / 出中低危0 / 没出洞-5；新条目初始=同层中位数（冷启动）。

_LAYER_BASE = {1: 10, 2: 20}
_TITLE_BONUS = 5


def _norm_components(components: List[str]) -> List[str]:
    """组件名归一（小写去空白去重排序）。"""
    return sorted({(c or "").strip().lower() for c in (components or []) if c and str(c).strip()})


def _playbook_layer_key(components: List[str]) -> Any:
    """按组件数定层级 + 目录 key。1 个组件=Layer1，≥2=Layer2（组合排序 join）。"""
    comps = _norm_components(components)
    if not comps:
        return None
    if len(comps) == 1:
        return (1, comps[0])
    return (2, "|".join(comps))


def _median_effective_score(layer: int) -> int:
    """同层所有打法有效分的中位数（新条目冷启动初始值）。空库返 0。"""
    try:
        scores = [int(d.get("effective_score", 0) or 0)
                  for d in get_repo().collection(Collections.INTEL_PLAYBOOK).find(
                      {"fingerprint_layer": layer}, {"effective_score": 1})]
        if not scores:
            return 0
        scores.sort()
        n = len(scores)
        return scores[n // 2] if n % 2 else (scores[n // 2 - 1] + scores[n // 2]) // 2
    except Exception:
        return 0


def match_playbook(fingerprints: List[str], title: str = "") -> Dict[str, Any]:
    """按确认指纹逐层匹配打法库（Layer2 组合 → Layer1 单组件），按推荐分排序。
    推荐分 = 层级基础分 + 有效分 + title辅助。铁律一：跨单位打法是待验证假设，须本目标自证。"""
    comps = _norm_components(fingerprints)
    out: Dict[str, Any] = {"count": 0, "playbooks": [],
                           "note": "跨单位打法是待验证假设(可能二开/已打补丁)，必须本目标实证，不可当结论直接报洞。"}
    if not comps:
        return out
    comp_set = set(comps)
    title_l = (title or "").strip().lower()
    try:
        rows = list(get_repo().collection(Collections.INTEL_PLAYBOOK).find({}))
    except Exception as exc:
        logger.debug("match_playbook query degraded: %s", exc)
        return out
    scored = []
    for d in rows:
        pb_comps = set(d.get("fingerprints") or [])
        if not pb_comps or not pb_comps.issubset(comp_set):
            continue  # 打法要求的组件必须都在目标指纹里才匹配
        layer = int(d.get("fingerprint_layer", 1) or 1)
        base = _LAYER_BASE.get(layer, 10)
        eff = int(d.get("effective_score", 0) or 0)
        rec = base + eff
        pb_title = (d.get("title") or "").strip().lower()
        if title_l and pb_title and pb_title in title_l:
            rec += _TITLE_BONUS
        scored.append((rec, d))
    scored.sort(key=lambda x: x[0], reverse=True)
    out["playbooks"] = [{
        "playbook_id": str(d.get("_id", "")),
        "vuln_type": d.get("vuln_type", ""),
        "method": d.get("method", ""),
        "fingerprints": d.get("fingerprints") or [],
        "recommend_score": rec,
        "useful_count": int(d.get("useful_count", 0) or 0),
    } for rec, d in scored]
    out["count"] = len(out["playbooks"])
    return out


def read_system_playbook(system_id: str) -> Dict[str, Any]:
    """契约兼容入口（旧签名按 system_id）：解析该系统指纹 → 转调 match_playbook。
    缺 system_id/指纹 → 空。新体系按指纹匹配，不再读 intel_system.success_paths 平铺。"""
    if not system_id:
        return {"count": 0, "playbooks": [], "note": "无 system_id"}
    try:
        sysdoc = get_repo().collection(Collections.INTEL_SYSTEM).find_one({"_id": _oid(system_id)})
        if not sysdoc:
            return {"count": 0, "playbooks": [], "note": "system not found"}
        return match_playbook(sysdoc.get("finger_names") or [], sysdoc.get("title", ""))
    except Exception as exc:
        logger.debug("read_system_playbook error: %s", exc)
        return {"count": 0, "playbooks": []}


def write_playbook(components: List[str], vuln_type: str, method: str = "",
                   title: str = "", unit: str = "", **kwargs: Any) -> Dict[str, Any]:
    """打穿后回写打法到 intel_playbook（AI 归档时自判层级=组件数）。
    幂等（同层级+同组件+同 vuln_type+同 method 累计 seen_count）；新条目初始有效分=同层中位数（冷启动）。
    仅 verified 漏洞该回写（调用方保证）。返回 {ok,dup,playbook_id}。"""
    if not vuln_type:
        return {"ok": False, "error": "vuln_type 必填"}
    lk = _playbook_layer_key(components)
    if not lk:
        return {"ok": False, "error": "无有效组件指纹，无法归档"}
    layer, _dir = lk
    comps = _norm_components(components)
    m = (method or "").strip()
    now = models_now()
    try:
        coll = get_repo().collection(Collections.INTEL_PLAYBOOK)
        key = {"fingerprint_layer": layer, "fingerprints": comps,
               "vuln_type": vuln_type, "method": m}
        existed = coll.find_one(key)
        if existed:
            upd = {"$inc": {"seen_count": 1}, "$set": {"update_date": now}}
            if unit:
                upd["$addToSet"] = {"source_units": unit}
            coll.update_one({"_id": existed["_id"]}, upd)
            return {"ok": True, "dup": True, "playbook_id": str(existed["_id"])}
        doc = {
            "fingerprint_layer": layer, "fingerprints": comps,
            "vuln_type": vuln_type, "method": m, "title": (title or "").strip(),
            "seen_count": 1, "useful_count": 0,
            "effective_score": _median_effective_score(layer),  # 冷启动=同层中位数
            "source_units": [unit] if unit else [],
            "save_date": now, "update_date": now,
        }
        rid = coll.insert_one(doc).inserted_id
        return {"ok": True, "dup": False, "playbook_id": str(rid)}
    except Exception as exc:
        logger.debug("write_playbook error: %s", exc)
        return {"ok": False, "error": str(exc)}


def write_system_playbook(system_id: str, vuln_type: str, method: str = "", **kwargs: Any) -> Dict[str, Any]:
    """契约兼容入口（旧签名按 system_id）：解析系统指纹 → 转调 write_playbook。"""
    if not system_id or not vuln_type:
        return {"ok": False, "error": "system_id/vuln_type 必填"}
    try:
        sysdoc = get_repo().collection(Collections.INTEL_SYSTEM).find_one({"_id": _oid(system_id)})
        comps = (sysdoc or {}).get("finger_names") or []
        title = (sysdoc or {}).get("title", "")
        units = (sysdoc or {}).get("units") or []
        unit = units[0] if units else kwargs.get("unit", "")
        return write_playbook(comps, vuln_type, method=method, title=title, unit=unit)
    except Exception as exc:
        logger.debug("write_system_playbook error: %s", exc)
        return {"ok": False, "error": str(exc)}


def mark_playbook_useful(playbook_id: str = "", vuln_type: str = "", method: str = "",
                         out_high: bool = True, **kwargs: Any) -> Dict[str, Any]:
    """AI 引用打法后回写有效分（核心链路 §6.2）：**只有出高危及以上才 +5，其余一律不加分（0）**。
    out_high=True(出高危及以上)→+5 且 useful_count+1 / out_high=False(其余)→0 不动。
    返回 {ok,effective_score,delta}。"""
    pid = playbook_id or kwargs.get("system_id", "")
    if not pid:
        return {"ok": False, "error": "playbook_id 必填"}
    delta = 5 if out_high else 0
    try:
        coll = get_repo().collection(Collections.INTEL_PLAYBOOK)
        doc = coll.find_one({"_id": _oid(pid)})
        if not doc:
            return {"ok": False, "error": "playbook not found"}
        new_score = int(doc.get("effective_score", 0) or 0) + delta
        upd = {"$set": {"effective_score": new_score, "update_date": models_now()}}
        if out_high:
            upd["$inc"] = {"useful_count": 1}
        coll.update_one({"_id": doc["_id"]}, upd)
        return {"ok": True, "effective_score": new_score, "delta": delta}
    except Exception as exc:
        logger.debug("mark_playbook_useful error: %s", exc)
        return {"ok": False, "error": str(exc)}


# ========== AI 指纹纠错回写（record_component，核心链路 P5）==========

def record_component(asset_key: str, component: str, evidence: str = "",
                     confidence: str = "medium", remove: str = "") -> Dict[str, Any]:
    """AI 渗透中确认/纠正真实技术栈 → 回写 intel_asset.finger_names + 联动 intel_system。
    component=新确认的组件；remove=内核误报要移除的组件。提升指纹覆盖率，后续会话情报匹配受益。
    返回 {ok, finger_names}。缺 asset_key/component 且无 remove → 拒绝。"""
    if not asset_key or (not component and not remove):
        return {"ok": False, "error": "asset_key 必填，component/remove 至少一个"}
    comp = (component or "").strip()
    rm = (remove or "").strip().lower()
    try:
        coll = get_repo().collection(Collections.INTEL_ASSET)
        asset = coll.find_one({"key": asset_key})
        if not asset:
            return {"ok": False, "error": "asset not found"}
        names = list(asset.get("finger_names", []) or [])
        # 移除误报（大小写不敏感）
        if rm:
            names = [n for n in names if (n or "").strip().lower() != rm]
        # 加新组件（去重，大小写不敏感）
        if comp and comp.lower() not in {(n or "").strip().lower() for n in names}:
            names.append(comp)
        merged = sorted({n for n in names if n})
        set_data = {"finger_names": merged, "update_date": models_now(),
                    "system_name": _pick_sys_name(merged, asset.get("title", ""))}
        coll.update_one({"_id": asset["_id"]}, {"$set": set_data})
        # 联动 intel_system：把纠正后的指纹并入系统身份的 finger_names
        sid = asset.get("system_id", "")
        if sid:
            try:
                scoll = get_repo().collection(Collections.INTEL_SYSTEM)
                sysdoc = scoll.find_one({"_id": _oid(sid)})
                if sysdoc:
                    sys_names = sorted({n for n in (list(sysdoc.get("finger_names", []) or []) + merged) if n})
                    scoll.update_one({"_id": sysdoc["_id"]},
                                     {"$set": {"finger_names": sys_names, "update_date": models_now()}})
            except Exception:
                pass
        return {"ok": True, "finger_names": merged, "confidence": confidence}
    except Exception as exc:
        logger.debug("record_component error: %s", exc)
        return {"ok": False, "error": str(exc)}


def get_pentest_report(report_id: str, mode: str = "index", vuln_no: Any = None) -> Dict[str, Any]:
    """读取历史报告；兼容新 source_session 与旧 session_id 数据形状。"""
    try:
        doc = get_repo().collection(Collections.INTEL_REPORT).find_one({"_id": _oid(report_id)})
        if not doc:
            return {"error": "report not found", "report_id": report_id}
        out = {"report_id": str(doc.get("_id", "")), "title": doc.get("title", ""),
               "unit": doc.get("unit", ""), "asset_key": doc.get("asset_key", ""),
               "system_name": doc.get("system_name", ""), "max_severity": doc.get("max_severity", ""),
               "vuln_index": doc.get("vuln_index") or [], "useful_count": int(doc.get("useful_count", 0) or 0),
               "session_id": doc.get("source_session") or doc.get("session_id", ""),
               "save_date": doc.get("save_date", "")}
        if str(mode).lower() == "full":
            out["content"] = doc.get("content", "") or doc.get("report", "")
        if vuln_no not in (None, ""):
            try:
                out["vuln"] = out["vuln_index"][int(vuln_no)]
            except (ValueError, TypeError, IndexError):
                out["vuln"] = None
        return out
    except Exception as exc:
        return {"error": str(exc), "report_id": report_id}


def mark_report_useful(report_id: str, session_id: str = "") -> Dict[str, Any]:
    """借鉴报告后真实出洞才调用；同会话重复调用不重复加分。"""
    try:
        coll = get_repo().collection(Collections.INTEL_REPORT)
        doc = coll.find_one({"_id": _oid(report_id)})
        if not doc:
            return {"ok": False, "error": "report not found"}
        used = list(doc.get("useful_sessions") or [])
        if session_id and session_id in used:
            return {"ok": True, "useful_count": int(doc.get("useful_count", 0) or 0), "dup": True}
        if session_id:
            used.append(session_id)
        count = int(doc.get("useful_count", 0) or 0) + 1
        coll.update_one({"_id": doc["_id"]}, {"$set": {"useful_count": count,
                         "useful_sessions": used, "update_date": models_now()}})
        return {"ok": True, "useful_count": count, "dup": False}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def get_code_audit(system_id: str) -> Dict[str, Any]:
    """按 system.code_id 读取源码审计情报；无数据返回明确空态。"""
    try:
        sysdoc = get_repo().collection(Collections.INTEL_SYSTEM).find_one({"_id": _oid(system_id)}) or {}
        code_id = sysdoc.get("code_id", "")
        code = get_repo().collection(Collections.INTEL_CODE).find_one({"_id": _oid(code_id)}) if code_id else None
        if not code:
            return {"system_id": system_id, "available": False, "findings": [], "message": "暂无源码审计情报"}
        return {"system_id": system_id, "available": True, "code_id": str(code.get("_id", "")),
                "name": code.get("name", ""), "audit_status": code.get("audit_status", ""),
                "findings": code.get("findings") or code.get("vuln_index") or [],
                "report": code.get("report", "") or code.get("content", "")}
    except Exception as exc:
        return {"system_id": system_id, "available": False, "findings": [], "error": str(exc)}


# ========== 报告情报查询（供 ai_pentest 开局/研判用，对齐 §12.11）==========

def _mark_asset_pentested(asset_key: str, report_id: str) -> None:
    """会话出报告后回填资产 pentest_status=done + report_id（治流式多触发重复派发 + 三层联动读历史）。
    异常吞（不反噬报告写入）。对齐旧平台 §13.6.3。"""
    if not asset_key:
        return
    try:
        get_repo().collection(Collections.INTEL_ASSET).update_one(
            {"key": asset_key},
            {"$set": {"pentest_status": "done", "report_id": report_id, "update_date": models_now()}})
    except Exception as exc:
        logger.debug("mark_asset_pentested degraded: %s", exc)


def query_unit_reports(unit: str, domain: str = "", limit: int = 0) -> Dict[str, Any]:
    """按单位查往期报告摘要。limit=0 返回全部；正数由调用方主动限制。"""
    out: Dict[str, Any] = {"unit": unit, "count": 0, "reports": []}
    if not unit:
        return out
    try:
        q: Dict[str, Any] = {"unit": unit}
        cur = get_repo().collection(Collections.INTEL_REPORT).find(q)
        if limit and int(limit) > 0:
            cur = cur.limit(int(limit))
        rows = list(cur)
        reps = []
        for r in rows:
            ak = r.get("asset_key", "") or ""
            if domain and domain not in ak and domain not in (r.get("title", "") or ""):
                continue
            reps.append({
                "report_id": str(r.get("_id", "")), "title": r.get("title", ""),
                "system_name": r.get("system_name", ""), "max_severity": r.get("max_severity", ""),
                "asset_key": ak, "vuln_count": len(r.get("vuln_index") or []),
            })
        out["count"] = len(reps)
        out["reports"] = reps
        return out
    except Exception as exc:
        logger.debug("query_unit_reports error: %s", exc)
        return out


def report_tree() -> Dict[str, Any]:
    """渗透报告三级目录树（BUG-014）：按 任务名 > 单位 > 资产 归档全部 intel_report。
    前端 IntelCenter「三级目录」默认视图消费；返回 {tree:[{task_name, report_cnt,
    units:[{unit, report_cnt, assets:[{asset, report_cnt, reports:[{_id,asset_key,
    system_name,max_severity,save_date}]}]}]}]}。
    task_name 由 report.source_task_id 反查 task 集合的 name（查不到→用 id/「未分类任务」降级）。"""
    _UNKNOWN_UNIT = "未知单位"
    try:
        repo = get_repo()
        reports = list(repo.collection(Collections.INTEL_REPORT).find({}).sort("_id", -1))
    except Exception as exc:
        logger.debug("report_tree error: %s", exc)
        return {"tree": []}
    # 反查 task_id → task_name（一次性批量，避免逐条查库）
    task_names: Dict[str, str] = {}
    tids = {str(r.get("source_task_id") or "").strip() for r in reports if r.get("source_task_id")}
    for tid in tids:
        try:
            t = repo.collection(Collections.TASK).find_one({"_id": _oid(tid)}) if tid else None
            if t and t.get("name"):
                task_names[tid] = t["name"]
        except Exception:
            continue
    # 三级嵌套聚合：task_name -> unit -> asset -> [reports]
    tree: Dict[str, Dict[str, Any]] = {}
    for r in reports:
        tid = str(r.get("source_task_id") or "").strip()
        tname = task_names.get(tid) or (("任务 " + tid[:8]) if tid else "未分类任务")
        unit = (r.get("unit") or "").strip() or _UNKNOWN_UNIT
        asset = (r.get("asset_key") or "").strip() or "未知资产"
        item = {"_id": str(r.get("_id", "")), "asset_key": r.get("asset_key", ""),
                "system_name": r.get("system_name", ""), "max_severity": r.get("max_severity", ""),
                "save_date": r.get("save_date", "")}
        tnode = tree.setdefault(tname, {"task_name": tname, "report_cnt": 0, "_units": {}})
        tnode["report_cnt"] += 1
        unode = tnode["_units"].setdefault(unit, {"unit": unit, "report_cnt": 0, "_assets": {}})
        unode["report_cnt"] += 1
        anode = unode["_assets"].setdefault(asset, {"asset": asset, "report_cnt": 0, "reports": []})
        anode["report_cnt"] += 1
        anode["reports"].append(item)
    # 折叠内部 dict → list（前端要数组）
    out = []
    for tnode in tree.values():
        units = []
        for unode in tnode["_units"].values():
            unode["assets"] = list(unode.pop("_assets").values())
            units.append(unode)
        tnode["units"] = units
        tnode.pop("_units", None)
        out.append(tnode)
    return {"tree": out}


def query_subdomain_intel(subdomain: str, sections: Optional[List[str]] = None) -> Dict[str, Any]:
    """按子域名查灯塔侦察情报（该资产已归集的 recon 快照：端口/漏洞/泄漏/密钥/端点摘要）。
    sections 限定返回板块（缺省全返）。经 intel_asset.recon 快照（归集时已抓），缺失降级空。"""
    out: Dict[str, Any] = {"subdomain": subdomain, "found": False, "recon": {}}
    if not subdomain:
        return out
    try:
        coll = get_repo().collection(Collections.INTEL_ASSET)
        # 按 hostname/subdomain 或 key 含子域名匹配（多端口取首条有 recon 的）
        asset = coll.find_one({"$or": [{"subdomain": subdomain}, {"hostname": subdomain},
                                       {"key": {"$regex": _re.escape(subdomain)}}]})
        if not asset:
            return out
        recon = asset.get("recon", {}) or {}
        if sections:
            recon = {k: v for k, v in recon.items() if k in set(sections)}
        out["found"] = True
        out["recon"] = recon
        out["system_name"] = asset.get("system_name", "")
        out["system_id"] = asset.get("system_id", "")
        return out
    except Exception as exc:
        logger.debug("query_subdomain_intel error: %s", exc)
        return out


class IntelServiceImpl:
    """INTEL 实现（满足 contracts.IntelService）+ 叶子非 ROLE 能力。"""
    def collect_from_task(self, task_id: str) -> Dict[str, Any]:
        return collect_from_task(task_id)

    # —— 指纹分层打法库门面（核心链路 §6.2，供 ai_pentest 经 ROLE.INTEL 调）——
    def match_playbook(self, fingerprints: List[str], title: str = "") -> Dict[str, Any]:
        return match_playbook(fingerprints, title)

    def write_playbook(self, components: List[str], vuln_type: str, method: str = "", **kw: Any) -> Dict[str, Any]:
        return write_playbook(components, vuln_type, method=method, **kw)

    def read_system_playbook(self, system_id: str) -> Dict[str, Any]:
        return read_system_playbook(system_id)

    def write_system_playbook(self, system_id: str, vuln_type: str, method: str = "", **kw: Any) -> Dict[str, Any]:
        return write_system_playbook(system_id, vuln_type, method=method, **kw)

    def mark_playbook_useful(self, playbook_id: str = "", vuln_type: str = "", method: str = "",
                             out_high: bool = True, **kw: Any) -> Dict[str, Any]:
        return mark_playbook_useful(playbook_id, vuln_type, method, out_high=out_high, **kw)

    def record_component(self, asset_key: str, component: str, evidence: str = "",
                         confidence: str = "medium", remove: str = "") -> Dict[str, Any]:
        return record_component(asset_key, component, evidence, confidence, remove)

    def query_unit_reports(self, unit: str, domain: str = "", limit: int = 0) -> Dict[str, Any]:
        return query_unit_reports(unit, domain, limit)

    def report_tree(self) -> Dict[str, Any]:
        return report_tree()

    def get_pentest_report(self, report_id: str, mode: str = "index", vuln_no: Any = None) -> Dict[str, Any]:
        return get_pentest_report(report_id, mode, vuln_no)

    def mark_report_useful(self, report_id: str, session_id: str = "") -> Dict[str, Any]:
        return mark_report_useful(report_id, session_id)

    def get_code_audit(self, system_id: str) -> Dict[str, Any]:
        return get_code_audit(system_id)

    def query_subdomain_intel(self, subdomain: str, sections: Optional[List[str]] = None) -> Dict[str, Any]:
        return query_subdomain_intel(subdomain, sections)

    def save_pentest_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        return save_pentest_report(report)

    def auto_collect_after_scan(self, task_id: str) -> Dict[str, Any]:
        return auto_collect_after_scan(task_id)

    def stat(self) -> Dict[str, Any]:
        return stat()

    def list_collection(self, collection: str, **kw: Any) -> Dict[str, Any]:
        return list_collection(collection, **kw)

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return get_report(report_id)

    def delete_records(self, collection: str, ids: List[str]) -> Dict[str, Any]:
        return delete_records(collection, ids)

    def match_asset(self, site: str) -> Optional[Dict[str, Any]]:
        return match_asset(site)

    def build_pentest_context(self, asset_key: str) -> Dict[str, Any]:
        return build_pentest_context(asset_key)

    def resolve_icp(self, domain: str) -> Dict[str, Any]:
        return resolve_icp(domain)


_service = IntelServiceImpl()


def get_service() -> IntelServiceImpl:
    return _service



