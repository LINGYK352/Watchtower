"""risk_intel/vuln_intel 的本地情报源辅助（同类别私有，主叶子 import 它，不对外）。

**2026-09-28 中心化改造**：开源外部漏洞情报（CISA KEV/NVD/GitHub/国内源等 8 源）的**主动拉取已移出本系统**，
统一由分发系统（云端 Watchtower）中心爬取，实例经 modules/risk_intel/intel_pull 从云端拉取入库
（见 云端/docs/漏洞情报中心化分发设计.md）。本文件**只保留本地可执行能力源**——它们读本实例本地数据
（NPoC 插件 poc 集合 / nuclei 模板文件），产出 executable 情报，反映本实例真实可打能力，天然 per-instance、
无法也不应中心化。故本系统不再携带任何主动爬取开源外部源的代码。

Fetcher 契约：无参函数返回 list[标准 dict]。入库统一经 vuln_intel.upsert_vuln 去重聚合。
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, List, Optional

from sentinel_platform.core import get_repo, get_config, get_logger
from sentinel_platform.contracts import Collections, get_registry, ROLE

logger = get_logger()

DEFAULT_FEED_INTERVAL = 6 * 3600  # 6h


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ============================ 本地可执行源（瞭望塔能直接打，per-instance） ============================
def fetch_arl_npoc() -> List[Dict[str, Any]]:
    """瞭望塔本地 NPoC 插件（poc 集合）→ 情报（source=arl_npoc，executable=可直接执行）。

    poc 集合每条是「组件(app_name)→ 可执行验证手段(vul_name)」映射，纳入情报库，
    AI 查组件时能拿到本地直接能打的 PoC，而非只有外部 CVE 编号。
    """
    out = []
    try:
        docs = list(get_repo().collection(Collections.POC).find({}))
    except Exception as exc:
        logger.debug("fetch_arl_npoc read poc failed: %s", exc)
        return out
    for p in docs:
        app_name = p.get("app_name", "")
        if not app_name:
            continue
        plugin = p.get("plugin_name", "")
        out.append({
            "cve_id": "", "title": p.get("vul_name", "") or "{} 漏洞".format(app_name),
            "severity": "high", "products": [app_name], "poc_urls": [], "in_kev": False,
            "executable": True, "exec_kind": "arl_npoc", "exec_ref": plugin,
            "source": "arl_npoc", "source_url": "",
            "source_raw_id": "npoc:{}".format(plugin), "published_date": "",
        })
    return out


def _nuclei_templates_dir() -> str:
    """定位 nuclei 模板目录：配置 NUCLEI.TEMPLATES_DIR 优先，否则标准候选路径。缺失返回空。"""
    import os
    cfg_dir = ""
    try:
        cfg_dir = get_config().section("NUCLEI", "TEMPLATES_DIR", default="") or ""
    except Exception:
        cfg_dir = ""
    candidates = [cfg_dir, os.path.expanduser("~/nuclei-templates"),
                  os.path.expanduser("~/.config/nuclei-templates")]
    return next((c for c in candidates if c and os.path.isdir(c)), "")


def fetch_nuclei_templates(limit: int = 0) -> List[Dict[str, Any]]:
    """瞭望塔本地 nuclei 模板 → 情报（source=nuclei，executable=可直接扫）。模板目录不存在则跳过（返回空不报错）。"""
    import os
    import glob
    base = _nuclei_templates_dir()
    if not base:
        return []
    import yaml  # 惰性（vendor: PyYAML-5.4.1）
    out = []
    paths = glob.glob(os.path.join(base, "**", "*.yaml"), recursive=True)
    if limit and limit > 0:
        paths = paths[:limit]
    for fp in paths:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                tpl = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(tpl, dict):
            continue
        tid = tpl.get("id", "")
        info = tpl.get("info", {}) or {}
        tags = info.get("tags", "")
        tags_l = tags.split(",") if isinstance(tags, str) else (tags or [])
        out.append({
            "cve_id": tid if str(tid).upper().startswith("CVE") else "",
            "title": info.get("name", "") or tid,
            "severity": (info.get("severity", "") or "unknown").lower(),
            "products": tags_l, "poc_urls": [], "in_kev": False,
            "executable": True, "exec_kind": "nuclei", "exec_ref": tid,
            "source": "nuclei", "source_url": "",
            "source_raw_id": "nuclei:{}".format(tid), "published_date": "",
        })
    return out


# ============================ 源注册表（仅本地可执行源）+ 平台展示信息 ============================
# 外部开源源（cisa_kev/nvd/... 共 8 个）的抓取已移到分发系统 云端/distribution/intel_feed.py，本系统不再携带。
FETCHERS: Dict[str, Callable[[], List[Dict[str, Any]]]] = {
    "arl_npoc": fetch_arl_npoc,
    "nuclei": fetch_nuclei_templates,
}

SOURCE_PLATFORMS = {
    # 云端 Watchtower 中心情报库（外部 CVE 情报的唯一来源，经 intel_pull 拉取）
    "central": {"label": "Watchtower 云端情报库", "kind": "cloud", "url": ""},
    # 本地可执行能力源（per-instance）
    "arl_npoc": {"label": "本地 NPoC 插件（可直接执行）", "kind": "local", "url": ""},
    "nuclei": {"label": "本地 Nuclei 模板（可直接扫）", "kind": "local",
               "url": "https://github.com/projectdiscovery/nuclei-templates"},
}


def source_label(name: str) -> str:
    """源名 → 公开平台中文短名（展示用），未知源回退原名。外部源名（cisa_kev 等）历史数据仍可能出现，回退原名即可。"""
    return SOURCE_PLATFORMS.get(name, {}).get("label", name)


def _meta_coll():
    return get_repo().collection(Collections.VULN_FEED_META)


def get_feed_interval() -> int:
    """拉取间隔（秒），从 vuln_feed_meta 读，无则默认 6h，下限 10 分钟。"""
    try:
        doc = _meta_coll().find_one({"name": "default"}) or {}
        v = int(doc.get("interval_seconds") or DEFAULT_FEED_INTERVAL)
        return max(600, v)
    except (TypeError, ValueError):
        return DEFAULT_FEED_INTERVAL
    except Exception:
        return DEFAULT_FEED_INTERVAL


def set_feed_interval(seconds: Any) -> int:
    """设置拉取间隔（秒，下限 600）。返回落库值。"""
    seconds = max(600, int(seconds))
    _meta_coll().update_one({"name": "default"},
                            {"$set": {"interval_seconds": seconds}}, upsert=True)
    return seconds


def _notify_new_highrisk(new_highrisk: List[Dict[str, Any]]) -> None:
    """新增在野/严重漏洞经 ROLE.NOTIFY 汇总推送（可在 API 密钥>飞书>情报推送 开关控制）。"""
    if not new_highrisk:
        return
    try:
        keys_svc = get_registry().get("api_keys_service")
        if keys_svc and hasattr(keys_svc, "get_key"):
            if not (keys_svc.get_key("feishu") or {}).get("vuln_feed_notify", True):
                return
    except Exception:
        pass
    try:
        svc = get_registry().get(ROLE.NOTIFY)
        if not svc:
            return
        lines = ["漏洞情报库新增 {} 条在野/严重漏洞：".format(len(new_highrisk))]
        for v in new_highrisk[:10]:
            tag = "[KEV]" if v.get("in_kev") else "[{}]".format(v.get("severity", ""))
            lines.append("{} {} {}".format(tag, v.get("cve_id") or "", (v.get("title") or "")[:60]))
        svc.notify("\n".join(lines), title="瞭望塔 Watchtower · 漏洞情报更新", level="high")
    except Exception as exc:
        logger.debug("vuln_feed notify failed: %s", exc)


def run_feed(sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """拉取本地可执行源（arl_npoc/nuclei）→ 去重入库。**不再拉取任何外部开源源**（已移到分发系统中心爬）。
    外部 CVE 情报由 scheduler 经 intel_pull 从云端拉取，本函数只负责本地能力源。"""
    from .vuln_intel import upsert_vuln
    sources = sources or list(FETCHERS.keys())   # arl_npoc, nuclei
    report: Dict[str, Any] = {}
    new_highrisk: List[Dict[str, Any]] = []
    for name in sources:
        fetcher = FETCHERS.get(name)
        if not fetcher:
            report[name] = {"error": "unknown source"}
            continue
        try:
            vulns = fetcher()
            new_cnt = merged_cnt = 0
            for v in vulns:
                action, _ = upsert_vuln(v)
                if action == "new":
                    new_cnt += 1
                    if v.get("in_kev") or (v.get("severity") or "").lower() == "critical":
                        new_highrisk.append(v)
                elif action == "merged":
                    merged_cnt += 1
            report[name] = {"fetched": len(vulns), "new": new_cnt, "merged": merged_cnt}
            logger.info("vuln_feed(local) %s -> %s", name, report[name])
        except Exception as e:
            report[name] = {"error": str(e)[:200]}
            logger.warning("vuln_feed(local) %s failed: %s", name, str(e)[:120])
    _save_feed_meta(report)
    _notify_new_highrisk(new_highrisk)
    return report


def _save_feed_meta(report: Dict[str, Any]) -> None:
    """持久化拉取时间 + 每源结果到 vuln_feed_meta（单文档），前端展示用。失败静默。"""
    try:
        now = _now()
        coll = _meta_coll()
        doc = coll.find_one({"name": "default"}) or {"name": "default", "sources": {}}
        srcs = doc.get("sources", {})
        for name, r in report.items():
            srcs[name] = dict(r, last_fetch=now)
        coll.update_one({"name": "default"},
                        {"$set": {"sources": srcs, "last_fetch": now}}, upsert=True)
    except Exception as exc:
        logger.debug("vuln_feed save meta failed: %s", exc)


def feed_status() -> Dict[str, Any]:
    """情报来源健康：云端 Watchtower 中心库（外部 CVE 唯一来源）+ 本地可执行源。供前端可视化。"""
    try:
        doc = _meta_coll().find_one({"name": "default"}) or {}
    except Exception:
        doc = {}
    src_meta = doc.get("sources", {})
    sources = []
    # 1) 云端 Watchtower 中心情报库（外部开源 CVE 情报的唯一来源，经 intel_pull 拉取）
    try:
        from sentinel_platform.modules.system import activation
        cloud_url = activation.source_url() or ""
    except Exception:
        cloud_url = ""
    cen = src_meta.get("central", {}) or {}
    last_pull = doc.get("intel_last_pull") or cen.get("last_fetch", "")
    remote_cnt = doc.get("intel_remote_count", 0) or 0
    sources.append({
        "name": "central", "label": SOURCE_PLATFORMS["central"]["label"], "kind": "cloud",
        "url": cloud_url, "health": "ok" if last_pull else "unknown",
        "fetched": cen.get("fetched", 0) or remote_cnt, "new": 0, "error": "",
        "last_fetch": last_pull, "remote_count": remote_cnt,
    })
    # 2) 本地可执行源（arl_npoc/nuclei，per-instance）
    for name in FETCHERS.keys():
        plat = SOURCE_PLATFORMS.get(name, {})
        m = src_meta.get(name, {})
        fetched = m.get("fetched", 0)
        err = m.get("error", "")
        if err:
            health = "error"
        elif m.get("last_fetch") and fetched > 0:
            health = "ok"
        elif m.get("last_fetch"):
            health = "empty"
        else:
            health = "unknown"
        sources.append({
            "name": name, "label": plat.get("label", name), "kind": plat.get("kind", ""),
            "url": plat.get("url", ""), "health": health, "fetched": fetched,
            "new": m.get("new", 0), "error": err, "last_fetch": m.get("last_fetch", ""),
        })
    interval = get_feed_interval()
    return {"last_fetch": doc.get("last_fetch", ""), "interval_seconds": interval,
            "interval_hours": round(interval / 3600, 1), "sources": sources, "mode": "cloud"}

