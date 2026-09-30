"""从分发系统中心拉取漏洞情报 → 经现有 upsert_vuln 入本地 Mongo（vuln_intel 中心化拉取端）。

仿 modules/ai_pentest/_extension_store._get 的授权（activation.read_key + source_url + X-Update-Key）
与错误分类。中心不可达时由 scheduler._tick_vuln_feed 降级本地 run_feed 直拉，本模块只负责"拉+入库"。
消费方零改动：入的还是本地 Mongo vuln_intel 集合，仅数据来源从"本地爬"变"中心拉"。
"""
import gzip
import json
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections
from sentinel_platform.modules.system import activation

logger = get_logger()
_META_NAME = "default"


def _meta_coll():
    return get_repo().collection(Collections.VULN_FEED_META)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _get(path, timeout=60):
    """带 X-Update-Key 的授权 GET，返回解析后的 JSON（自动 gunzip）。未激活抛 RuntimeError。"""
    key = activation.read_key()
    if not key:
        raise RuntimeError("未激活（无 UPDATE.KEY），无法拉取中心情报")
    url = activation.source_url() + path
    req = Request(url, headers={"X-Update-Key": key, "Accept-Encoding": "gzip",
                                "Accept": "application/json"})
    resp = urlopen(req, timeout=timeout)
    raw = resp.read()
    if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8", "ignore"))


def _last_ts():
    try:
        d = _meta_coll().find_one({"name": _META_NAME}) or {}
        return float(d.get("intel_last_ts") or 0)
    except Exception:
        return 0.0


def _save_progress(ts, remote_cnt, pulled):
    try:
        _meta_coll().update_one({"name": _META_NAME}, {"$set": {
            "intel_last_ts": ts, "intel_remote_count": remote_cnt,
            "intel_last_pull": _now(),
            "sources.central": {"fetched": pulled, "last_fetch": _now()},
        }}, upsert=True)
    except Exception:
        pass


def pull_and_upsert():
    """拉中心情报增量 → upsert_vuln 入本地库。返回 {ok, pulled, new, merged} 或 {ok:False, reason}。"""
    from .vuln_intel import upsert_vuln
    # 1) 版本比对
    try:
        ver = _get("/intel/version", timeout=20)
    except HTTPError as e:
        reason = "unauthorized" if e.code in (401, 403) else "http_{}".format(e.code)
        try:
            if reason == "unauthorized":
                activation.note_remote_result("unauthorized")
        except Exception:
            pass
        return {"ok": False, "reason": reason}
    except (URLError, RuntimeError, Exception) as e:
        return {"ok": False, "reason": "network:{}".format(str(e)[:80])}
    remote_ts = float(ver.get("updated_at") or 0)
    remote_cnt = int(ver.get("count") or 0)
    if remote_cnt == 0:
        return {"ok": True, "pulled": 0, "note": "central empty"}
    last = _last_ts()
    if remote_ts <= last:
        return {"ok": True, "pulled": 0, "note": "up to date"}
    # 2) 增量拉取
    try:
        data = _get("/intel/pull?since={}".format(last), timeout=180)
    except Exception as e:
        return {"ok": False, "reason": "pull_failed:{}".format(str(e)[:80])}
    items = data.get("items") or []
    new = merged = 0
    for it in items:
        src0 = ((it.get("sources") or [{}])[0]) or {}
        vdict = {
            "cve_id": it.get("cve_id", ""), "title": it.get("title", ""),
            "severity": it.get("severity", "unknown"), "cvss": it.get("cvss", ""),
            "products": it.get("products") or [], "poc_urls": it.get("poc_urls") or [],
            "in_kev": bool(it.get("in_kev")), "executable": bool(it.get("executable")),
            "exec_kind": it.get("exec_kind", ""), "exec_ref": it.get("exec_ref", ""),
            "source": src0.get("name") or "central", "source_url": src0.get("url", ""),
            "source_raw_id": src0.get("raw_id", ""), "published_date": it.get("published_date", ""),
        }
        try:
            action, _ = upsert_vuln(vdict)
        except Exception:
            continue
        if action == "new":
            new += 1
        elif action == "merged":
            merged += 1
    until = float(data.get("until") or remote_ts)
    _save_progress(until, remote_cnt, len(items))
    try:
        activation.note_remote_result("")
    except Exception:
        pass
    logger.info("intel_pull: pulled %d (new=%d merged=%d) until=%s", len(items), new, merged, until)
    return {"ok": True, "pulled": len(items), "new": new, "merged": merged}
