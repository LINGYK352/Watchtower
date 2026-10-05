"""GitHub 监控 github_monitor —— 周期 GitHub 关键字监控任务 CRUD + 结果查询（asset 叶子）。

管理 github_scheduler 集合（cron 周期监控任务）+ github_monitor_result 集合（每轮命中）。
净室重写 routes/github_scheduler.py + github_monitor_result.py：任务 CRUD/启停/cron 校验从零写。
cron 校验/下次运行用 croniter（已 vendored 本地库，同 task_schedule）。无 ROLE（核心路由暴露）。

实际周期投递 GitHub 搜索是 orchestration/scheduler 职责（未建）——本叶子做监控任务定义 CRUD +
启停，编排层到点拾取执行；未建时定义可管理（诚实降级）。只依赖 core + croniter + stdlib。
分页与最小间隔均不设硬编码上限（禁硬限制参数）。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from sentinel_platform.core import get_config, get_logger, get_repo

logger = get_logger()

SCHED_COLL = "github_scheduler"
RESULT_COLL = "github_monitor_result"
STATUS_RUNNING = "running"
STATUS_STOPPED = "stopped"

_TEXT_FIELDS = {"name", "keyword"}
_EQUAL_FIELDS = {"status"}
_QUERY_KEYS = {"page", "size", "order"}


def _min_interval_sec() -> int:
    """周期监控最小间隔（秒）。配置决定，默认 0=不限（禁硬编码上限，同 task_schedule）。"""
    try:
        return int(get_config().section("GITHUB", "MONITOR_MIN_INTERVAL_SEC", default=0) or 0)
    except (TypeError, ValueError):
        return 0


def validate_cron(cron: str) -> bool:
    if not cron or not str(cron).strip():
        return False
    try:
        from croniter import croniter
        return bool(croniter.is_valid(str(cron).strip()))
    except ImportError:
        return len(str(cron).split()) == 5
    except Exception:
        return False


def next_run_epoch(cron: str) -> int:
    try:
        from croniter import croniter
        return int(croniter(str(cron).strip(), time.time()).get_next())
    except Exception:
        return 0


def check_interval_ok(cron: str) -> bool:
    """相邻两次间隔 >= 配置最小间隔；默认 0 恒放行（不设硬上限）。"""
    min_iv = _min_interval_sec()
    if min_iv <= 0:
        return True
    try:
        from croniter import croniter
        it = croniter(str(cron).strip(), time.time())
        t1 = it.get_next()
        t2 = it.get_next()
        return (t2 - t1) >= min_iv
    except Exception:
        return True


def _oid(v: Any) -> Any:
    if not v:
        return v
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v
    except Exception:
        return v


def _clean(doc: Dict[str, Any]) -> Dict[str, Any]:
    import datetime as _dt
    out = {}
    for k, v in doc.items():
        if isinstance(v, (_dt.datetime, _dt.date)):
            out[k] = v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, _dt.datetime) else str(v)
        elif k == "_id" or type(v).__name__ == "ObjectId":
            out[k] = str(v)
        else:
            out[k] = v
    return out


def _build_query(args: Dict[str, Any], extra_text=None) -> Dict[str, Any]:
    q: Dict[str, Any] = {}
    text = _TEXT_FIELDS | set(extra_text or [])
    for key, val in (args or {}).items():
        if key in _QUERY_KEYS or val in (None, "") or key == "_id":
            continue
        if key in text:
            q[key] = {"$regex": re.escape(str(val)), "$options": "i"}
        elif key in _EQUAL_FIELDS or key == "github_scheduler_id":
            q[key] = val
    return q


def _paginate(coll_name: str, args: Dict[str, Any], extra_text=None) -> Dict[str, Any]:
    args = args or {}
    try:
        page = max(1, int(args.get("page", 1) or 1))
        size = max(1, int(args.get("size", 10) or 10))     # 无硬上限（禁硬限制参数）
    except (TypeError, ValueError):
        page, size = 1, 10
    query = _build_query(args, extra_text)
    try:
        coll = get_repo().collection(coll_name)
        total = coll.count_documents(query)
        cur = coll.find(query).sort("_id", -1).skip((page - 1) * size).limit(size)
        items = [_clean(d) for d in cur]
    except Exception as e:
        logger.warning("%s list error: %s", coll_name, e)
        total, items = 0, []
    return {"page": page, "size": size, "total": total, "items": items}


def list_monitors(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """周期监控任务分页查询。"""
    return _paginate(SCHED_COLL, args)


def list_results(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """监控命中结果分页查询（可按 github_scheduler_id 过滤）。"""
    return _paginate(RESULT_COLL, args, extra_text={"url", "repo"})


def add_monitor(name: str, keyword: str, cron: str) -> Dict[str, Any]:
    """新建周期监控任务。校验关键字/cron。返回 {_id,name,keyword,cron,status} 或 {error}。"""
    name = (name or "").strip()
    keyword = (keyword or "").strip()
    cron = (cron or "").strip()
    if not keyword:
        return {"error": "关键字必填"}
    if not name:
        name = keyword
    if not validate_cron(cron):
        return {"error": "cron 表达式非法"}
    if not check_interval_ok(cron):
        return {"error": "运行间隔小于配置的最小间隔 GITHUB.MONITOR_MIN_INTERVAL_SEC"}
    import datetime
    nxt = next_run_epoch(cron)
    doc = {"name": name, "keyword": keyword, "cron": cron, "status": STATUS_RUNNING,
           "run_number": 0, "last_run_date": "-",
           "next_run_date": (datetime.datetime.fromtimestamp(nxt).strftime("%Y-%m-%d %H:%M:%S")
                             if nxt else "-"),
           "save_date": datetime.datetime.now()}
    try:
        get_repo().collection(SCHED_COLL).insert_one(doc)
        return {"_id": str(doc.get("_id", "")), "name": name, "keyword": keyword,
                "cron": cron, "status": STATUS_RUNNING}
    except Exception as e:
        logger.warning("add_monitor error: %s", e)
        return {"error": "新建失败: {}".format(e)}


def update_monitor(monitor_id: str, **kwargs: Any) -> Dict[str, Any]:
    """更新监控任务（name/keyword/cron）。返回 {_id} 或 {error}。"""
    monitor_id = (monitor_id or "").strip()
    if not monitor_id:
        return {"error": "_id 必填"}
    upd: Dict[str, Any] = {}
    if kwargs.get("name"):
        upd["name"] = str(kwargs["name"]).strip()
    if kwargs.get("keyword"):
        upd["keyword"] = str(kwargs["keyword"]).strip()
    if kwargs.get("cron"):
        cron = str(kwargs["cron"]).strip()
        if not validate_cron(cron):
            return {"error": "cron 表达式非法"}
        if not check_interval_ok(cron):
            return {"error": "运行间隔小于配置的最小间隔"}
        upd["cron"] = cron
        import datetime
        nxt = next_run_epoch(cron)
        upd["next_run_date"] = (datetime.datetime.fromtimestamp(nxt).strftime("%Y-%m-%d %H:%M:%S")
                                if nxt else "-")
    if not upd:
        return {"error": "无更新字段"}
    try:
        r = get_repo().collection(SCHED_COLL).update_one({"_id": _oid(monitor_id)}, {"$set": upd})
        if getattr(r, "matched_count", 0) == 0:
            return {"error": "监控任务不存在"}
        return {"_id": monitor_id}
    except Exception as e:
        logger.warning("update_monitor error: %s", e)
        return {"error": "更新失败: {}".format(e)}


def _set_status(ids: List[str], status: str) -> Dict[str, Any]:
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    n = 0
    try:
        coll = get_repo().collection(SCHED_COLL)
        for mid in ids:
            n += getattr(coll.update_one({"_id": _oid(mid)}, {"$set": {"status": status}}),
                         "modified_count", 0)
        return {"modified": n, "ids": ids}
    except Exception as e:
        logger.warning("_set_status error: %s", e)
        return {"error": "操作失败: {}".format(e)}


def stop_monitors(ids: List[str]) -> Dict[str, Any]:
    """停止（暂停）监控任务。"""
    return _set_status(ids, STATUS_STOPPED)


def recover_monitors(ids: List[str]) -> Dict[str, Any]:
    """恢复监控任务。"""
    return _set_status(ids, STATUS_RUNNING)


def delete_monitors(ids: List[str]) -> Dict[str, Any]:
    """删除监控任务 + 级联删其结果。返回 {deleted, results_deleted, ids}。"""
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    deleted = results_deleted = 0
    try:
        coll = get_repo().collection(SCHED_COLL)
        rcoll = get_repo().collection(RESULT_COLL)
        for mid in ids:
            deleted += getattr(coll.delete_one({"_id": _oid(mid)}), "deleted_count", 0)
            results_deleted += getattr(rcoll.delete_many({"github_scheduler_id": mid}), "deleted_count", 0)
        return {"deleted": deleted, "results_deleted": results_deleted, "ids": ids}
    except Exception as e:
        logger.warning("delete_monitors error: %s", e)
        return {"error": "删除失败: {}".format(e)}


# —— 执行层（scheduler tick 经 registry 调 run_due；补净室迁移丢失的周期执行闭环）——

def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def run_one(monitor_id: str) -> Dict[str, Any]:
    """执行一个周期监控任务：搜索→跨轮去重存→推进 next_run/run_number。跨轮幂等（同任务 hash 不重存）。"""
    from . import _github_client as gh
    import datetime
    mid = _oid(monitor_id)
    job = get_repo().collection(SCHED_COLL).find_one({"_id": mid}) or {}
    if not job:
        return {"error": "监控任务不存在", "monitor_id": monitor_id}
    keyword = job.get("keyword", "") or ""
    cron = job.get("cron", "") or ""
    coll = get_repo().collection(SCHED_COLL)
    # 先推进 next_run（即使搜索失败也不卡在过去时间导致每 tick 重跑）
    nxt = next_run_epoch(cron)
    coll.update_one({"_id": mid}, {
        "$set": {"last_run_date": _now_str(),
                 "next_run_date": (datetime.datetime.fromtimestamp(nxt).strftime("%Y-%m-%d %H:%M:%S")
                                   if nxt else "-")},
        "$inc": {"run_number": 1}})
    try:
        if not gh.has_token():
            logger.warning("github_monitor %s 跳过：token 未配置", monitor_id)
            return {"monitor_id": monitor_id, "skipped": "no_token"}
        results = gh.search(keyword)
        rcoll = get_repo().collection(RESULT_COLL)
        saved = 0
        for r in results:
            if rcoll.find_one({"github_scheduler_id": monitor_id, "hash_md5": r.get("hash_md5")}):
                continue    # 跨轮去重：该监控历史已报过的命中不重复
            item = dict(r)
            item.update({"keyword": keyword, "github_scheduler_id": monitor_id, "save_date": _now_str()})
            rcoll.insert_one(item)
            saved += 1
        logger.info("github_monitor %s run: keyword=%s new=%d", monitor_id, keyword, saved)
        return {"monitor_id": monitor_id, "new_results": saved}
    except Exception as e:
        logger.warning("github_monitor run_one %s error: %s", monitor_id, e)
        return {"monitor_id": monitor_id, "error": str(e)}


def run_due() -> Dict[str, Any]:
    """扫到期的运行中监控任务（next_run_date<=now 且 status=running）逐个执行（scheduler tick 调）。"""
    now = _now_str()
    picked = ran = 0
    try:
        coll = get_repo().collection(SCHED_COLL)
        for job in coll.find({"status": STATUS_RUNNING}):
            nxt = job.get("next_run_date", "") or ""
            if not nxt or nxt == "-" or nxt > now:
                continue
            picked += 1
            r = run_one(str(job["_id"]))
            if "error" not in r:
                ran += 1
    except Exception as e:
        logger.warning("github_monitor run_due error: %s", e)
    return {"picked": picked, "ran": ran}
