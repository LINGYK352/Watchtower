"""GitHub 任务 github_task —— GitHub 敏感信息搜索任务 CRUD + 结果查询（asset 叶子，核心路由暴露）。

管理 github_task 集合（一次性关键字搜索任务）+ github_result 集合（命中结果）。
净室重写 routes/github_task.py + github_result.py + utils/github_task.py：任务记录 CRUD /
运行态校验 / 级联删结果，从零写。无 ROLE（核心路由暴露）。只依赖 core + stdlib，无第三方库。

实际 GitHub 搜索执行（调 GitHub API 需 token + 网络）是 orchestration/引擎职责——本叶子
创建任务记录（status=waiting）后由编排层拾取执行；编排未建时任务停在 waiting（诚实降级，不伪造）。
分页不设硬上限（禁硬限制参数）。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from sentinel_platform.core import get_logger, get_repo

logger = get_logger()

TASK_COLL = "github_task"
RESULT_COLL = "github_result"

STATUS_WAITING = "waiting"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_STOP = "stop"
STATUS_ERROR = "error"
_DELETABLE = {STATUS_DONE, STATUS_STOP, STATUS_ERROR}   # 运行中不可删

_TEXT_FIELDS = {"name", "keyword"}
_EQUAL_FIELDS = {"status"}
_QUERY_KEYS = {"page", "size", "order"}


def _oid(v: Any) -> Any:
    """字符串→ObjectId（惰性 bson，无则回退原值；对齐平台范式）。"""
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
    """ObjectId/datetime 按类型转 str（flask_restx JSON 编码器不支持 datetime）。"""
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
        elif key in _EQUAL_FIELDS or key == "github_task_id":
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


def list_tasks(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """GitHub 任务分页查询。返回 {page,size,total,items}。"""
    return _paginate(TASK_COLL, args)


def list_results(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """GitHub 搜索结果分页查询（可按 github_task_id 过滤）。"""
    return _paginate(RESULT_COLL, args, extra_text={"url", "repo"})


def add_task(name: str, keyword: str) -> Dict[str, Any]:
    """新建 GitHub 搜索任务（status=waiting，待编排层拾取执行）。返回 {_id,name,keyword,status} 或 {error}。"""
    name = (name or "").strip()
    keyword = (keyword or "").strip()
    if not keyword:
        return {"error": "关键字必填"}
    if not name:
        name = keyword
    import datetime
    doc = {"name": name, "keyword": keyword, "status": STATUS_WAITING,
           "start_time": "-", "end_time": "-", "result_count": 0,
           "save_date": datetime.datetime.now()}
    try:
        get_repo().collection(TASK_COLL).insert_one(doc)
        return {"_id": str(doc.get("_id", "")), "name": name, "keyword": keyword,
                "status": STATUS_WAITING}
    except Exception as e:
        logger.warning("add_task error: %s", e)
        return {"error": "新建失败: {}".format(e)}


def delete_tasks(ids: List[str]) -> Dict[str, Any]:
    """删除任务（运行中不可删）+ 级联删其结果。返回 {deleted, results_deleted, ids} 或 {error}。"""
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    try:
        coll = get_repo().collection(TASK_COLL)
        # 先校验：运行中任务不可删（防中断执行态）
        for tid in ids:
            doc = coll.find_one({"_id": _oid(tid)})
            if doc and doc.get("status") not in _DELETABLE:
                return {"error": "任务运行中不可删: {}".format(tid)}
        deleted = results_deleted = 0
        rcoll = get_repo().collection(RESULT_COLL)
        for tid in ids:
            deleted += getattr(coll.delete_one({"_id": _oid(tid)}), "deleted_count", 0)
            results_deleted += getattr(rcoll.delete_many({"github_task_id": tid}), "deleted_count", 0)
        return {"deleted": deleted, "results_deleted": results_deleted, "ids": ids}
    except Exception as e:
        logger.warning("delete_tasks error: %s", e)
        return {"error": "删除失败: {}".format(e)}


def stop_tasks(ids: List[str]) -> Dict[str, Any]:
    """停止任务（置 status=stop）。返回 {modified, ids}。"""
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    n = 0
    try:
        coll = get_repo().collection(TASK_COLL)
        for tid in ids:
            n += getattr(coll.update_one({"_id": _oid(tid)}, {"$set": {"status": STATUS_STOP}}),
                         "modified_count", 0)
        return {"modified": n, "ids": ids}
    except Exception as e:
        logger.warning("stop_tasks error: %s", e)
        return {"error": "停止失败: {}".format(e)}


# —— 执行层（scheduler tick 经 registry 调 run_waiting；补净室迁移丢失的执行闭环）——

def _now() -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _claim(tid: Any) -> bool:
    """原子认领 waiting→running，防多 scheduler 重复执行同任务。"""
    try:
        r = get_repo().collection(TASK_COLL).update_one(
            {"_id": tid, "status": STATUS_WAITING},
            {"$set": {"status": STATUS_RUNNING, "start_time": _now()}})
        return bool(getattr(r, "modified_count", 0))
    except Exception as e:
        logger.warning("github_task claim error: %s", e)
        return False


def _is_stopped(tid: Any) -> bool:
    """协作式取消：读 DB status，被置 stop 即真停。"""
    try:
        doc = get_repo().collection(TASK_COLL).find_one({"_id": tid}, {"status": 1}) or {}
        return doc.get("status") == STATUS_STOP
    except Exception:
        return False


def run_one(task_id: str) -> Dict[str, Any]:
    """执行一个 GitHub 搜索任务：认领→搜索→存结果→done。协作式取消，token 缺失标 error（不静默返 0）。"""
    from . import _github_client as gh
    tid = _oid(task_id)
    doc = get_repo().collection(TASK_COLL).find_one({"_id": tid}) or {}
    if not doc:
        return {"error": "任务不存在", "task_id": task_id}
    if not _claim(tid):
        return {"skipped": "非 waiting 或已被认领", "task_id": task_id}
    keyword = doc.get("keyword", "") or ""
    coll = get_repo().collection(TASK_COLL)
    try:
        if not gh.has_token():
            coll.update_one({"_id": tid}, {"$set": {
                "status": STATUS_ERROR, "end_time": _now(),
                "error": "GitHub token 未配置（系统设置 > API 密钥 > GitHub Token）"}})
            return {"error": "no_token", "task_id": task_id}
        results = gh.search(keyword, cancel_check=lambda: _is_stopped(tid))
        if _is_stopped(tid):
            return {"stopped": True, "task_id": task_id}
        rcoll = get_repo().collection(RESULT_COLL)
        saved = 0
        for r in results:
            item = dict(r)
            item.update({"keyword": keyword, "github_task_id": task_id, "save_date": _now()})
            # 幂等：同任务同 repo/path 命中不重复入库
            if rcoll.find_one({"github_task_id": task_id, "hash_md5": r.get("hash_md5")}):
                continue
            rcoll.insert_one(item)
            saved += 1
        coll.update_one({"_id": tid}, {"$set": {
            "status": STATUS_DONE, "end_time": _now(), "result_count": saved}})
        logger.info("github_task %s done: keyword=%s saved=%d", task_id, keyword, saved)
        return {"task_id": task_id, "status": STATUS_DONE, "result_count": saved}
    except Exception as e:
        logger.warning("github_task run_one %s error: %s", task_id, e)
        coll.update_one({"_id": tid}, {"$set": {"status": STATUS_ERROR, "end_time": _now(),
                                                "error": str(e)[:500]}})
        return {"error": str(e), "task_id": task_id}


def run_waiting() -> Dict[str, Any]:
    """扫 status=waiting 的 GitHub 任务逐个执行（scheduler tick 调）。串行执行尊重 GitHub 限速。"""
    picked = done = 0
    try:
        coll = get_repo().collection(TASK_COLL)
        waiting = [d["_id"] for d in coll.find({"status": STATUS_WAITING}, {"_id": 1})]
        for tid in waiting:
            picked += 1
            r = run_one(str(tid))
            if r.get("status") == STATUS_DONE:
                done += 1
    except Exception as e:
        logger.warning("github_task run_waiting error: %s", e)
    return {"picked": picked, "done": done}
