"""task_plan/task_list —— 任务列表与管理（查询/停止/续跑/重启/删除/结果同步资产库）。

对应前端 pages/tasks/TaskList.vue（主页面之一，task 集合有任何扫描产生的数据即可用，不孤岛）。
任务的「创建/下发」归 task_create 叶子；实际「执行/调度」归 kernel/orchestration；本叶子只管
已存在任务的查询与生命周期动作（协作式取消：改 DB status，worker 建成后在边界自检自停）。

对外（供 router endpoints/task_list.py + 未来编排调）：
  list_tasks(...)          分页查询（禁硬限制 size<=0 全量）
  stop_task / resume_task / restart_task / delete_tasks / batch_stop
  sync_to_scope(task_id, scope_id)   结果同步资产库 → 经 registry 调 asset_group_service.sync_task_to_scope（闭合 groups 缺口）
  sync_scope_candidates(target)      按目标反查可同步的资产组

注册：字符串键 `"task_list_service"`（照 api_keys 先例，不进冻结 ROLE）。端点 endpoints/task_list.py。
迁移来源：routes/task.py（list/stop/resume/restart/delete/sync）+ commonTask。依赖：仅 stdlib（re）+ bson(guard)。
**无新增 vendor，默认本地库**。**协作式取消**（见踩坑铁律 revoke 不可靠）：stop 只改 DB status，worker 自检自停。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_logger, models
from sentinel_platform.contracts import Collections, get_registry

logger = get_logger()

# 删除任务时级联清理的结果集合（task_id 匹配）。
_CASCADE_COLLS = ("domain", "site", "ip", "url", "fileleak", "cert", "service",
                  "task_schedule", "cip", "npoc_service", "stat_finger",
                  "nuclei_result", "vuln", "wih")

def _oid(_id: str):
    """字符串 _id → ObjectId（生产）；bson 缺失/非法（测试/普通键）原样返回，兼容两态。"""
    try:
        from bson import ObjectId
        return ObjectId(_id)
    except Exception:
        return _id


def _coll():
    return get_repo().collection(Collections.TASK)


def _compute_statistic(task_id: str) -> Dict[str, Any]:
    """按 task_id 动态计算 statistic（兼容旧任务/statistic 缺失场景）。
    前端 TaskList/TaskDetail 通过 statistic.domain_cnt 等展示资产数量。异常返全零不阻断。"""
    try:
        repo = get_repo()
        q = {"task_id": task_id}
        return {
            "domain_cnt": repo.collection("domain").count_documents(q),
            "ip_cnt": repo.collection("ip").count_documents(q),
            "site_cnt": repo.collection("site").count_documents(q),
            "url_cnt": repo.collection("url").count_documents(q),
            "vuln_cnt": (repo.collection("vuln").count_documents(q)
                         + repo.collection("nuclei_result").count_documents(q)),
            "wih_cnt": repo.collection("wih").count_documents(q),
        }
    except Exception:
        return {"domain_cnt": 0, "ip_cnt": 0, "site_cnt": 0,
                "url_cnt": 0, "vuln_cnt": 0, "wih_cnt": 0}


def list_tasks(page: int = 1, size: int = 10, **filters: Any) -> Dict[str, Any]:
    """任务列表（分页 + name/target/status/task_tag 过滤，时间倒序）。
    **禁硬限制参数**：size<=0 返全量（供导出/审计），无 min(size,N) 硬顶。"""
    q: Dict[str, Any] = {}
    if filters.get("status"):
        q["status"] = filters["status"]
    if filters.get("task_tag"):
        q["task_tag"] = filters["task_tag"]
    for f in ("name", "target"):
        if filters.get(f):
            q[f] = {"$regex": re.escape(filters[f]), "$options": "i"}
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 10
    try:
        coll = _coll()
        total = coll.count_documents(q)
        cur = coll.find(q).sort("_id", -1)
        if size and size > 0:
            cur = cur.skip((page - 1) * size).limit(size)
        items = []
        for d in cur:
            d["_id"] = str(d.get("_id", ""))
            # 兼容旧任务/statistic 缺失：动态补算（前端靠 statistic 展示域名/IP/站点数量）
            if not d.get("statistic"):
                d["statistic"] = _compute_statistic(d["_id"])
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        logger.debug("list_tasks degraded: %s", exc)
        return {"items": [], "total": 0, "page": page, "size": size}


def _set_status(task_id: str, status: str) -> Dict[str, Any]:
    """改任务 DB status（协作式取消原语：worker 在边界自检自停，revoke 不可靠故不依赖）。"""
    try:
        r = _coll().update_one({"_id": _oid(task_id)}, {"$set": {"status": status}})
        if getattr(r, "matched_count", 1) == 0:
            return {"error": "任务不存在: {}".format(task_id)}
        return {"_id": task_id, "status": status}
    except Exception as exc:
        return {"error": str(exc)}


def stop_task(task_id: str) -> Dict[str, Any]:
    """停止任务（协作式：置 status=stop；worker 自检自停 + best-effort revoke 由编排层做）。"""
    return _set_status(task_id, models.TaskStatus.STOP)


def resume_task(task_id: str) -> Dict[str, Any]:
    """续跑任务（置 status=waiting 让编排层重新投递；worker/编排未建时仅改状态，documented）。"""
    return _set_status(task_id, models.TaskStatus.WAITING)


def restart_task(task_id: str) -> Dict[str, Any]:
    """重启任务：置 waiting + **清 checkpoint**（踩坑铁律：克隆/重跑不清 checkpoint→续跑跳过已完成阶段结果全空）。
    实际重新执行由 kernel/orchestration 投递（未建时仅重置状态）。"""
    try:
        r = _coll().update_one(
            {"_id": _oid(task_id)},
            {"$set": {"status": models.TaskStatus.WAITING}, "$unset": {"checkpoint": ""}})
        if getattr(r, "matched_count", 1) == 0:
            return {"error": "任务不存在: {}".format(task_id)}
        return {"_id": task_id, "status": models.TaskStatus.WAITING, "note": "checkpoint 已清，待编排层重跑"}
    except Exception as exc:
        return {"error": str(exc)}


def batch_stop(task_ids: List[str]) -> Dict[str, Any]:
    """批量停止。"""
    stopped = 0
    for tid in (task_ids or []):
        if not stop_task(tid).get("error"):
            stopped += 1
    return {"stopped": stopped, "task_id": task_ids}


def delete_tasks(task_ids: List[str], del_task_data: bool = False) -> Dict[str, Any]:
    """删除任务；del_task_data=True 时级联清结果集合（domain/site/ip/... 按 task_id）。"""
    deleted = 0
    purged = 0
    try:
        repo = get_repo()
        for tid in (task_ids or []):
            # P2-b：删前先协作式停止（置 status=stop）——若任务在跑，worker 在阶段边界读到 stop 自停，
            # 避免"记录已删但 worker 仍空跑到边界"。stop_task 幂等，非运行态置 stop 也无害。
            try:
                stop_task(tid)
            except Exception:
                pass
            repo.collection(Collections.TASK).delete_one({"_id": _oid(tid)})
            deleted += 1
            if del_task_data:
                # task_id 在结果集合里存字符串（_persist_records），但历史/其他路径可能存 ObjectId。
                # 用 $in 同时匹配字符串与 ObjectId，避免类型不一致导致"删了任务资产仍残留"。
                oid = _oid(tid)
                match = {"task_id": {"$in": [tid, oid]}} if oid != tid else {"task_id": tid}
                for name in _CASCADE_COLLS:
                    try:
                        r = repo.collection(name).delete_many(match)
                        purged += int(getattr(r, "deleted_count", 0) or 0)
                    except Exception:
                        continue
    except Exception as exc:
        return {"error": str(exc), "deleted": deleted, "purged": purged}
    return {"deleted": deleted, "purged": purged, "del_task_data": bool(del_task_data), "task_id": task_ids}


def _live_task_ids() -> set:
    """现存任务 _id 全集（字符串形态）。结果集合 task_id 存字符串，故统一转字符串比对。"""
    ids = set()
    try:
        for t in _coll().find({}, {"_id": 1}):
            ids.add(str(t.get("_id")))
    except Exception:
        pass
    return ids


def _orphan_match(live_ids: set) -> Dict[str, Any]:
    """孤儿匹配条件：task_id 存在且非空、且不在现存任务集合。
    **安全护栏**：task_id 为空/null/缺失的记录绝不算孤儿（可能是手动导入/非任务资产，误删=数据事故）。"""
    return {"$and": [
        {"task_id": {"$exists": True, "$nin": ["", None]}},
        {"task_id": {"$nin": list(live_ids)}},
    ]}


def scan_orphan_assets() -> Dict[str, Any]:
    """扫描孤儿资产（task_id 指向已删除任务的结果记录）——只统计不删。
    返回 {total, by_collection:{coll:count}, live_task_count}。供前端清理前预览。"""
    repo = get_repo()
    live = _live_task_ids()
    match = _orphan_match(live)
    by_coll: Dict[str, int] = {}
    total = 0
    for name in _CASCADE_COLLS:
        try:
            n = repo.collection(name).count_documents(match)
        except Exception:
            n = 0
        if n:
            by_coll[name] = n
            total += n
    return {"total": total, "by_collection": by_coll, "live_task_count": len(live)}


def purge_orphan_assets() -> Dict[str, Any]:
    """清理孤儿资产（删 task_id 指向已删除任务的结果记录）。返回 {purged, by_collection}。
    护栏同 scan：task_id 空/null 绝不删。live 集合为空时（无任何任务）跳过（防误删全部）。"""
    repo = get_repo()
    live = _live_task_ids()
    if not live:
        # 一个任务都没有时，无法可靠区分"孤儿"与"合法保留资产"，保守不删（防清空全部资产）。
        return {"purged": 0, "by_collection": {}, "skipped": "no_live_task", "note": "无现存任务，跳过清理以防误删"}
    match = _orphan_match(live)
    by_coll: Dict[str, int] = {}
    purged = 0
    for name in _CASCADE_COLLS:
        try:
            r = repo.collection(name).delete_many(match)
            n = int(getattr(r, "deleted_count", 0) or 0)
        except Exception:
            n = 0
        if n:
            by_coll[name] = n
            purged += n
    return {"purged": purged, "by_collection": by_coll, "live_task_count": len(live)}


def sync_to_scope(task_id: str, scope_id: str) -> Dict[str, Any]:
    """把任务结果同步进资产库 → 经 registry 调 asset_group_service.sync_task_to_scope（**闭合 groups 对接**）。
    资产分组叶子未注册时降级报错（不崩）。能力在 groups、路由归本叶子（/api/task/sync）。"""
    if not task_id or not scope_id:
        return {"error": "task_id / scope_id 必填"}
    svc = get_registry().get("asset_group_service")
    if not (svc and hasattr(svc, "sync_task_to_scope")):
        return {"error": "资产分组服务未就绪，无法同步"}
    try:
        return svc.sync_task_to_scope(task_id, scope_id)
    except Exception as exc:
        return {"error": "同步失败: {}".format(exc)}


def sync_scope_candidates(target: str) -> Dict[str, Any]:
    """按目标反查可同步的资产组（target 命中某组 scope_array 即候选）。读库失败降级空。"""
    target = (target or "").strip().lower()
    out: List[Dict[str, Any]] = []
    if not target:
        return {"items": out, "total": 0}
    try:
        for s in get_repo().collection(Collections.ASSET_SCOPE).find({}):
            arr = [str(x).lower() for x in (s.get("scope_array") or [])]
            if any(target == a or target.endswith("." + a) or a in target for a in arr):
                out.append({"_id": str(s.get("_id", "")), "name": s.get("name", ""),
                            "scope_type": s.get("scope_type", "")})
    except Exception as exc:
        logger.debug("sync_scope_candidates degraded: %s", exc)
    return {"items": out, "total": len(out)}


class TaskListServiceImpl:
    """任务列表服务。注册字符串键 "task_list_service"。"""
    def list_tasks(self, **kw): return list_tasks(**kw)
    def stop_task(self, task_id): return stop_task(task_id)
    def resume_task(self, task_id): return resume_task(task_id)
    def restart_task(self, task_id): return restart_task(task_id)
    def batch_stop(self, task_ids): return batch_stop(task_ids)
    def delete_tasks(self, task_ids, del_task_data=False): return delete_tasks(task_ids, del_task_data)
    def sync_to_scope(self, task_id, scope_id): return sync_to_scope(task_id, scope_id)
    def sync_scope_candidates(self, target): return sync_scope_candidates(target)
    def scan_orphan_assets(self): return scan_orphan_assets()
    def purge_orphan_assets(self): return purge_orphan_assets()


_service = TaskListServiceImpl()


def get_service() -> TaskListServiceImpl:
    return _service

