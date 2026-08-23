"""asset/monitor —— 资产监控周期任务（scheduler 集合 job 增删改查/状态流转）。

对资产范围（asset_scope）配置周期性监控：域名监控（新子域/新解析）、站点更新监控、
WIH 更新监控。任务文档存 scheduler 集合，本叶子只做 job 的创建/列表/删除/停止/恢复，
净室重写 routes/scheduler.py + scheduler.py 的 job 管理逻辑，不 import app。

无 ROLE（对核心路由暴露能力，registry 字符串键 `monitor_service`，照 asset_search_service /
api_keys_service 先例）。只依赖 core（get_repo + core.query.one_clause 复用列表口径）+
contracts（Collections/SchedulerStatus），无第三方库。endpoints/asset_monitor.py 挂 /api/scheduler/*。

**实际周期执行待 kernel/orchestration 建成后接管**：本叶子只维护 scheduler 集合里 job 的数据状态
（诚实降级，不伪造执行）；停止/恢复只翻转 DB status（协同式取消，真正的执行调度由编排层据 status 消费）。
**禁止硬限制参数（铁律）**：list size 按调用方请求取值，不设上限；默认 size=10 仅无参缺省。
6 小时间隔下限是领域安全规则（防高频监控打爆目标），非分页上限，保留。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from sentinel_platform.core import get_repo, get_logger, models
from sentinel_platform.core.query import one_clause
from sentinel_platform.contracts import Collections

logger = get_logger()

# 监控任务最小间隔：6 小时（领域安全规则，防高频监控打爆目标；非分页上限）。
MIN_INTERVAL = 6 * 3600
# scope_type 取值
SCOPE_DOMAIN = "domain"
SCOPE_SITE = "site_update_monitor"
SCOPE_WIH = "wih_update_monitor"
# stop 后置的哨兵时间（远未来，编排层不会取到该 job）
_STOP_NEXT_RUN = 9999999999
# 新建 job 首次触发延迟（秒）
_FIRST_DELAY = 30
_SKIP_KEYS = {"page", "size", "order"}


def _to_oid(i: Any) -> Any:
    """字符串 id → bson.ObjectId（惰性、可选）。无 bson（Windows/离线单测）或非法 → 原值返回。
    对齐 asset/search 的 _to_oid：真实 Linux 部署 ObjectId 生效。"""
    try:
        from bson import ObjectId
        return ObjectId(i)
    except Exception:
        return i

def _build_query(filters: Dict[str, Any]) -> Dict[str, Any]:
    """请求过滤参数转 Mongo 查询。复用 core.query.one_clause 保持列表口径一致，
    _id 转 ObjectId，跳过分页字段。"""
    q: Dict[str, Any] = {}
    for key, val in (filters or {}).items():
        if key in _SKIP_KEYS or val is None or val == "":
            continue
        if key == "_id":
            q["_id"] = _to_oid(val)
            continue
        q.update(one_clause(key, val))
    return q


def _page_size_order(args: Dict[str, Any]):
    """解析分页/排序。size 无上限（禁止硬限制）；page/size 下限保护防非法值。"""
    try:
        page = max(1, int(args.get("page") or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        size = max(1, int(args.get("size") or 10))   # 无参默认 10；不设上限，按需取
    except (TypeError, ValueError):
        size = 10
    order = str(args.get("order") or "-_id")
    return page, size, order


def _stringify(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """_id/save_date 序列化为字符串（对齐 asset/search._stringify）。"""
    special = ("_id", "save_date", "update_date")
    for d in docs:
        for k in special:
            if k in d:
                d[k] = str(d[k])
    return docs


def _now() -> int:
    return int(time.time())


def _save_date() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _new_job(scope_id: str, domain: str, interval: int, name: str, scope_type: str) -> Dict[str, Any]:
    """按 job 文档 schema 组装一条待插入的监控任务。"""
    return {
        "domain": domain, "scope_id": scope_id, "interval": interval,
        "next_run_time": _now() + _FIRST_DELAY, "next_run_date": "-",
        "last_run_time": 0, "last_run_date": "-", "run_number": 0,
        "status": models.SchedulerStatus.RUNNING, "monitor_options": {},
        "name": name, "scope_type": scope_type, "save_date": _save_date(),
    }

def list_jobs(args: Dict[str, Any]) -> Dict[str, Any]:
    """监控任务分页查询。返回 {page,size,total,items}；size 不设上限。"""
    page, size, order = _page_size_order(args)
    query = _build_query(args)
    try:
        coll = get_repo().collection(Collections.SCHEDULER)
        total = coll.count_documents(query)
        direction = 1 if order.startswith("+") else -1
        field = order.lstrip("+-") or "_id"
        cur = coll.find(query).sort(field, direction).skip((page - 1) * size).limit(size)
        items = _stringify(list(cur))
        return {"page": page, "size": size, "total": total, "items": items}
    except Exception as exc:
        logger.debug("scheduler list failed: %s", exc)
        return {"page": page, "size": size, "total": 0, "items": []}


def _scope_exists(scope_id: str):
    """读 asset_scope，返回资产范围文档或 None。"""
    try:
        return get_repo().collection(Collections.ASSET_SCOPE).find_one({"_id": _to_oid(scope_id)})
    except Exception as exc:
        logger.debug("scope lookup failed: %s", exc)
        return None


def _norm_interval(interval: Any) -> int:
    """间隔归一为 int 秒；None/非法 → 下限（交由调用方做下限校验）。"""
    try:
        return int(interval)
    except (TypeError, ValueError):
        return MIN_INTERVAL


def add_domain_job(scope_id: str, domain: str, interval: Any = MIN_INTERVAL,
                   name: str = "", policy_id: str = "") -> Dict[str, Any]:
    """新增域名监控任务。domain 支持逗号分隔 → 每个域名一条 job。返回 {ok,jobs:[...]}。"""
    iv = _norm_interval(interval)
    if iv < MIN_INTERVAL:
        return {"error": "间隔不能小于6小时"}
    scope = _scope_exists(scope_id)
    if not scope:
        return {"error": "资产范围不存在"}
    scope_name = scope.get("name", "") or scope_id
    domains = [d.strip() for d in str(domain or "").split(",") if d.strip()]
    if not domains:
        return {"error": "domain 必填"}
    try:
        coll = get_repo().collection(Collections.SCHEDULER)
        jobs = []
        for d in domains:
            job_name = name or "监控-{}-{}".format(scope_name, d)
            doc = _new_job(scope_id, d, iv, job_name, SCOPE_DOMAIN)
            if policy_id:
                doc["monitor_options"] = {"policy_id": policy_id}
            res = coll.insert_one(doc)
            jobs.append({"domain": d, "scope_id": scope_id, "job_id": str(res.inserted_id)})
        return {"ok": True, "jobs": jobs}
    except Exception as exc:
        logger.debug("add domain job failed: %s", exc)
        return {"error": str(exc)[:120]}


def _add_scope_monitor(scope_id: str, interval: Any, name: str,
                       scope_type: str, name_prefix: str, dup_msg: str) -> Dict[str, Any]:
    """站点/WIH 监控共用：间隔下限 + 资产范围存在 + 同类去重 → 插入一条 job。"""
    iv = _norm_interval(interval)
    if iv < MIN_INTERVAL:
        return {"error": "间隔不能小于6小时"}
    scope = _scope_exists(scope_id)
    if not scope:
        return {"error": "资产范围不存在"}
    try:
        coll = get_repo().collection(Collections.SCHEDULER)
        if coll.find_one({"scope_id": scope_id, "scope_type": scope_type}):
            return {"error": dup_msg}
        scope_name = scope.get("name", "") or scope_id
        job_name = name or "{}-{}".format(name_prefix, scope_name)
        res = coll.insert_one(_new_job(scope_id, "", iv, job_name, scope_type))
        return {"ok": True, "schedule_id": str(res.inserted_id)}
    except Exception as exc:
        logger.debug("add %s monitor failed: %s", scope_type, exc)
        return {"error": str(exc)[:120]}


def add_site_monitor(scope_id: str, interval: Any = MIN_INTERVAL, name: str = "") -> Dict[str, Any]:
    """新增站点更新监控（scope_type=site_update_monitor，单资产范围唯一）。返回 {ok,schedule_id}。"""
    return _add_scope_monitor(scope_id, interval, name, SCOPE_SITE,
                              "站点监控", "该资产范围已有站点监控任务")


def add_wih_monitor(scope_id: str, interval: Any = MIN_INTERVAL, name: str = "") -> Dict[str, Any]:
    """新增 WIH 更新监控（scope_type=wih_update_monitor，单资产范围唯一）。返回 {ok,schedule_id}。"""
    return _add_scope_monitor(scope_id, interval, name, SCOPE_WIH,
                              "WIH 监控", "该资产范围已有 WIH 监控任务")

def delete_jobs(job_ids: List[str]) -> Dict[str, Any]:
    """按 job_id 批量删除监控任务。返回 {deleted:N}；空 ids → error。"""
    if not isinstance(job_ids, list) or not job_ids:
        return {"error": "job_id 必填"}
    try:
        oids = [_to_oid(i) for i in job_ids]
        res = get_repo().collection(Collections.SCHEDULER).delete_many({"_id": {"$in": oids}})
        return {"deleted": getattr(res, "deleted_count", 0)}
    except Exception as exc:
        logger.debug("delete jobs failed: %s", exc)
        return {"error": str(exc)[:120], "deleted": 0}


def stop_jobs(job_ids: List[str]) -> Dict[str, Any]:
    """停止监控任务（协同式）：仅翻转 DB status=STOP + 置远未来 next_run_time，
    实际执行停止由编排层据 status 消费。非 RUNNING/不存在的跳过。返回 {ok,job_id,stopped}。"""
    if not isinstance(job_ids, list) or not job_ids:
        return {"error": "job_id 必填"}
    coll = get_repo().collection(Collections.SCHEDULER)
    stopped = []
    for jid in job_ids:
        try:
            oid = _to_oid(jid)
            job = coll.find_one({"_id": oid})
            if not job or job.get("status") != models.SchedulerStatus.RUNNING:
                continue
            coll.update_one({"_id": oid}, {"$set": {
                "status": models.SchedulerStatus.STOP,
                "next_run_date": "-", "next_run_time": _STOP_NEXT_RUN}})
            stopped.append(str(jid))
        except Exception as exc:
            logger.debug("stop job %s failed: %s", jid, exc)
    return {"ok": True, "job_id": stopped, "stopped": len(stopped)}


def recover_jobs(job_ids: List[str]) -> Dict[str, Any]:
    """恢复监控任务（协同式）：仅翻转 DB status=RUNNING + 重置 next_run_time=now+interval，
    实际重新调度由编排层据 status 消费。非 STOP 的跳过。返回 {ok,job_id,recovered}。"""
    if not isinstance(job_ids, list) or not job_ids:
        return {"error": "job_id 必填"}
    coll = get_repo().collection(Collections.SCHEDULER)
    recovered = []
    for jid in job_ids:
        try:
            oid = _to_oid(jid)
            job = coll.find_one({"_id": oid})
            if not job or job.get("status") != models.SchedulerStatus.STOP:
                continue
            iv = _norm_interval(job.get("interval"))
            coll.update_one({"_id": oid}, {"$set": {
                "status": models.SchedulerStatus.RUNNING,
                "next_run_date": "-", "next_run_time": _now() + iv}})
            recovered.append(str(jid))
        except Exception as exc:
            logger.debug("recover job %s failed: %s", jid, exc)
    return {"ok": True, "job_id": recovered, "recovered": len(recovered)}


# —— 执行层（scheduler tick 经 registry 调 run_due；补净室迁移丢失的监控执行闭环）——

def _advance_next_run(coll, job_id: Any, interval: int) -> None:
    """推进 next_run_time=now+interval + run_number++（先推进防到期任务每 tick 重跑）。"""
    coll.update_one({"_id": job_id}, {
        "$set": {"last_run_time": _now(), "last_run_date": _save_date(),
                 "next_run_time": _now() + max(interval, MIN_INTERVAL),
                 "next_run_date": time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.localtime(_now() + max(interval, MIN_INTERVAL)))},
        "$inc": {"run_number": 1}})


def run_one(job: Dict[str, Any]) -> Dict[str, Any]:
    """执行一个到期监控 job。
      - 域名监控（scope_type=domain）：复用 task_create.create_by_policy 建一篇监控扫描任务（周期重扫发现新子域/站点）——完整实现。
      - 站点/WIH 更新监控：增量快照 diff（旧 AssetSiteMonitor）净室未移植，诚实降级（只推进 next_run + 记日志，不伪造执行）。"""
    coll = get_repo().collection(Collections.SCHEDULER)
    job_id = job.get("_id")
    scope_type = job.get("scope_type", "")
    interval = _norm_interval(job.get("interval"))
    _advance_next_run(coll, job_id, interval)   # 先推进，防执行失败每 tick 重跑
    if scope_type == SCOPE_DOMAIN:
        domain = job.get("domain", "") or ""
        policy_id = (job.get("monitor_options") or {}).get("policy_id", "") or ""
        if not domain:
            return {"job_id": str(job_id), "skipped": "no_domain"}
        if not policy_id:
            logger.info("monitor domain job %s 无 policy_id，跳过（新建时未绑策略）", job_id)
            return {"job_id": str(job_id), "skipped": "no_policy"}
        svc = _registry_task_create()
        if not svc:
            return {"job_id": str(job_id), "skipped": "task_create_unavailable"}
        try:
            name = job.get("name", "") or "监控-{}".format(domain)
            r = svc.create_by_policy(name, policy_id, domain, task_tag="monitor",
                                     source={"type": "monitor", "scheduler_id": str(job_id)})
            logger.info("monitor domain job %s 触发扫描: %s → %s", job_id, domain, r.get("created", r))
            return {"job_id": str(job_id), "scope_type": scope_type, "dispatched": True,
                    "created": r.get("created", 0)}
        except Exception as e:
            logger.warning("monitor run_one domain %s error: %s", job_id, e)
            return {"job_id": str(job_id), "error": str(e)}
    # 站点/WIH 更新监控：增量 diff 引擎（AssetSiteMonitor/Domain2SiteMonitor）净室未移植
    logger.info("monitor %s job %s: 增量 diff 引擎净室未移植（诚实降级，只推进调度不伪造执行）",
                scope_type, job_id)
    return {"job_id": str(job_id), "scope_type": scope_type, "pending": "diff_engine_not_migrated"}


def _registry_task_create():
    try:
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("task_create_service")
        return svc if (svc and hasattr(svc, "create_by_policy")) else None
    except Exception:
        return None


def run_due() -> Dict[str, Any]:
    """扫到期的运行中监控 job（status=RUNNING 且 next_run_time<=now）逐个执行（scheduler tick 调）。"""
    now = _now()
    picked = ran = 0
    try:
        coll = get_repo().collection(Collections.SCHEDULER)
        for job in coll.find({"status": models.SchedulerStatus.RUNNING}):
            nrt = job.get("next_run_time", 0) or 0
            if nrt > now:
                continue
            picked += 1
            r = run_one(job)
            if r.get("dispatched") or r.get("pending"):
                ran += 1
    except Exception as e:
        logger.warning("monitor run_due error: %s", e)
    return {"picked": picked, "ran": ran}


# —— 门面（供 endpoints 经 registry 调，不 import 叶子内部）——
class MonitorServiceImpl:
    """monitor_service 门面。方法与模块函数一一对应。"""
    list_jobs = staticmethod(list_jobs)
    add_domain_job = staticmethod(add_domain_job)
    add_site_monitor = staticmethod(add_site_monitor)
    add_wih_monitor = staticmethod(add_wih_monitor)
    delete_jobs = staticmethod(delete_jobs)
    stop_jobs = staticmethod(stop_jobs)
    recover_jobs = staticmethod(recover_jobs)
    run_due = staticmethod(run_due)


_service = MonitorServiceImpl()


def get_service() -> MonitorServiceImpl:
    return _service



