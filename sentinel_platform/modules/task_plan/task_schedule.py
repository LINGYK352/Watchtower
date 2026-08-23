"""计划任务 task_schedule —— 周期/定时扫描任务定义的 CRUD（task_plan 叶子，核心路由暴露）。

管理 task_schedule 集合：future_scan（未来某时刻跑一次）/ recurrent_scan（cron 周期跑）。
本叶子只做**定义 CRUD + 启停**；到点实际触发调度是 orchestration 的职责（未建时定义仍可管理）。

净室重写 routes/task_schedule.py + helpers/task_schedule.py：cron 校验/下次运行时间用 croniter
（已 vendored，默认本地库安装），不抄旧 python-crontab 实现。无 ROLE（核心路由暴露）。
只依赖 core + croniter(本地库) + stdlib。分页与最小间隔均**不设硬编码上限（禁硬限制参数）**。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_config, get_logger, get_repo

logger = get_logger()

SCHED_COLL = "task_schedule"
POLICY_COLL = "policy"

VALID_SCHEDULE_TYPES = ("future_scan", "recurrent_scan")
VALID_TASK_TAGS = ("task", "risk_cruising")
STATUS_SCHEDULED = "scheduled"
STATUS_STOPPED = "stopped"

_TEXT_FIELDS = {"name", "target", "policy_name"}
_EQUAL_FIELDS = {"schedule_type", "status", "task_tag"}
_QUERY_KEYS = {"page", "size", "order"}


def _min_interval_sec() -> int:
    """周期任务最小间隔（秒）。由配置决定，默认 0=不限（禁硬编码上限）。
    运维要防扫描风暴可设 SCHEDULE.MIN_INTERVAL_SEC，代码不写死魔数。"""
    try:
        return int(get_config().section("SCHEDULE", "MIN_INTERVAL_SEC", default=0) or 0)
    except (TypeError, ValueError):
        return 0


def validate_cron(cron: str) -> bool:
    """cron 语法是否合法（croniter 本地库）。"""
    if not cron or not str(cron).strip():
        return False
    try:
        from croniter import croniter
        return bool(croniter.is_valid(str(cron).strip()))
    except ImportError:
        # 无 croniter（极端离线未装）→ 退化为 5 字段粗校验，不静默放行乱串
        return len(str(cron).split()) == 5
    except Exception:
        return False


def next_run_epoch(cron: str, base: Optional[float] = None) -> int:
    """按 cron 求下次运行 epoch 秒；无 croniter 或非法返回 0（交调度层兜底）。"""
    try:
        from croniter import croniter
        it = croniter(str(cron).strip(), base if base is not None else time.time())
        return int(it.get_next())
    except Exception:
        return 0


def check_interval_ok(cron: str) -> bool:
    """相邻两次运行间隔是否 >= 配置的最小间隔。min=0(默认)时恒放行（不设硬上限）。"""
    min_iv = _min_interval_sec()
    if min_iv <= 0:
        return True
    try:
        from croniter import croniter
        base = time.time()
        it = croniter(str(cron).strip(), base)
        t1 = it.get_next()
        t2 = it.get_next()
        return (t2 - t1) >= min_iv
    except Exception:
        return True      # 算不出间隔不阻断（交调度层）


def _oid(v: Any) -> Any:
    """字符串→ObjectId（惰性 bson，无则回退原值；对齐 vuln_center/fingerprint 范式）。"""
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
    """序列化：ObjectId/datetime 按类型转 str（flask_restx JSON 编码器不支持 datetime）。"""
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


def _build_query(args: Dict[str, Any]) -> Dict[str, Any]:
    q: Dict[str, Any] = {}
    for key, val in (args or {}).items():
        if key in _QUERY_KEYS or val in (None, "") or key == "_id":
            continue
        if key in _TEXT_FIELDS:
            q[key] = {"$regex": re.escape(str(val)), "$options": "i"}
        elif key in _EQUAL_FIELDS:
            q[key] = val
    return q


def list_schedules(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """分页查询计划任务。返回 {page,size,total,items}（size 无硬上限，禁硬限制参数）。"""
    args = args or {}
    try:
        page = max(1, int(args.get("page", 1) or 1))
        size = max(1, int(args.get("size", 10) or 10))
    except (TypeError, ValueError):
        page, size = 1, 10
    query = _build_query(args)
    try:
        coll = get_repo().collection(SCHED_COLL)
        total = coll.count_documents(query)
        cur = coll.find(query).sort("_id", -1).skip((page - 1) * size).limit(size)
        items = [_clean(d) for d in cur]
    except Exception as e:
        logger.warning("list_schedules error: %s", e)
        total, items = 0, []
    return {"page": page, "size": size, "total": total, "items": items}


def add_schedule(payload: Dict[str, Any]) -> Dict[str, Any]:
    """新建计划任务。校验类型/tag/cron + 解析 policy_name + 算 next_run。返回 {_id,...} 或 {error}。"""
    p = payload or {}
    name = (p.get("name") or "").strip()
    target = (p.get("target") or "").strip()
    schedule_type = (p.get("schedule_type") or "").strip().lower()
    task_tag = (p.get("task_tag") or "").strip()
    policy_id = (p.get("policy_id") or "").strip()
    if not name or not target:
        return {"error": "名称与目标必填"}
    if schedule_type not in VALID_SCHEDULE_TYPES:
        return {"error": "计划类型非法（future_scan|recurrent_scan）"}
    if task_tag not in VALID_TASK_TAGS:
        return {"error": "任务类别非法（task|risk_cruising）"}
    if not policy_id:
        return {"error": "策略 ID 必填"}

    import datetime
    doc: Dict[str, Any] = {
        "name": name, "target": target, "task_tag": task_tag,
        "schedule_type": schedule_type, "policy_id": policy_id,
        "status": STATUS_SCHEDULED, "run_number": 0, "last_run_date": "-",
        "cron": "", "start_date": p.get("start_date", ""),
        "save_date": datetime.datetime.now(),
    }

    if schedule_type == "future_scan":
        sd = (p.get("start_date") or "").strip()
        if not sd:
            return {"error": "定时任务需 start_date"}
        doc["next_run_date"] = sd
    else:  # recurrent_scan
        cron = (p.get("cron") or "").strip()
        if not validate_cron(cron):
            return {"error": "cron 表达式非法"}
        if not check_interval_ok(cron):
            return {"error": "运行间隔小于配置的最小间隔 SCHEDULE.MIN_INTERVAL_SEC"}
        doc["cron"] = cron
        nxt = next_run_epoch(cron)
        doc["next_run_date"] = (datetime.datetime.fromtimestamp(nxt).strftime("%Y-%m-%d %H:%M:%S")
                                if nxt else "-")

    try:
        # policy_name 反查（策略缺失不阻断建计划，留空由展示层兜底）
        try:
            policy = get_repo().collection(POLICY_COLL).find_one({"_id": _oid(policy_id)})
        except Exception:
            policy = None
        doc["policy_name"] = (policy or {}).get("name", "")
        get_repo().collection(SCHED_COLL).insert_one(doc)
        return {"_id": str(doc.get("_id", "")), "name": name}
    except Exception as e:
        logger.warning("add_schedule error: %s", e)
        return {"error": "新建失败: {}".format(e)}


def _set_status(ids: List[str], status: str) -> Dict[str, Any]:
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    n = 0
    try:
        coll = get_repo().collection(SCHED_COLL)
        for _id in ids:
            r = coll.update_one({"_id": _oid(_id)}, {"$set": {"status": status}})
            n += getattr(r, "modified_count", 0)
        return {"modified": n, "ids": ids}
    except Exception as e:
        logger.warning("_set_status error: %s", e)
        return {"error": "操作失败: {}".format(e)}


def stop_schedules(ids: List[str]) -> Dict[str, Any]:
    """停止（暂停）计划任务。"""
    return _set_status(ids, STATUS_STOPPED)


def recover_schedules(ids: List[str]) -> Dict[str, Any]:
    """恢复计划任务。"""
    return _set_status(ids, STATUS_SCHEDULED)


def delete_schedules(ids: List[str]) -> Dict[str, Any]:
    """删除计划任务。返回 {deleted, ids}。"""
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    deleted = 0
    try:
        coll = get_repo().collection(SCHED_COLL)
        for _id in ids:
            r = coll.delete_one({"_id": _oid(_id)})
            deleted += getattr(r, "deleted_count", 0)
        return {"deleted": deleted, "ids": ids}
    except Exception as e:
        logger.warning("delete_schedules error: %s", e)
        return {"error": "删除失败: {}".format(e)}


# —— 执行层（scheduler tick 经 registry 调 run_due；补净室迁移丢失的执行闭环）——

def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _task_create_svc():
    try:
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("task_create_service")
        return svc if (svc and hasattr(svc, "create_by_policy")) else None
    except Exception:
        return None


def run_one(job: Dict[str, Any]) -> Dict[str, Any]:
    """执行一个到期计划任务：复用 task_create.create_by_policy 建真扫描任务。
      - future_scan：跑一次 → status=stopped（一次性，不再触发）；
      - recurrent_scan：按 cron 推进 next_run_date + run_number++（周期继续）。
    先推进/收尾调度态再建任务（防建任务失败每 tick 重触发）。"""
    coll = get_repo().collection(SCHED_COLL)
    jid = job.get("_id")
    stype = job.get("schedule_type", "")
    # 先推进调度态（幂等，防重复触发）
    if stype == "future_scan":
        coll.update_one({"_id": jid}, {"$set": {"status": STATUS_STOPPED, "last_run_date": _now_str()},
                                       "$inc": {"run_number": 1}})
    else:  # recurrent_scan：按 cron 算下次
        nxt = next_run_epoch(job.get("cron", ""))
        import datetime
        nxt_str = datetime.datetime.fromtimestamp(nxt).strftime("%Y-%m-%d %H:%M:%S") if nxt else "-"
        coll.update_one({"_id": jid}, {"$set": {"last_run_date": _now_str(), "next_run_date": nxt_str},
                                       "$inc": {"run_number": 1}})
    svc = _task_create_svc()
    if not svc:
        return {"job_id": str(jid), "skipped": "task_create 服务未就绪"}
    target = job.get("target", "") or ""
    policy_id = job.get("policy_id", "") or ""
    if not target or not policy_id:
        return {"job_id": str(jid), "skipped": "target/policy_id 缺失"}
    try:
        name = job.get("name", "") or "计划-{}".format(target)
        tag = job.get("task_tag", "task") or "task"
        r = svc.create_by_policy(name, policy_id, target, task_tag=tag,
                                 source={"type": "schedule", "schedule_id": str(jid)})
        logger.info("task_schedule %s 触发扫描: %s → %s", jid, target, r.get("created", r))
        return {"job_id": str(jid), "schedule_type": stype, "dispatched": True,
                "created": r.get("created", 0)}
    except Exception as e:
        logger.warning("task_schedule run_one %s error: %s", jid, e)
        return {"job_id": str(jid), "error": str(e)}


def run_due() -> Dict[str, Any]:
    """扫到期计划任务（status=scheduled 且 next_run_date<=now）逐个执行（scheduler tick 调）。"""
    now = _now_str()
    picked = ran = 0
    try:
        coll = get_repo().collection(SCHED_COLL)
        for job in coll.find({"status": STATUS_SCHEDULED}):
            nxt = job.get("next_run_date", "") or ""
            if not nxt or nxt == "-" or nxt > now:
                continue
            picked += 1
            r = run_one(job)
            if r.get("dispatched"):
                ran += 1
    except Exception as e:
        logger.warning("task_schedule run_due error: %s", e)
    return {"picked": picked, "ran": ran}
