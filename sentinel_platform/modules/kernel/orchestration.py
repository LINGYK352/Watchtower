"""任务编排 orchestration —— 框架无关的任务生命周期 + handler 注册表 + run_task 入口。

把「任务」与「侦察执行(RECON) + 归集(INTEL) + 派发(PENTEST_DISPATCH)」串起来的编排层。
本核心**不绑 celery**：celery worker / scheduler 只是薄适配（调 run_task），编排逻辑框架无关、
可脱离 celery 单测。task_create 等经字符串键 `orchestration_service` 调本层下发执行。

净室重写 celerytask.run_task 的 handler 分发 + 生命周期：
- handler 注册表：按 task_type 注册处理函数（可插，加任务类型不改 run_task）。
- 生命周期：waiting→running→done/stop/error/preempted，每步写 task 集合 status。
- **协作式取消（铁律，见记忆 dengta-stop-cooperative-cancellation）**：revoke 不可靠（celery_id 在
  worker 重启/重投后漂移、任务可能已在执行），故执行体在阶段边界主动查 DB status，见 stop/preempted
  即抛 Stopped 自停——不依赖 revoke，也不依赖 ack 语义（问题14 起 worker 改早 ack，崩溃恢复统一由
  scheduler 从 DB 真相源 reclaim，与 ack 无关）。

只依赖 core + contracts(registry 取 RECON/INTEL/PENTEST_DISPATCH，缺失降级) + stdlib，无第三方库。
禁硬限制参数（无轮数/条数上限，编排只按客观 status 与 handler 返回推进）。
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from sentinel_platform.core import get_logger, get_repo
from sentinel_platform.contracts import get_registry, ROLE

logger = get_logger()

TASK_COLL = "task"

# 任务状态（复用 core.models.TaskStatus 语义；RUNNING 核心未定义，本层补充局部常量，不改冻结 core）
S_WAITING = "waiting"
S_QUEUED = "queued"
S_RUNNING = "running"
S_DONE = "done"
S_ERROR = "error"
S_STOP = "stop"
S_PREEMPTED = "preempted"
_STOP_STATES = {S_STOP, S_PREEMPTED}


class StoppedException(RuntimeError):
    """协作式取消：执行体在边界查到 DB status=stop/preempted 时抛出，中止编排。"""


# —— handler 注册表（按 task_type 注册，可插）——
_HANDLERS: Dict[str, Callable[[str, "TaskContext"], Any]] = {}


def register_handler(task_type: str, handler: Callable[[str, "TaskContext"], Any]) -> None:
    """注册任务类型的处理函数。handler 签名 (task_id:str, ctx:TaskContext)->任意。"""
    _HANDLERS[task_type] = handler


def get_handler(task_type: str) -> Optional[Callable]:
    return _HANDLERS.get(task_type)


def registered_types() -> list:
    return sorted(_HANDLERS.keys())


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


def _task_query(task_id: str) -> Dict[str, Any]:
    return {"_id": _oid(task_id)}


def _read_status(task_id: str) -> str:
    """读任务当前 status（DB 是真相源，协作式取消据此判定）。查不到返回空串。"""
    try:
        doc = get_repo().collection(TASK_COLL).find_one(_task_query(task_id), {"status": 1})
        return (doc or {}).get("status", "") if doc else ""
    except Exception as e:
        logger.warning("read_status %s error: %s", task_id, e)
        return ""


def _claim_run(task_id: str) -> bool:
    """原子认领执行权（幂等去重，防重复 run_task 占满 worker 池）。
    仅当任务处于 queued/waiting 时切 running；同时刷 update_date 心跳。
    背景：崩溃恢复靠 scheduler DB-reclaim（running→waiting 重投）+ queued 孤儿回收，重投时会累积
    多份 run_task 消息（worker 停摆/重启期尤甚）。原 run_task 用普通 _set_status(running)，N 份消息
    全部置 running 并各跑一遍 handler → 池被同一任务的重复实例占死，真正的会话饿死。
    改原子认领后：第一份认领成功跑，其余看到 running/done/stopped → 认领失败 → 调用方跳过不重复跑。
    DB 故障返回 True（放行，宁可偶发重复也不漏跑，与 _claim_session 异常放行同口径）。"""
    import time
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        r = get_repo().collection(TASK_COLL).update_one(
            {"_id": _oid(task_id), "status": {"$in": [S_QUEUED, S_WAITING]}},
            {"$set": {"status": S_RUNNING, "start_time": now, "update_date": now}})
        return bool(getattr(r, "modified_count", 0))
    except Exception as e:
        logger.warning("claim_run %s error: %s", task_id, e)
        return True


def _set_status(task_id: str, status: str, extra: Optional[Dict[str, Any]] = None) -> None:
    upd = {"status": status}
    if extra:
        upd.update(extra)
    op = {"$set": upd}
    # 终态防死徽标（问题11）：任务进终态时清 resource_wait，避免 worker 中途死留下"资源等待"徽标。
    if status in (S_DONE, S_ERROR, S_STOP, S_PREEMPTED):
        op["$unset"] = {"resource_wait": ""}
    try:
        get_repo().collection(TASK_COLL).update_one(_task_query(task_id), op)
    except Exception as e:
        logger.warning("set_status %s=%s error: %s", task_id, status, e)


class TaskContext:
    """编排上下文：给 handler 用。提供协作式取消自检 + 能力服务（经 registry，缺失 None 降级）。"""

    def __init__(self, task_id: str, options: Optional[Dict[str, Any]] = None):
        self.task_id = task_id
        self.options = options or {}
        self._reg = get_registry()

    # —— 协作式取消：handler 在阶段边界调，见 stop/preempted 抛 Stopped 自停 ——
    def checkpoint(self) -> None:
        st = _read_status(self.task_id)
        if st in _STOP_STATES:
            raise StoppedException("task {} status={} → 协作式自停".format(self.task_id, st))

    def is_stopped(self) -> bool:
        return _read_status(self.task_id) in _STOP_STATES

    # —— 能力服务（缺失降级 None，handler 自行判空）——
    @property
    def recon(self):
        return self._reg.get(ROLE.RECON)

    @property
    def intel(self):
        return self._reg.get(ROLE.INTEL)

    @property
    def dispatch(self):
        return self._reg.get(ROLE.PENTEST_DISPATCH)


def run_task(task_id: str, task_type: str = "", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """编排入口：置 running → 查 handler → 执行(协作式取消) → 归集/派发 → 收尾。

    返回 {task_id, task_type, result: done|stopped|error|no_handler, error}。
    task_type 空则从 task 文档读。handler 缺失=no_handler（不崩）。协作式取消抛 Stopped→result=stopped。
    """
    import time
    result: Dict[str, Any] = {"task_id": task_id, "task_type": task_type,
                              "result": S_DONE, "error": None}
    # task_type / options 缺省从任务文档补
    if not task_type or options is None:
        try:
            doc = get_repo().collection(TASK_COLL).find_one(_task_query(task_id)) or {}
            task_type = task_type or doc.get("task_type", "") or doc.get("type", "")
            options = options if options is not None else (doc.get("options", {}) or {})
        except Exception as exc:
            # 引用型消息必须成功加载持久参数后才能执行；禁止读取失败时用空配置启动。
            _rollback_task_claim(task_id, "任务参数暂时无法读取")
            result["result"] = "waiting"
            result["error"] = "任务参数暂时无法读取，已保留等待重投"
            logger.warning("run_task configuration unavailable: task=%s error_type=%s", task_id, type(exc).__name__)
            return result
    result["task_type"] = task_type

    # 入口挡:已是停止态不启动（协作式取消 + 抢占）
    if _read_status(task_id) in _STOP_STATES:
        result["result"] = "stopped"
        return result

    handler = get_handler(task_type)
    if not handler:
        logger.warning("run_task no handler for type=%s (task %s)", task_type, task_id)
        result["result"] = "no_handler"
        result["error"] = "未注册的任务类型: {}".format(task_type)
        return result

    ctx = TaskContext(task_id, options)
    # 原子认领执行权（幂等去重）：认领不到 = 已被另一实例跑着/或已终态 = 这是重复投递的多余消息，跳过。
    if not _claim_run(task_id):
        cur = _read_status(task_id)
        logger.info("run_task 跳过重复投递 task=%s（当前 status=%s，已被认领或已终态）", task_id, cur)
        result["result"] = "skipped_duplicate"
        return result
    try:
        handler_result = handler(task_id, ctx)          # handler 内部按 ctx.checkpoint() 自检
        partial_err = ""
        if isinstance(handler_result, dict):
            # 各类 handler 状态键统一识别：_recon_handler=recon、_fofa_handler=fofa、_unit_handler=unit/result。
            # 原 bug：只读 result/recon → _fofa_handler 的 fofa=partial_error（网络不稳致部分站点漏派）被吞 → 落 S_DONE 假性完成。
            handler_state = (handler_result.get("result") or handler_result.get("recon")
                             or handler_result.get("fofa") or handler_result.get("unit"))
            if handler_state == "stopped":
                raise StoppedException(handler_result.get("error") or "recon pipeline stopped")
            if handler_state == "error":
                raise RuntimeError(handler_result.get("error") or "recon pipeline failed")
            if handler_state == "partial_error":
                # 部分目标未派发：仍先 _post_scan 派发已形成的站点，再标 error（不标 done）——使不完整可见、可重投补派。
                partial_err = handler_result.get("error") or "部分目标未派发（网络不稳），可重投补派"
        ctx.checkpoint()                                 # handler 返回后再次确认，停止态不得归集/写 done
        _post_scan(ctx)                                  # 扫完归集 + 按 options.auto_pentest 派发（partial 也派已成站点）
        ctx.checkpoint()
        if partial_err:
            _set_status(task_id, S_ERROR, {"error": partial_err[:500],
                                           "end_time": time.strftime("%Y-%m-%d %H:%M:%S")})
            result["result"] = "partial_error"
            result["error"] = partial_err
        else:
            _set_status(task_id, S_DONE, {"end_time": time.strftime("%Y-%m-%d %H:%M:%S")})
    except StoppedException as e:
        logger.info("run_task stopped: %s", e)
        result["result"] = "stopped"
        # 不覆盖 status（已是 stop/preempted，保留真相）
    except Exception as e:
        logger.exception("run_task error task=%s: %s", task_id, e)
        # error 分支也回填 end_time（BUG-006）：否则统计/排序/僵尸回收判定都拿不到结束时间，
        # done 与 error 两条收尾路径都必须落 end_time。
        _set_status(task_id, S_ERROR, {"error": str(e)[:500],
                                       "end_time": time.strftime("%Y-%m-%d %H:%M:%S")})
        result["result"] = S_ERROR
        result["error"] = str(e)
    return result


def _post_scan(ctx: TaskContext) -> None:
    """扫描完成后：归集 + 按策略派发（经 registry 调 INTEL，缺失降级不阻断）。"""
    if ctx.is_stopped():
        return
    intel = ctx.intel
    if intel and hasattr(intel, "auto_collect_after_scan"):
        try:
            intel.auto_collect_after_scan(ctx.task_id)   # INTEL 内部按 options.auto_pentest 派发
        except Exception as e:
            logger.warning("post_scan auto_collect error: %s", e)


# —— 编排服务门面（供 task_create 等经字符串键 orchestration_service 调）——
class OrchestrationService:
    def run_task(self, task_id: str, task_type: str = "", options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return run_task(task_id, task_type, options)

    def submit_task(self, task_id: str, task_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """入队执行（task_create 下发后经此触发；默认后台线程，celery 适配投 worker）。"""
        return submit_task(task_id, task_doc)

    def run_waiting_tasks(self, limit: int = 0) -> Dict[str, Any]:
        """调度轮询 WAITING 任务（scheduler tick 调）。"""
        return run_waiting_tasks(limit)

    def register_handler(self, task_type: str, handler: Callable) -> None:
        register_handler(task_type, handler)

    def registered_types(self) -> list:
        return registered_types()


# =============================================================================
# phase-2 绑定：执行器(可插) + submit_task(入队) + run_waiting_tasks(调度轮询) + 默认 scan handler
# 核心 run_task/协作式取消不动；这里只加"怎么把 run_task 异步跑起来"的适配层。
# 执行器抽象：默认后台线程（web 请求不阻塞）；测试/celery 可 set_executor 注入。无 celery 硬依赖。
# =============================================================================

_DELIVERY = None


def set_delivery(dispatcher) -> None:
    """Optional persistent runtime transport; default Web/Celery is unchanged."""
    global _DELIVERY
    _DELIVERY = dispatcher


def _thread_executor(fn: Callable[[], Any]) -> None:
    """默认执行器：后台 daemon 线程跑 fn（web 下发不阻塞；无 celery 也能真跑）。"""
    import threading
    threading.Thread(target=fn, daemon=True).start()


_EXECUTOR: Callable[[Callable[[], Any]], Any] = _thread_executor


def set_executor(executor: Callable[[Callable[[], Any]], Any]) -> None:
    """注入执行器（测试用同步内联；Linux 部署用 celery 适配把 fn 投递到 worker）。"""
    global _EXECUTOR
    _EXECUTOR = executor


def reset_executor() -> None:
    global _EXECUTOR
    _EXECUTOR = _thread_executor


def _broker_fail(context: str = "") -> None:
    """celery 投递失败上报 broker 健康（60s内3次自动降级线程模式）。延迟 import 防循环依赖；失败静默。"""
    try:
        from sentinel_platform.modules.kernel import _broker_health
        _broker_health.record_delivery_failure(context)
    except Exception:
        pass


def _broker_ok() -> None:
    """celery 投递成功 → 清失败窗（健康信号）。延迟 import 防循环依赖；失败静默。"""
    try:
        from sentinel_platform.modules.kernel import _broker_health
        _broker_health.record_delivery_success()
    except Exception:
        pass


def _read_target(task_id: str) -> str:
    try:
        doc = get_repo().collection(TASK_COLL).find_one(_task_query(task_id), {"target": 1}) or {}
        return doc.get("target", "") or ""
    except Exception:
        return ""


def _claim_task(task_id: str) -> bool:
    """原子认领 WAITING 任务。只有成功切到 queued 的调度方可以投递。
    记 queued_at 时间戳：供 scheduler 回收「queued 孤儿」——认领后投递进程若在 delay/spawn 前崩溃，
    任务会永停 queued（run_waiting_tasks 只捡 waiting、僵尸回收只管 running），且占 in_flight 槽位。"""
    import time
    try:
        r = get_repo().collection(TASK_COLL).update_one(
            {"_id": _oid(task_id), "status": S_WAITING},
            {"$set": {"status": S_QUEUED, "queued_at": time.strftime("%Y-%m-%d %H:%M:%S")}})
        return bool(getattr(r, "modified_count", 0))
    except Exception as e:
        logger.warning("claim task %s error: %s", task_id, e)
        return False


def _rollback_task_claim(task_id: str, error: str = "") -> None:
    """投递失败时仅把仍处于 queued 的任务回滚 waiting，不覆盖 running/stop。"""
    try:
        get_repo().collection(TASK_COLL).update_one(
            {"_id": _oid(task_id), "status": S_QUEUED},
            {"$set": {"status": S_WAITING, "dispatch_error": str(error)[:500]}})
    except Exception:
        pass


def submit_task(task_id: str, task_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """原子认领并入队一个任务。投递失败回滚 waiting，避免 queued 永久卡住。"""
    st = _read_status(task_id)
    if st in _STOP_STATES:
        return {"ok": False, "task_id": task_id, "submitted": False, "claimed": False, "reason": "stopped"}
    if not _claim_task(task_id):
        return {"ok": False, "task_id": task_id, "submitted": False, "claimed": False,
                "reason": "not_waiting", "status": _read_status(task_id)}
    task_type = ""
    options = None
    if isinstance(task_doc, dict):
        task_type = task_doc.get("task_type", "") or task_doc.get("type", "")
        options = task_doc.get("options")
    if _DELIVERY is not None:
        try:
            job = _DELIVERY("task", task_id, task_type=task_type, options=options)
            return {"ok": True, "task_id": task_id, "submitted": True, "claimed": True, "via": "native", "job_id": job}
        except Exception as exc:
            _rollback_task_claim(task_id, str(exc))
            return {"ok": False, "task_id": task_id, "submitted": False, "claimed": True, "error": str(exc)}
    delay = globals().get("_celery_delay")
    if callable(delay):
        try:
            res = delay(task_id, task_type, options)
            cid = getattr(res, "id", "") or ""   # 记 celery_id：可观测 + 可 revoke（原来恒空，无法追踪/撤销重复投递）
            if cid:
                try:
                    get_repo().collection(TASK_COLL).update_one(_task_query(task_id), {"$set": {"celery_id": cid}})
                except Exception:
                    pass
            _broker_ok()
            return {"ok": True, "task_id": task_id, "submitted": True, "claimed": True, "celery_id": cid}
        except Exception as e:
            _broker_fail("task 投递失败: {}".format(str(e)[:80]))
            logger.warning("submit_task %s celery err, fallback thread: %s", task_id, e)
    try:
        _EXECUTOR(lambda: run_task(task_id, task_type, options))
        return {"ok": True, "task_id": task_id, "submitted": True, "claimed": True, "via": "thread"}
    except Exception as e:
        _rollback_task_claim(task_id, str(e))
        logger.warning("submit_task %s thread error: %s", task_id, e)
        return {"ok": False, "task_id": task_id, "submitted": False, "claimed": True, "error": str(e)}


def _claim_session(session_id: str, from_status: str) -> bool:
    """原子认领会话：queued/paused_transient -> dispatching。
    BUG-019：认领条件加 `stop_requested != True`——若用户已显式 stop（即使状态因竞态落在
    paused_transient），调度器绝不恢复；停止意图是终态优先。原子 update 的 filter 里带该条件，
    有停止标记则 modified_count=0 认领失败，会话保持不被拉回 running。"""
    try:
        import time as _t
        # 进 dispatching 时盖 update_date 心跳：给 dispatch 窗口一个可测起点。
        # 原来只 set status 不刷心跳 → 会话保留上一次 running 的旧 update_date，
        # scheduler 的 dispatching 停滞回收无法区分「刚派发」与「派发后卡死」，会误回收/抖动。
        update: Dict[str, Any] = {"$set": {"status": "dispatching",
                                           "update_date": _t.strftime("%Y-%m-%d %H:%M:%S")}}
        if from_status == "paused_transient":
            update["$inc"] = {"retry_count": 1}
        r = get_repo().collection("intel_pentest_session").update_one(
            {"_id": _oid(session_id), "status": from_status,
             "stop_requested": {"$ne": True}}, update)
        return bool(getattr(r, "modified_count", 0))
    except Exception:
        return False


def submit_session(session_id: str, from_status: str = "queued") -> Dict[str, Any]:
    """原子认领并入队 AI 会话。失败回滚来源状态，重复消息因认领失败被拒绝。"""
    if not session_id:
        return {"ok": False, "submitted": False, "reason": "no session_id"}
    if from_status not in ("queued", "paused_transient", "paused_resource"):
        return {"ok": False, "submitted": False, "reason": "invalid source status"}
    if not _claim_session(session_id, from_status):
        return {"ok": False, "session_id": session_id, "submitted": False, "claimed": False,
                "reason": "not_{}".format(from_status)}

    def _run():
        try:
            svc = get_registry().get(ROLE.PENTEST_DISPATCH)
            if svc and hasattr(svc, "run_session"):
                svc.run_session(session_id)
        except Exception as e:
            logger.debug("submit_session run %s degraded: %s", session_id, e)
    if _DELIVERY is not None:
        try:
            job = _DELIVERY("session", session_id)
            return {"ok": True, "session_id": session_id, "submitted": True, "claimed": True, "via": "native", "job_id": job}
        except Exception as exc:
            get_repo().collection("intel_pentest_session").update_one(
                {"_id": _oid(session_id), "status": "dispatching"},
                {"$set": {"status": from_status, "dispatch_error": str(exc)[:500]}})
            return {"ok": False, "session_id": session_id, "submitted": False, "error": str(exc)}
    delay = globals().get("_celery_session_delay")
    if callable(delay):
        try:
            delay(session_id)
            _broker_ok()
            return {"ok": True, "session_id": session_id, "submitted": True, "claimed": True, "via": "celery"}
        except Exception as e:
            _broker_fail("session 投递失败: {}".format(str(e)[:80]))
            logger.warning("submit_session %s celery err, fallback thread: %s", session_id, e)
    try:
        _EXECUTOR(_run)
        return {"ok": True, "session_id": session_id, "submitted": True, "claimed": True, "via": "thread"}
    except Exception as e:
        try:
            get_repo().collection("intel_pentest_session").update_one(
                {"_id": _oid(session_id), "status": "dispatching"},
                {"$set": {"status": from_status, "dispatch_error": str(e)[:500]}})
        except Exception:
            pass
        logger.warning("submit_session %s thread error: %s", session_id, e)
        return {"ok": False, "session_id": session_id, "submitted": False, "claimed": True, "error": str(e)}


# —— 会话台后台回合投递（v1.21.157-62，与自动会话 submit_session 解耦；绝不走 run_agent）——
# _celery_console_delay：celery adapter 装载时赋值（lambda sid: _RUN_CONSOLE.delay(sid)）；无 celery 走线程执行器。
_celery_console_delay = None


def _claim_console_session(session_id: str) -> bool:
    """CAS 认领会话台后台回合：console_running != True → 置 True。已 True 返 False（防重复投——消息已入队，
    在跑的循环下轮消费）。paused_manual 会话不进 scheduler 自动认领，故用独立 console_running 锁，与 auto 零交叉。"""
    try:
        import time
        from ..ai_pentest.session import console_eligible_query, _now
        query = dict(console_eligible_query(), _id=_oid(session_id), console_running={"$ne": True},
                     pending_user_msgs={"$exists": True, "$ne": []})
        r = get_repo().collection("intel_pentest_session").update_one(query,
            {"$set": {"console_running": True, "console_dispatch_at": int(time.time()), "console_update": _now()}})
        return bool(getattr(r, "modified_count", 0))
    except Exception:
        return False


def submit_console_turn(session_id: str) -> Dict[str, Any]:
    """认领并投一个会话台后台回合（run_console_agent）。已在跑→already_running（不重复投，消息已入队待消费）。
    投递失败回滚 console_running 锁。console 会话执行独立于自动会话（不改 status、不走 run_agent）。"""
    if not session_id:
        return {"ok": False, "submitted": False, "reason": "no session_id"}
    if not _claim_console_session(session_id):
        current = get_repo().collection("intel_pentest_session").find_one({"_id": _oid(session_id)}) or {}
        if current.get("console_running"):
            return {"ok": True, "session_id": session_id, "submitted": False, "already_running": True}
        return {"ok": False, "session_id": session_id, "submitted": False, "reason": "console claim failed or status changed"}

    def _run():
        try:
            svc = get_registry().get(ROLE.PENTEST_DISPATCH)
            if svc and hasattr(svc, "run_console_session"):
                svc.run_console_session(session_id)
            else:
                raise RuntimeError("console execution service unavailable")
        except Exception as e:
            logger.debug("submit_console_turn run %s degraded: %s", session_id, e)
    if _DELIVERY is not None:
        try:
            job = _DELIVERY("console", session_id)
            return {"ok": True, "session_id": session_id, "submitted": True, "via": "native", "job_id": job}
        except Exception as exc:
            get_repo().collection("intel_pentest_session").update_one(
                {"_id": _oid(session_id)}, {"$set": {"console_running": False, "console_error": str(exc)[:500]}})
            return {"ok": False, "session_id": session_id, "submitted": False, "error": str(exc)}
            get_repo().collection("intel_pentest_session").update_one({"_id": _oid(session_id)},
                {"$set": {"console_running": False, "console_error": "执行服务不可用，请重试"}})
    delay = globals().get("_celery_console_delay")
    if callable(delay):
        try:
            delay(session_id)
            _broker_ok()
            return {"ok": True, "session_id": session_id, "submitted": True}
        except Exception as e:
            # celery 投递失败：记录（60s内3次触发降级）+ 本次立即回退线程执行，消息不丢、会话不卡
            _broker_fail("console 投递失败: {}".format(str(e)[:80]))
            logger.warning("submit_console_turn %s celery err, fallback thread: %s", session_id, e)
    try:
        _EXECUTOR(_run)
        return {"ok": True, "session_id": session_id, "submitted": True, "via": "thread"}
    except Exception as e:
        try:
            get_repo().collection("intel_pentest_session").update_one(
                {"_id": _oid(session_id)}, {"$set": {"console_running": False}})   # 回滚锁
        except Exception:
            pass
        logger.warning("submit_console_turn %s thread error: %s", session_id, e)
        return {"ok": False, "session_id": session_id, "submitted": False, "error": str(e)}


def _task_budget() -> Dict[str, Any]:
    try:
        svc = get_registry().get("log_service")
        if svc and hasattr(svc, "get_resource_budget"):
            return svc.get_resource_budget() or {}
        if svc and hasattr(svc, "get_resource_level"):
            level = svc.get_resource_level()
            return {"level": level, "task_slots": {"critical": 0, "tight": 1, "normal": 3, "relaxed": 5}.get(level, 3)}
    except Exception:
        pass
    return {"level": "normal", "task_slots": 3}


def run_waiting_tasks(limit: int = 0) -> Dict[str, Any]:
    """按资源预算和当前在途数投递 WAITING；原子认领保证多 scheduler 不重复发送。"""
    picked = submitted = 0
    budget = _task_budget()
    level = budget.get("level", "normal")
    slots = max(0, int(budget.get("task_slots", 0) or 0))
    try:
        coll = get_repo().collection(TASK_COLL)
        try:
            in_flight = coll.count_documents({"status": {"$in": [S_QUEUED, S_RUNNING]}})
        except (AttributeError, TypeError):
            in_flight = sum(1 for d in coll.find({}) if d.get("status") in (S_QUEUED, S_RUNNING))
        available = max(0, slots - in_flight)
        if limit > 0:
            available = min(available, int(limit))
        if available <= 0:
            return {"picked": 0, "submitted": 0, "slots": slots, "in_flight": in_flight,
                    "available": 0, "level": level}
        cur = coll.find({"status": S_WAITING}, {"_id": 1, "type": 1, "task_type": 1}).sort("priority", 1)
        for doc in cur:
            picked += 1
            tid = str(doc.get("_id", ""))
            if not tid:
                continue
            r = submit_task(tid, doc)
            if r.get("submitted"):
                submitted += 1
            if submitted >= available:
                break
    except Exception as e:
        logger.warning("run_waiting_tasks error: %s", e)
        in_flight = 0
        available = 0
    return {"picked": picked, "submitted": submitted, "slots": slots, "in_flight": in_flight,
            "available": available, "level": level}


# —— 默认 scan handler：把 task_type 驱动到 RECON（缺失优雅降级，不崩） ——
def _recon_handler(task_id: str, ctx: "TaskContext") -> Dict[str, Any]:
    """domain/ip 任务：经 ROLE.RECON 跑侦察。RECON 未注册/无工具→降级记日志不阻断（任务仍收尾）。"""
    ctx.checkpoint()                                    # 协作式取消：起步先自检
    recon = ctx.recon
    if not (recon and hasattr(recon, "run_recon")):
        logger.info("orchestration: RECON 未就绪，task %s 降级跳过侦察（仍归集/收尾）", task_id)
        return {"recon": "skipped_no_service"}
    task_type = ctx.options.get("_task_type", "") or _read_task_type(task_id)
    target = _read_target(task_id)
    # 多目标聚合任务（v1.21.157-48）：options.multi_targets={ip:[...],domain:[...]}，分批侦察
    # （域名批保留子域枚举，与单域名任务同待遇；不同于 FOFA 已知资产强制关爆破）。target 是展示串，不用它。
    mt = (ctx.options or {}).get("multi_targets") or {}
    if mt and (mt.get("ip") or mt.get("domain")):
        base = dict(ctx.options or {}); base["cancel_check"] = ctx.is_stopped
        merged = {"recon": "done", "batches": []}
        for ttype, tlist in (("domain", mt.get("domain") or []), ("ip", mt.get("ip") or [])):
            if not tlist:
                continue
            ctx.checkpoint()
            try:
                r = recon.run_recon(ttype, task_id, list(tlist), **dict(base)) or {}
                merged["batches"].append({"type": ttype, "count": len(tlist), "result": r.get("result")})
            except Exception as e:
                logger.warning("orchestration: multi-target run_recon task %s (%s) error: %s", task_id, ttype, e)
                merged["batches"].append({"type": ttype, "count": len(tlist), "error": str(e)})
        return merged
    try:
        opts = dict(ctx.options or {})
        opts["cancel_check"] = ctx.is_stopped
        return recon.run_recon(task_type or "domain", task_id, target, **opts)
    except Exception as e:
        logger.warning("orchestration: run_recon task %s error: %s", task_id, e)
        return {"recon": "error", "error": str(e)}


def _unit_handler(task_id: str, ctx: "TaskContext") -> Dict[str, Any]:
    """反查生产种子，单一侦察消费者逐目标推进；不等待种子阈值或全部单位结束。"""
    import inspect
    import queue
    import threading

    ctx.checkpoint()
    units = [u for u in (ctx.options or {}).get("unit_names", []) if str(u or "").strip()]
    if not units:
        return {"unit": "no_units", "unit_count": 0}
    ext = ctx._reg.get("ext_source_service")
    if not (ext and hasattr(ext, "reverse_lookup_units")):
        return {"unit": "ext_source_unavailable", "unit_count": len(units)}
    recon = ctx.recon
    enabled = bool(recon and hasattr(recon, "run_recon"))
    # 有界队列只做背压，不截断目标。消费者保持单个，避免同进程扫描代理环境并发串线。
    window = max(1, int((ctx.options or {}).get("scan_parallelism") or 4))
    jobs = queue.Queue(maxsize=window)
    abort = threading.Event()
    seen = {"domain": set(), "ip": set()}
    errors = []
    completed = []
    merged_map = {}
    res = {}
    worker = None

    def stopped():
        return abort.is_set() or ctx.is_stopped()

    def merge_map(values):
        if not values:
            return
        # 域名含点，不能用 unit_map.example.com 的更新路径；$literal 保留整个键。
        # incoming 在前、existing 在后：已有归属优先，原子合并避免多 worker 覆盖。
        result = get_repo().collection(TASK_COLL).update_one(_task_query(task_id), [{"$set": {
            "unit_map": {"$mergeObjects": [{"$literal": values}, {"$ifNull": ["$unit_map", {}]}]}}}])
        if getattr(result, "matched_count", 1) == 0:
            raise RuntimeError("任务不存在，不能写回单位归属")
        for key, value in values.items():
            merged_map.setdefault(key, value)

    def consume():
        while True:
            job = jobs.get()
            try:
                if job is None:
                    return
                if stopped():
                    continue
                kind, target = job
                options = dict(ctx.options or {})
                options.update(cancel_check=stopped, use_checkpoint=False)
                output = recon.run_recon(kind, task_id, [target], **options) or {}
                state = output.get("result") or output.get("recon")
                if state == "stopped":
                    abort.set()
                elif state == "error":
                    errors.append("{} {}: {}".format(kind, target, output.get("error") or "recon failed"))
                else:
                    completed.append((kind, target))
            except Exception as exc:
                errors.append("recon: {}".format(exc))
            finally:
                jobs.task_done()

    def enqueue(kind, target):
        if target in seen[kind]:
            return
        if not enabled:
            seen[kind].add(target)
            return
        while not stopped():
            if not worker.is_alive():
                raise RuntimeError("侦察消费者已退出")
            try:
                jobs.put((kind, target), timeout=0.1)
                seen[kind].add(target)
                return
            except queue.Full:
                pass

    def on_unit(unit, domains, ips, fld_map):
        if stopped():
            return
        merge_map(fld_map)
        for kind, targets in (("domain", domains), ("ip", ips)):
            for target in sorted(targets or []):
                if stopped():
                    return
                enqueue(kind, target)

    if enabled:
        worker = threading.Thread(target=consume, name="unit-recon-" + str(task_id), daemon=True)
        worker.start()
    try:
        fn = ext.reverse_lookup_units
        parameters = inspect.signature(fn).parameters
        variadic = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values())
        supports_callback = "on_unit" in parameters or variadic
        supports_cancel = "cancel_check" in parameters or variadic
        if supports_callback and supports_cancel:
            res = fn(units, on_unit=on_unit, cancel_check=stopped) or {}
        else:
            # 旧扩展按单位调用，仍不攒全部单位；不捕获函数内部 TypeError 后重跑全部查询。
            combined = {"seeds": set(), "ip_seeds": set(), "unit_map": {}, "unit_status": {}}
            for unit in units:
                if stopped():
                    break
                item = fn([unit]) or {}
                on_unit(unit, item.get("seeds"), item.get("ip_seeds"), item.get("unit_map"))
                combined["seeds"].update(item.get("seeds") or [])
                combined["ip_seeds"].update(item.get("ip_seeds") or [])
                combined["unit_status"].update(item.get("unit_status") or {})
                for key, value in (item.get("unit_map") or {}).items():
                    combined["unit_map"].setdefault(key, value)
            res = combined
        # 回调偶发失败或旧扩展忽略回调时，补交最终结果中尚未入队的种子，不重复侦察已入队项。
        if not stopped():
            on_unit("", res.get("seeds"), res.get("ip_seeds"), res.get("unit_map"))
    except Exception as exc:
        errors.append("reverse_lookup: {}".format(exc))
    finally:
        if enabled:
            while worker.is_alive():
                try:
                    jobs.put(None, timeout=0.1)
                    break
                except queue.Full:
                    pass
            worker.join()
    result = {"unit": "reverse_lookup_done", "unit_count": len(units),
              "seed_count": len(seen["domain"]), "ip_seed_count": len(seen["ip"]),
              "chunks": len(completed), "streamed": enabled}
    if stopped() or res.get("cancelled"):
        result["result"] = "stopped"
        return result
    if errors:
        result.update(result="error", error="; ".join(errors))
        return result
    if not seen["domain"] and not seen["ip"]:
        statuses = res.get("unit_status") or {}
        result["unit"] = "no_asset" if statuses and all(v == "no_asset" for v in statuses.values()) else "no_seeds"
        result["unit_status"] = statuses
    elif not enabled:
        result["unit"] = "recon_unavailable"
    return result


def _normalize_fofa_target(raw: str) -> str:
    """FOFA 目标归一：剥 scheme（http(s)://）与路径，留 host 或 host:port，供 RECON 探测。
    'https://1.2.3.4:9443' → '1.2.3.4:9443'；'www.x.cn' 原样；空/非法返回空串。"""
    s = (raw or "").strip()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].strip().lower()   # 去路径/query，只留 authority
    return s


def _is_ip_host(host: str) -> bool:
    """判定 host（可能带 :port）是否纯 IPv4——FOFA 目标混合 IP 与域名，据此分流 ip/domain 侦察。"""
    h = host.split(":", 1)[0]
    parts = h.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _fofa_handler(task_id: str, ctx: "TaskContext") -> Dict[str, Any]:
    """FOFA 导入任务：目标在 options.fofa_ip（已由端点经 ext_source.fofa_query 解析的资产列表，
    形如 'https://host:port'/'host:port'/'host'）。归一剥 scheme → 按 IP/域名分流喂 RECON。
    FOFA 目标是**已知资产**，语义为直接探测，不做子域名枚举（强制关 domain_brute/alt_dns，
    避免对已导入资产重复爆破）。IP 与域名分两批 run_recon，合并计数返回。
    目标空/RECON 未就绪 → honest degrade（不伪造，记日志返回，任务正常收尾）。"""
    ctx.checkpoint()
    raw_targets = (ctx.options or {}).get("fofa_ip", []) or []
    normalized = []
    seen = set()
    for raw in raw_targets:
        n = _normalize_fofa_target(str(raw))
        if n and n not in seen:
            seen.add(n)
            normalized.append(n)
    if not normalized:
        logger.info("orchestration: fofa 任务 %s 无目标（options.fofa_ip 空）", task_id)
        return {"fofa": "no_targets", "target_count": 0}
    recon = ctx.recon
    if not (recon and hasattr(recon, "run_recon")):
        logger.info("orchestration: fofa %s 有 %d 目标但 RECON 未就绪，降级", task_id, len(normalized))
        return {"fofa": "recon_unavailable", "target_count": len(normalized)}
    ip_targets = [t for t in normalized if _is_ip_host(t)]
    domain_targets = [t for t in normalized if not _is_ip_host(t)]
    # FOFA 已知资产不再枚举子域名（关爆破/altdns），只探活+扫描导入的目标本身
    base_opts = dict(ctx.options or {})
    base_opts["cancel_check"] = ctx.is_stopped
    base_opts["domain_brute"] = False
    base_opts["alt_dns"] = False
    logger.info("orchestration: fofa 任务 %s 共 %d 目标（IP %d / 域名 %d），分流侦察",
                task_id, len(normalized), len(ip_targets), len(domain_targets))
    merged = {"fofa": "done", "target_count": len(normalized),
              "ip_count": len(ip_targets), "domain_count": len(domain_targets)}
    errors = []
    for ttype, tlist in (("ip", ip_targets), ("domain", domain_targets)):
        if not tlist:
            continue
        ctx.checkpoint()
        try:
            r = recon.run_recon(ttype, task_id, tlist, **dict(base_opts)) or {}
            if r.get("result") == "stopped":
                raise StoppedException(r.get("error") or "fofa recon stopped")
            merged.setdefault("counts", {}).update(r.get("counts", {}) or {})
            if r.get("result") == "error":
                errors.append("{}:{}".format(ttype, r.get("error")))
        except StoppedException:
            raise
        except Exception as e:
            logger.warning("orchestration: fofa %s %s 侦察失败: %s", task_id, ttype, e)
            errors.append("{}:{}".format(ttype, e))
    if errors:
        merged["fofa"] = "partial_error"
        merged["error"] = "; ".join(errors)[:500]
    return merged


def _read_task_type(task_id: str) -> str:
    try:
        doc = get_repo().collection(TASK_COLL).find_one(_task_query(task_id), {"type": 1, "task_type": 1}) or {}
        return doc.get("task_type", "") or doc.get("type", "")
    except Exception:
        return ""


def register_default_handlers() -> None:
    """注册内置 scan handler（domain/ip→RECON，fofa→归一分流 RECON，unit→反查降级）。
    幂等，bootstrap/首次 import 调。github/monitor 归各自叶子，不在此硬绑。"""
    from sentinel_platform.core import models
    register_handler(models.TaskType.DOMAIN, _recon_handler)
    register_handler(models.TaskType.IP, _recon_handler)
    register_handler(models.TaskType.FOFA, _fofa_handler)
    register_handler("unit", _unit_handler)


# 首次 import 即注册默认 handler（bootstrap 装配 + 直接 import 都覆盖；register_handler 幂等覆盖同名）
register_default_handlers()


_SINGLETON: Optional[OrchestrationService] = None


def get_service() -> OrchestrationService:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = OrchestrationService()
    return _SINGLETON
