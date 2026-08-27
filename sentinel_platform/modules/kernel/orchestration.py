"""任务编排 orchestration —— 框架无关的任务生命周期 + handler 注册表 + run_task 入口。

把「任务」与「侦察执行(RECON) + 归集(INTEL) + 派发(PENTEST_DISPATCH)」串起来的编排层。
本核心**不绑 celery**：celery worker / scheduler 只是薄适配（调 run_task），编排逻辑框架无关、
可脱离 celery 单测。task_create 等经字符串键 `orchestration_service` 调本层下发执行。

净室重写 celerytask.run_task 的 handler 分发 + 生命周期：
- handler 注册表：按 task_type 注册处理函数（可插，加任务类型不改 run_task）。
- 生命周期：waiting→running→done/stop/error/preempted，每步写 task 集合 status。
- **协作式取消（铁律，见记忆 dengta-stop-cooperative-cancellation）**：revoke 在 acks_late 下不可靠，
  故执行体在阶段边界主动查 DB status，见 stop/preempted 即抛 Stopped 自停——不依赖 revoke。

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


def _set_status(task_id: str, status: str, extra: Optional[Dict[str, Any]] = None) -> None:
    upd = {"status": status}
    if extra:
        upd.update(extra)
    try:
        get_repo().collection(TASK_COLL).update_one(_task_query(task_id), {"$set": upd})
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
        except Exception:
            options = options or {}
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
    _set_status(task_id, S_RUNNING, {"start_time": time.strftime("%Y-%m-%d %H:%M:%S")})
    try:
        handler_result = handler(task_id, ctx)          # handler 内部按 ctx.checkpoint() 自检
        if isinstance(handler_result, dict):
            handler_state = handler_result.get("result") or handler_result.get("recon")
            if handler_state == "stopped":
                raise StoppedException(handler_result.get("error") or "recon pipeline stopped")
            if handler_state == "error":
                raise RuntimeError(handler_result.get("error") or "recon pipeline failed")
        ctx.checkpoint()                                 # handler 返回后再次确认，停止态不得归集/写 done
        _post_scan(ctx)                                  # 扫完归集 + 按 options.auto_pentest 派发
        ctx.checkpoint()
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
    try:
        delay = globals().get("_celery_delay")
        if callable(delay):
            delay(task_id, task_type, options)
        else:
            _EXECUTOR(lambda: run_task(task_id, task_type, options))
        return {"ok": True, "task_id": task_id, "submitted": True, "claimed": True}
    except Exception as e:
        _rollback_task_claim(task_id, str(e))
        logger.warning("submit_task %s error: %s", task_id, e)
        return {"ok": False, "task_id": task_id, "submitted": False, "claimed": True, "error": str(e)}


def _claim_session(session_id: str, from_status: str) -> bool:
    """原子认领会话：queued/paused_transient -> dispatching。
    BUG-019：认领条件加 `stop_requested != True`——若用户已显式 stop（即使状态因竞态落在
    paused_transient），调度器绝不恢复；停止意图是终态优先。原子 update 的 filter 里带该条件，
    有停止标记则 modified_count=0 认领失败，会话保持不被拉回 running。"""
    try:
        update: Dict[str, Any] = {"$set": {"status": "dispatching"}}
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
    try:
        delay = globals().get("_celery_session_delay")
        if callable(delay):
            delay(session_id)
        else:
            _EXECUTOR(_run)
        return {"ok": True, "session_id": session_id, "submitted": True, "claimed": True}
    except Exception as e:
        try:
            get_repo().collection("intel_pentest_session").update_one(
                {"_id": _oid(session_id), "status": "dispatching"},
                {"$set": {"status": from_status, "dispatch_error": str(e)[:500]}})
        except Exception:
            pass
        logger.warning("submit_session %s error: %s", session_id, e)
        return {"ok": False, "session_id": session_id, "submitted": False, "claimed": True, "error": str(e)}


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
    try:
        opts = dict(ctx.options or {})
        opts["cancel_check"] = ctx.is_stopped
        return recon.run_recon(task_type or "domain", task_id, target, **opts)
    except Exception as e:
        logger.warning("orchestration: run_recon task %s error: %s", task_id, e)
        return {"recon": "error", "error": str(e)}


def _unit_handler(task_id: str, ctx: "TaskContext") -> Dict[str, Any]:
    """单位名任务（补净室迁移丢失的执行闭环）：单位→资产反查（ext_source.reverse_lookup_units，
    Hunter icp.name 备案维度）→ 拿种子域名 → 经 RECON 跑侦察（流式归集/派发自然触发，单位归属走 icp_query）。
    反查不到种子/服务缺失 → honest degrade（不伪造资产，记日志返回，任务正常收尾）。"""
    ctx.checkpoint()
    units = (ctx.options or {}).get("unit_names", [])
    if not units:
        return {"unit": "no_units", "unit_count": 0}
    ext = ctx._reg.get("ext_source_service")
    if not (ext and hasattr(ext, "reverse_lookup_units")):
        logger.info("orchestration: unit 任务 %s 反查服务未就绪，降级（不伪造资产）", task_id)
        return {"unit": "ext_source_unavailable", "unit_count": len(units)}
    try:
        res = ext.reverse_lookup_units(units) or {}
    except Exception as e:
        logger.warning("orchestration: unit %s 反查失败: %s", task_id, e)
        return {"unit": "reverse_lookup_error", "error": str(e)}
    seeds = res.get("seeds") or []
    ip_seeds = res.get("ip_seeds") or []
    if not seeds and not ip_seeds:
        logger.info("orchestration: unit 任务 %s 反查 %d 单位无种子（无备案资产/无 Hunter key）", task_id, len(units))
        return {"unit": "no_seeds", "unit_count": len(units), "seed_count": 0}
    ctx.checkpoint()
    recon = ctx.recon
    if not (recon and hasattr(recon, "run_recon")):
        logger.info("orchestration: unit %s 反查得 %d 域名/%d IP 种子但 RECON 未就绪，降级",
                    task_id, len(seeds), len(ip_seeds))
        return {"unit": "recon_unavailable", "seed_count": len(seeds), "ip_seed_count": len(ip_seeds)}
    opts = dict(ctx.options or {})
    opts["cancel_check"] = ctx.is_stopped
    opts["unit_map"] = res.get("unit_map", {})   # fld→单位 归属（供归集参考）
    logger.info("orchestration: unit 任务 %s 反查 %d 单位得 %d 域名 + %d IP 种子，转侦察（域名/IP 两路互补）",
                task_id, len(units), len(seeds), len(ip_seeds))
    # 域名种子走 domain pipeline（子域名/解析/建站）；IP 种子走 ip pipeline（省 subdomain/resolve，
    # 直接 portscan/site，绕开 DNS 瓶颈——治主域无 A 记录时反查资产被丢）。两路都幂等落库+流式派发。
    result: Dict[str, Any] = {"unit": "reverse_lookup_done", "seed_count": len(seeds),
                              "ip_seed_count": len(ip_seeds)}
    errs = []
    if seeds:
        try:
            rd = recon.run_recon("domain", task_id, seeds, **opts) or {}
            result["domain_result"] = rd.get("result")
        except Exception as e:
            logger.warning("orchestration: unit %s 域名侦察失败: %s", task_id, e)
            errs.append("domain: {}".format(e))
    if ip_seeds and not ctx.is_stopped():
        try:
            ri = recon.run_recon("ip", task_id, ip_seeds, **opts) or {}
            result["ip_result"] = ri.get("result")
        except Exception as e:
            logger.warning("orchestration: unit %s IP 侦察失败: %s", task_id, e)
            errs.append("ip: {}".format(e))
    if errs:
        result["error"] = "; ".join(errs)
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
