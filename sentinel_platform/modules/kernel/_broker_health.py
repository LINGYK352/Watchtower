"""kernel/_broker_health —— celery broker 降级健康管理。

背景（116 生产事故）：小内存机 rabbitmq 被 OOM 杀进崩溃循环 → worker 连不上 broker →
会话台/任务投 celery 后无人消费 → AI 对话卡住不回复。

设计（用户 2026-09-20 定调）：
- **celery 优先**：broker 健康时照常投 worker（分布式能力不变）。
- **60 秒内投递失败 3 次 → 自动降级线程模式**：orchestration 的 submit_* 改走 web 进程内线程执行器
  （run_task/run_session/run_console_session 直接在本进程后台线程跑），绕开死 broker，会话立即恢复。
- **状态存 Mongo 单文档**（多 gunicorn worker 共享 fresh 读，重启不丢；对齐 ai_config 单例模式）。
- **可手动切回**：用户点「切回 rabbitmq 模式」→ 真 ping 一次 broker，通了才清降级、恢复 celery；不通则拒绝并提示。
- 降级/恢复各发一次系统通知（前端顶栏红标签轮询本状态 + 弹窗告知）。

纯 stdlib + core；不放 HTTP 路由（端点在 router/endpoints/system 侧调本模块）。
"""
from __future__ import annotations

import time
import threading
from typing import Any, Dict, Optional

from sentinel_platform.core import get_logger, get_repo
from sentinel_platform.contracts import Collections

logger = get_logger()

_FAIL_WINDOW_SECONDS = 60      # 失败计数时间窗
_FAIL_THRESHOLD = 3            # 窗口内失败达此次数 → 降级
_DOC = {"name": "default"}     # 单例文档键

# 进程内失败时间戳滑窗（每 worker 独立计数；任一 worker 达阈值即写 Mongo 降级，全局生效）
_fail_ts: list = []
_lock = threading.Lock()


def _coll():
    return get_repo().collection(Collections.BROKER_HEALTH)


def get_mode() -> str:
    """当前投递模式：'celery'（默认/健康）或 'thread'（已降级）。读 Mongo 单例（多 worker 共享真相源）。
    读失败/无文档 → 默认 celery（不因读不到就误降级）。"""
    try:
        doc = _coll().find_one(_DOC) or {}
        return "thread" if doc.get("mode") == "thread" else "celery"
    except Exception:
        return "celery"


def is_degraded() -> bool:
    return get_mode() == "thread"


def status() -> Dict[str, Any]:
    """给前端/端点的状态视图。"""
    try:
        doc = _coll().find_one(_DOC) or {}
    except Exception:
        doc = {}
    mode = "thread" if doc.get("mode") == "thread" else "celery"
    return {
        "mode": mode,
        "degraded": mode == "thread",
        "reason": doc.get("reason", ""),
        "degraded_at": doc.get("degraded_at", 0),
        "recovered_at": doc.get("recovered_at", 0),
    }


def _set_mode(mode: str, reason: str = "") -> None:
    now = int(time.time())
    upd: Dict[str, Any] = {"mode": mode, "reason": reason, "updated_at": now}
    if mode == "thread":
        upd["degraded_at"] = now
    else:
        upd["recovered_at"] = now
    try:
        _coll().update_one(_DOC, {"$set": upd}, upsert=True)
    except Exception as exc:
        logger.warning("broker_health set_mode %s degraded: %s", mode, exc)


def record_delivery_failure(context: str = "") -> bool:
    """记录一次 celery 投递失败。60 秒窗口内累计达 3 次 → 触发降级（写 Mongo + 卸载 web 侧 celery 投递器）。
    返回 True=本次触发了降级。"""
    now = time.time()
    with _lock:
        _fail_ts.append(now)
        # 清窗口外的旧记录
        while _fail_ts and now - _fail_ts[0] > _FAIL_WINDOW_SECONDS:
            _fail_ts.pop(0)
        reached = len(_fail_ts) >= _FAIL_THRESHOLD
    if not reached:
        return False
    if is_degraded():
        return False   # 已降级，不重复触发
    reason = "rabbitmq 投递 {}s 内连续失败 {} 次（{}），自动降级为线程执行模式".format(
        _FAIL_WINDOW_SECONDS, _FAIL_THRESHOLD, context or "broker 不可达")
    logger.warning("broker_health: %s", reason)
    _set_mode("thread", reason)
    _apply_degrade()
    with _lock:
        _fail_ts.clear()
    _notify("【调度降级】" + reason + "。会话/任务改由应用进程内线程执行，功能不受影响；"
            "broker 恢复后可在顶栏点「降级模式」标签手动切回。")
    return True


def record_delivery_success() -> None:
    """一次投递成功 → 清进程内失败窗（健康信号）。不自动切回（切回须人工确认 broker 真恢复）。"""
    with _lock:
        _fail_ts.clear()


def _apply_degrade() -> None:
    """卸载 web 侧 celery 投递器 → orchestration 的 submit_* 落回线程执行器（_EXECUTOR）。幂等。"""
    try:
        from sentinel_platform.modules.kernel import orchestration
        orchestration._celery_delay = None
        orchestration._celery_session_delay = None
        orchestration._celery_console_delay = None
        orchestration.reset_executor()   # 恢复默认线程执行器
        logger.info("broker_health: 已卸载 celery 投递器，submit_* 走线程执行器")
    except Exception as exc:
        logger.warning("broker_health apply_degrade 降级: %s", exc)


def ping_broker(timeout: float = 5.0) -> bool:
    """真连一次 broker 判活（切回前校验）。成功=能建连接。"""
    try:
        from sentinel_platform.modules.kernel import _celery_adapter
        from sentinel_platform.core import get_config
        broker = (get_config().section("CELERY", "BROKER_URL", default="")
                  or "amqp://guest:guest@127.0.0.1:5672//")
        app = _celery_adapter.make_celery(broker)
        conn = app.connection()
        conn.ensure_connection(max_retries=1, timeout=timeout)
        conn.release()
        return True
    except Exception as exc:
        logger.info("broker_health ping_broker 失败: %s", str(exc)[:120])
        return False


def switch_back(force: bool = False) -> Dict[str, Any]:
    """手动切回 celery：先 ping broker，通了才清降级 + 重装 celery 投递器。不通则拒绝（除非 force）。
    返回 {ok, mode, message}。"""
    if not is_degraded():
        return {"ok": True, "mode": "celery", "message": "当前已是 rabbitmq(celery) 模式，无需切换"}
    if not force and not ping_broker():
        return {"ok": False, "mode": "thread",
                "message": "rabbitmq 仍不可用（连接失败），已保持线程模式；请先恢复 broker 再切回"}
    try:
        from sentinel_platform.modules.kernel import _celery_adapter
        from sentinel_platform.core import get_config
        broker = (get_config().section("CELERY", "BROKER_URL", default="")
                  or "amqp://guest:guest@127.0.0.1:5672//")
        _celery_adapter.make_celery(broker)
        _celery_adapter.install_celery_executor()
    except Exception as exc:
        return {"ok": False, "mode": "thread", "message": "重装 celery 投递器失败：{}".format(str(exc)[:120])}
    _set_mode("celery", "人工切回 rabbitmq 模式（broker ping 通过）")
    with _lock:
        _fail_ts.clear()
    _notify("【调度恢复】已切回 rabbitmq(celery) 模式，会话/任务恢复投递到 worker。")
    logger.info("broker_health: 人工切回 celery 模式")
    return {"ok": True, "mode": "celery", "message": "已切回 rabbitmq(celery) 模式"}


def sync_executor_on_boot() -> None:
    """web 启动装 celery 投递器后调：若 Mongo 记录为已降级（上次降级未恢复）→ 保持线程模式（卸载投递器）。
    保证重启不会把一个已知坏的 broker 又用起来。"""
    try:
        if is_degraded():
            _apply_degrade()
            logger.info("broker_health: 启动时检测到已降级状态，保持线程模式")
    except Exception as exc:
        logger.debug("broker_health sync_on_boot 降级: %s", exc)


def _notify(msg: str) -> None:
    try:
        from sentinel_platform.contracts import get_registry, ROLE
        svc = get_registry().get(ROLE.NOTIFY)
        if svc and hasattr(svc, "notify"):
            svc.notify(msg, title="调度模式变更")
    except Exception:
        pass
