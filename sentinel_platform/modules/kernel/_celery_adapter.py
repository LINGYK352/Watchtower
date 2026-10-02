"""orchestration 的 celery 薄适配（**惰性可选**，仅 Linux worker 部署用）。

编排核心 `orchestration.py` **零 celery 依赖**（框架无关，可脱 celery 单测）。本适配把执行器
从"后台线程"切成"投递到 celery worker"——只在真有 celery infra 时由 worker 入口 import 本模块调
`install_celery_executor()`。无 celery（开发/离线单测）时**根本不 import 本文件**，故核心不受影响。

设计（对齐旧 celerytask：一个 asset_task 入口 + run_task 分发）：
- `make_celery(broker_url, backend_url)`：建 Celery app（惰性 import celery，未装则抛 ImportError 由调用方处理）。
- `@app.task sentinel_run_task(task_id, task_type, options)`：worker 侧调 orchestration.run_task。
- `install_celery_executor(app)`：把 orchestration 的执行器换成"投递 sentinel_run_task.delay(...)"——
  于是 submit_task 从"起线程"变"进 celery 队列"，run_task 在 worker 侧真跑。

celery 全家桶已 vendor（celery/kombu/amqp/billiard/vine，见 requirements.txt）。
"""
from __future__ import annotations

from typing import Any, Optional

from sentinel_platform.core import get_logger
from . import orchestration

logger = get_logger()

_APP = None
_RUN_TASK = None
_RUN_SESSION = None
_RUN_CONSOLE = None


def make_celery(broker_url: str, backend_url: Optional[str] = None, name: str = "sentinel"):
    """建并返回 Celery app（惰性 import；未装 celery 抛 ImportError）。注册 sentinel_run_task。"""
    global _APP, _RUN_TASK, _RUN_SESSION, _RUN_CONSOLE
    from celery import Celery                       # 惰性：无 celery 环境不会执行到这
    app = Celery(name, broker=broker_url, backend=backend_url or None)
    # ack 策略（问题14 根治）：**早 ack**（task_acks_late=False，任务一领就 ack）。
    # 背景：AI 渗透会话设计上可跑几百轮 >30min（实测 round 451/74min）。晚 ack 下 RabbitMQ 默认
    # consumer_timeout=30min 测量「投递→ack」间隔——长会话必超时 → 断 channel(PreconditionFailed 406)
    # → consumer 主循环 Unrecoverable 崩（稳定引爆，非偶发）。
    # 为何早 ack 安全（不丢崩溃恢复）：本平台崩溃恢复**不依赖 RabbitMQ 重投**——scheduler 从 DB 真相源
    # 回收（_reclaim_on_startup 重启即回收 running/dispatching + _reclaim_stalled_tasks 心跳超时 watchdog
    # 带 reclaim_count 上限），停止走协作式取消（DB status，不靠 ack）。故 acks_late 的「崩溃重投」保障
    # 与 DB-reclaim 完全冗余；且 rabbitmq 容器无持久卷，recreate 本就丢消息，恢复全靠 DB-reclaim。
    # 早 ack 让 consumer_timeout 不再计长任务执行时长（治本）；compose 侧再调大 consumer_timeout=12h 兜底。
    # task_track_started 保留（web/前端看 started 态）；task_reject_on_worker_lost 早 ack 下已无效（任务
    # 已 ack，worker 丢失不会重投），删除避免误解——崩溃回收统一由 scheduler DB-reclaim 负责。
    # 断线重连健壮性（治「worker 消费者掉线后不自愈 → consumers=0 → 任务永卡 queued/dispatching」）：
    # broker_connection_retry(_on_startup) + max_retries=None → 与 RabbitMQ 连接断了永久重试重连，
    # 不放弃消费者。长任务(渗透会话>30min)期间若 TCP 连接抖动/被断，worker 会自动重建消费连接。
    app.conf.update(task_acks_late=False, task_track_started=True,
                    broker_connection_retry=True,
                    broker_connection_retry_on_startup=True,
                    broker_connection_max_retries=None)

    def _ensure_registry():
        """确保当前 fork 子进程已装配 registry（prefork 模型下子进程全局变量可能为空）。幂等。"""
        from sentinel_platform.contracts import get_registry
        if not get_registry()._impls:
            from sentinel_platform.bootstrap import register_all
            register_all()

    @app.task(name="sentinel.run_task")
    def sentinel_run_task(task_id: str, task_type: str = "", options: Any = None):
        _ensure_registry()
        return orchestration.run_task(task_id, task_type, options)

    @app.task(name="sentinel.run_session")
    def sentinel_run_session(session_id: str):
        _ensure_registry()
        from sentinel_platform.contracts import get_registry, ROLE
        svc = get_registry().get(ROLE.PENTEST_DISPATCH)
        if not (svc and hasattr(svc, "run_session")):
            return {"session_id": session_id, "status": "unavailable"}
        return svc.run_session(session_id)

    @app.task(name="sentinel.run_console_session")
    def sentinel_run_console_session(session_id: str):
        """会话台后台回合（v1.21.157-62）：worker 跑 run_console_agent（console 语义，非 run_agent）。"""
        _ensure_registry()
        from sentinel_platform.contracts import get_registry, ROLE
        svc = get_registry().get(ROLE.PENTEST_DISPATCH)
        if not (svc and hasattr(svc, "run_console_session")):
            return {"session_id": session_id, "status": "unavailable"}
        return svc.run_console_session(session_id)

    _APP = app
    _RUN_TASK = sentinel_run_task
    _RUN_SESSION = sentinel_run_session
    _RUN_CONSOLE = sentinel_run_console_session

    # 确保每个 fork 子进程都装配 registry（prefork 模型下子进程 registry 可能为空）
    from celery.signals import worker_process_init

    @worker_process_init.connect
    def _init_worker_process(**kwargs):
        try:
            from sentinel_platform.bootstrap import register_all
            register_all()
        except Exception as exc:
            logger.warning("worker_process_init register_all degraded: %s", exc)

    return app


def _large_task_options(options) -> bool:
    """小消息走原路径；有界估算驻留大小，不序列化整个大配置，只选择传输方式。"""
    import sys
    from itertools import chain
    pending, seen, size = [iter((options,))], set(), 0
    for _ in range(256):
        while pending:
            try:
                value = next(pending[-1])
                break
            except StopIteration:
                pending.pop()
        else:
            return False
        if id(value) in seen:
            continue
        seen.add(id(value))
        size += sys.getsizeof(value)
        if size >= 32768:
            return True
        if isinstance(value, dict):
            pending.append(chain(value.keys(), value.values()))
        elif isinstance(value, (list, tuple)):
            pending.append(iter(value))
    return bool(pending)


def install_celery_executor(app=None) -> bool:
    """把 orchestration 执行器切成"投递到 celery worker"。app 缺省用 make_celery 建的。
    成功返回 True；未先 make_celery（无 _RUN_TASK）返回 False（调用方决定降级线程）。"""
    if _RUN_TASK is None:
        logger.warning("celery adapter: 未 make_celery，执行器保持默认（线程）")
        return False

    def _celery_executor(fn):
        # submit_task 传进来的是 lambda: run_task(task_id, type, opts)；但 celery 要可序列化参数，
        # 不能投 lambda。故这里不使用 fn，而由 submit_task 走专用投递路径（见下 submit_via_celery）。
        # 为兼容既有执行器签名，直接本地跑（不应走到——submit_task 会优先用 submit_via_celery）。
        return fn()

    # 更稳妥：直接替换 submit_task 的投递实现为 celery delay（可序列化参数）
    orchestration.set_executor(_celery_executor)
    def _task_delay(task_id, task_type, options):
        # 已持久化且相同的任务配置由 worker 原有缺省读取路径取回；队列保留轻量引用。
        # 未持久化/显式覆盖/读取失败仍按原协议发送完整参数，兼容旧 worker 的三个位置参数。
        if options is not None and _large_task_options(options):
            try:
                query = {**orchestration._task_query(task_id), "status": orchestration.S_QUEUED}
                doc = orchestration.get_repo().collection(orchestration.TASK_COLL).find_one(
                    query, {"task_type": 1, "type": 1, "options": 1})
                stored_type = (doc or {}).get("task_type", "") or (doc or {}).get("type", "")
                if doc and (not task_type or task_type == stored_type) and options == doc.get("options", {}):
                    options = None
            except Exception:
                pass
        return _RUN_TASK.delay(task_id, task_type, options)
    orchestration._celery_delay = _task_delay
    if _RUN_SESSION is not None:
        orchestration._celery_session_delay = lambda session_id: _RUN_SESSION.delay(session_id)
    if _RUN_CONSOLE is not None:
        orchestration._celery_console_delay = lambda session_id: _RUN_CONSOLE.delay(session_id)
    logger.info("celery adapter installed: task/session/console 将投递到 worker")
    return True
