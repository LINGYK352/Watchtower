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


def make_celery(broker_url: str, backend_url: Optional[str] = None, name: str = "sentinel"):
    """建并返回 Celery app（惰性 import；未装 celery 抛 ImportError）。注册 sentinel_run_task。"""
    global _APP, _RUN_TASK, _RUN_SESSION
    from celery import Celery                       # 惰性：无 celery 环境不会执行到这
    app = Celery(name, broker=broker_url, backend=backend_url or None)
    # 对齐旧项目稳态配置：晚 ack + worker 丢失重投 + 追踪 started，SIGTERM 不误标 stop
    app.conf.update(task_acks_late=True, task_reject_on_worker_lost=True, task_track_started=True)

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

    _APP = app
    _RUN_TASK = sentinel_run_task
    _RUN_SESSION = sentinel_run_session

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
    orchestration._celery_delay = lambda task_id, task_type, options: _RUN_TASK.delay(task_id, task_type, options)
    if _RUN_SESSION is not None:
        orchestration._celery_session_delay = lambda session_id: _RUN_SESSION.delay(session_id)
    logger.info("celery adapter installed: task/session 将投递到 worker")
    return True
