"""WSGI 入口 —— gunicorn / uwsgi 部署用。

生产启动（服务器）：
    gunicorn -w 4 -b 0.0.0.0:5003 sentinel_platform.wsgi:application

`application` 由 bootstrap.create_app() 构建：装配全模块能力(register_all) → 建 Flask+RESTX Api
→ 挂所有 endpoints Namespace → 装鉴权/RBAC 网关。config 从 config/config.yaml 读（见 core/config）。

Mongo/RabbitMQ 等外部依赖在首次请求访问集合时惰性连接，import 本模块不触发连接。

**任务投递到 celery worker（关键）**：web 进程作为任务「投递方」也需装 celery 执行器——
否则 task_create → orchestration.submit_task 会在 gunicorn 进程内起线程跑扫描（阻塞 web 资源、
重启即丢），而非投给专用 celery worker。故这里 best-effort make_celery + install_celery_executor：
web 侧只用 celery app 的 `.delay()` 把任务投 broker（不消费，消费在 worker），submit_task 随即
路由到 worker。celery 未装/broker 不可达（开发/离线）→ 降级为默认线程执行器，dev 仍可跑。
"""
from __future__ import annotations

from sentinel_platform.bootstrap import create_app
from sentinel_platform.core import get_config, get_logger

logger = get_logger()

# gunicorn 约定名：`模块:application`
application = create_app()

# 兼容 `flask run` 等找 `app` 的场景
app = application


def _install_celery_delivery() -> None:
    """web 侧装 celery 投递（submit_task → 投 worker）。best-effort，失败降级线程不阻断启动。"""
    try:
        broker = (get_config().section("CELERY", "BROKER_URL", default="")
                  or "amqp://guest:guest@127.0.0.1:5672//")
        from sentinel_platform.modules.kernel import _celery_adapter
        _celery_adapter.make_celery(broker)                 # 建 app + 注册 sentinel.run_task（供 .delay 投递）
        installed = _celery_adapter.install_celery_executor()
        logger.info("wsgi celery delivery installed=%s broker=%s", installed, broker)
        # broker 降级自愈：若上次已降级（Mongo 记录 mode=thread）→ 保持线程模式，不把已知坏的 broker 又用起来。
        try:
            from sentinel_platform.modules.kernel import _broker_health
            _broker_health.sync_executor_on_boot()
        except Exception as exc:
            logger.debug("wsgi broker_health sync 降级: %s", exc)
    except ImportError:
        logger.warning("wsgi: celery 未装，submit_task 降级线程执行器（开发/离线可，生产应装 celery）")
    except Exception as exc:
        logger.warning("wsgi: celery delivery 安装降级: %s", exc)


_install_celery_delivery()
