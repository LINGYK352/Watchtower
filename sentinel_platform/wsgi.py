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

# A killed updater may have left source replacements unfinished. Recover BEFORE
# importing application modules, using a stdlib-only helper and the same OS lock.
def _recover_update_before_import():
    from pathlib import Path
    import json,importlib.util
    root=Path(__file__).resolve().parents[1];journal=root/'.update_stage/.commit.json'
    if not journal.exists() or json.loads(journal.read_text()).get('phase')!='committing':return
    import fcntl
    with (root/'.update_stage/.apply.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        spec=importlib.util.spec_from_file_location('watchtower_update_recovery',root/'sentinel_platform/core/update_commit.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper);helper.recover(root)

_recover_update_before_import()

#172 installs a signed controller and a persistent read-only startup mount.
#It survives historical business rollback; this one-time migration does not
#rebuild the image or replace user configuration and databases.
from pathlib import Path as _GuardianPath
from sentinel_platform.core.guardian_loader import ensure as _ensure_guardian
try:
    _ensure_guardian(_GuardianPath(__file__).resolve().parents[1])
except RuntimeError as _migration_error:
    # Keep login, diagnostics and resume reachable. Integrity failures continue
    # to fail closed; only a verified controller's operational migration fails soft.
    if type(_migration_error).__name__!='GuardianMigrationError' and not str(_migration_error).startswith('Persistent guardian startup migration failed:'):
        raise
    import logging as _migration_logging
    _migration_logging.getLogger('sentinel.updater').error('更新启动迁移未完成，保留服务并等待修复：%s',_migration_error)

from sentinel_platform.bootstrap import create_app
from sentinel_platform.core import get_config, get_logger

logger = get_logger()

# gunicorn 约定名：`模块:application`
application = create_app()

# 兼容 `flask run` 等找 `app` 的场景
app = application

def _guard_current_controller_health():
    """Older pinned routes must not acknowledge a not-yet-loaded new guardian."""
    from flask import request,jsonify
    if request.path!='/api/meta/health/update-ready':return None
    import json,os
    state=_GuardianPath(__file__).resolve().parents[1]/'.update_stage/guardian/installation.json'
    if not state.is_file():return None
    installed=json.loads(state.read_text())
    if installed.get('installed') and (installed.get('requires_recreate') or os.environ.get('SENTINEL_GUARDIAN_GENERATION')!=installed.get('generation')):
        root=state.parents[2]
        return jsonify(code=200,message='启动迁移未完成',data={'ready':False,'version':(root/'version.txt').read_text().strip(),
            'migration':{'required':True,'phase':installed.get('dispatch_state',''),'error':installed.get('last_error','')}})
application.before_request_funcs.setdefault(None,[]).insert(0,_guard_current_controller_health)


def _install_celery_delivery() -> None:
    """web 侧装 celery 投递（submit_task → 投 worker）。best-effort，失败降级线程不阻断启动。"""
    try:
        broker = (get_config().section("CELERY", "BROKER_URL", default="")
                  or "amqp://guest:guest@127.0.0.1:5672//")
        from sentinel_platform.modules.kernel import _celery_adapter
        _celery_adapter.make_celery(broker)                 # 建 app + 注册 sentinel.run_task（供 .delay 投递）
        installed = _celery_adapter.install_celery_executor()
        from urllib.parse import urlsplit as _broker_split
        logger.info("wsgi celery delivery installed=%s broker_host=%s", installed, _broker_split(broker).hostname or 'local')
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
