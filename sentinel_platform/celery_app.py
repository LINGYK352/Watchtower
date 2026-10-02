"""Celery worker 进程入口 —— 真起 worker，任务被真正驱动执行。

部署（Linux 服务器，celery infra 就绪时）：
    celery -A sentinel_platform.celery_app:celery_app worker -l info -c 4

启动做三件事（import 本模块即完成，供 celery -A 发现）：
  ① bootstrap.bootstrap(with_indexes=True)：非 HTTP 进程装配全模块能力进 registry + 建索引
     （worker 侧和 web 侧共用同一装配，handler 里 registry 取 RECON/INTEL/... 才有服务）。
  ② _celery_adapter.make_celery(broker)：建 Celery app + 注册 sentinel.run_task。
  ③ install_celery_executor()：把 orchestration.submit_task 的投递从"后台线程"切成"投 worker 队列"，
     于是 web 端 submit_task → 进 celery 队列 → 本 worker 侧 orchestration.run_task 真跑 14 阶段扫描。

broker 从 config `CELERY.BROKER_URL` 读（默认 RabbitMQ 本地）。无 celery（开发机）时 import 会在
make_celery 抛 ImportError——本模块只在真部署 worker 时被 celery 命令 import，开发/单测不 import。
核心 orchestration/_celery_adapter 不改，本文件只做进程入口装配。
"""
from __future__ import annotations

from sentinel_platform.core import get_config, get_logger

logger = get_logger()


def _normalize_broker_url(url: str) -> str:
    """容错纠正 broker URL 的 vhost 前导斜杠误配（治「任务永卡 queued」的存量部署）。

    背景：compose 的 `RABBITMQ_DEFAULT_VHOST=/sentinelhost` 建出的 vhost 名**带前导斜杠**
    （`/sentinelhost`）。AMQP URL `amqp://host:port/VHOST` 里 host:port 后第一个 `/` 是分隔符，
    故要连该 vhost 必须写 `//sentinelhost`（双斜杠）。历史 config.yaml 曾误写单斜杠
    `/sentinelhost` → 解析成 vhost `sentinelhost`（无斜杠）→ worker 报 530 vhost not found →
    无消费者 → 任务永卡 queued。

    修复只落配置文件对存量用户无效（更新机制有意排除 config.yaml 保护密钥），故在读取处做
    幂等归一：仅当 vhost 恰为无斜杠的 `sentinelhost` 时补成 `/sentinelhost`（→URL 双斜杠）；
    已是双斜杠 / 其它自定义 vhost / 空 vhost 一律不动，避免误伤别的部署。
    """
    try:
        import re
        # 匹配 amqp(s)://[user:pass@]host[:port]/<vhost>，只在 vhost 恰为 sentinelhost（单斜杠误配）时纠正
        m = re.match(r'^(amqps?://[^/]+)/(sentinelhost)(/?.*)$', url)
        if m:
            fixed = "{}//sentinelhost{}".format(m.group(1), m.group(3))
            logger.warning("broker vhost 误配纠正: 单斜杠 /sentinelhost → 双斜杠 //sentinelhost "
                           "(vhost 实际名带前导斜杠;治任务卡 queued)")
            return fixed
    except Exception:
        pass
    return url


def _broker_url() -> str:
    cfg = get_config()
    raw = (cfg.section("CELERY", "BROKER_URL", default="")
           or "amqp://guest:guest@127.0.0.1:5672//")
    return _normalize_broker_url(raw)


def _backend_url():
    return get_config().section("CELERY", "RESULT_BACKEND", default=None) or None


def build() -> object:
    """装配 worker 运行时：模块能力 + celery app + 执行器切 worker 投递。返回 celery app。"""
    # ① 非 HTTP 进程装配（同 web 侧 register_all，worker 内 handler 才取得到 RECON/INTEL 等服务）
    from sentinel_platform import bootstrap
    try:
        bootstrap.bootstrap(with_indexes=True)
    except Exception as exc:                       # 装配失败不该静默——worker 起不来要看得见
        logger.warning("celery worker bootstrap degraded: %s", exc)

    # ② 建 Celery app（惰性 import celery；未装抛 ImportError，由 celery 命令侧暴露）
    from sentinel_platform.modules.kernel import _celery_adapter
    app = _celery_adapter.make_celery(_broker_url(), _backend_url())

    # ③ 执行器切 celery：submit_task 从起线程变投 worker 队列
    installed = _celery_adapter.install_celery_executor(app)
    from urllib.parse import urlsplit
    logger.info("celery_app built: broker_host=%s executor_installed=%s",
                urlsplit(_broker_url()).hostname or "", installed)
    return app


# celery -A sentinel_platform.celery_app:celery_app 发现此名。
# 模块级容错：celery 已装（真 worker 部署）→ 建真 app；未装（开发/单测机）→ celery_app=None +
# 告警，不让 import 崩（否则整个包在无 celery 环境不可 import/测试）。celery 命令只在装了 celery 的
# worker 上 import 本模块，届时拿到真 app；拿到 None 时 celery 命令自会明确报错。
try:
    celery_app = build()
except ImportError as _exc:
    celery_app = None
    logger.warning("celery 未安装，celery_app=None（仅真 worker 部署需 celery）：%s", _exc)

