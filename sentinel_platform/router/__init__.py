"""核心路由 —— 全项目唯一 HTTP 入口（Flask app 工厂）。

装配顺序：建 Flask app → 注册所有模块能力进 registry（bootstrap）→ 建 Api（挂 /api + Swagger）
→ 挂各类别 Namespace → 装鉴权/RBAC 网关。前端经此调到所有叶子能力（不再是孤岛）。

叶子只提供 registry 能力，端点集中在 endpoints/<类别>.py。新增类别端点 = 加一个 endpoints
文件 + 在 _mount_namespaces 挂一行，其余零改动。
"""
from __future__ import annotations

from typing import Any


def _register_modules() -> None:
    """委托 sentinel_platform.bootstrap.register_all 统一装配（闭合交接待办①，消除双份类别列表）。

    类别注册的单一事实源在 bootstrap.CATEGORY_REGISTERS；新增类别只改 bootstrap 一处。
    单类别失败不阻断（bootstrap 内已缺失降级）。celery worker/scheduler 无 Flask app 时直接调 bootstrap.register_all。
    """
    from sentinel_platform.bootstrap import register_all
    register_all()


def _mount_namespaces(api: Any) -> None:
    """挂各类别 Namespace。新增类别端点在此加一行 add_namespace。"""
    from sentinel_platform.core import get_logger
    logger = get_logger()
    # (模块路径, ns 属性名)；导入失败跳过不阻断（该类别端点未建）
    endpoint_modules = [
        ("sentinel_platform.router.endpoints.meta", "ns"),
        ("sentinel_platform.router.endpoints.image", "ns"),          # /api/image/*（截图静态服务,公开,解SiteTab截图岛,Claude-Opus[proxy-ep]）
        ("sentinel_platform.router.endpoints.risk_intel", "ns"),   # /api/intel/vuln_feed/*
        ("sentinel_platform.router.endpoints.risk_intel", "ns_finding"),  # /api/pentest/finding/*（漏洞中心）
        ("sentinel_platform.router.endpoints.risk_intel", "ns_poc"),      # /api/poc/*（PoC 信息）
        ("sentinel_platform.router.endpoints.asset_intel", "ns"),         # /api/intel/{stat,asset,system,code,report,collect,...}（资产情报,Claude-Opus[intel]）
        ("sentinel_platform.router.endpoints.system", "ns"),        # /api/user/* 登录鉴权
        ("sentinel_platform.router.endpoints.system", "ns_manage"),  # /api/user_manage/* 用户角色管理
        ("sentinel_platform.router.endpoints.api_keys", "ns"),       # /api/api_keys/* 密钥中心(Claude-Opus[keys])
        ("sentinel_platform.router.endpoints.access_log", "ns"),     # /api/access_log/* 访问审计(Claude-Opus[alog])
        ("sentinel_platform.router.endpoints.log_monitor", "ns"),    # /api/log_monitor/* 日志监测+保留(Claude-Opus[logmon])
        ("sentinel_platform.router.endpoints.proxy", "ns"),          # /api/proxy/* 代理中心(Claude-Opus[proxy-ep],解ProxySetting岛;core/池=phase-2降级)
        # asset 资产检索：8 侦察集合各一 Namespace（/api/{domain,ip,site,url,cert,service,fileleak,wih}/*）
        ("sentinel_platform.router.endpoints.asset", "ns_domain"),
        ("sentinel_platform.router.endpoints.asset", "ns_ip"),
        ("sentinel_platform.router.endpoints.asset", "ns_site"),
        ("sentinel_platform.router.endpoints.asset", "ns_url"),
        ("sentinel_platform.router.endpoints.asset", "ns_cert"),
        ("sentinel_platform.router.endpoints.asset", "ns_service"),
        ("sentinel_platform.router.endpoints.asset", "ns_fileleak"),
        ("sentinel_platform.router.endpoints.asset", "ns_wih"),
        ("sentinel_platform.router.endpoints.asset", "ns_fingerprint"),  # /api/fingerprint/*（指纹管理）
        ("sentinel_platform.router.endpoints.github", "ns_task"),    # /api/github_task/*（GitHub 任务）
        ("sentinel_platform.router.endpoints.github", "ns_result"),  # /api/github_result/*（GitHub 结果）
        ("sentinel_platform.router.endpoints.github", "ns_scheduler"),        # /api/github_scheduler/*（GitHub 周期监控）
        ("sentinel_platform.router.endpoints.github", "ns_monitor_result"),   # /api/github_monitor_result/*（监控结果）
        ("sentinel_platform.router.endpoints.asset_groups", "ns_scope"),        # /api/asset_scope/*（资产组，Claude-Opus[groups]）
        ("sentinel_platform.router.endpoints.asset_groups", "ns_asset_domain"),  # /api/asset_domain/*
        ("sentinel_platform.router.endpoints.asset_groups", "ns_asset_ip"),      # /api/asset_ip/*
        ("sentinel_platform.router.endpoints.asset_groups", "ns_asset_site"),    # /api/asset_site/*（含 tag）
        ("sentinel_platform.router.endpoints.asset_groups", "ns_asset_wih"),     # /api/asset_wih/*
        ("sentinel_platform.router.endpoints.workspace", "ns"),      # /api/console/*（态势总览设备监控）
        ("sentinel_platform.router.endpoints.task_plan", "ns"),      # /api/policy/*（策略配置）
        ("sentinel_platform.router.endpoints.task_plan", "ns_schedule"),  # /api/task_schedule/*（计划任务）
        ("sentinel_platform.router.endpoints.task_list", "ns"),      # /api/task/*（任务列表与生命周期,Claude-Opus[tasklist]）
        ("sentinel_platform.router.endpoints.task_create", "ns"),        # /api/task/policy/（按策略下发,Claude-Opus[taskcreate]）
        ("sentinel_platform.router.endpoints.task_create", "ns_fofa"),   # /api/task_fofa/*（FOFA/单位名建任务）
        ("sentinel_platform.router.endpoints.guard_log", "ns"),      # /api/log_monitor/guard/*（拦截日志,Claude-Opus[guard]）
        ("sentinel_platform.router.endpoints.ai_pentest", "ns"),     # /api/ai_config/*（AI 配置中心）
        ("sentinel_platform.router.endpoints.ai_tools", "ns"),       # /api/pentest/tools（AI 最终有效工具目录）
        ("sentinel_platform.router.endpoints.ai_extension", "ns"),   # /api/pentest/extensions/*（扩展管理/商店）
        ("sentinel_platform.router.endpoints.session", "ns"),        # /api/pentest/session*（AI 渗透会话,Claude-Opus[session]）
        ("sentinel_platform.router.endpoints.attack_chain", "ns"),   # /api/intel/chain/*（攻击链情报,Claude-Opus[chain]）
        ("sentinel_platform.router.endpoints.asset_monitor", "ns"),  # /api/scheduler/*（资产监控周期任务）
        ("sentinel_platform.router.endpoints.about", "ns"),          # /api/about/*（更新检测）
        ("sentinel_platform.router.endpoints.network", "ns"),        # /api/network/*（网络检测 ping）
        ("sentinel_platform.router.endpoints.probe", "ns"),          # /api/probe/*（探针管理）
        ("sentinel_platform.router.endpoints.miniapp", "ns"),        # /api/miniapp/*（小程序渗透：解包+提接口）
        ("sentinel_platform.router.endpoints.app_pentest", "ns"),    # /api/app_pentest/*（APP 渗透：设备管理+光纤生成）
        ("sentinel_platform.router.endpoints.appbridge", "ns"),      # /api/appbridge/*（光纤桥接：握手/取命令/回结果，platform_key 鉴权）
        ("sentinel_platform.router.endpoints.scan_result", "ns_vuln"),    # /api/vuln/*（PoC 扫描结果 list+delete）
        ("sentinel_platform.router.endpoints.scan_result", "ns_nuclei"),  # /api/nuclei_result/*（nuclei 命中 list+delete）
        ("sentinel_platform.router.endpoints.scan_result", "ns_npoc"),    # /api/npoc_service/*（非Web服务识别，仅 list）
        ("sentinel_platform.router.endpoints.attack_alert", "ns"),        # /api/attack_alert/*（攻击告警，v1.21.160 新增）
        ("sentinel_platform.router.endpoints.mascot", "ns"),              # /api/mascot/*（桌宠 AI 对话，复用 ai_config provider）
        ("sentinel_platform.router.endpoints.broker_health", "ns"),       # /api/system/broker/*（调度降级状态查询+手动切回）
        # 其余类别端点各 AI 建好后在此追加：ai_pentest(session/ai_tools)/risk_intel(asset_intel/unit_view)
    ]
    for mod_path, ns_attr in endpoint_modules:
        try:
            mod = __import__(mod_path, fromlist=[ns_attr])
            api.add_namespace(getattr(mod, ns_attr))
        except Exception as e:
            logger.warning("mount namespace skip %s: %s", mod_path, e)


def create_app() -> Any:
    """建并返回配置好的 Flask app（gunicorn/celery/本地 run 统一入口）。"""
    from flask import Flask
    from .openapi import build_api
    from .gateway import install_gateway

    app = Flask(__name__)
    try:
        from sentinel_platform.core import get_config
        max_mb = int(get_config().section("AI_EXTENSION", "UPLOAD_MAX_MB", default=512) or 512)
        app.config["MAX_CONTENT_LENGTH"] = max_mb * 1024 * 1024
    except Exception:
        pass
    _register_modules()          # 先注册能力，端点才能经 registry 调到
    api = build_api()
    _mount_namespaces(api)
    api.init_app(app)            # 挂载后再 init，确保 Namespace 都进 swagger
    install_gateway(app)         # 网关最后装（before_request）
    from pathlib import Path
    from .endpoints.meta import _BOOT_UPDATE_VERSION
    from sentinel_platform.modules.about._update_chain import runtime_ready
    runtime_ready(Path(__file__).resolve().parents[2],_BOOT_UPDATE_VERSION)
    return app
