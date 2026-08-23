"""sentinel_platform 装配底座 —— 全项目「注册能力 + 建索引」的单一事实源。

scaffold（LAYOUT §sentinel_platform / MODULES §装配）要求的**唯一 import 各模块 register 的地方**。
三类进程共用它，各取所需：
  - Web/API：`router.create_app()` 内调 `register_all()`（HTTP 入口，见 router/__init__）。
  - Celery Worker / Scheduler：**无 Flask app**，直接 `register_all(get_registry())` 装配能力 + `ensure_indexes()`。
本模块是"唯一知道所有类别"的地方；类别之间仍互不认识（经 registry + Protocol 解耦）。
单个类别 register 失败不阻断其余（缺失降级）——某类别没建好，其余仍可注册。

**不 import 任何 modules 内部实现**：只按路径字符串 import 各类别 `register` 模块调 `register(registry)`；
索引只用 `contracts.Collections` 常量 + `core.get_repo()`（pymongo 惰性；无 mongo/离线环境建索引失败静默降级，不崩）。
"""
from __future__ import annotations

from typing import Any, Dict, List

from sentinel_platform.core import get_logger, get_repo
from sentinel_platform.contracts import get_registry, Collections

logger = get_logger()

# —— 类别注册单一事实源（新增类别在此加一行；router 委托本列表，消除双份漂移）——
CATEGORY_REGISTERS: List[str] = [
    "sentinel_platform.modules.kernel.register",       # RECON/NOTIFY/EXPLOIT_CLUE/SYSTEM_TAGS + orchestration
    "sentinel_platform.modules.risk_intel.register",   # VULN_INTEL/FINDING/INTEL + attack_chain 等
    "sentinel_platform.modules.system.register",       # PROXY/USER/RBAC + api_keys/audit/log
    "sentinel_platform.modules.asset.register",        # asset_search/asset_group/fingerprint/github/monitor
    "sentinel_platform.modules.workspace.register",    # dashboard_service
    "sentinel_platform.modules.task_plan.register",    # policy/task_list/task_schedule/task_create
    "sentinel_platform.modules.ai_pentest.register",   # ai_config/ai_tools/PENTEST_DISPATCH(session)
    "sentinel_platform.modules.about.register",        # update_check（更新检测）
]


def register_all(registry: Any = None) -> Dict[str, Any]:
    """装配：依次 import 各类别 register.py 调 register(registry)。单类别失败不阻断（缺失降级）。
    返回 {"registered": [类别...], "failed": {类别: 错误}}，供集成方体检。幂等：重复调覆盖同键。"""
    registry = registry or get_registry()
    registered, failed = [], {}
    for mod_path in CATEGORY_REGISTERS:
        cat = mod_path.rsplit(".", 2)[-2]
        try:
            mod = __import__(mod_path, fromlist=["register"])
            mod.register(registry)
            registered.append(cat)
        except Exception as exc:
            failed[cat] = str(exc)
            logger.warning("bootstrap register skip %s: %s", mod_path, exc)
    # 挂 MongoLogHandler 采集 WARNING+ 程序日志进 log_monitor 集合（web/worker/scheduler 三进程各自 logger 都挂）。
    # 净室迁移曾丢此调用（install_log_capture 只在注释提、从没被调）→ log_monitor 恒 0、日志监测页空。幂等，缺失降级。
    try:
        from sentinel_platform.modules.system.log_monitor import install_log_capture
        install_log_capture()
    except Exception as exc:
        logger.warning("bootstrap install_log_capture skip: %s", exc)
    return {"registered": registered, "failed": failed}


# —— 索引规格（收口各叶子遗留的"待 bootstrap 统一建索引"）——
# 每条：(集合, [(keys, kwargs)])。keys=[(字段, 方向)]；kwargs 支持 unique/expireAfterSeconds/sparse/name。
# TTL 天数(_ttl/update_date/ts)只建默认值，运行时由 system/log_monitor 的 log_retention collMod 改。
# 侦察集合(domain/ip/site/...)由引擎产出，平台侧只补最常用的 task_id 查询索引（引擎可能已建，重复建幂等）。
_DAY = 86400
INDEX_SPECS: List = [
    # 情报中心（asset_intel / vuln_center / exploit_clue / attack_chain）
    (Collections.INTEL_ASSET, [([("key", 1)], {"unique": True}), ([("unit", 1)], {}),
                               ([("system_id", 1)], {}), ([("pentest_status", 1)], {}),
                               ([("source_task_id", 1)], {})]),
    (Collections.INTEL_SYSTEM, [([("key", 1)], {"unique": True}), ([("units", 1)], {}),
                               ([("instance_keys", 1)], {})]),
    (Collections.INTEL_FINDING, [([("norm_target", 1), ("norm_type", 1)], {}),
                                 ([("unit", 1)], {}), ([("severity", 1)], {}),
                                 ([("session_id", 1)], {}), ([("handle_status", 1)], {})]),
    (Collections.INTEL_REPORT, [([("session_id", 1)], {}), ([("unit", 1)], {}),
                                ([("asset_key", 1)], {})]),
    (Collections.INTEL_EXPLOIT_CLUE, [([("unit", 1)], {}),
                                      ([("unit", 1), ("clue_type", 1), ("title", 1)], {"unique": True})]),
    (Collections.INTEL_ATTACK_CHAIN, [([("unit", 1)], {}), ([("sessions", 1)], {})]),
    # 漏洞情报
    (Collections.VULN_INTEL, [([("dedup_key", 1)], {"unique": True, "sparse": True}),
                              ([("sources.name", 1)], {}), ([("severity", 1)], {})]),
    # AI 渗透会话
    (Collections.PENTEST_SESSION, [([("status", 1)], {}), ([("active_key", 1)], {"unique": True, "sparse": True}),
                                   ([("asset_key", 1)], {}),
                                   ([("source_task_id", 1)], {})]),
    (Collections.AI_EXTENSION, [([("extension_id", 1), ("version", 1)], {"unique": True}),
                                ([("enabled", 1), ("available", 1)], {}),
                                ([("source", 1)], {})]),
    (Collections.AI_EXTENSION_LOG, [([("extension_id", 1)], {}), ([("save_date", 1)], {}),
                                    ([("session_id", 1)], {}), ([("status", 1)], {})]),
    # 资产分组（组内资产按 scope_id）
    (Collections.ASSET_DOMAIN, [([("scope_id", 1)], {})]),
    (Collections.ASSET_IP, [([("scope_id", 1)], {})]),
    (Collections.ASSET_SITE, [([("scope_id", 1)], {})]),
    (Collections.ASSET_WIH, [([("scope_id", 1)], {})]),
    # 审计/日志/资源（TTL 默认值，天数由 log_retention 运行时改）
    (Collections.ACCESS_LOG, [([("_ttl", 1)], {"expireAfterSeconds": 14 * _DAY}),
                              ([("username", 1)], {}), ([("is_write", 1)], {})]),
    (Collections.LOG_MONITOR, [([("update_date", 1)], {"expireAfterSeconds": 7 * _DAY}),
                               ([("level", 1)], {})]),
    (Collections.RESOURCE_HISTORY, [([("ts", 1)], {}),
                                    ([("ts", 1)], {"expireAfterSeconds": 400 * _DAY, "name": "ts_ttl"})]),
    # 侦察集合最常用 task_id 查询（引擎可能已建，幂等）
    (Collections.SITE, [([("task_id", 1)], {})]),
    (Collections.DOMAIN, [([("task_id", 1)], {})]),
    (Collections.IP, [([("task_id", 1)], {})]),
]


def ensure_indexes() -> Dict[str, Any]:
    """统一建索引（收口各叶子遗留）。逐条 create_index，失败静默降级（无 mongo/离线/已存在冲突均不崩）。
    返回 {"created": N, "skipped": N}。部署/worker/scheduler 启动时调一次即可（幂等：已存在的 create_index 无副作用）。"""
    repo = get_repo()
    created, skipped = 0, 0
    for coll_name, specs in INDEX_SPECS:
        for keys, kwargs in specs:
            try:
                repo.collection(coll_name).create_index(keys, **kwargs)
                created += 1
            except Exception as exc:
                skipped += 1
                logger.debug("ensure_index skip %s %s: %s", coll_name, keys, exc)
    logger.info("bootstrap ensure_indexes: created=%d skipped=%d", created, skipped)
    # 开箱即用：user.username 唯一索引（防并发播种双插）+ 首次播种默认管理员（幂等，空库才建）
    try:
        repo.collection("user").create_index([("username", 1)], unique=True)
    except Exception as exc:
        logger.debug("ensure_index skip user.username: %s", exc)
    try:
        from sentinel_platform.modules.system.user_manage import seed_default_admin
        seed = seed_default_admin()
        if seed.get("seeded"):
            logger.info("bootstrap: 已播种默认管理员 %s（首次登录请立即改密）", seed.get("username"))
    except Exception as exc:
        logger.debug("seed_default_admin skip: %s", exc)
    # PoC 插件自动同步（空库时扫描 external/npoc 目录填充，保证策略编辑页插件列表不空）
    try:
        poc_coll = repo.collection("poc")
        if poc_coll.count_documents({}, limit=1) == 0:
            from sentinel_platform.modules.risk_intel.poc import sync_poc
            result_sync = sync_poc()
            if result_sync.get("plugin_cnt"):
                logger.info("bootstrap: poc 自动同步 %d 插件", result_sync["plugin_cnt"])
    except Exception as exc:
        logger.debug("bootstrap poc sync skip: %s", exc)
    # AI 提示词播种（内置三套渗透模式+闸刀+代码审计，幂等不覆盖在线编辑）
    try:
        from sentinel_platform.modules.ai_pentest.ai_config import seed_prompts
        seeded = seed_prompts()
        if seeded:
            logger.info("bootstrap: AI 提示词播种 %d 个场景", seeded)
    except Exception as exc:
        logger.debug("bootstrap seed_prompts skip: %s", exc)
    return {"created": created, "skipped": skipped}


def bootstrap(registry: Any = None, with_indexes: bool = False) -> Dict[str, Any]:
    """一站式装配（celery worker / scheduler 用）：register_all + 可选 ensure_indexes。
    with_indexes 默认 False（避免每个 worker 都建；由部署/一个进程建一次即可）。返回体检摘要。"""
    result = register_all(registry)
    if with_indexes:
        result["indexes"] = ensure_indexes()
    return result


def create_app() -> Any:
    """Web/API 入口：委托 router.create_app（router 内部调 register_all 装配 + 挂 HTTP）。
    集中于此便于 gunicorn 统一 import `sentinel_platform.bootstrap:create_app`。
    额外 ensure_indexes（含默认管理员播种，幂等）——保证 web 独立起也能开箱即用登录。"""
    from sentinel_platform.router import create_app as _create_app
    app = _create_app()
    try:
        ensure_indexes()          # 幂等：建索引 + 空库播种默认 admin（多进程/多入口重复调无副作用）
    except Exception as exc:
        logger.debug("create_app ensure_indexes skip: %s", exc)
    return app

