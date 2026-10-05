"""system/proxy —— 代理中心（实现 PROXY / ProxyService）。

出口代理决策 + 健康检测 + 配置层，对应前端「系统设置 > 代理中心」。
双轨出口（扫描出口 vs 攻击出口）由调用方按策略传 prefer/source；本模块只做「给定偏好→解析出口 URL + 是否强制」。

契约（冻结，见 INTERFACES.md §二 PROXY）——本模块对外经 registry 暴露：
  resolve_egress(prefer, source="") -> (proxy_url: str, force: bool)   无代理返回 ("", force)
  check_health(**kwargs) -> bool                                        经代理探出口 IP，异常视为不健康

前端对接（api/proxy.ts）：get_config/save_config 对齐 ProxyConfig；status 对齐 ProxyStatus；
detect_exit_ip 对齐 ExitIpResult。这些 capability 函数供 router/endpoints/system.py 挂 /api/proxy/* 时调用。

依赖库：requests（已在 vendor/wheels，经 core.http.http_req 统一出站）。**无新增 vendor**。
迁移来源：app/services/proxy_core.py。决策/配置/健康/NOTIFY 告警在本文件；**mihomo 子进程生命周期
(start/stop/restart/自愈) + profiles CRUD + 节点操作 + 流量账本**在同类别私有辅助 `system/_mihomo.py`
（净室重写自 proxy_core，2026-08-02 补齐——此前是 phase-2 占位，整条机场订阅出口轨曾不可用）。
公开代理池(crawl/verify/pick_best)在 `system/_pool.py`。
不放 HTTP 路由；被 registry 以 ROLE.PROXY 注册；失效告警经 ROLE.NOTIFY（缺失降级）。
"""
from __future__ import annotations

import time
import re
from typing import Any, Dict, List, Optional, Tuple

from sentinel_platform.core import get_repo, get_config as _platform_config, get_logger
from sentinel_platform.contracts import Collections, get_registry, ROLE

logger = get_logger()

DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
# 出口 IP 检测端点（返回纯文本 IP），多端点并行故障转移（国内外混排：ipify/ifconfig 海外，ipip 国内）。
EXIT_IP_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://myip.ipip.net/s")
_EXIT_IP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
_ALLOWED_MODES = ("rule", "global", "direct")
# 出口 IP 探测结果进程内缓存（态势总览轮询提速：出口 IP 秒级不变，无需每次实探外网 4~6s）。
# 手动测试传 use_cache=False 强制实探。TTL 内命中直接返回，miss/过期才探。
_EXIT_IP_CACHE = {"ts": 0.0, "data": None}   # type: Dict[str, Any]
_EXIT_IP_CACHE_TTL = 45
# 出口探测网络波动重试：期望值探到空就整轮重连，单次超时自愈，避免连刷时状态跳变（治 bug1）。
_EXIT_IP_RETRY = 3
_EXIT_IP_BACKOFF = 0.4   # 重试间隔（秒）
# save_config 允许更新的字段（对齐前端 ProxyConfig）。
# 2026-08 代理4模式重构：加 global_mode_enabled/global_source/smart_source（平台三模式的全局+智能绑定）。
_ALLOWED_CFG_KEYS = {
    "enabled", "mode", "http_port", "socks_port", "mixed_port", "controller_port",
    "auto_select", "test_url", "active_profile_id",
    "health_check_url", "health_check_interval", "health_fail_threshold", "doh_endpoints",
    "global_mode_enabled", "global_source", "smart_source",
}
_INT_KEYS = ("http_port", "socks_port", "mixed_port", "controller_port",
             "health_check_interval", "health_fail_threshold")

# 健康检测短期缓存 + 失活去抖（连续 N 次失败才告警，吸收瞬时抖动）。
_HEALTH_CACHE: Dict[str, Any] = {"ok": False, "ts": 0.0, "fail_streak": 0, "notified_down": False}
_LOG_FAIL_THRESHOLD = 2

def default_config() -> Dict[str, Any]:
    """代理中心默认配置（对齐前端 ProxyConfig）。secret 供 mihomo controller 鉴权（phase-2 用）。"""
    import secrets
    return {
        "name": "default", "enabled": False, "mode": "rule",
        "http_port": 17890, "socks_port": 17891, "mixed_port": 17892,
        "controller_host": "127.0.0.1", "controller_port": 19090,
        "secret": secrets.token_urlsafe(24), "active_profile_id": "",
        "auto_select": True, "test_url": DEFAULT_TEST_URL,
        "health_check_url": DEFAULT_TEST_URL, "health_check_interval": 60,
        "health_fail_threshold": 3, "doh_endpoints": [],
        # 平台代理模式（2026-08 4模式重构）：全局开关+全局绑定源+智能降级基准源。
        # source={type: custom/subscription/pool, ref_id: custom的_id(其余空)}。默认全局关、源=订阅。
        "global_mode_enabled": False,
        "global_source": {"type": "subscription", "ref_id": ""},
        "smart_source": {"type": "subscription", "ref_id": ""},
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_config() -> Dict[str, Any]:
    """读代理配置（proxy_config.default）；不存在则建默认。读库失败降级返回内存默认（不崩）。"""
    try:
        coll = get_repo().collection(Collections.PROXY_CONFIG)
        cfg = coll.find_one({"name": "default"})
        if not cfg:
            cfg = default_config()
            coll.insert_one(dict(cfg))
        cfg["_id"] = str(cfg.get("_id", ""))
        return cfg
    except Exception as exc:
        logger.debug("proxy get_config degraded: %s", exc)
        return default_config()


def _validate_source_bound(source: Optional[Dict[str, Any]], label: str) -> str:
    """校验一个代理源「结构性是否为空」——只查源有没有内容可用，**绝不探可达性**（守 proxy.py:274 设计边界：
    内网无公网出口，探可达会误判所有源不可用）。返回错误信息串（空串=校验通过）。
      - custom：必须选了具体条目(ref_id)，且该条目存在且启用(能取到 url)——否则=没绑有效自定义代理。
      - pool：公共代理池必须有「启用且可用(delay≥0)」的代理——池空/全失效=选了个空源，此时保存等于配了个永远出不去的出口。
      - subscription：内核代理必须已导入并激活订阅(active_profile_id 非空)——无订阅=没内容可走。
    区别于「配了但此刻连不通」（如节点超时）——那类由 smart 自动降级 / global 保存后探测提示，不在此拦。"""
    if not isinstance(source, dict):
        return ""
    t = source.get("type", "")
    if t == "custom":
        if not source.get("ref_id"):
            return "{}选了「自定义代理」但未选择具体条目，请先选一条自定义代理再保存。".format(label)
        if not custom_proxy_url(source.get("ref_id", "")):
            return "{}绑定的自定义代理不存在或已禁用，请重新选择一条可用的自定义代理。".format(label)
        return ""
    if t == "pool":
        try:
            pool = get_registry().get("proxy_pool_service")
            st = pool.stats() if (pool and hasattr(pool, "stats")) else {}
        except Exception as exc:
            logger.debug("validate pool source degraded: %s", exc)
            st = {}
        # 池内既要有启用的、又要有可用(存活)的，否则选「公共代理」等于配了空出口
        if not (int(st.get("enabled", 0) or 0) > 0 and int(st.get("alive", 0) or 0) > 0):
            return ("{}选了「公共代理」但代理池当前无可用代理（启用 {} / 可用 {}）。"
                    "请先到「公共代理」抓取并验活，或改选其它代理源。").format(
                        label, st.get("enabled", 0), st.get("alive", 0))
        return ""
    if t == "subscription":
        if not (get_config().get("active_profile_id") or ""):
            return "{}选了「内核代理」但尚未导入并激活任何机场订阅，请先在「内核代理」导入订阅并激活。".format(label)
        return ""
    return ""


def _validate_sources(update: Dict[str, Any]) -> str:
    """保存前校验代理源绑定是否有效（只在真正启用对应模式时校验，避免误伤直连占位）。
    返回错误信息串（空串=通过）。全局：仅当 global_mode_enabled=True 时校验 global_source；
    智能：仅当 smart_source 已配置(非订阅空占位)时校验（未配置=直连，不拦）。"""
    if update.get("global_mode_enabled"):
        err = _validate_source_bound(update.get("global_source"), "全局代理")
        if err:
            return err
    smart = update.get("smart_source")
    if _source_configured(smart):   # 智能源真被绑定了才校验；默认订阅空占位=直连，放行
        err = _validate_source_bound(smart, "智能代理")
        if err:
            return err
    return ""


def _reachability_check_on_save(update: Dict[str, Any]) -> str:
    """保存时对「启用了代理」的配置真探一次可达性（需求1）。返回错误串（空=通过/无需探）。

    只探 **强制走代理** 的场景（前端「启用代理」= global_mode_enabled=True）——这类保存后流量必走该出口，
    源结构上配了但节点全挂时应当拦下并提示「代理失效」，而不是显示保存成功。
    smart 模式设计上不可达会自动降级直连，不因探测失败拦保存（保持原有直连兜底语义）。

    探测目标 = 本次保存后**实际生效的出口 URL**（用 update 覆盖当前 config 计算，subscription 走
    mihomo runtime，host/端口按实际生效地址——即用户指出的 host/端口可能不同的场景）。
    """
    if not update.get("global_mode_enabled"):
        return ""
    # 用本次 update 覆盖当前配置，算出保存后生效的 global 出口 URL（未落库前的前瞻判定）。
    merged = dict(get_config())
    merged.update(update)
    src = merged.get("global_source") or {}
    proxy_url = _source_url(src)
    if not proxy_url:
        return ""   # 源结构性校验已在前面拦过；这里取不到 URL 不重复报错
    if not _proxy_reachable(proxy_url):
        return ("代理失效（全部节点不可达），未保存。请检查内核代理订阅节点是否可用、"
                "或更换代理源后重试。")
    return ""


def save_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """更新代理配置（白名单字段，类型规整，mode 校验，代理源结构性校验，启用代理时探可达性）。返回更新后的完整配置。"""
    update: Dict[str, Any] = {}
    for key in _ALLOWED_CFG_KEYS:
        if key in data:
            update[key] = data[key]
    if isinstance(update.get("doh_endpoints"), str):  # 前端可传逗号/换行分隔串
        update["doh_endpoints"] = [x.strip() for x in update["doh_endpoints"].replace(",", "\n").splitlines() if x.strip()]
    for key in _INT_KEYS:
        if key in update:
            try:
                update[key] = int(update[key])
            except (TypeError, ValueError):
                return {"error": "{} 必须为整数".format(key)}
    if "mode" in update and update["mode"] not in _ALLOWED_MODES:
        return {"error": "mode 必须为 rule/global/direct"}
    # 代理源结构性校验（只查源是否为空，不探可达性——守内网无出口不误判的设计边界）。
    # 只在提交里带了源字段时校验（改端口/DoH 等不带源的保存不受影响）。
    if "global_source" in update or "smart_source" in update or "global_mode_enabled" in update:
        src_err = _validate_sources(update)
        if src_err:
            return {"error": src_err}
        # 需求1：结构性校验通过后，对「启用代理（强制走代理）」的保存真探一次可达性，节点全挂则拦下。
        reach_err = _reachability_check_on_save(update)
        if reach_err:
            return {"error": reach_err}
    update["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        get_repo().collection(Collections.PROXY_CONFIG).update_one(
            {"name": "default"}, {"$set": update}, upsert=True)
    except Exception as exc:
        logger.debug("proxy save_config failed: %s", exc)
        return {"error": "保存失败: {}".format(exc)}
    return get_config()


def _mihomo_host() -> str:
    """mihomo HTTP/controller 服务地址：容器模式(MIHOMO_HOST=mihomo)经服务名，本地回退 127.0.0.1。"""
    from . import _mihomo
    return _mihomo._mihomo_host()


def runtime_proxy_url() -> str:
    """代理中心运行时本地代理地址（机场订阅走 mihomo HTTP 端口）；未启用返回 ""。
    容器模式下 host=mihomo 服务名（独立容器），本地模式 127.0.0.1（自 spawn）。"""
    cfg = get_config()
    if not cfg.get("enabled"):
        return ""
    return "http://{}:{}".format(_mihomo_host(), cfg.get("http_port", 17890))


def normalize_egress_pref(prefer: str) -> str:
    """归一出口偏好为三档。兼容旧值 follow→smart / on→proxy / off→direct。默认 smart。
      smart：代理优先，连不通由调用方回退直连（force=False）
      proxy：强制走代理，无代理则熔断不回退（force=True）
      direct：直连不走代理"""
    p = (prefer or "smart").lower()
    if p in ("off", "direct"):
        return "direct"
    if p in ("on", "proxy"):
        return "proxy"
    return "smart"


def egress_proxy_url(source: str = "subscription") -> str:
    """按代理源类型返回出口 URL。subscription→mihomo runtime；pool→公开代理池选优；custom→无 ref_id 时不支持。
    （custom 需 ref_id 查具体条目，用 _source_url({type,ref_id}) 或 custom_proxy_url(id)。）"""
    if source == "pool":
        try:
            pool = get_registry().get("proxy_pool_service")
            if pool and hasattr(pool, "pick_best"):
                return pool.pick_best() or ""
        except Exception as exc:
            logger.debug("proxy pool pick degraded: %s", exc)
        return ""
    return runtime_proxy_url()


def custom_proxy_url(ref_id: str) -> str:
    """按 proxy_custom._id 返回该自定义代理的 URL（enabled 才返回）。缺失/禁用返 ""。"""
    if not ref_id:
        return ""
    try:
        from bson import ObjectId
        doc = get_repo().collection(Collections.PROXY_CUSTOM).find_one({"_id": ObjectId(ref_id)})
        if doc and doc.get("enabled", True):
            return (doc.get("url") or "").strip()
    except Exception as exc:
        logger.debug("custom_proxy_url degraded: %s", exc)
    return ""


def _source_url(source: Optional[Dict[str, Any]]) -> str:
    """代理源 {type, ref_id} → 出口 URL 统一入口。空/未知源返 ""（调用方降级直连）。
    type: custom(查 proxy_custom[ref_id]) / subscription(mihomo runtime) / pool(公开池选优)。"""
    if not isinstance(source, dict):
        return ""
    t = source.get("type", "")
    if t == "custom":
        return custom_proxy_url(source.get("ref_id", ""))
    if t == "pool":
        return egress_proxy_url("pool")
    if t == "subscription":
        return runtime_proxy_url()
    return ""


def _source_label(source: Optional[Dict[str, Any]]) -> str:
    """代理源 {type, ref_id} → 人类可读归属名（态势总览「代理出口 IP 归属」展示）。
    custom→自定义代理名 / subscription→当前机场配置名(active profile) / pool→公共代理池。空/未知→"—"。"""
    if not isinstance(source, dict):
        return "—"
    t = source.get("type", "")
    if t == "custom":
        try:
            from bson import ObjectId
            doc = get_repo().collection(Collections.PROXY_CUSTOM).find_one({"_id": ObjectId(source.get("ref_id", ""))})
            if doc:
                return "自定义代理 · {}".format(doc.get("name") or doc.get("url") or "?")
        except Exception as exc:
            logger.debug("_source_label custom degraded: %s", exc)
        return "自定义代理"
    if t == "pool":
        return "公共代理池"
    if t == "subscription":
        # 机场订阅：取当前激活 profile 名 + 当前选中节点
        try:
            from . import _mihomo
            cfg = get_config()
            pid = cfg.get("active_profile_id", "")
            pname = ""
            if pid:
                prof = _mihomo.get_profile(pid)
                pname = (prof or {}).get("name", "") if prof else ""
            node = _safe_current_node()
            base = "机场订阅" + (" · {}".format(pname) if pname else "")
            return base + (" · {}".format(node) if node else "")
        except Exception as exc:
            logger.debug("_source_label subscription degraded: %s", exc)
        return "机场订阅"
    return "—"


def current_platform_egress() -> Dict[str, Any]:
    """代理中心**当前实际生效**的出口（态势总览代理卡片单一事实源）。
    判定与前端 ProxySetting 顶层模式一致：
      - global_mode_enabled=True → mode=global，源=global_source
      - 否则 smart_source 配了非默认（有 custom ref_id 或非 subscription 空档）→ mode=smart，源=smart_source
      - 否则 → mode=direct
    返回 {mode(direct/global/smart), mode_label(中文), source(dict), source_label(归属名), proxy_url(出口URL,direct为空)}。"""
    cfg = get_config()
    _LABELS = {"direct": "直连", "global": "全局", "smart": "智能"}
    if cfg.get("global_mode_enabled"):
        src = cfg.get("global_source") or {}
        return {"mode": "global", "mode_label": _LABELS["global"],
                "source": src, "source_label": _source_label(src),
                "proxy_url": _source_url(src)}
    # 智能是否"配了"：必须与前端 ProxySetting 的 smartConfigured 判据完全一致——
    # subscription 类型且 ref_id 空 = 默认占位 = 未配置（直连）；绝不能用 _source_url()!=""
    # 判断（subscription 只要 mihomo 内核 enabled 就返回 URL，与 ref_id 无关，会把直连误判成智能——
    # 这正是"代理中心选了直连、总览却显智能"的根因）。
    smart = cfg.get("smart_source") or {}
    if _source_configured(smart):
        return {"mode": "smart", "mode_label": _LABELS["smart"],
                "source": smart, "source_label": _source_label(smart),
                "proxy_url": _source_url(smart)}
    return {"mode": "direct", "mode_label": _LABELS["direct"],
            "source": {}, "source_label": "—", "proxy_url": ""}


def _source_configured(source: Optional[Dict[str, Any]]) -> bool:
    """源是否真的被用户绑定——**与前端 ProxySetting `smartConfigured` 判据逐字一致**（唯一权威）：
      `smart_source.type 存在 && !(type==='subscription' && !ref_id)`
    即：subscription 且 ref_id 空 = 默认占位 = 未配置（直连）；custom/pool 或 subscription 带 ref_id = 已配置。
    绝不看 `_source_url()!=""`（subscription 只要内核 enabled 就返 URL，会把直连误判成智能——本 bug 根因），
    也不看 active_profile_id（前端判据不含它，跟着它走会与前端不一致）。"""
    if not isinstance(source, dict):
        return False
    t = source.get("type", "")
    if not t:
        return False
    if t == "subscription" and not source.get("ref_id"):
        return False   # 订阅默认占位 = 未配置 = 直连（对齐前端 smartConfigured）
    if t == "custom" and not source.get("ref_id"):
        return False   # 自定义必须选一条（对齐 saveMode 校验：custom 无 ref 拦保存）
    return True


def egress_options() -> Dict[str, Any]:
    """出口模式可选性（新建任务页「AI 攻击出口」用：未配置源的模式变灰 + 悬停提示）。
    **只校验"是否配置了源"，不探代理可达性**——内网环境无公网出口，探可达会误判所有模式不可用（用户明确要求）。
    - direct 直连：永远可用（内网/公网都靠它打目标，是否出网由目标决定，非平台该拦）。
    - global 全局：需 global_mode_enabled=True 且 global_source 已配置（否则「全局」等于直连，无意义→变灰）。
    - smart 智能：需 smart_source 已配置（未配置则智能无源可走→变灰；配了则可用，代理不通会自动降级直连）。
    返回 {direct/global/smart: {available: bool, reason: str}}。reason 供前端 tooltip 显示变灰原因。"""
    cfg = get_config()
    opts: Dict[str, Any] = {"direct": {"available": True, "reason": ""}}
    # 全局：开关开 + 源已配置
    g_on = bool(cfg.get("global_mode_enabled"))
    g_cfg = _source_configured(cfg.get("global_source") or {})
    if g_on and g_cfg:
        opts["global"] = {"available": True, "reason": ""}
    elif not g_on:
        opts["global"] = {"available": False, "reason": "代理中心未开启「全局代理」，无法选全局出口。请到代理中心开启并绑定代理源。"}
    else:
        opts["global"] = {"available": False, "reason": "「全局代理」已开启但未绑定有效代理源。请到代理中心为全局代理选择一个源。"}
    # 智能：源已配置即可（不探可达，代理不通时自动降级直连）
    s_cfg = _source_configured(cfg.get("smart_source") or {})
    opts["smart"] = ({"available": True, "reason": ""} if s_cfg
                     else {"available": False, "reason": "「智能代理」未绑定代理源。请到代理中心为智能代理选择一个源（智能=可达走代理、不可达自动直连）。"})
    return opts


# 旧偏好值 → 新4模式（迁移期兼容存量策略/调用方透传的旧值）。
_LEGACY_MODE_MAP = {"proxy": "global", "on": "global", "off": "direct",
                    "direct": "direct", "follow": "smart", "smart": "smart",
                    "global": "global", "rule": "rule"}


def resolve_egress(mode: str, rule_id: str = "", source: str = "") -> Tuple[str, bool]:
    """出口决策统一入口（4模式）。返回 (proxy_url, allow_fallback)。
      direct→("",False) / global→(全局源,False) / rule→(规则源,False) / smart→(智能源,True)。
    源取不到（未配/禁用）一律返回 ("", ...) 让调用方降级直连，不抛异常。

    **旧调用兼容**（迁移期，recon_bridge/_feed 等仍传旧参）：第二/三参 `source`（subscription/pool）
    是旧的"代理源"语义；旧 mode 值 proxy/on→直接走该 source（不依赖全局开关，保持存量"强制走代理"行为），
    off→direct，follow→smart。新代码用 (mode, rule_id) 4模式语义，不传 source。"""
    raw = (mode or "").strip().lower()
    m = _LEGACY_MODE_MAP.get(raw, "smart")
    # —— 旧调用路径：传了 source(subscription/pool) 说明是旧 prefer 语义，直接按 source 出口 ——
    if source:
        if raw in ("off", "direct"):
            return "", False
        force = raw in ("proxy", "on")
        return egress_proxy_url(source), force        # proxy=强制(False fallback)/smart=可回退
    if m == "direct":
        return "", False
    cfg = get_config()
    if m == "global":
        if not cfg.get("global_mode_enabled"):
            return "", False                          # 全局未开→直连
        return _source_url(cfg.get("global_source")), False
    if m == "rule":
        if not rule_id:
            return "", False
        try:
            from bson import ObjectId
            r = get_repo().collection(Collections.PROXY_RULE).find_one({"_id": ObjectId(rule_id)})
            if r and r.get("enabled", True):
                return _source_url(r.get("source")), False
        except Exception as exc:
            logger.debug("resolve_egress rule degraded: %s", exc)
        return "", False
    # smart：智能源优先，可回退（allow_fallback=True）；调用方探不通时按叠加降级回退全局/直连
    return _source_url(cfg.get("smart_source")), True


def resolve_egress_url(mode: str, rule_id: str = "") -> str:
    """便捷：直接返回最终出口 URL（含 smart 叠加降级）。空串=真直连。
    供扫描/渗透调用方"给我一个能用的出口"——smart 不可达时按 §叠加降级回退全局，全局也无则空(直连)。"""
    url, allow_fb = resolve_egress(mode, rule_id)
    if url:
        # smart 模式探一下可达性；不可达且允许回退→尝试全局→仍无则直连
        if allow_fb and not _proxy_reachable(url):
            cfg = get_config()
            gurl = _source_url(cfg.get("global_source")) if cfg.get("global_mode_enabled") else ""
            return gurl if (gurl and _proxy_reachable(gurl)) else ""
        return url
    return ""


def _proxy_reachable(proxy_url: str, timeout: int = 5) -> bool:
    """探代理是否可达（经它请求一个轻量端点）。用于 smart 降级判定 + 源健康探测。"""
    if not proxy_url:
        return False
    try:
        import requests
        sess = requests.Session(); sess.trust_env = False
        r = sess.get("http://www.gstatic.com/generate_204",
                     proxies={"http": proxy_url, "https": proxy_url},
                     timeout=timeout, allow_redirects=False)
        sess.close()
        return r.status_code in (204, 200)
    except Exception:
        return False


# ============================ 自定义代理 CRUD（proxy_custom） ============================
def list_custom() -> List[Dict[str, Any]]:
    """列出所有自定义代理（_id 转 str）。"""
    try:
        out = []
        for d in get_repo().collection(Collections.PROXY_CUSTOM).find({}):
            d["_id"] = str(d.get("_id", "")); out.append(d)
        return out
    except Exception as exc:
        logger.debug("list_custom degraded: %s", exc); return []


def save_custom(data: Dict[str, Any]) -> Dict[str, Any]:
    """新增/更新自定义代理。data: {_id?, name, url, enabled?}。url 必填且格式校验。返回 {ok, _id/error}。"""
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    if not name or not url:
        return {"ok": False, "error": "name / url 必填"}
    if not re.match(r"^(https?|socks5)://", url, re.I):
        return {"ok": False, "error": "url 须以 http:// / https:// / socks5:// 开头"}
    doc = {"name": name, "url": url, "enabled": bool(data.get("enabled", True)),
           "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        coll = get_repo().collection(Collections.PROXY_CUSTOM)
        from bson import ObjectId
        if data.get("_id"):
            coll.update_one({"_id": ObjectId(data["_id"])}, {"$set": doc})
            return {"ok": True, "_id": data["_id"]}
        doc["created_at"] = doc["updated_at"]; doc["last_health_ok"] = None; doc["last_check"] = ""
        r = coll.insert_one(doc)
        return {"ok": True, "_id": str(r.inserted_id)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_custom(cid: str) -> Dict[str, Any]:
    if not cid:
        return {"ok": False, "error": "id 必填"}
    try:
        from bson import ObjectId
        get_repo().collection(Collections.PROXY_CUSTOM).delete_one({"_id": ObjectId(cid)})
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def test_custom(cid: str) -> Dict[str, Any]:
    """探测自定义代理可达性，回写 last_health_ok/last_check。返回 {ok, reachable}。"""
    url = custom_proxy_url(cid)
    if not url:
        return {"ok": False, "error": "代理不存在或已禁用"}
    ok = _proxy_reachable(url)
    try:
        from bson import ObjectId
        get_repo().collection(Collections.PROXY_CUSTOM).update_one(
            {"_id": ObjectId(cid)}, {"$set": {"last_health_ok": ok, "last_check": time.strftime("%Y-%m-%d %H:%M:%S")}})
    except Exception:
        pass
    return {"ok": True, "reachable": ok}


# ============================ 规则代理 CRUD（proxy_rule） ============================
def list_rule() -> List[Dict[str, Any]]:
    try:
        out = []
        for d in get_repo().collection(Collections.PROXY_RULE).find({}):
            d["_id"] = str(d.get("_id", "")); out.append(d)
        return out
    except Exception as exc:
        logger.debug("list_rule degraded: %s", exc); return []


def save_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    """新增/更新规则代理。data: {_id?, name, source:{type,ref_id}, enabled?}。返回 {ok, _id/error}。"""
    name = (data.get("name") or "").strip()
    source = data.get("source") or {}
    if not name or not isinstance(source, dict) or source.get("type") not in ("custom", "subscription", "pool"):
        return {"ok": False, "error": "name 必填，source.type 须为 custom/subscription/pool"}
    doc = {"name": name, "source": {"type": source["type"], "ref_id": source.get("ref_id", "")},
           "enabled": bool(data.get("enabled", True)), "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        coll = get_repo().collection(Collections.PROXY_RULE)
        from bson import ObjectId
        if data.get("_id"):
            coll.update_one({"_id": ObjectId(data["_id"])}, {"$set": doc})
            return {"ok": True, "_id": data["_id"]}
        doc["created_at"] = doc["updated_at"]; doc["last_health_ok"] = None
        r = coll.insert_one(doc)
        return {"ok": True, "_id": str(r.inserted_id)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_rule(rid: str) -> Dict[str, Any]:
    if not rid:
        return {"ok": False, "error": "id 必填"}
    try:
        from bson import ObjectId
        get_repo().collection(Collections.PROXY_RULE).delete_one({"_id": ObjectId(rid)})
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def test_rule(rid: str) -> Dict[str, Any]:
    """探测规则代理绑定源的可达性。返回 {ok, reachable}。"""
    try:
        from bson import ObjectId
        r = get_repo().collection(Collections.PROXY_RULE).find_one({"_id": ObjectId(rid)})
        if not r:
            return {"ok": False, "error": "规则不存在"}
        url = _source_url(r.get("source"))
        ok = _proxy_reachable(url) if url else False
        get_repo().collection(Collections.PROXY_RULE).update_one(
            {"_id": ObjectId(rid)}, {"$set": {"last_health_ok": ok}})
        return {"ok": True, "reachable": ok}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _fetch_exit_ip(proxies: Optional[Dict[str, str]] = None, timeout: int = 4,
                   deadline: float = 0.0) -> Tuple[str, str]:
    """并行探测多个出口 IP 端点，返回首个成功的 (ip, "")。全失败返 ("", last_err)。proxies=None 直连。
    **并行 fan-out（2026-08-08 修）**：原先串行按 EXIT_IP_URLS 顺序探——首端点若被墙（如国内直连
    探 api.ipify.org 超时 4s）会吃满整个 wall-clock 预算，后面可达端点（ifconfig.me ~0.9s）根本没
    机会跑→直连出口被误报为空（表现为「本机直连出口为空」）。改为所有端点并发打，谁先返回合法 IP
    谁赢，彻底消除队头阻塞，不再依赖端点顺序或某端点是否可达。单请求 timeout 仍约束每路，deadline
    作整体墙钟兜底（无外网时不拖挂 gunicorn worker→502）。
    **直连探测必须真直连（2026-08-08 修）**：proxies=None 时用 trust_env=False 的 Session，杜绝
    requests 回落读取平台为扫描出口注入的 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY 环境变量——否则「直连」探测
    被环境代理劫持走了 mihomo，去探国内 myip.ipip.net 反而不通，直连出口 IP 恒空且报 proxy 错。"""
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _one(url: str) -> str:
        sess = requests.Session()
        if proxies is None:
            sess.trust_env = False          # 直连：忽略环境 *_proxy，真直连不被扫描出口注入劫持
            use_proxies = None
        else:
            use_proxies = proxies           # 显式代理：按传入走
        try:
            resp = sess.get(url, proxies=use_proxies, timeout=timeout,
                            allow_redirects=False, verify=False,
                            headers={"User-Agent": _EXIT_IP_UA})
            if resp.status_code >= 400:
                raise ValueError("status {} from {}".format(resp.status_code, url))
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", (resp.text or "").strip())
            if not m:
                raise ValueError("no ip from {}".format(url))
            return m.group(1)
        finally:
            try:
                sess.close()
            except Exception:
                pass

    urls = list(EXIT_IP_URLS)
    if not urls:
        return "", "no exit-ip endpoints configured"
    last_err = ""
    budget = max(0.1, deadline - time.time()) if deadline else None
    ex = ThreadPoolExecutor(max_workers=len(urls))
    try:
        futs = [ex.submit(_one, u) for u in urls]
        try:
            for fut in as_completed(futs, timeout=budget):
                try:
                    ip = fut.result()
                    if ip:
                        return ip, ""
                except Exception as exc:
                    last_err = str(exc)
        except Exception:                        # as_completed 整体超时（命中 deadline）
            last_err = last_err or "exit-ip probe timeout (可能无外网出口)"
    finally:
        ex.shutdown(wait=False)                  # 不等悬挂的被墙端点线程回收，立即返回
    return "", last_err


def detect_exit_ip(use_cache: bool = True, cache_ttl: int = _EXIT_IP_CACHE_TTL) -> Dict[str, Any]:
    """对比检测：代理出口 IP vs 直连出口 IP（前端确认「流量是否真走了代理」）。对齐 ExitIpResult。
    **并行 + 有界**（2026-08-08 优化）：direct 段与 proxy 段逻辑独立（仅末尾对比判 proxied），
    并发探测互不等待；单次请求 3s、每段 deadline 5s。无外网时总时长 ~5s（而非串行 16s），
    远低于 gunicorn worker 超时，快速优雅返回。
    **缓存**（2026-08-20 提速态势总览）：默认命中 TTL 内缓存直接返回（出口 IP 秒级不变，
    没必要每次实探外网 4~6s）；代理页手动「测出口」传 use_cache=False 强制实探。
    只缓存成功结果（探到 direct_ip 或 proxy_ip），失败不缓存以便下次重试。"""
    import time as _t
    if use_cache and _EXIT_IP_CACHE["data"] is not None and (_t.time() - _EXIT_IP_CACHE["ts"]) < cache_ttl:
        cached = dict(_EXIT_IP_CACHE["data"]); cached["cached"] = True
        # 模式/归属从 config 实时覆盖（零探测开销）——用户在代理中心切模式后总览立即反映，
        # 不必等 45s IP 缓存过期（治"改了模式总览还显旧模式"）。IP 仍用缓存值避免每次实探。
        egr = current_platform_egress()
        cached["platform_mode"] = egr["mode"]; cached["mode_label"] = egr["mode_label"]
        cached["source_label"] = egr["source_label"]
        return cached
    cfg = get_config()
    # 代理中心当前生效出口（模式 + 源 + 归属）——探"实际在用的代理"，不再写死 mihomo 订阅。
    egr = current_platform_egress()
    result = {"proxy_ip": "", "direct_ip": "", "proxied": False, "error": "",
              "platform_mode": egr["mode"], "mode_label": egr["mode_label"],
              "source_label": egr["source_label"]}
    # enabled = 当前模式确实要走代理（direct 模式不探代理出口，只探直连真实出口）。
    proxy = egr["proxy_url"]
    enabled = bool(proxy)
    # 用线程 + future.result(timeout) 做**墙钟硬超时**——真正卡点是 DNS 解析(getaddrinfo)在无外网时
    # 阻塞到 libc 默认 ~16s，requests 的 socket timeout 管不住 DNS 阶段。故不靠 timeout 参数，靠 future
    # 墙钟切断；且 **shutdown(wait=False)** 不等悬挂线程回收（否则 with 退出会 join 满 16s，等于没提速）。
    from concurrent.futures import ThreadPoolExecutor

    def _probe_once() -> Tuple[str, str, str]:
        """一轮并发探测，返回 (direct_ip, proxy_ip, proxy_err)。"""
        ex = ThreadPoolExecutor(max_workers=2)
        d_ip = p_ip = ""; p_err = ""
        try:
            f_direct = ex.submit(_fetch_exit_ip, None, 4, 0)
            f_proxy = ex.submit(_fetch_exit_ip, {"http": proxy, "https": proxy}, 4, 0) if enabled else None
            try:
                d_ip, _ = f_direct.result(timeout=6)
            except Exception:
                d_ip = ""
            if f_proxy is not None:
                try:
                    p_ip, err = f_proxy.result(timeout=6)
                except Exception:
                    p_ip, err = "", "探测超时（可能无外网出口/DNS 解析不通）"
                p_err = _friendly_proxy_error(err) or ("" if p_ip else "经代理探出口 IP 失败（可能无外网出口/节点不通）")
        finally:
            ex.shutdown(wait=False)   # 不阻塞等待悬挂的 DNS 线程回收，立即返回
        return d_ip, p_ip, p_err

    # —— 网络波动重试（治 bug1 连续刷新闪烁）——
    # 出口探测偶发单次超时(时空时有)、多端点谁快谁赢致 IP 抖动，是连刷时状态跳变的根因。
    # 朴素修法：期望值探到空(direct 空、或代理启用时 proxy 空)就整轮重连，最多 _EXIT_IP_RETRY 次、
    # 短退避。单次波动自愈，不留缓存/粘滞状态（多 worker 下进程内状态本就不共享，缓存无意义）。
    d_ip = p_ip = p_err = ""
    for attempt in range(_EXIT_IP_RETRY):
        d_ip, p_ip, p_err = _probe_once()
        need_retry = (not d_ip) or (enabled and not p_ip)
        if not need_retry:
            break
        if attempt < _EXIT_IP_RETRY - 1:
            time.sleep(_EXIT_IP_BACKOFF)
    result["direct_ip"] = d_ip
    if enabled:
        result["proxy_ip"] = p_ip
        result["error"] = p_err
    else:
        result["error"] = "proxy not enabled"
    # proxied 判定必须**两个出口都探到**才做比较：direct 探空时无从判断代理是否改变了出口，
    # 绝不能凭 proxy_ip != "" 就武断说"代理生效"（这正是 bug1 三态跳的直接原因——direct 偶发探空时
    # proxy_ip != "" 恒真，误判生效）。两 IP 都有且不同=真生效；相同=代理没改变出口(未生效)；
    # 任一为空=无法判定(proxied=False，前端按"直连出口/—"展示，不误报生效)。
    dip, pip = result["direct_ip"], result["proxy_ip"]
    result["proxied"] = bool(dip and pip and pip != dip)
    # 只缓存成功结果（探到 direct 或 proxy），TTL 内直接返回免每次实探外网 4~6s；失败不缓存以便下次重探。
    if result["direct_ip"] or result["proxy_ip"]:
        _EXIT_IP_CACHE["data"] = dict(result)
        _EXIT_IP_CACHE["ts"] = time.time()
    result["cached"] = False
    return result


_PROXY_FAIL_SIGNS = (
    "proxyerror", "cannot connect to proxy", "max retries exceeded",
    "handshake operation timed out", "connection refused", "connection aborted",
    "connectionpool", "failed to establish a new connection", "tunnel connection failed",
)


def _friendly_proxy_error(raw: str) -> str:
    """归一代理探测异常文案（需求2）：底层 requests/urllib3 抛出的
    `HTTPSConnectionPool(...ProxyError('Cannot connect to proxy'...))` 等原文对用户无意义，
    命中「连不上代理/全部节点不可达」特征时统一显示「代理失效（全部节点不可达）」；
    非代理连通类错误（如 proxy not enabled、无外网出口提示）保持原样透出，不误伤。"""
    s = (raw or "").strip()
    if not s:
        return s
    low = s.lower()
    if any(sign in low for sign in _PROXY_FAIL_SIGNS):
        return "代理失效（全部节点不可达）"
    return s


def _proxy_alert_enabled() -> bool:
    """代理告警推送开关（需求3，默认开启）：复用 api_keys 飞书渠道下 proxy_down_notify 字段。
    **只有显式 False 才算关闭**——存量安装未存过该字段时 get_key 返回 ""（或飞书未启用时字段被清空），
    不能被误判为关闭，故用 `is not False` 而非 bool()（bool("")=False 会把默认开误关，坑）。
    取不到配置一律按开启处理（默认 True）。"""
    try:
        keys = get_registry().get("api_keys_service")
        if keys and hasattr(keys, "get_key"):
            cfg = keys.get_key("feishu") or {}
            return cfg.get("proxy_down_notify", True) is not False
    except Exception as exc:
        logger.debug("proxy alert switch degraded: %s", exc)
    return True


def _notify_down(fail_streak: int, err: str) -> None:
    """代理连续失活告警，经 ROLE.NOTIFY（缺失降级不崩）。默认开启，可在「API 密钥 > 告警推送」关闭。"""
    if not _proxy_alert_enabled():
        return
    svc = get_registry().get(ROLE.NOTIFY)
    if not svc:
        return
    try:
        svc.notify("代理健康检测连续失败 {} 次: {}".format(fail_streak, _friendly_proxy_error(err) or "unknown"),
                   title="代理告警", level="error")
    except Exception as exc:
        logger.debug("proxy notify failed: %s", exc)


def check_health(use_cache: bool = True, cache_ttl: int = 15, **kwargs: Any) -> bool:
    """检测代理是否真正可用：经代理请求出口 IP 成功即健康。结果写回 proxy_config（last_health_*）。
    连续失活经 NOTIFY 告警（去抖：≥阈值才告警，恢复重置）。异常视为不健康返回 False（守 §0.4）。"""
    now = time.time()
    if use_cache and (now - _HEALTH_CACHE["ts"] < cache_ttl):
        return _HEALTH_CACHE["ok"]
    cfg = get_config()
    ok, err, exit_ip = False, "", ""
    if not cfg.get("enabled"):
        err = "proxy not enabled"
    else:
        proxy = "http://{}:{}".format(_mihomo_host(), cfg.get("http_port", 17890))
        # 墙钟硬超时（同 detect_exit_ip）：DNS 解析阻塞 requests timeout 管不住，用 future 6s 切断，
        # shutdown(wait=False) 不等悬挂线程，无外网时快速判不健康而非拖挂 worker→502
        from concurrent.futures import ThreadPoolExecutor
        _ex = ThreadPoolExecutor(max_workers=1)
        try:
            _f = _ex.submit(_fetch_exit_ip, {"http": proxy, "https": proxy}, 4, 0)
            try:
                exit_ip, err = _f.result(timeout=6)
            except Exception:
                exit_ip, err = "", "探测超时（可能无外网出口/DNS 不通）"
        finally:
            _ex.shutdown(wait=False)
        ok = bool(exit_ip)
        err = _friendly_proxy_error(err)   # 需求2：代理连不通类原文归一为「代理失效」
    _HEALTH_CACHE["ok"] = ok
    _HEALTH_CACHE["ts"] = now
    try:
        upd = {"last_health_ok": ok, "last_health_error": err,
               "last_health_check_time": time.strftime("%Y-%m-%d %H:%M:%S")}
        if ok and exit_ip:
            upd["last_exit_ip"] = exit_ip
        get_repo().collection(Collections.PROXY_CONFIG).update_one(
            {"name": "default"}, {"$set": upd}, upsert=True)
    except Exception:
        pass
    # 失活去抖 + 告警（仅代理启用时）
    if cfg.get("enabled"):
        if ok:
            _HEALTH_CACHE["fail_streak"] = 0
            _HEALTH_CACHE["notified_down"] = False
        else:
            _HEALTH_CACHE["fail_streak"] += 1
            if _HEALTH_CACHE["fail_streak"] >= _LOG_FAIL_THRESHOLD and not _HEALTH_CACHE["notified_down"]:
                _notify_down(_HEALTH_CACHE["fail_streak"], err)
                _HEALTH_CACHE["notified_down"] = True
    return ok


def status() -> Dict[str, Any]:
    """代理中心状态（对齐前端 ProxyStatus）。running/pid 取自 mihomo 真实进程态（_mihomo）。"""
    from . import _mihomo
    cfg = get_config()
    running = False
    pid = None
    try:
        running, pid = _mihomo.is_running(), _mihomo.get_pid()
    except Exception as exc:
        logger.debug("proxy status mihomo probe degraded: %s", exc)
    return {
        "config": cfg, "running": running, "pid": pid,
        "proxy_url": runtime_proxy_url(),
        "current_node": _safe_current_node() if running else "",
        "last_health_ok": cfg.get("last_health_ok"),
        "last_health_error": cfg.get("last_health_error"),
        "last_health_check_time": cfg.get("last_health_check_time"),
        "last_exit_ip": cfg.get("last_exit_ip"),
    }


def _safe_current_node() -> str:
    try:
        from . import _mihomo
        return _mihomo.current_node()
    except Exception:
        return ""


class ProxyServiceImpl:
    """PROXY 实现。满足 contracts.ProxyService（结构化子类型，无需继承）。"""

    def resolve_egress(self, mode: str, rule_id: str = "", source: str = "") -> Tuple[str, bool]:
        """出口决策（2026-08 4模式重构）。返回 (proxy_url, allow_fallback)。
          direct → ("", False) / global → (全局源URL, False) / rule → (规则源URL, False) / smart → (智能源URL, True)
        兼容旧调用（传 source=subscription/pool + 旧 mode proxy/smart/off）——见模块函数 resolve_egress 文档。"""
        return resolve_egress(mode, rule_id, source)

    def resolve_egress_url(self, mode: str, rule_id: str = "") -> str:
        """便捷：返回最终出口 URL（含 smart 叠加降级），空串=真直连。扫描/渗透"给我能用的出口"用。"""
        return resolve_egress_url(mode, rule_id)

    def check_health(self, **kwargs: Any) -> bool:
        return check_health(**kwargs)

    # —— 供 router endpoints/proxy.py 挂 /api/proxy/* 调（前端代理中心页）——
    def status(self) -> Dict[str, Any]:
        return status()

    def get_config(self) -> Dict[str, Any]:
        return get_config()

    def save_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return save_config(data)

    def detect_exit_ip(self, use_cache: bool = True) -> Dict[str, Any]:
        return detect_exit_ip(use_cache=use_cache)

    def egress_options(self) -> Dict[str, Any]:
        return egress_options()

    # —— mihomo 内核生命周期 + profile/节点/流量/日志（委托 _mihomo，endpoints 经此调）——
    def core_action(self, action: str) -> Dict[str, Any]:
        """启停 mihomo 内核。action: start/stop/restart。start/restart 后自动选活节点。"""
        from . import _mihomo
        act = (action or "").lower()
        try:
            if act == "stop":
                return _mihomo.stop_core()
            if act == "restart":
                r = _mihomo.restart_core()
            elif act == "start":
                r = _mihomo.start_core()
            else:
                return {"error": "action 必须为 start/stop/restart"}
            # 启动后确保落到活节点（global 模式默认 DIRECT 会泄露真实 IP）
            try:
                _mihomo.ensure_proxy_selected()
            except Exception as exc:
                logger.debug("ensure_proxy_selected after %s degraded: %s", act, exc)
            return r
        except FileNotFoundError as e:
            return {"error": str(e)}
        except Exception as e:
            logger.warning("proxy core_action %s error: %s", act, e)
            return {"error": str(e)}

    def list_profiles(self) -> Dict[str, Any]:
        from . import _mihomo
        return {"items": _mihomo.list_profiles()}

    def import_profile(self, name: str = "", content: str = "", url: str = "") -> Dict[str, Any]:
        """导入机场订阅档：url（订阅链接，SSRF 校验）或 content（上传 YAML）二选一。"""
        from . import _mihomo
        try:
            if url:
                return _mihomo.import_profile_url(url, name)
            if content:
                return _mihomo.import_profile_content(name, content, source="upload")
            return {"error": "url 或 content 必填其一"}
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            logger.warning("proxy import_profile error: %s", e)
            return {"error": "导入失败: {}".format(e)}

    def delete_profile(self, profile_id: str) -> Dict[str, Any]:
        from . import _mihomo
        return _mihomo.delete_profile(profile_id)

    def activate_profile(self, profile_id: str) -> Dict[str, Any]:
        """激活订阅档：存 active_profile_id → 内核在跑则重启重载新配置 + 选活节点。返回最新配置。"""
        from . import _mihomo
        if not profile_id:
            return {"error": "profile_id 必填"}
        save_config({"active_profile_id": profile_id})
        if _mihomo.is_running():
            try:
                _mihomo.restart_core()
                _mihomo.ensure_proxy_selected()
            except Exception as e:
                logger.warning("activate_profile restart degraded: %s", e)
                return dict(get_config(), restart_error=str(e))
        return get_config()

    def list_proxies(self) -> Dict[str, Any]:
        """mihomo 节点列表（controller /proxies）。未运行返空不崩。"""
        from . import _mihomo
        if not _mihomo.is_running():
            return {"proxies": {}, "running": False}
        try:
            return _mihomo.get_proxies()
        except Exception as e:
            return {"proxies": {}, "error": str(e)}

    def select_node(self, group: str, name: str) -> Dict[str, Any]:
        from . import _mihomo
        try:
            return _mihomo.select_proxy(group, name)
        except Exception as e:
            return {"error": str(e)}

    def auto_select(self, group: str = "GLOBAL") -> Dict[str, Any]:
        from . import _mihomo
        try:
            return _mihomo.auto_select(group)
        except Exception as e:
            return {"error": str(e)}

    def traffic(self) -> Dict[str, Any]:
        from . import _mihomo
        live = _mihomo.traffic()
        stats = _mihomo.traffic_stats()
        return dict(stats, **{"running": live.get("running", False),
                              "connections": live.get("connections", 0),
                              "upload_total": live.get("upload_total", 0),
                              "download_total": live.get("download_total", 0)})

    def reset_traffic(self, scope: str = "", key: str = "") -> Dict[str, Any]:
        from . import _mihomo
        return _mihomo.reset_traffic_stats(scope, key)

    def read_logs(self, lines: int = 200) -> str:
        from . import _mihomo
        return _mihomo.read_logs(lines)

    def maintain(self) -> Dict[str, Any]:
        """周期维护（scheduler 调）：内核自愈(崩了/发布重启后自动拉起) + 节点验活failover + 流量采样。
        仅代理启用时动作；全程不抛异常（不反噬 scheduler）。"""
        from . import _mihomo
        out: Dict[str, Any] = {}
        try:
            out["core"] = _mihomo.ensure_core_running()
            if _mihomo.is_running():
                out["node"] = _mihomo.ensure_proxy_selected()
                _mihomo.sample_traffic()
        except Exception as exc:
            logger.debug("proxy maintain degraded: %s", exc)
        return out

    # —— 4模式重构：自定义代理 / 规则代理 CRUD + 探测（router endpoints 经 ROLE.PROXY 调）——
    def custom_proxy_url(self, ref_id: str) -> str:
        """按 proxy_custom._id 取该自定义代理 URL（enabled 才返回，缺失/禁用返 ""）。
        供 AI 配置的「入口代理」（provider.proxy_id）经 registry 取代理 URL 用（问题18）。"""
        return custom_proxy_url(ref_id)

    def list_custom(self) -> List[Dict[str, Any]]:
        return list_custom()

    def save_custom(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return save_custom(data)

    def delete_custom(self, cid: str) -> Dict[str, Any]:
        return delete_custom(cid)

    def test_custom(self, cid: str) -> Dict[str, Any]:
        return test_custom(cid)

    def list_rule(self) -> List[Dict[str, Any]]:
        return list_rule()

    def save_rule(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return save_rule(data)

    def delete_rule(self, rid: str) -> Dict[str, Any]:
        return delete_rule(rid)

    def test_rule(self, rid: str) -> Dict[str, Any]:
        return test_rule(rid)


_service = ProxyServiceImpl()


def get_service() -> ProxyServiceImpl:
    return _service

