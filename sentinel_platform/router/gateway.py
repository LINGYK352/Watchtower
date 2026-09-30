"""鉴权 + RBAC 网关 —— 全项目 HTTP 入口的统一前置校验（before_request）。

三段（各自对未建依赖优雅降级，故现在能跑、模块齐了自动增强）：
  ①鉴权：AUTH 关→放行；开→校验 Token 头（master key / 用户会话 token）。公开路径豁免。
  ②RBAC：取 ROLE 权限服务判 path+method；服务未注册→降级放行（已认证前提下），不阻断。
  ③access_log：有审计服务则记一条；无则跳过。

失败返回统一信封（envelope），HTTP 与业务 code 一致（前端两者都认）。
纯判定逻辑（is_public / verify_token / need_permission）抽成函数，可脱离 flask 单测。
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from sentinel_platform.core import get_config, get_logger
from sentinel_platform.contracts import get_registry, ROLE
from .envelope import CODE_UNAUTHORIZED, CODE_FORBIDDEN, CODE_ACTIVATION_REQUIRED, envelope

logger = get_logger()

# 公开路径前缀（无需鉴权）：登录/登出/API 文档/健康检查/静态。
PUBLIC_PREFIXES = (
    "/api/user/login", "/api/user/logout",
    "/api/doc", "/swagger",
    "/api/meta/health", "/api/meta/version",
    "/api/image/",   # 截图 <img> 直连无 Token 头，必须公开（否则 auth 开启时截图全 401）
    "/api/appbridge/",  # 光纤桥接：光纤非浏览器用户、不带用户 Token，改由端点内 platform_key 鉴权（见 appbridge.py/§6.9）
)

# 仅特定方法公开的路径（method, prefix）：免责声明签署状态 GET 必须公开——
# 首登强制弹窗要在登录前后任何鉴权状态下读到签署状态；POST(记录同意)仍需登录 token。
PUBLIC_METHOD_PREFIXES = (
    ("GET", "/api/meta/disclaimer"),
)


def is_public(path: str, method: str = "") -> bool:
    """该路径是否豁免鉴权。method 传入时额外匹配"仅某方法公开"的路径。"""
    if any(path.startswith(p) for p in PUBLIC_PREFIXES):
        return True
    m = (method or "").upper()
    return any(m == pm and path.startswith(pp) for pm, pp in PUBLIC_METHOD_PREFIXES)


# —— 激活门控：核心业务端点（未激活/过期时硬拦，返回 CODE_ACTIVATION_REQUIRED）——
# 只锁"值钱能力"：AI 渗透 / 扫描任务 / 情报 / 扩展 / 小程序 / 探针 / PoC / GitHub 采集。
# 只读展示类（仪表盘/设置/日志/代理/关于/资产查看）不锁——未激活也能进来看、能到激活页激活。
ACTIVATION_GATED_PREFIXES = (
    "/api/pentest",        # AI 渗透会话 + 扩展商店（/pentest/extensions）
    "/api/task",           # 扫描任务（含 /task_fofa /task_schedule，startswith 覆盖）
    "/api/intel",          # 资产情报归集/派发
    "/api/miniapp",        # 小程序渗透
    "/api/app_pentest",    # APP 渗透（设备管理/光纤生成；appbridge 光纤连接层不门控，见 appbridge.py）
    "/api/probe",          # 探针/Agent
    "/api/poc",            # PoC 插件
    "/api/github_task",    # GitHub 情报采集任务
    "/api/scheduler",      # 调度触发
)


def activation_enforced() -> bool:
    """是否强制激活门控（默认开）。配置 ACTIVATION.ENFORCE=false 可关（特殊部署/调试）。
    段名候选 SENTINEL.ACTIVATION_ENFORCE → ACTIVATION.ENFORCE，默认 True（未配即强制）。"""
    cfg = get_config()
    val = cfg.section("SENTINEL", "ACTIVATION_ENFORCE", default=None)
    if val is None:
        val = cfg.section("ACTIVATION", "ENFORCE", default=None)
    return True if val is None else bool(val)


def is_activation_gated(path: str) -> bool:
    """该路径是否属于"需激活才能用"的核心业务端点。"""
    return any(path.startswith(p) for p in ACTIVATION_GATED_PREFIXES)


def activation_ok() -> bool:
    """系统当前是否处于"已激活且未过期"状态（本地离线校验 JWT 时效，唯一权威 activation.local_status）。

    走 registry 弱依赖：activation 模块缺失/异常时**降级放行**（fail-open，守孤岛可跑，
    与 auth/rbac 的降级哲学一致——门控是增强项，不能因依赖未就绪反而锁死系统）。
    无宽限期：activated 为真才放行，过期即拦（remaining_days 归零那一刻起 local_status.activated=False）。
    """
    try:
        from sentinel_platform.modules.system import activation
        return bool(activation.local_status().get("activated"))
    except Exception as e:      # 模块缺失/读盘异常：降级放行，不阻断（同 rbac_error_failopen）
        logger.warning("activation gate check error (fail-open): %s", e)
        return True


def auth_enabled() -> bool:
    """配置是否开启鉴权（关则全放行，与旧 @auth 行为一致）。

    段名候选顺序 SENTINEL → 顶层 → ARL（与 config.yaml.example「SENTINEL 优先，
    兼容旧 ARL 段」及 user_manage.py 一致）。修复前只读 AUTH/ARL.AUTH，漏了实际生效的
    SENTINEL.AUTH → 鉴权被静默关闭（platform 裸奔 + 会话 token 不设 g.current_user →
    自助改密 401）。
    """
    cfg = get_config()
    val = cfg.section("SENTINEL", "AUTH", default=None)
    if val is None:
        val = cfg.section("AUTH", default=None)
    if val is None:
        val = cfg.section("ARL", "AUTH", default=False)
    return bool(val)


def verify_token(token: str) -> Optional[dict]:
    """校验 Token，返回用户上下文 dict（含 role）或 None。

    优先 master key（config API_KEY）→ admin 上下文；否则交用户服务查会话 token（未建则 None）。
    """
    if not token:
        return None
    # master key 段名候选同 auth_enabled：SENTINEL 优先，兼容顶层/ARL（迁移期）。
    cfg = get_config()
    master = cfg.section("SENTINEL", "API_KEY", default="") or \
        cfg.section("API_KEY", default="") or \
        cfg.section("ARL", "API_KEY", default="")
    if master and token == master:
        return {"username": "master", "role": "admin", "via": "master_key"}
    # 用户会话 token 校验交用户服务（system/user_manage 实现 ROLE.USER；未注册则降级 None）
    user_svc = get_registry().get(ROLE.USER)
    if user_svc and hasattr(user_svc, "verify_token"):
        try:
            return user_svc.verify_token(token)
        except Exception:
            return None
    return None


def check_rbac(user: dict, path: str, method: str) -> Tuple[bool, str]:
    """RBAC 校验。权限服务未注册 → 读操作降级放行，敏感写操作拒绝。返回 (allow, reason)。"""
    if (user or {}).get("role") == "admin":
        return True, "admin"
    rbac_svc = get_registry().get(ROLE.RBAC)
    if not (rbac_svc and hasattr(rbac_svc, "check_permission")):
        if _is_rbac_fail_closed(path, method):
            return False, "rbac_not_ready_failclosed"
        return True, "rbac_not_ready"
    try:
        allow, reason = rbac_svc.check_permission(user, path, method)
        return bool(allow), str(reason)
    except Exception as e:
        logger.warning("rbac check error: %s", e)
        if _is_rbac_fail_closed(path, method):
            return False, "rbac_error_failclosed"
        return True, "rbac_error_failopen"


_RBAC_FAIL_CLOSED_PREFIXES = ("/api/probe", "/api/system")
_RBAC_FAIL_CLOSED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _is_rbac_fail_closed(path: str, method: str) -> bool:
    if method.upper() not in _RBAC_FAIL_CLOSED_METHODS:
        return False
    return any(path.startswith(p) for p in _RBAC_FAIL_CLOSED_PREFIXES)


def install_gateway(app: Any) -> None:
    """把网关装进 Flask app 的 before_request / after_request。"""
    from flask import request, g, jsonify

    import time as _time

    @app.before_request
    def _gate():
        path = request.path or ""
        method = (request.method or "GET").upper()
        g._alog_start = _time.time()   # 计时起点（供 after_request 审计算 elapsed_ms）
        if not path.startswith("/api") or method == "OPTIONS":
            return None
        # 攻击告警 IP 封禁拦截（**最前置，在 public 判断之前**：被封 IP 连探活/登录等 public 端点也一律 403，
        # 不给任何可乘之机）。取真实客户端 IP 用 X-Real-IP（nginx 反代时 remote_addr 是 nginx 内网 IP）。
        # 封禁服务缺失/异常一律 fail-open（不因封禁模块问题拖垮全站）。
        try:
            from sentinel_platform.modules.honeypot_defense.attack_alert import is_banned
            _cip = (request.headers.get("X-Real-IP", "")
                    or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                    or request.remote_addr or "")
            if _cip and is_banned(_cip):
                resp = jsonify(envelope(code=CODE_FORBIDDEN, message="您的 IP 因攻击行为已被封禁"))
                resp.status_code = 403
                return resp
        except Exception:
            pass   # fail-open
        # public 端点（探活/登录等）在封禁检查之后放行
        if is_public(path, method):
            return None
        # 激活硬门控：核心业务端点未激活/过期即拦（独立于 auth——关掉 AUTH 也不能绕过 license 锁）。
        # 无宽限期，activation_ok() 依赖缺失时 fail-open（守孤岛可跑）。激活页/登录/状态查询均不在门控前缀内，不会死锁。
        if activation_enforced() and is_activation_gated(path) and not activation_ok():
            resp = jsonify(envelope(code=CODE_ACTIVATION_REQUIRED))
            resp.status_code = CODE_ACTIVATION_REQUIRED
            return resp
        if not auth_enabled():
            return None
        token = request.headers.get("Token", "") or request.headers.get("token", "")
        user = verify_token(token)
        if not user:
            resp = jsonify(envelope(code=CODE_UNAUTHORIZED))
            resp.status_code = CODE_UNAUTHORIZED
            return resp
        g.current_user = user
        allow, reason = check_rbac(user, path, method)
        if not allow:
            resp = jsonify(envelope(code=CODE_FORBIDDEN, message="无权限: {}".format(reason)))
            resp.status_code = CODE_FORBIDDEN
            return resp
        return None

    @app.after_request
    def _access_log(resp):
        # 闭合交接待办③：access_log 叶子经字符串键 "audit_service" 提供 record/should_record。
        # 审计失败绝不阻断响应（日志系统不反噬业务）。审计服务未建时静默跳过（缺失降级）。
        try:
            audit = get_registry().get("audit_service")
            path = request.path or ""
            method = (request.method or "GET").upper()
            if audit and audit.should_record(path, method):
                start = getattr(g, "_alog_start", None)
                elapsed_ms = int((_time.time() - start) * 1000) if start else 0
                user = getattr(g, "current_user", None) or {}
                audit.record(
                    method=method, path=path, status=resp.status_code,
                    username=user.get("username", ""),
                    ip=(request.headers.get("X-Forwarded-For", "") or request.remote_addr or "").split(",")[0].strip(),
                    elapsed_ms=elapsed_ms)
        except Exception:
            pass
        return resp
