"""system 类别装配 —— 把系统设置各叶子实现注册进 registry。

bootstrap 启动时调本模块 register(registry)。当前已就绪叶子：proxy(PROXY)、user_manage(USER+RBAC)。
其余 system 叶子（api_keys/log_monitor/access_log/guard_log）
多数只对核心路由暴露能力、不实现 ROLE，无需在此注册；实现 ROLE 的叶子在此追加。
"""
from __future__ import annotations

from sentinel_platform.contracts import ROLE


def register(registry) -> None:
    # proxy：出口代理决策/健康（ROLE.PROXY）
    from .proxy import get_service as _proxy_service
    registry.register(ROLE.PROXY, _proxy_service())

    # api_keys：统一密钥中心（字符串键 "api_keys_service"，照 gateway user_service/rbac_service 先例，不进冻结 ROLE）
    from .api_keys import get_service as _api_keys_service
    registry.register("api_keys_service", _api_keys_service())

    # user_manage：登录/token/用户·角色（一实现满足 USER + RBAC，router 网关消费）
    from .user_manage import get_service as _user_service
    _um = _user_service()
    registry.register(ROLE.USER, _um)
    registry.register(ROLE.RBAC, _um)

    # access_log：访问/操作审计（字符串键 "audit_service"，gateway after_request 经此写审计）
    from .access_log import get_service as _audit_service
    registry.register("audit_service", _audit_service())

    # log_monitor：程序日志 + 保留策略 + 资源监控（字符串键 "log_service"）
    from .log_monitor import get_service as _log_service
    registry.register("log_service", _log_service())

    # guard_log：闸刀拦截日志 capped 环形（字符串键 "guard_log_service"，未来闸刀经此写事件）
    from .guard_log import get_service as _guard_log_service
    registry.register("guard_log_service", _guard_log_service())

    # proxy 公开抓取代理池（phase-2，字符串键 "proxy_pool_service"，endpoints/proxy.py 的 pool/* 调）
    from ._pool import get_service as _proxy_pool_service
    registry.register("proxy_pool_service", _proxy_pool_service())

    # network_check：网络检测（ping + DNS 配置，字符串键 "network_check_service"）
    from .network_check import get_service as _network_check_service
    registry.register("network_check_service", _network_check_service())
