"""ServiceRegistry —— 模块间依赖注入容器（多 AI 并行开发的核心机制）。

模块 A 需要模块 B 的能力时，不 import B，而是 `get_registry().get(ROLE.XXX)` 取到
B 注册的实现。装配层（web 启动/celery 启动）负责把各模块实现注册进来。

于是：
- 开发期：AI 只需按 contracts.interfaces 的接口编码，get 到的是接口，不依赖 B 的存在。
- 缺失容错：某模块未注册时 get 返回 None，调用方优雅降级（不炸）。
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class ROLE:
    """模块服务角色名（注册/获取的键，冻结）。对应 contracts.interfaces 里的接口。"""
    INTEL = "intel_service"                 # IntelService: 归集/查资产/系统
    FINDING = "finding_service"             # FindingService: 漏洞发现登记/查询/统计
    PENTEST_DISPATCH = "pentest_dispatcher"  # PentestDispatcher: 派发/管理 AI 渗透会话
    VULN_INTEL = "vuln_intel_service"       # VulnIntelService: 漏洞情报查询
    RECON = "recon_service"                 # ReconService: 调 sentinel_engine 侦察（recon_bridge 实现）
    PROXY = "proxy_service"                 # ProxyService: 出口代理决策/健康
    NOTIFY = "notify_service"               # NotifyService: 通知推送
    EXPLOIT_CLUE = "exploit_clue_service"   # ExploitClueService: 共享情报池读写
    SYSTEM_TAGS = "system_tags_service"     # SystemTagsService: 系统命名/标签
    USER = "user_service"                   # UserService: 登录/token 校验/用户CRUD（system/user_manage 实现，router 网关消费）
    RBAC = "rbac_service"                   # RbacService: 权限校验/角色（system/user_manage 实现，router 网关消费）


class ServiceRegistry:
    def __init__(self) -> None:
        self._impls: Dict[str, Any] = {}

    def register(self, role: str, impl: Any) -> None:
        self._impls[role] = impl

    def get(self, role: str) -> Optional[Any]:
        """取角色实现；未注册返回 None（调用方优雅降级）。"""
        return self._impls.get(role)

    def require(self, role: str) -> Any:
        """取角色实现；未注册抛错（用于硬依赖）。"""
        impl = self._impls.get(role)
        if impl is None:
            raise RuntimeError("service role not registered: {}".format(role))
        return impl

    def has(self, role: str) -> bool:
        return role in self._impls


_registry: Optional[ServiceRegistry] = None


def get_registry() -> ServiceRegistry:
    global _registry
    if _registry is None:
        _registry = ServiceRegistry()
    return _registry


def reset_registry() -> None:
    global _registry
    _registry = None
