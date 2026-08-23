"""asset 类别装配 —— 把资产中心各叶子实现注册进 registry。

bootstrap 启动时调本模块 register(registry)。当前已就绪叶子：search（资产检索）。
asset 叶子多数无冻结 ROLE，用字符串键注册（照 gateway user_service / api_keys_service 先例），
不进冻结 contracts.ROLE。其余叶子（groups/monitor/fingerprint/github_*）实现后在此追加一行。
"""
from __future__ import annotations


def register(registry) -> None:
    # search：资产检索（字符串键 "asset_search_service"，非 ROLE）
    from .search import get_service as _asset_search_service
    registry.register("asset_search_service", _asset_search_service())

    # groups：资产分组（字符串键 "asset_group_service"，非 ROLE）
    from .groups import get_service as _asset_group_service
    registry.register("asset_group_service", _asset_group_service())

    # monitor：资产监控周期任务（字符串键 "monitor_service"，非 ROLE）
    from .monitor import get_service as _monitor_service
    registry.register("monitor_service", _monitor_service())

    # fingerprint：指纹管理（字符串键 "fingerprint_service"，非 ROLE）。
    # 叶子是模块级函数集合，注册模块对象作门面（router 经 registry 取，不再直连 import 叶子）。
    from . import fingerprint as _fingerprint
    registry.register("fingerprint_service", _fingerprint)

    # github_task：GitHub 搜索任务（字符串键 "github_task_service"，非 ROLE）
    from . import github_task as _github_task
    registry.register("github_task_service", _github_task)

    # github_monitor：GitHub 周期监控（字符串键 "github_monitor_service"，非 ROLE）
    from . import github_monitor as _github_monitor
    registry.register("github_monitor_service", _github_monitor)
