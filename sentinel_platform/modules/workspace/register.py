"""workspace 类别装配 —— 把本类别各叶子实现注册进 registry。

bootstrap/router 启动时调 register(registry)。当前叶子：dashboard（态势总览，无 ROLE）。
dashboard 无 Protocol ROLE（纯查询叶子），以**字符串键 `"dashboard_service"`** 注册
（照 gateway user_service / api_keys_service 先例），router endpoints 经该键取用。
"""
from __future__ import annotations


def register(registry) -> None:
    # dashboard：态势总览设备监控（无 ROLE，字符串键）
    from .dashboard import get_service as _dashboard_service
    registry.register("dashboard_service", _dashboard_service())
