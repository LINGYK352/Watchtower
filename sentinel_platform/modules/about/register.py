"""about 类别装配 —— 把关于系统各叶子实现注册进 registry。

bootstrap 启动时调本模块 register(registry)。当前叶子：update_check（更新检测，无 ROLE）。
changelog/developer 为纯前端页面，无后端叶子。update_check 是模块级函数集合，
注册模块对象作门面（router 经 registry 取，不再直连 import 叶子）。
"""
from __future__ import annotations


def register(registry) -> None:
    # update_check：版本/更新检测（字符串键 "update_check_service"，非 ROLE）
    from . import update_check as _update_check
    registry.register("update_check_service", _update_check)
