"""task_plan 类别装配 —— 把本类别各叶子实现注册进 registry。

bootstrap/router 启动时调 register(registry)。当前叶子：policy（策略配置，无 ROLE）。
policy 无 Protocol ROLE（纯配置叶子），以**字符串键 `"policy_service"`** 注册
（照 dashboard_service / api_keys_service 先例），router endpoints + task_create 经该键取用。
其余叶子（task_list/task_create/task_schedule）实现后在此追加注册（各自字符串键）。
"""
from __future__ import annotations


def register(registry) -> None:
    # policy：策略配置（无 ROLE，字符串键）
    from .policy import get_service as _policy_service
    registry.register("policy_service", _policy_service())

    # task_list：任务列表与生命周期动作（无 ROLE，字符串键）
    from .task_list import get_service as _task_list_service
    registry.register("task_list_service", _task_list_service())

    # task_create：新建任务下发（无 ROLE，字符串键）
    from .task_create import get_service as _task_create_service
    registry.register("task_create_service", _task_create_service())

    # task_schedule：计划任务（无 ROLE，字符串键 "task_schedule_service"）。
    # 叶子是模块级函数集合，注册模块对象作门面（router 经 registry 取，不再直连 import 叶子）。
    from . import task_schedule as _task_schedule
    registry.register("task_schedule_service", _task_schedule)
