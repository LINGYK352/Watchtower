"""kernel 类别装配 —— 把内核各叶子实现注册进 registry。

bootstrap 启动时调本模块 register(registry)。当前已就绪叶子：notify(NOTIFY)、exploit_clue(EXPLOIT_CLUE)、
system_tags(SYSTEM_TAGS)、recon_bridge(RECON)。其余内核叶子（orchestration/ext_source）实现后在此追加注册。
"""
from __future__ import annotations

from sentinel_platform.contracts import ROLE


def register(registry) -> None:
    # notify：集成推送（ROLE.NOTIFY）
    from .notify import get_service as _notify_service
    registry.register(ROLE.NOTIFY, _notify_service())

    # system_tags：系统命名/标签（ROLE.SYSTEM_TAGS）
    from .system_tags import get_service as _system_tags_service
    registry.register(ROLE.SYSTEM_TAGS, _system_tags_service())

    # exploit_clue：单位级共享情报池（ROLE.EXPLOIT_CLUE）
    from .exploit_clue import get_service as _exploit_clue_service
    registry.register(ROLE.EXPLOIT_CLUE, _exploit_clue_service())

    # recon_bridge：侦察桥，调 external 工具对接层（ROLE.RECON）
    from .recon_bridge import get_service as _recon_service
    registry.register(ROLE.RECON, _recon_service())

    # orchestration：任务编排入口（字符串键 orchestration_service，供 task_create 等调）
    from .orchestration import get_service as _orch_service
    registry.register("orchestration_service", _orch_service())

    # ext_source：外部测绘源（FOFA/crtsh/ICP，无 ROLE，字符串键 "ext_source_service"）。
    # 叶子是模块级函数集合，注册模块对象作门面（router/task_create 经 registry 取，不再直连 import 叶子）。
    from . import ext_source as _ext_source
    registry.register("ext_source_service", _ext_source)
