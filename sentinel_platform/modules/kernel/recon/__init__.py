"""recon —— 侦察工具对接层（防腐层）。

结构：base(执行底座) / models(结构化记录) / tools/(一工具一对接) / registry(角色降级)。
external/ 工具的原始输出止于本层，只把 models 结构化记录交给上层 recon_bridge。
"""
from .registry import ToolRegistry, build_registry
from . import models

__all__ = ["ToolRegistry", "build_registry", "models"]
