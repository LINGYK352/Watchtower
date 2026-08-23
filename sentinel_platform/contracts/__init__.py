"""contracts —— 模块间契约层（冻结）。

**这是多 AI 并行开发的关键**：模块之间从不直接 import 对方内部，而是：
- 需要别的模块的能力时，声明/依赖这里的 Protocol 接口；
- 通过 registry 在运行时取到实现（谁实现由装配层注入）。

于是「AI-1 开发 intel、AI-2 开发 ai_pentest」各自只看自己模块 + 本契约层，
接口是冻结的约定，双方并行、不冲突、不需读对方代码。

- interfaces.py : 模块间 Protocol 接口（IntelService/FindingService/PentestDispatcher/...）
- registry.py   : ServiceRegistry（按角色注册/获取实现，依赖注入）
- collections.py: 对外 Mongo 集合名（与引擎/既有数据共享的数据契约事实源）

依赖方向：contracts 只 import core，不 import modules。
"""
from .registry import ServiceRegistry, get_registry, ROLE
from .collections import Collections

__all__ = ["ServiceRegistry", "get_registry", "ROLE", "Collections"]
