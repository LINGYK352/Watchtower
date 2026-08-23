"""sentinel_platform —— 哨兵平台层（净室重迁，不依赖 ARL）。

强解耦分层，支持多 AI 并行开发：core（共享底座）/ contracts（模块间契约）/
modules（各平台模块，互不 import）/ web（路由）。详见 README.md、docs/。
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
