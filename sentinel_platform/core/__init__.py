"""core —— 平台共享底座（冻结层）。

所有模块只依赖这里，替代原 app 的 utils.conn_db / config / modules 枚举 / routes 基类。
本层不 import 本包任何其他层（contracts/modules/web），也不 import app.*。

- config.py : 配置加载（读同一 config.yaml，惰性、缺省安全）
- db.py     : Repository（Mongo 访问，pymongo 惰性导入，收口 conn_db）
- models.py : 领域枚举与轻量数据类型（替代 app.modules 的枚举契约）
- query.py  : REST→Mongo 查询纯函数（零框架依赖，纯查询叶子直接用，不必碰路由基类）
- web.py    : BaseResource（Flask-RESTX 路由基类，查询/分页委托 query.py）
- http.py   : http_req / 标题头解析（出站 HTTP，走平台自己的实现）
- log.py    : get_logger
- paths.py  : 项目根 / 截图目录等跨模块共享路径约定（共享常量下沉，避免叶子间直连拿路径）
"""
from .config import get_config, PlatformConfig
from .db import Repository, get_repo, set_repo
from .log import get_logger
from .paths import project_root, image_dir
from . import models
from . import query

__all__ = [
    "get_config", "PlatformConfig",
    "Repository", "get_repo", "set_repo",
    "get_logger", "project_root", "image_dir", "models", "query",
]
