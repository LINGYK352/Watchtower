"""平台 Web 路由基类 BaseResource（替代 ARLResource，净室重写查询/分页契约）。

保持与旧路由相同的用法契约（parse_args / build_db_query / build_data 分页返回），
使 routes 迁移改动最小。查询运算符（__dgt/__dlt/__neq/__not/__gt/__lt/正则/等值）
按通用 REST→Mongo 惯例重新实现，不抄 ARL 表达。

**查询纯函数已下沉 `core/query.py`**（零框架依赖）：本类的 `_one_clause`/`build_db_query`/
`build_return_items` 改为**委托** `core.query` 的模块级纯函数，纯查询叶子直接 import
`core.query` 不再碰本路由基类。常量从 `core.query` 重导出保持向后兼容。
"""
from __future__ import annotations

from typing import Any, Dict

from . import query as _query
# 常量向后兼容重导出（历史 `from core.web import EQUAL_FIELDS` 仍可用）
from .query import EQUAL_FIELDS, BASE_QUERY_KEYS  # noqa: F401

try:
    from flask_restx import Resource, reqparse, fields
except Exception:  # 无 flask 环境（如离线单测）时降级，不阻断 import
    Resource = object
    reqparse = None
    fields = None


class BaseResource(Resource):
    """平台路由基类。子类沿用 parse_args/build_db_query/build_data。"""

    def parse_args(self, model, location="json"):
        parser = reqparse.RequestParser(bundle_errors=True)
        for name, f in model.items():
            parser.add_argument(name, required=getattr(f, "required", False),
                                type=getattr(f, "format", str),
                                help=getattr(f, "description", ""), location=location)
        return parser.parse_args()

    def build_db_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _query.build_query(args)

    @staticmethod
    def _one_clause(key: str, val: Any) -> Dict[str, Any]:
        return _query.one_clause(key, val)

    @staticmethod
    def build_return_items(data):
        return _query.serialize_items(data)

    def build_data(self, args=None, collection=None):
        """分页查询，返回 {page,size,total,items}。collection 为集合名。"""
        from .db import get_repo
        args = args or {}
        page = max(1, int(args.get("page", 1) or 1))
        try:
            size = int(args.get("size", 10) or 10)
        except (TypeError, ValueError):
            size = 10
        order = args.get("order", "_id") or "_id"
        query = self.build_db_query(args)
        coll = get_repo().collection(collection)
        total = coll.count_documents(query)
        direction = -1 if not str(order).startswith("+") else 1
        field = str(order).lstrip("+-") or "_id"
        cur = coll.find(query).sort(field, direction)
        if size > 0:
            cur = cur.skip((page - 1) * size).limit(size)
        return {"page": page, "size": size, "total": total,
                "items": self.build_return_items(list(cur))}
