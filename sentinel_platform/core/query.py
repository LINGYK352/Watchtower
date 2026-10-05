"""core/query —— REST 查询参数 → Mongo 查询的纯函数（零框架依赖）。

从 `core/web.py:BaseResource` 下沉而来：原纯函数（`_one_clause`/`build_db_query`/
`build_return_items`）挂在继承 `flask_restx.Resource` 的路由基类上，导致纯查询叶子
（asset/search、asset/monitor、risk_intel/scan_result）为复用它们被迫 import 路由基类，
隐式把「叶子不碰路由层」的边界弄脏。

本模块把这批纯函数抽成模块级函数——只依赖 stdlib（re/datetime）+ 惰性可选 bson，
`BaseResource` 委托它保持向后兼容（router 层零改动），叶子直接 import 纯函数、不再碰
路由基类。查询运算符（__dgt/__dlt/__neq/__not/__gt/__lt/正则/等值）语义与原实现逐一等价。
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, List

# 只用等值查询的字段（非正则）
EQUAL_FIELDS = {"task_id", "task_tag", "ip_type", "scope_id", "type"}
# 分页/排序控制键（不进查询条件）
BASE_QUERY_KEYS = {"page", "size", "order"}
# 序列化为字符串的特殊字段（ObjectId/时间）
_SERIALIZE_FIELDS = ("_id", "save_date", "update_date")


def one_clause(key: str, val: Any) -> Dict[str, Any]:
    """单个「字段→值」转一条 Mongo 查询子句（运算符按 REST 后缀惯例解析）。

    与原 `BaseResource._one_clause` 逐分支等价：日期区间 __dgt/__dlt、__neq、__not（正则否定）、
    整数 __gt/__lt、字符串默认大小写不敏感正则（EQUAL_FIELDS 除外走等值）、其余原样等值。
    """
    for suf, op in (("__dgt", "$gt"), ("__dlt", "$lt")):
        if key.endswith(suf):
            real = key[: -len(suf)]
            return {real: {op: datetime.strptime(val, "%Y-%m-%d %H:%M:%S")}}
    if key.endswith("__neq"):
        return {key[:-5]: {"$ne": val}}
    if key.endswith("__not"):
        return {key[:-5]: {"$not": re.compile(re.escape(val))}}
    if key.endswith("__gt") and isinstance(val, int):
        return {key[:-4]: {"$gt": val}}
    if key.endswith("__lt") and isinstance(val, int):
        return {key[:-4]: {"$lt": val}}
    if isinstance(val, str):
        if key in EQUAL_FIELDS:
            return {key: val}
        return {key: {"$regex": re.escape(val), "$options": "i"}}
    return {key: val}


def build_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """请求参数字典 → 完整 Mongo 查询（跳过分页键、_id 惰性转 ObjectId、None 跳过）。

    与原 `BaseResource.build_db_query` 等价。无 bson 环境（离线单测）下 _id 原值兜底。
    """
    q: Dict[str, Any] = {}
    for key, val in args.items():
        if key in BASE_QUERY_KEYS:
            continue
        if key == "_id":
            if val:
                q["_id"] = to_object_id(val)
            continue
        if val is None:
            continue
        q.update(one_clause(key, val))
    return q


def to_object_id(val: Any) -> Any:
    """字符串 id → bson.ObjectId（惰性、可选）。无 bson/非法 → 原值兜底（对齐叶子既有范式）。"""
    try:
        from bson import ObjectId
        return ObjectId(val)
    except Exception:
        return val


def serialize_items(data: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """_id/save_date/update_date 就地转字符串（flask_restx JSON 编码器不吃 datetime/ObjectId）。

    与原 `BaseResource.build_return_items` 等价（就地改并返回 list）。
    """
    out: List[Dict[str, Any]] = []
    for item in data:
        for k in list(item.keys()):
            if k in _SERIALIZE_FIELDS:
                item[k] = str(item[k])
        out.append(item)
    return out
