"""内存 Mongo 替身 —— 覆盖 vuln_intel/_feed 用到的操作，不连真库。

支持：find_one(精确键)、update_one($set/$addToSet/$each,upsert)、insert_one、
find($or + 字段 $regex/精确) → 可 .sort().skip().limit() 的游标、count_documents、
aggregate($unwind + $group $sum)。够本模块测试用，不追求通用 Mongo 语义。
"""
from __future__ import annotations

import re
import itertools
from typing import Any, Dict, List

from sentinel_platform.core.db import Repository


def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    if not query:
        return True
    for k, cond in query.items():
        if k == "$or":
            if not any(_match(doc, sub) for sub in cond):
                return False
            continue
        if k == "$and":
            if not all(_match(doc, sub) for sub in cond):
                return False
            continue
        if k == "$nor":
            if any(_match(doc, sub) for sub in cond):
                return False
            continue
        val = doc.get(k)
        if isinstance(cond, dict):
            if not _match_ops(val, cond):
                return False
        else:
            if val != cond and not (isinstance(val,list) and cond in val):
                return False
    return True


def _match_ops(val: Any, cond: Dict[str, Any]) -> bool:
    """字段级操作符匹配：$regex/$ne/$in/$nin/$gte/$lte/$gt/$lt/$exists。未知操作符→False。"""
    for op, arg in cond.items():
        if op == "$regex":
            flags = re.I if "i" in cond.get("$options", "") else 0
            hay = val if isinstance(val, list) else [val]
            if not any(isinstance(h, str) and re.search(arg, h, flags) for h in hay):
                return False
        elif op == "$options":
            continue
        elif op == "$ne":
            if val == arg:
                return False
        elif op == "$in":
            if val not in arg:
                return False
        elif op == "$nin":
            if val in arg:
                return False
        elif op == "$gte":
            if val is None or val < arg:
                return False
        elif op == "$lte":
            if val is None or val > arg:
                return False
        elif op == "$gt":
            if val is None or val <= arg:
                return False
        elif op == "$lt":
            if val is None or val >= arg:
                return False
        elif op == "$exists":
            if bool(arg) != (val is not None):
                return False
        else:
            return False  # 未支持的操作符
    return True


class _Cursor:
    def __init__(self, docs: List[Dict[str, Any]]):
        self._docs = docs

    def sort(self, spec, direction=None):
        # 支持 pymongo 两种形态：.sort("field", -1) 与 .sort([("f",-1),...])
        if isinstance(spec, str):
            spec = [(spec, direction if direction is not None else 1)]
        for key, d in reversed(spec):
            self._docs.sort(key=lambda doc: _sort_key(doc.get(key)), reverse=(d < 0))
        return self

    def skip(self, n):
        self._docs = self._docs[n:]
        return self

    def limit(self, n):
        if n:
            self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)


def _sort_key(v):
    """None/bool/数字/字符串混排时给个可比较键（bool→int，None→空串/0）。"""
    if isinstance(v, bool):
        return (1, int(v))
    if isinstance(v, (int, float)):
        return (1, v)
    return (0, str(v) if v is not None else "")


class FakeCollection:
    _seq = itertools.count(1)

    def __init__(self):
        self.docs: List[Dict[str, Any]] = []

    def _ref(self, query):
        """内部：返回匹配的真实文档引用（供 update/delete 就地改）。"""
        for d in self.docs:
            if _match(d, query):
                return d
        return None

    def find_one(self, query, *a, **k):
        # 真实 pymongo 返回的是 BSON 解码出的新 dict，调用方改它不影响库；
        # 故这里返回深拷贝，避免业务代码（如 list_providers 掩码）就地改动污染存储。
        import copy
        d = self._ref(query)
        return copy.deepcopy(d) if d is not None else None

    def find(self, query=None):
        import copy
        return _Cursor([copy.deepcopy(d) for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        # 用字符串 _id（"oid{n}"）模拟真实 ObjectId 的 str 行为：调用方 str(inserted_id)
        # 再 _to_oid 查询能 round-trip 命中（int 自增 id 会因 str!=int 查不中，失真）。
        doc.setdefault("_id", "oid{}".format(next(self._seq)))
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def insert_many(self, docs):
        ids = [self.insert_one(doc).inserted_id for doc in docs]
        return type("R", (), {"inserted_ids": ids})()

    def update_one(self, query, update, upsert=False):
        target = self._ref(query)   # 就地改真实文档（非拷贝）
        if target is None and upsert:
            target = dict(query)
            target.setdefault("_id", "oid{}".format(next(self._seq)))
            self.docs.append(target)
        if target is None:
            return type("R", (), {"modified_count": 0})()
        for k, v in (update.get("$set") or {}).items():
            target[k] = v
        for k,v in (update.get('$inc') or {}).items():target[k]=target.get(k,0)+v
        for k, v in (update.get("$addToSet") or {}).items():
            cur = target.setdefault(k, [])
            vals = v["$each"] if isinstance(v, dict) and "$each" in v else [v]
            for item in vals:
                if item not in cur:
                    cur.append(item)
        for k, v in (update.get("$push") or {}).items():
            cur = target.setdefault(k, [])
            vals = v["$each"] if isinstance(v, dict) and "$each" in v else [v]
            cur.extend(vals)
        for k in (update.get("$unset") or {}):
            target.pop(k, None)
        return type("R", (), {"modified_count": 1})()

    def update_many(self, query, update):
        n = 0
        for d in self.docs:
            if _match(d, query):
                for k, v in (update.get("$set") or {}).items():
                    d[k] = v
                n += 1
        return type("R", (), {"modified_count": n})()

    def delete_many(self, query):
        keep = [d for d in self.docs if not _match(d, query)]
        n = len(self.docs) - len(keep)
        self.docs = keep
        return type("R", (), {"deleted_count": n})()

    def delete_one(self, query):
        for i, d in enumerate(self.docs):
            if _match(d, query):
                self.docs.pop(i)
                return type("R", (), {"deleted_count": 1})()
        return type("R", (), {"deleted_count": 0})()

    def count_documents(self, query):
        return sum(1 for d in self.docs if _match(d, query or {}))

    def aggregate(self, pipeline):
        docs = list(self.docs)
        for stage in pipeline:
            if "$unwind" in stage:
                field = stage["$unwind"].lstrip("$")
                nxt = []
                for d in docs:
                    for item in (d.get(field) or []):
                        nd = dict(d)
                        nd[field] = item
                        nxt.append(nd)
                docs = nxt
            elif "$group" in stage:
                gid = stage["$group"]["_id"]
                keyf = gid.lstrip("$").split(".") if isinstance(gid, str) else None
                groups: Dict[Any, int] = {}
                for d in docs:
                    kv = d
                    for part in (keyf or []):
                        kv = kv.get(part) if isinstance(kv, dict) else None
                    groups[kv] = groups.get(kv, 0) + 1
                docs = [{"_id": k, "n": v} for k, v in groups.items()]
        return iter(docs)


class FakeRepo(Repository):
    """按集合名分发多个 FakeCollection，不连真库。"""
    def __init__(self, collections: Dict[str, FakeCollection] = None):
        self._colls = collections or {}

    def collection(self, name: str):
        return self._colls.setdefault(name, FakeCollection())
