"""回归层自有内存 Mongo 替身（单一权威，独立演进）。

**为什么不复用 _fakedb.py / 各模块 test 内部类**：
- risk_intel/tests/_fakedb.py 被 13 个文件依赖且缺 $inc/$setOnInsert/matched_count，升级它=典型负优化（改一处扰动他处）。
- 各模块 test 内部的 _FakeColl 是私有实现，回归层依赖它=被其重构波及。
故回归层自带一份够用的替身：支持 CAS 所需的 $inc/$setOnInsert/$push/$pull/$exists + matched_count/upserted_id。
只有资源池 CAS 用例需要它；纯函数用例根本不碰 repo。
"""
from __future__ import annotations

import re as _re
from typing import Any, Dict, List


class _Res:
    """update_one 返回体替身：带 matched_count/modified_count/upserted_id（CAS 判定用）。"""
    def __init__(self, matched: int, upserted_id=None):
        self.matched_count = matched
        self.modified_count = matched
        self.upserted_id = upserted_id


def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    for k, cond in (query or {}).items():
        if k == "$or":
            if not any(_match(doc, sub) for sub in cond):
                return False
            continue
        if k == "$and":
            if not all(_match(doc, sub) for sub in cond):
                return False
            continue
        cur = doc.get(k)
        if isinstance(cond, dict):
            if "$exists" in cond:
                if bool(k in doc) != bool(cond["$exists"]):
                    return False
            elif "$regex" in cond:
                flags = _re.I if "i" in cond.get("$options", "") else 0
                if not (isinstance(cur, str) and _re.search(cond["$regex"], cur, flags)):
                    return False
            elif "$ne" in cond:
                if cur == cond["$ne"]:
                    return False
            elif "$in" in cond:
                if cur not in cond["$in"]:
                    return False
            else:
                return False   # 未知算子保守不匹配
        else:
            if cur != cond:
                return False
    return True


class _FakeColl:
    """最小内存 collection：支持回归用例（尤其资源池 CAS 单文档账本）用到的算子。"""
    def __init__(self):
        self.docs: List[Dict[str, Any]] = []
        self._n = 0

    def find_one(self, query=None, *a, **k):
        for d in self.docs:
            if _match(d, query or {}):
                return d
        return None

    def find(self, query=None, *a, **k):
        return [d for d in self.docs if _match(d, query or {})]

    def count_documents(self, query=None, **k):
        return len([d for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "d%d" % self._n)
        self.docs.append(doc)
        return _Res(1, doc["_id"])

    def update_one(self, query, update, upsert=False):
        doc = self.find_one(query)
        if doc is None:
            if not upsert:
                return _Res(0)
            self._n += 1
            doc = {k: v for k, v in (query or {}).items() if not isinstance(v, dict)}
            doc.setdefault("_id", "d%d" % self._n)
            self.docs.append(doc)
            for kk, vv in update.get("$setOnInsert", {}).items():
                doc[kk] = vv
            for kk, vv in update.get("$set", {}).items():
                doc[kk] = vv
            for kk, vv in update.get("$inc", {}).items():
                doc[kk] = doc.get(kk, 0) + vv
            _apply_push(doc, update.get("$push", {}))
            return _Res(0, doc["_id"])
        for kk, vv in update.get("$set", {}).items():
            doc[kk] = vv
        for kk, vv in update.get("$inc", {}).items():
            doc[kk] = doc.get(kk, 0) + vv
        _apply_push(doc, update.get("$push", {}))
        for kk, cond in update.get("$pull", {}).items():
            arr = doc.get(kk, [])
            doc[kk] = [x for x in arr if not _match(x, cond) if isinstance(x, dict)] \
                if arr and isinstance(arr[0], dict) else \
                [x for x in arr if not _pull_scalar(x, cond)]
        return _Res(1)


def _apply_push(doc, push_spec):
    for kk, spec in (push_spec or {}).items():
        arr = doc.setdefault(kk, [])
        if isinstance(spec, dict) and "$each" in spec:
            arr.extend(spec["$each"])
            sl = spec.get("$slice")
            if sl is not None and sl < 0:
                doc[kk] = arr[sl:]
        else:
            arr.append(spec)


def _pull_scalar(item, cond):
    if isinstance(cond, dict) and "$in" in cond:
        return item in cond["$in"]
    return item == cond


class _FakeRepo:
    def __init__(self):
        self._colls: Dict[str, _FakeColl] = {}

    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())
