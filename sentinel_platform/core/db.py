"""平台存储层 —— Repository（收口 Mongo 访问，替代 app.utils.conn_db）。

净室实现，pymongo 惰性导入。平台与 sentinel_engine 写同一 Mongo 实例/DB（同集合），
但本 Repository 是平台自己的，不 import 引擎的 store。

迁移契约：旧代码 `conn_db("x")` → 新代码 `get_repo().collection("x")`（返回 pymongo collection，
API 不变，upsert/find/update 等照旧），迁移改动最小。另提供常用高阶 helper。
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


class Repository:
    """Mongo 访问封装。collection(name) 返回原生 pymongo collection（保持旧 conn_db 调用习惯），
    另有 find/find_one/insert/update/count 高阶 helper。"""

    def __init__(self, uri: str, db_name: str):
        self._uri = uri
        self._db_name = db_name
        self._client = None
        self._lock = threading.Lock()

    def _db(self):
        if self._client is None:
            with self._lock:
                if self._client is None:
                    from pymongo import MongoClient  # 惰性
                    self._client = MongoClient(self._uri)
        return self._client[self._db_name]

    def collection(self, name: str):
        """返回 pymongo collection（等价旧 conn_db(name)）。"""
        return self._db()[name]

    # —— 高阶 helper（可选用，便于测试替身）——
    def find(self, name: str, query: Dict[str, Any] = None, limit: int = 0,
             sort: Optional[List] = None) -> List[Dict[str, Any]]:
        cur = self.collection(name).find(query or {})
        if sort:
            cur = cur.sort(sort)
        if limit:
            cur = cur.limit(limit)
        return list(cur)

    def find_one(self, name: str, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self.collection(name).find_one(query)

    def insert_one(self, name: str, doc: Dict[str, Any]):
        return self.collection(name).insert_one(doc)

    def insert_many(self, name: str, docs: List[Dict[str, Any]]):
        docs = list(docs)
        if docs:
            return self.collection(name).insert_many(docs)

    def update_one(self, name: str, query: Dict[str, Any], update: Dict[str, Any],
                   upsert: bool = False):
        return self.collection(name).update_one(query, update, upsert=upsert)

    def delete_one(self, name: str, query: Dict[str, Any]):
        return self.collection(name).delete_one(query)

    def count(self, name: str, query: Dict[str, Any] = None) -> int:
        return self.collection(name).count_documents(query or {})


# —— 进程级单例 ——
_repo: Optional[Repository] = None
_repo_lock = threading.Lock()


def get_repo() -> Repository:
    global _repo
    if _repo is None:
        with _repo_lock:
            if _repo is None:
                from .config import get_config
                cfg = get_config()
                _repo = Repository(cfg.mongo_uri, cfg.mongo_db)
    return _repo


def set_repo(repo: Repository) -> None:
    """测试/依赖注入用：替换全局 repo。"""
    global _repo
    _repo = repo


def reset_repo() -> None:
    global _repo
    _repo = None
