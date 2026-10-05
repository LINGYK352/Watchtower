"""system/access_log 单测 —— core 内存替身，不连真 Mongo。

覆盖：should_record 过滤、record 写入 + is_write 判定、list 分页/过滤/**size<=0 全量(禁硬限)**、
stat、降级不抛、register 注册（字符串键 audit_service）。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemCollection:
    def __init__(self):
        self._docs = []
        self._auto = 0

    def insert_one(self, doc):
        self._auto += 1
        d = dict(doc)
        d.setdefault("_id", "id%d" % self._auto)
        self._docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        out = []
        for d in self._docs:
            ok = True
            for k, v in (q or {}).items():
                if isinstance(v, dict):
                    if "$gte" in v and not (d.get(k, 0) >= v["$gte"]):
                        ok = False
                    if "$regex" in v:
                        import re as _re
                        if not _re.search(v["$regex"], str(d.get(k, "")), _re.I if "i" in v.get("$options", "") else 0):
                            ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out

    def find(self, q):
        return _Cursor(self._match(q))


class _Cursor:
    def __init__(self, docs):
        self._docs = list(docs)

    def sort(self, key, direction=-1):
        self._docs = list(reversed(self._docs)) if direction == -1 else self._docs
        return self

    def skip(self, n):
        self._docs = self._docs[n:]
        return self

    def limit(self, n):
        self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)


class _MemRepo(Repository):
    def __init__(self):
        self._coll = _MemCollection()

    def collection(self, name):
        return self._coll


class AccessLogTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_register_string_key(self):
        from sentinel_platform.modules.system.register import register
        reg = get_registry(); register(reg)
        svc = reg.get("audit_service")
        self.assertIsNotNone(svc)
        for m in ("record", "should_record", "list_access", "stat_access"):
            self.assertTrue(hasattr(svc, m))

    def test_should_record_skips_noise(self):
        from sentinel_platform.modules.system.access_log import should_record
        self.assertTrue(should_record("/api/task/", "GET"))
        self.assertFalse(should_record("/api/access_log/", "GET"))   # 自身
        self.assertFalse(should_record("/api/doc", "GET"))            # 文档
        self.assertFalse(should_record("/api/task/", "OPTIONS"))      # 预检
        self.assertFalse(should_record("/static/x.js", "GET"))        # 非 /api

    def test_record_and_is_write(self):
        from sentinel_platform.modules.system.access_log import record, list_access
        record(method="GET", path="/api/task/", status=200, username="alice", ip="1.2.3.4", elapsed_ms=12)
        record(method="POST", path="/api/task/", status=201, username="bob", ip="5.6.7.8", elapsed_ms=30)
        r = list_access()
        self.assertEqual(r["total"], 2)
        types = {i["method"]: i["is_write"] for i in r["items"]}
        self.assertFalse(types["GET"])
        self.assertTrue(types["POST"])
        # _ttl 不出现在输出（避免 datetime 序列化报错）
        self.assertTrue(all("_ttl" not in i for i in r["items"]))

    def test_list_filters(self):
        from sentinel_platform.modules.system.access_log import record, list_access
        record(method="POST", path="/api/vuln/", status=200, username="alice")
        record(method="GET", path="/api/task/", status=500, username="bob")
        self.assertEqual(list_access(is_write=True)["total"], 1)
        self.assertEqual(list_access(username="alice")["total"], 1)
        self.assertEqual(list_access(status="500")["total"], 1)
        self.assertEqual(list_access(path="task")["total"], 1)

    def test_size_zero_returns_all_no_hard_limit(self):
        """禁硬限制参数：size<=0 返全量，不被截断。"""
        from sentinel_platform.modules.system.access_log import record, list_access
        for i in range(50):
            record(method="GET", path="/api/x/%d" % i, status=200)
        # size<=0 → 全量（不硬限），证明无 min(size,N) 硬顶
        self.assertEqual(len(list_access(size=0)["items"]), 50)
        # 大 size 也不被截（比如前端要一次拉 1000）
        self.assertEqual(len(list_access(size=1000)["items"]), 50)

    def test_stat(self):
        from sentinel_platform.modules.system.access_log import record, stat_access
        record(method="GET", path="/api/a", status=200)
        record(method="POST", path="/api/b", status=403)
        s = stat_access()
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["writes"], 1)
        self.assertEqual(s["errors"], 1)     # 403 属错误(>=400)

    def test_record_failure_never_raises(self):
        from sentinel_platform.modules.system.access_log import record

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        record(method="GET", path="/api/x", status=200)   # 不抛即通过（审计不反噬业务）

    def test_list_stat_degrade(self):
        from sentinel_platform.modules.system.access_log import list_access, stat_access

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        self.assertEqual(list_access()["total"], 0)
        self.assertEqual(stat_access()["total"], 0)


if __name__ == "__main__":
    unittest.main()
