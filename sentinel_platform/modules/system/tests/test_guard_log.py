"""system/guard_log 单测 —— core 内存替身，不需真 Mongo / 不需 pymongo。

覆盖：register 字符串键、record 写事件 + 异常不反噬、list 过滤/分页/$natural 倒序、
stat 统计、set_size_mb 物理下限无上限、capped 无 db 优雅降级（fake repo）、禁硬限制 size 透传。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


def _match(doc, query):
    for k, v in (query or {}).items():
        if doc.get(k) != v:
            return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
        # $natural 倒序 = 插入序倒序（最新在前）：用列表反转模拟
        if key == "$natural" and direction < 0:
            self._docs = list(reversed(self._docs))
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


class _Coll:
    """无 .database 属性 → 触发 guard_log capped 优雅降级（模拟无 pymongo 环境）。"""
    def __init__(self):
        self.docs = []
        self._n = 0

    def find_one(self, query, projection=None):
        for d in self.docs:
            if _match(d, query):
                return d
        return None

    def find(self, query=None, projection=None):
        return _Cursor([d for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "g{}".format(self._n))
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def update_one(self, query, update, upsert=False):
        t = self.find_one(query)
        if t is None and upsert:
            t = dict(query)
            self.docs.append(t)
        if t is not None:
            t.update(update.get("$set") or {})
        return type("R", (), {"modified_count": 1})()

    def count_documents(self, query):
        return sum(1 for d in self.docs if _match(d, query or {}))


class _Repo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _Coll())


def _reset_ensured():
    from sentinel_platform.modules.system import guard_log as g
    g._ensured["size_bytes"] = 0


class GuardLogTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        set_repo(_Repo())
        _reset_ensured()

    def tearDown(self):
        reset_repo()
        reset_registry()
        _reset_ensured()

    def _impl(self):
        from sentinel_platform.modules.system.guard_log import GuardLogServiceImpl
        return GuardLogServiceImpl()

    # —— register 字符串键 ——
    def test_register_string_key(self):
        from sentinel_platform.modules.system.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get("guard_log_service")
        self.assertIsNotNone(svc)
        for m in ("record", "list_logs", "stat", "set_size_mb", "get_size_mb"):
            self.assertTrue(hasattr(svc, m))

    # —— record 写事件（capped 无 db 降级，insert 仍落 fake）——
    def test_record_and_list(self):
        im = self._impl()
        im.record("POST", "http://t/del", "src", allow=False, level="danger", reason="删除操作")
        im.record("GET", "http://t/info", "src", allow=True, level="safe")
        r = im.list_logs()
        self.assertEqual(r["total"], 2)
        # $natural 倒序：最新(GET)在前
        self.assertEqual(r["items"][0]["method"], "GET")
        self.assertEqual(r["items"][1]["method"], "POST")

    # —— record 字段完整 + 截断 ——
    def test_record_fields(self):
        im = self._impl()
        im.record("post", "u" * 600, "redteam", allow=True, level="ai_safe",
                  reason="x" * 400, session_id="s1", site="t.com")
        d = im.list_logs()["items"][0]
        self.assertEqual(d["method"], "POST")          # 大写归一
        self.assertEqual(len(d["url"]), 500)           # url 截断 500
        self.assertEqual(len(d["reason"]), 300)        # reason 截断 300
        self.assertEqual(d["session_id"], "s1")
        self.assertIn("ts", d)

    # —— record 异常绝不反噬业务 ——
    def test_record_never_raises(self):
        im = self._impl()
        with mock.patch("sentinel_platform.modules.system.guard_log._coll",
                        side_effect=RuntimeError("db boom")):
            im.record("GET", "x", "src", True, "safe")   # 不应抛
        # 无异常即通过

    # —— list 过滤：allow / mode / level ——
    def test_list_filters(self):
        im = self._impl()
        im.record("POST", "a", "src", allow=False, level="danger")
        im.record("GET", "b", "redteam", allow=True, level="safe")
        im.record("POST", "c", "src", allow=True, level="ai_safe")
        self.assertEqual(im.list_logs(allow=False)["total"], 1)
        self.assertEqual(im.list_logs(mode="redteam")["total"], 1)
        self.assertEqual(im.list_logs(level="ai_safe")["total"], 1)

    # —— stat 统计 ——
    def test_stat(self):
        im = self._impl()
        im.record("POST", "a", "src", allow=False, level="danger")
        im.record("GET", "b", "src", allow=True, level="safe")
        im.record("GET", "c", "src", allow=True, level="safe")
        st = im.stat()
        self.assertEqual(st["total"], 3)
        self.assertEqual(st["blocked"], 1)
        self.assertEqual(st["allowed"], 2)
        self.assertEqual(st["default_size_mb"], 500)

    # —— set_size_mb：物理下限 1，无上限（禁硬限制）——
    def test_set_size_no_upper_limit(self):
        im = self._impl()
        self.assertEqual(im.set_size_mb(99999), 99999)   # 无人为上限，透传
        self.assertEqual(im.set_size_mb(0), 1)           # 物理下限 1（capped 必须 >0）
        self.assertEqual(im.set_size_mb("bad"), 500)     # 非法回落默认

    def test_get_size_default(self):
        self.assertEqual(self._impl().get_size_mb(), 500)   # 未配返默认

    # —— 禁硬限制：list size 传大值透传不砍 ——
    def test_list_no_hard_limit(self):
        im = self._impl()
        for i in range(40):
            im.record("GET", "u{}".format(i), "src", allow=True, level="safe")
        r = im.list_logs(size=1000)
        self.assertEqual(r["size"], 1000)
        self.assertEqual(r["total"], 40)
        self.assertEqual(len(r["items"]), 40)   # 全返（无硬上限）


if __name__ == "__main__":
    unittest.main()
