"""system/_pool 公开代理池单测 —— core 内存替身，不发真网络/不需真 socks。

覆盖：config CRUD + queries 校验、upsert 幂等去重、list 分页/status 过滤/size 透传、
enable/delete/add_manual、stats、pick_best 缓存、verify mock _fetch_ip(不发网)、crawl mock 抓取器。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo


def _match(doc, query):
    for k, v in (query or {}).items():
        if k == "_id" and isinstance(v, dict) and "$in" in v:
            if doc.get("_id") not in v["$in"]:
                return False
        elif isinstance(v, dict) and "$gte" in v:
            dv = doc.get(k)
            if dv is None or dv < v["$gte"]:
                return False
        elif doc.get(k) != v:
            return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, spec):
        for key, d in reversed(spec if isinstance(spec, list) else [spec]):
            self._docs.sort(key=lambda x: (x.get(key) is None, x.get(key)), reverse=(d < 0))
        return self

    def skip(self, n):
        self._docs = self._docs[n:]; return self

    def limit(self, n):
        if n:
            self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0

    def find_one(self, q, proj=None, sort=None):
        rows = [d for d in self.docs if _match(d, q)]
        if sort:
            for key, dr in reversed(sort):
                rows.sort(key=lambda x: (x.get(key) is None, x.get(key)), reverse=(dr < 0))
        return rows[0] if rows else None

    def find(self, q=None, proj=None):
        return _Cursor([d for d in self.docs if _match(d, q or {})])

    def insert_one(self, d):
        self._n += 1
        d.setdefault("_id", "p{}".format(self._n))
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def update_one(self, q, u, upsert=False):
        t = self.find_one(q)
        if t is None and upsert:
            t = dict(q); t.setdefault("_id", "p0"); self.docs.append(t)
        if t is not None:
            t.update(u.get("$set") or {})
        return type("R", (), {"modified_count": 1 if t else 0})()

    def update_many(self, q, u):
        n = 0
        for d in self.docs:
            if _match(d, q):
                d.update(u.get("$set") or {}); n += 1
        return type("R", (), {"modified_count": n})()

    def delete_one(self, q):
        for i, d in enumerate(self.docs):
            if _match(d, q):
                del self.docs[i]; return
    def delete_many(self, q):
        keep = [d for d in self.docs if not _match(d, q)]
        n = len(self.docs) - len(keep); self.docs = keep
        return type("R", (), {"deleted_count": n})()

    def count_documents(self, q):
        return sum(1 for d in self.docs if _match(d, q or {}))


class _Repo(Repository):
    def __init__(self):
        self._c = {}

    def collection(self, name):
        return self._c.setdefault(name, _Coll())


class PoolTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); set_repo(_Repo())
        from sentinel_platform.modules.system import _pool
        _pool._PICK_CACHE.update(url="", ts=0.0)

    def tearDown(self):
        reset_repo()

    def _m(self):
        from sentinel_platform.modules.system import _pool
        return _pool

    def test_register_string_key(self):
        from sentinel_platform.contracts import get_registry
        from sentinel_platform.contracts.registry import reset_registry
        reset_registry()
        from sentinel_platform.modules.system.register import register
        register(get_registry())
        svc = get_registry().get("proxy_pool_service")
        self.assertIsNotNone(svc)
        for m in ("list", "stats", "crawl", "verify", "enable", "delete", "add", "get_config", "save_config"):
            self.assertTrue(hasattr(svc, m))

    def test_config_default_and_save(self):
        m = self._m()
        cfg = m.get_config_pool()
        self.assertIn("queries", cfg)
        cfg2 = m.save_config_pool({"limit": 500, "queries": [
            {"source": "fofa", "type": "socks5", "q": 'protocol="socks5"', "enabled": True},
            {"source": "bad", "type": "x", "q": "y"},   # 非法源/类型被过滤
        ]})
        self.assertEqual(cfg2["limit"], 500)
        self.assertEqual(len(cfg2["queries"]), 1)       # 非法被过滤

    def test_upsert_dedup(self):
        m = self._m()
        self.assertTrue(m._upsert_one("socks5", "1.2.3.4", 1080, "fofa"))
        self.assertFalse(m._upsert_one("socks5", "1.2.3.4", 1080, "fofa"))   # 幂等去重
        self.assertFalse(m._upsert_one("socks5", "1.2.3.4", 99999, "fofa"))  # 非法端口

    def test_add_manual(self):
        m = self._m()
        self.assertEqual(m.add_manual("http", "5.6.7.8", 8080)["added"], 1)
        self.assertFalse(m.add_manual("ftp", "x", 1)["ok"])   # 非法 type
        r = m.add_manual("http", "5.6.7.8", 8080)             # 重复
        self.assertTrue(r["dup"])

    def test_list_pagination_status(self):
        m = self._m()
        c = m._coll()
        c.insert_one({"type": "http", "host": "a", "port": 1, "delay": 100, "enabled": True})
        c.insert_one({"type": "http", "host": "b", "port": 2, "delay": -1, "enabled": True})
        c.insert_one({"type": "http", "host": "c", "port": 3, "delay": None, "enabled": True})
        self.assertEqual(m.list_proxies(status="alive")["total"], 1)
        self.assertEqual(m.list_proxies(status="dead")["total"], 1)
        self.assertEqual(m.list_proxies(status="unchecked")["total"], 1)
        self.assertEqual(m.list_proxies()["total"], 3)
        # size 透传（禁硬限制）
        self.assertEqual(m.list_proxies(size=1000)["size"], 1000)

    def test_enable_delete(self):
        m = self._m()
        m._coll().insert_one({"_id": "x1", "type": "http", "host": "a", "port": 1, "enabled": True})
        self.assertEqual(m.set_enabled(["x1"], False)["modified"], 1)
        self.assertEqual(m.delete_proxies(["x1"])["deleted"], 1)

    def test_stats(self):
        m = self._m()
        c = m._coll()
        c.insert_one({"host": "a", "port": 1, "type": "http", "delay": 50, "enabled": True})
        c.insert_one({"host": "b", "port": 2, "type": "http", "delay": -1, "enabled": False})
        st = m.stats()
        self.assertEqual(st["total"], 2); self.assertEqual(st["alive"], 1); self.assertEqual(st["dead"], 1)

    def test_pick_best_cache(self):
        m = self._m()
        c = m._coll()
        c.insert_one({"host": "a", "port": 1, "type": "http", "url": "http://a:1", "delay": 200, "enabled": True})
        c.insert_one({"host": "b", "port": 2, "type": "http", "url": "http://b:2", "delay": 50, "enabled": True})
        self.assertEqual(m.pick_best(), "http://b:2")    # 延时最低
        # 缓存生效：删库后仍返缓存值
        c.docs.clear()
        self.assertEqual(m.pick_best(use_cache=True), "http://b:2")

    def test_verify_mock(self):
        m = self._m()
        m._coll().insert_one({"_id": "v1", "type": "socks5", "host": "1.1.1.1", "port": 1080,
                              "url": "socks5://1.1.1.1:1080", "delay": None, "fail_streak": 0, "enabled": True})
        # mock _fetch_ip：直连返 D，代理返 P（≠D=可用）
        with mock.patch.object(m, "_fetch_ip", side_effect=[("9.9.9.9", ""), ("8.8.8.8", "")]):
            r = m.verify(["v1"])
        self.assertEqual(r["checked"], 1); self.assertEqual(r["alive"], 1)
        self.assertTrue(m._coll().find_one({"_id": "v1"})["delay"] >= 0)

    def test_verify_fail_drop(self):
        m = self._m()
        m._coll().insert_one({"_id": "d1", "type": "socks5", "host": "x", "port": 1, "url": "socks5://x:1",
                              "delay": -1, "fail_streak": 2, "enabled": True})   # 已失败 2 次
        with mock.patch.object(m, "_fetch_ip", side_effect=[("9.9.9.9", ""), ("", "timeout")]):
            m.verify(["d1"])                              # 第 3 次失败 → 剔除
        self.assertIsNone(m._coll().find_one({"_id": "d1"}))

    def test_crawl_mock(self):
        m = self._m()
        m.save_config_pool({"queries": [{"source": "fofa", "type": "socks5", "q": "protocol=\"socks5\"", "enabled": True}], "limit": 10})
        with mock.patch.object(m, "_crawl_fofa", return_value=(3, "")):
            r = m.crawl()
        self.assertEqual(r["added"], 3)
        self.assertEqual(len(r["per_query"]), 1)


if __name__ == "__main__":
    unittest.main()
