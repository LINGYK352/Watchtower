"""proxy pool 端点 e2e —— 真起 app，test_client 打 /api/proxy/pool/*，验证从桩转真实不孤岛。

链路：前端(proxy.ts poolList/poolCrawl/...) → 网关 → endpoint(proxy ns pool 段) → registry 取
"proxy_pool_service"（system/_pool）→ 信封。用内存替身 seed proxy_pool，crawl/verify mock 不发网。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo, get_repo
from sentinel_platform.router import create_app
from sentinel_platform.contracts import Collections


class _Coll:
    def __init__(self):
        self.docs = []; self._n = 0
    def find_one(self, q, proj=None, sort=None):
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def find(self, q=None, proj=None):
        docs = list(self.docs)
        class C:
            def sort(s, *a): return s
            def skip(s, n): s.d = docs[n:]; return s
            def limit(s, n): s.d = getattr(s, "d", docs)[:n] if n else getattr(s, "d", docs); return s
            def __iter__(s): return iter(getattr(s, "d", docs))
        return C()
    def insert_one(self, d):
        self._n += 1; d.setdefault("_id", "p%d" % self._n); self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()
    def update_one(self, q, u, upsert=False):
        if upsert and not self.docs:
            self.docs.append(dict(q))
        for d in self.docs:
            d.update(u.get("$set") or {})
        return type("R", (), {"modified_count": len(self.docs)})()
    def count_documents(self, q=None):
        return len(self.docs)


class _Repo(Repository):
    def __init__(self):
        self._c = {}
    def collection(self, name):
        return self._c.setdefault(name, _Coll())


class ProxyPoolEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app(); cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo(); set_repo(_Repo())

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        b = resp.get_json(); self.assertEqual(b["code"], code); return b["data"]

    def test_swagger_has_pool_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        for p in ("/proxy/pool/list", "/proxy/pool/crawl", "/proxy/pool/verify",
                  "/proxy/pool/enable", "/proxy/pool/delete", "/proxy/pool/add", "/proxy/pool/config"):
            self.assertTrue(any(p in path for path in spec["paths"]), "缺 %s" % p)

    def test_pool_list_real_not_stub(self):
        # 之前是 _phase2 桩返 {phase2:true}；现应走真实服务返 {items,total,page,size}
        data = self._data(self.client.get("/api/proxy/pool/list"))
        self.assertIn("items", data); self.assertIn("total", data)
        self.assertNotIn("phase2", data)           # 不再是桩

    def test_pool_stats(self):
        data = self._data(self.client.get("/api/proxy/pool/stats"))
        self.assertIn("alive", data); self.assertNotIn("phase2", data)

    def test_pool_add(self):
        data = self._data(self.client.post("/api/proxy/pool/add",
                                           json={"type": "http", "host": "1.2.3.4", "port": 8080}))
        self.assertTrue(data["added"] >= 0)

    def test_pool_add_missing_400(self):
        r = self.client.post("/api/proxy/pool/add", json={"type": "http"})
        self.assertEqual(r.status_code, 400)

    def test_pool_config_get_post(self):
        data = self._data(self.client.get("/api/proxy/pool/config"))
        self.assertIn("queries", data)
        d2 = self._data(self.client.post("/api/proxy/pool/config", json={"limit": 300}))
        self.assertEqual(d2["limit"], 300)

    def test_pool_crawl(self):
        # mock 抓取器不发网
        import sentinel_platform.modules.system._pool as pool
        with mock.patch.object(pool, "_crawl_fofa", return_value=(2, "")):
            data = self._data(self.client.post("/api/proxy/pool/crawl"))
        self.assertIn("added", data)

    def test_pool_verify_empty_ids(self):
        import sentinel_platform.modules.system._pool as pool
        with mock.patch.object(pool, "_fetch_ip", return_value=("", "no proxies")):
            data = self._data(self.client.post("/api/proxy/pool/verify", json={"ids": []}))
        self.assertIn("checked", data)

    def test_pool_enable_missing_400(self):
        r = self.client.post("/api/proxy/pool/enable", json={"enabled": True})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
