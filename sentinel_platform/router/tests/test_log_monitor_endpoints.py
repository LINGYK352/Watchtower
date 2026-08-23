"""log_monitor 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封）。

证明不孤岛：端点挂进 swagger + GET/POST 走 log_service + 信封 + retention 往返（闭合 access_log retention 遗留）。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        d = dict(doc); d.setdefault("_id", "id%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len([d for d in self.docs if all(d.get(k) == v for k, v in (q or {}).items() if not isinstance(v, dict))])

    def find(self, q):
        return _Cursor(self.docs)

    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in (q or {}).items()):
                return dict(d)
        return None

    def update_one(self, q, update, upsert=False):
        doc = self.find_one(q)
        if doc is None and upsert:
            doc = dict(q); self.docs.append(doc)
        if doc is not None:
            doc.update(update.get("$set", {}))

    def create_index(self, *a, **k):
        return "idx"

    @property
    def database(self):
        return type("DB", (), {"command": lambda *a, **k: (_ for _ in ()).throw(Exception("no collmod"))})()


class _Cursor(list):
    def sort(self, *a, **k):
        return _Cursor(reversed(self))

    def skip(self, n):
        return _Cursor(list(self)[n:])

    def limit(self, n):
        return _Cursor(list(self)[:n])


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _MemColl())


class LogMonitorE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_endpoints_in_swagger(self):
        spec = self.client.get("/api/swagger.json").get_json()
        paths = spec.get("paths", {})
        self.assertIn("/log_monitor/", paths)
        self.assertIn("/log_monitor/stat/", paths)
        self.assertIn("/log_monitor/retention/", paths)

    def test_stat_envelope(self):
        body = self.client.get("/api/log_monitor/stat/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("total", body["data"])

    def test_list_envelope(self):
        body = self.client.get("/api/log_monitor/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("items", body["data"])

    def test_retention_roundtrip(self):
        # 查默认
        got = self.client.get("/api/log_monitor/retention/").get_json()
        self.assertEqual(got["code"], 200)
        self.assertIn("access_log", got["data"])
        # 设 1000 天（无上限，禁硬限验证）
        saved = self.client.post("/api/log_monitor/retention/", json={"access_log": 1000}).get_json()
        self.assertEqual(saved["code"], 200)
        self.assertEqual(saved["data"]["access_log"]["days"], 1000)

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/log_monitor/stat/").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
