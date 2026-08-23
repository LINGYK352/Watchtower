"""端到端：poc 端点经核心路由返回分页信封（数据 API 规范证明）。

真 Flask app + 内存 repo：GET /api/poc/ 返 {code,message,data:{page,size,total,items}}，
POST /api/poc/delete/ 返 delete_cnt，POST /api/poc/sync/ 诚实降级。证明前端 poc.ts 能调通。
"""
import unittest

from sentinel_platform.core import set_repo


class _FakeColl:
    def __init__(self):
        self.docs = [{"_id": "p1", "plugin_name": "weblogic_rce", "app_name": "WebLogic",
                      "plugin_type": "poc", "scheme": "http", "vul_name": "v", "category": "rce"}]
    def count_documents(self, q):
        return len(self.docs)
    def find(self, q):
        self._r = list(self.docs); return self
    def skip(self, n):
        self._r = self._r[n:]; return self
    def limit(self, n):
        self._r = self._r[:n]; return self
    def __iter__(self):
        return iter(self._r)
    def insert_many(self, docs):
        self.docs.extend(docs)
        return type("R", (), {"inserted_ids": list(range(len(docs)))})()
    def delete_many(self, q):
        n = len(self.docs); self.docs = []
        class _R: deleted_count = n
        return _R()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        # 按集合名分开（access_log 审计等其他集合写入不污染 poc 计数）
        return self._colls.setdefault(name, _FakeColl())


class TestPocE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(_FakeRepo())
        from sentinel_platform.router import create_app
        cls.client = create_app().test_client()

    def setUp(self):
        # 每个测试用例前重置 repo（delete 测试会清空，避免污染 list 测试；测试隔离）
        set_repo(_FakeRepo())

    @classmethod
    def tearDownClass(cls):
        set_repo(None)

    def test_list_pagination_envelope(self):
        body = self.client.get("/api/poc/").get_json()
        self.assertEqual(body["code"], 200)
        d = body["data"]
        self.assertEqual(set(d), {"page", "size", "total", "items"})  # 数据 API 规范
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["items"][0]["plugin_name"], "weblogic_rce")

    def test_list_query_filter(self):
        body = self.client.get("/api/poc/?plugin_type=poc").get_json()
        self.assertEqual(body["code"], 200)

    def test_sync_plugins(self):
        from unittest import mock
        record = {"plugin_name": "Demo", "app_name": "Demo", "scheme": "http",
                  "vul_name": "Demo", "plugin_type": "poc", "category": "漏洞PoC"}
        with mock.patch("sentinel_platform.modules.risk_intel.poc._locate_plugins_dir", return_value="/tmp/plugins"), \
             mock.patch("sentinel_platform.modules.risk_intel.poc._scan_plugins", return_value=[record]):
            body = self.client.post("/api/poc/sync/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["data"]["plugin_cnt"], 1)

    def test_delete_returns_count(self):
        body = self.client.post("/api/poc/delete/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["data"]["delete_cnt"], 1)

    def test_swagger_includes_poc(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/poc/" in p for p in spec["paths"]))


if __name__ == "__main__":
    unittest.main()
