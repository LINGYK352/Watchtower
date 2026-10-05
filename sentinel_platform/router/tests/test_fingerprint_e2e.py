"""端到端：fingerprint 端点经核心路由（分页信封 + 规则校验 + 前端可调）。

真 Flask app + 内存 repo：GET /api/fingerprint/ 返分页信封；POST 新增合法/拒非法规则；
POST /delete/ 删除。证明前端 fingerprint.ts 能调通 + validate 在链路上生效。
"""
import unittest

from sentinel_platform.core import set_repo


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def count_documents(self, q):
        return len(self.docs)
    def find(self, q):
        self._r = list(self.docs); return self
    def sort(self, *a):
        return self
    def skip(self, n):
        self._r = self._r[n:]; return self
    def limit(self, n):
        self._r = self._r[:n]; return self
    def __iter__(self):
        return iter(self._r)
    def insert_one(self, doc):
        doc["_id"] = "fp{}".format(len(self.docs) + 1); self.docs.append(doc)
    def delete_one(self, q):
        for x in list(self.docs):
            if str(x.get("_id")) == str(q.get("_id")):
                self.docs.remove(x)
                class _R: deleted_count = 1
                return _R()
        class _R0: deleted_count = 0
        return _R0()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        # 按集合名分开（否则 access_log 审计等其他集合写入会污染 fingerprint 计数）
        return self._colls.setdefault(name, _FakeColl())


class TestFingerprintE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(_FakeRepo())
        from sentinel_platform.router import create_app
        cls.client = create_app().test_client()

    def setUp(self):
        set_repo(_FakeRepo())      # 每例重置（避免测试间污染，教训自 poc e2e）

    @classmethod
    def tearDownClass(cls):
        set_repo(None)

    def test_list_pagination_envelope(self):
        body = self.client.get("/api/fingerprint/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(set(body["data"]), {"page", "size", "total", "items"})

    def test_add_valid_then_list(self):
        r = self.client.post("/api/fingerprint/", json={"name": "WebLogic", "human_rule": 'body="WebLogic"'})
        self.assertEqual(r.get_json()["code"], 200)
        lst = self.client.get("/api/fingerprint/").get_json()
        self.assertEqual(lst["data"]["total"], 1)

    def test_add_illegal_rule_400(self):
        r = self.client.post("/api/fingerprint/", json={"name": "bad", "human_rule": 'evil="x"'})
        self.assertEqual(r.get_json()["code"], 400)
        self.assertIn("非法", r.get_json()["message"])

    def test_add_injection_rejected(self):
        r = self.client.post("/api/fingerprint/",
                             json={"name": "x", "human_rule": '__import__("os").system("id")'})
        self.assertEqual(r.get_json()["code"], 400)

    def test_delete(self):
        self.client.post("/api/fingerprint/", json={"name": "A", "human_rule": 'body="x"'})
        fid = self.client.get("/api/fingerprint/").get_json()["data"]["items"][0]["_id"]
        r = self.client.post("/api/fingerprint/delete/", json={"_id": [fid]})
        self.assertEqual(r.get_json()["code"], 200)
        self.assertEqual(r.get_json()["data"]["deleted"], 1)

    def test_swagger_includes_fingerprint(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/fingerprint/" in p for p in spec["paths"]))


if __name__ == "__main__":
    unittest.main()
