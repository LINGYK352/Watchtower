"""guard_log 端点 e2e —— 真起 app，test_client 打 /api/log_monitor/guard/*，验证不孤岛。

链路：前端(GuardLog.vue/api logMonitor.ts guardLogApi) → 网关 → endpoint(guard_log ns) →
registry 取 "guard_log_service"（字符串键）→ guard_log 叶子 → 信封 {code,message,data}。
用内存 Mongo 替身（无 .database → 触发 capped 优雅降级），验证 CRUD 全链路 + 禁硬限制(size 透传)。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.contracts import Collections


def _match(doc, query):
    for k, v in (query or {}).items():
        if doc.get(k) != v:
            return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
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


class GuardLogEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = _Repo()
        set_repo(self.repo)
        # 经叶子门面直接 seed 几条（模拟闸刀写入）
        from sentinel_platform.modules.system.guard_log import GuardLogServiceImpl
        g = GuardLogServiceImpl()
        from sentinel_platform.modules.system import guard_log as gm
        gm._ensured["size_bytes"] = 0
        g.record("POST", "http://t/delete", "src", allow=False, level="danger", reason="删库")
        g.record("GET", "http://t/info", "src", allow=True, level="safe")

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    def test_swagger_contains_guard_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/log_monitor/guard" in p for p in spec["paths"]),
                        "guard 端点应进 OpenAPI 规范")

    def test_list(self):
        data = self._data(self.client.get("/api/log_monitor/guard/"))
        self.assertEqual(data["total"], 2)
        # capped 最新在前
        self.assertEqual(data["items"][0]["method"], "GET")

    def test_list_filter_blocked(self):
        data = self._data(self.client.get("/api/log_monitor/guard/?allow=0"))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["level"], "danger")

    def test_stat(self):
        data = self._data(self.client.get("/api/log_monitor/guard/stat/"))
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["blocked"], 1)
        self.assertEqual(data["allowed"], 1)
        self.assertEqual(data["size_mb"], 500)

    def test_set_size(self):
        data = self._data(self.client.post("/api/log_monitor/guard/size/", json={"size_mb": 800}))
        self.assertEqual(data["size_mb"], 800)         # 无上限透传

    def test_set_size_missing_400(self):
        resp = self.client.post("/api/log_monitor/guard/size/", json={})
        self.assertEqual(resp.status_code, 400)

    # —— 禁硬限制：list size 传大值透传不砍 ——
    def test_list_no_hard_limit(self):
        from sentinel_platform.modules.system.guard_log import GuardLogServiceImpl
        g = GuardLogServiceImpl()
        for i in range(40):
            g.record("GET", "u{}".format(i), "src", allow=True, level="safe")
        data = self._data(self.client.get("/api/log_monitor/guard/?size=1000"))
        self.assertEqual(data["size"], 1000)
        self.assertEqual(len(data["items"]), data["total"])
        self.assertTrue(data["total"] >= 42)


if __name__ == "__main__":
    unittest.main()
