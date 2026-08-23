"""端到端：github_scheduler/github_monitor_result 端点经核心路由（信封 + cron 校验 + 前端可调）。"""
import unittest

from sentinel_platform.core import set_repo


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find_one(self, q):
        for d in self.docs:
            if all(str(d.get(k)) == str(v) for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def count_documents(self, q):
        return len(self._filter(q))
    def _filter(self, q):
        import re
        out = []
        for d in self.docs:
            ok = True
            for k, v in q.items():
                if isinstance(v, dict) and "$regex" in v:
                    if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                        ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out
    def find(self, q):
        self._r = self._filter(q); return self
    def sort(self, *a):
        return self
    def skip(self, n):
        self._r = self._r[n:]; return self
    def limit(self, n):
        self._r = self._r[:n]; return self
    def __iter__(self):
        return iter(self._r)
    def insert_one(self, doc):
        doc["_id"] = "m%d" % (len(self.docs) + 1); self.docs.append(doc)
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            class _R: matched_count = 1; modified_count = 1
            return _R()
        class _R0: matched_count = 0; modified_count = 0
        return _R0()
    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)
            class _R: deleted_count = 1
            return _R()
        class _R0: deleted_count = 0
        return _R0()
    def delete_many(self, q):
        keep, n = [], 0
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                n += 1
            else:
                keep.append(d)
        self.docs = keep
        class _R: deleted_count = n
        return _R()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


class TestGithubMonitorE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(_FakeRepo())
        from sentinel_platform.router import create_app
        cls.client = create_app().test_client()

    def setUp(self):
        set_repo(_FakeRepo())

    @classmethod
    def tearDownClass(cls):
        set_repo(None)

    def test_monitor_list_envelope(self):
        body = self.client.get("/api/github_scheduler/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(set(body["data"]), {"page", "size", "total", "items"})

    def test_add_then_list(self):
        r = self.client.post("/api/github_scheduler/", json={"name": "监控", "keyword": "AKIA", "cron": "0 2 * * *"})
        self.assertEqual(r.get_json()["code"], 200)
        self.assertEqual(self.client.get("/api/github_scheduler/").get_json()["data"]["total"], 1)

    def test_add_bad_cron_400(self):
        r = self.client.post("/api/github_scheduler/", json={"name": "x", "keyword": "k", "cron": "garbage"})
        self.assertEqual(r.get_json()["code"], 400)

    def test_update_stop_recover_delete(self):
        self.client.post("/api/github_scheduler/", json={"keyword": "kw", "cron": "0 2 * * *"})
        mid = self.client.get("/api/github_scheduler/").get_json()["data"]["items"][0]["_id"]
        self.assertEqual(self.client.post("/api/github_scheduler/update/", json={"_id": mid, "keyword": "kw2"}).get_json()["code"], 200)
        self.assertEqual(self.client.post("/api/github_scheduler/stop/", json={"_id": [mid]}).get_json()["code"], 200)
        self.assertEqual(self.client.post("/api/github_scheduler/recover/", json={"_id": [mid]}).get_json()["code"], 200)
        self.assertEqual(self.client.post("/api/github_scheduler/delete/", json={"_id": [mid]}).get_json()["data"]["deleted"], 1)

    def test_monitor_result_list(self):
        body = self.client.get("/api/github_monitor_result/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("items", body["data"])

    def test_swagger_includes(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/github_scheduler/" in p for p in spec["paths"]))
        self.assertTrue(any("/github_monitor_result/" in p for p in spec["paths"]))


if __name__ == "__main__":
    unittest.main()
