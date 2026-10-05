"""端到端：task_schedule 端点经核心路由（分页信封 + cron 校验 + 前端可调）。

真 Flask app + 内存 repo（按集合名分开，避免 access_log 审计污染计数）。
"""
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
        doc["_id"] = "s{}".format(len(self.docs) + 1); self.docs.append(doc)
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            class _R: modified_count = 1
            return _R()
        class _R0: modified_count = 0
        return _R0()
    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)
            class _R: deleted_count = 1
            return _R()
        class _R0: deleted_count = 0
        return _R0()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        # 按集合名分开（access_log 审计等不污染 task_schedule 计数）
        return self._colls.setdefault(name, _FakeColl())


class TestTaskScheduleE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(_FakeRepo())
        from sentinel_platform.router import create_app
        cls.client = create_app().test_client()

    def setUp(self):
        r = _FakeRepo()
        r.collection("policy").insert_one({"name": "默认策略"})
        set_repo(r)
        self._pid = r.collection("policy").docs[0]["_id"]

    @classmethod
    def tearDownClass(cls):
        set_repo(None)

    def test_list_pagination_envelope(self):
        body = self.client.get("/api/task_schedule/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(set(body["data"]), {"page", "size", "total", "items"})

    def test_add_recurrent_then_list(self):
        r = self.client.post("/api/task_schedule/", json={
            "name": "每日", "target": "a.com", "schedule_type": "recurrent_scan",
            "task_tag": "task", "policy_id": self._pid, "cron": "0 2 * * *"})
        self.assertEqual(r.get_json()["code"], 200)
        lst = self.client.get("/api/task_schedule/").get_json()
        self.assertEqual(lst["data"]["total"], 1)      # 无双 insert

    def test_add_bad_cron_400(self):
        r = self.client.post("/api/task_schedule/", json={
            "name": "x", "target": "a", "schedule_type": "recurrent_scan",
            "task_tag": "task", "policy_id": self._pid, "cron": "garbage"})
        self.assertEqual(r.get_json()["code"], 400)

    def test_stop_recover_delete(self):
        self.client.post("/api/task_schedule/", json={
            "name": "s", "target": "a", "schedule_type": "recurrent_scan",
            "task_tag": "task", "policy_id": self._pid, "cron": "0 2 * * *"})
        sid = self.client.get("/api/task_schedule/").get_json()["data"]["items"][0]["_id"]
        self.assertEqual(self.client.post("/api/task_schedule/stop/", json={"_id": [sid]}).get_json()["code"], 200)
        self.assertEqual(self.client.post("/api/task_schedule/recover/", json={"_id": [sid]}).get_json()["code"], 200)
        self.assertEqual(self.client.post("/api/task_schedule/delete/", json={"_id": [sid]}).get_json()["data"]["deleted"], 1)

    def test_swagger_includes_schedule(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/task_schedule/" in p for p in spec["paths"]))


if __name__ == "__main__":
    unittest.main()
