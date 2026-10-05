"""github_monitor 叶子单测 —— cron 校验/CRUD/更新/启停/级联删/无硬限制，注入内存 repo。"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.asset import github_monitor as gm


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


class TestGithubMonitor(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())

    def tearDown(self):
        set_repo(None)

    def test_cron_valid_invalid(self):
        self.assertTrue(gm.validate_cron("0 */6 * * *"))
        self.assertFalse(gm.validate_cron("nope"))

    def test_add_and_list(self):
        r = gm.add_monitor("监控密钥", "AKIA", "0 2 * * *")
        self.assertNotIn("error", r)
        self.assertEqual(r["status"], "running")
        lst = gm.list_monitors({})
        self.assertEqual(lst["total"], 1)
        self.assertEqual(set(lst), {"page", "size", "total", "items"})

    def test_add_empty_keyword(self):
        self.assertIn("error", gm.add_monitor("x", "", "0 2 * * *"))

    def test_add_bad_cron(self):
        self.assertIn("error", gm.add_monitor("x", "kw", "garbage"))

    def test_add_name_defaults_keyword(self):
        self.assertEqual(gm.add_monitor("", "pw", "0 2 * * *")["name"], "pw")

    def test_update(self):
        gm.add_monitor("m", "kw", "0 2 * * *")
        mid = gm.list_monitors({})["items"][0]["_id"]
        self.assertNotIn("error", gm.update_monitor(mid, keyword="newkw"))
        self.assertEqual(gm.list_monitors({})["items"][0]["keyword"], "newkw")

    def test_update_bad_cron(self):
        gm.add_monitor("m", "kw", "0 2 * * *")
        mid = gm.list_monitors({})["items"][0]["_id"]
        self.assertIn("error", gm.update_monitor(mid, cron="bad"))

    def test_update_nonexistent(self):
        self.assertIn("error", gm.update_monitor("nope", keyword="x"))

    def test_stop_recover(self):
        gm.add_monitor("m", "kw", "0 2 * * *")
        mid = gm.list_monitors({})["items"][0]["_id"]
        self.assertEqual(gm.stop_monitors([mid])["modified"], 1)
        self.assertEqual(gm.list_monitors({})["items"][0]["status"], "stopped")
        self.assertEqual(gm.recover_monitors([mid])["modified"], 1)
        self.assertEqual(gm.list_monitors({})["items"][0]["status"], "running")

    def test_delete_cascades_results(self):
        gm.add_monitor("m", "kw", "0 2 * * *")
        mid = gm.list_monitors({})["items"][0]["_id"]
        from sentinel_platform.core import get_repo
        get_repo().collection("github_monitor_result").insert_one({"github_scheduler_id": mid, "url": "x"})
        r = gm.delete_monitors([mid])
        self.assertEqual(r["deleted"], 1)
        self.assertEqual(r["results_deleted"], 1)

    def test_delete_empty(self):
        self.assertIn("error", gm.delete_monitors([]))

    def test_list_results_filter(self):
        from sentinel_platform.core import get_repo
        get_repo().collection("github_monitor_result").insert_one({"github_scheduler_id": "m1", "url": "a"})
        get_repo().collection("github_monitor_result").insert_one({"github_scheduler_id": "m2", "url": "b"})
        self.assertEqual(gm.list_results({"github_scheduler_id": "m1"})["total"], 1)

    def test_list_no_hard_cap(self):
        self.assertEqual(gm.list_monitors({"size": 88888})["size"], 88888)


if __name__ == "__main__":
    unittest.main()
