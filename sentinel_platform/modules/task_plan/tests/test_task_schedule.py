"""task_schedule 叶子单测 —— cron 校验/CRUD/启停/无硬限制，注入内存 repo。

覆盖：①validate_cron(croniter 本地库)②future/recurrent 新建校验 ③非法类型/tag/cron 拒
④分页 size 无硬上限 ⑤stop/recover/delete ⑥policy_name 反查。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.task_plan import task_schedule as ts


class _FakeColl:
    def __init__(self, docs=None):
        self.docs = list(docs or [])
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
        return self._colls.setdefault(name, _FakeColl())


class TestCron(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(ts.validate_cron("0 2 * * *"))

    def test_invalid(self):
        self.assertFalse(ts.validate_cron("not a cron"))
        self.assertFalse(ts.validate_cron(""))

    def test_next_run(self):
        self.assertGreater(ts.next_run_epoch("0 2 * * *"), 0)

    def test_interval_ok_default_no_limit(self):
        # 默认 min=0 → 恒放行（禁硬限制参数）
        self.assertTrue(ts.check_interval_ok("* * * * *"))


class TestScheduleCRUD(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())
        # 种一个 policy 供反查
        get = __import__("sentinel_platform.core", fromlist=["get_repo"]).get_repo
        get().collection("policy").insert_one({"name": "默认策略"})

    def tearDown(self):
        set_repo(None)

    def _policy_id(self):
        from sentinel_platform.core import get_repo
        return get_repo().collection("policy").docs[0]["_id"]

    def test_add_recurrent(self):
        r = ts.add_schedule({"name": "每日扫", "target": "a.com", "schedule_type": "recurrent_scan",
                             "task_tag": "task", "policy_id": self._policy_id(), "cron": "0 2 * * *"})
        self.assertNotIn("error", r)
        lst = ts.list_schedules({})
        self.assertEqual(lst["total"], 1)
        self.assertEqual(lst["items"][0]["policy_name"], "默认策略")   # 反查生效
        self.assertEqual(lst["items"][0]["status"], "scheduled")

    def test_add_future(self):
        r = ts.add_schedule({"name": "定时", "target": "a.com", "schedule_type": "future_scan",
                             "task_tag": "task", "policy_id": self._policy_id(), "start_date": "2099-01-01 00:00:00"})
        self.assertNotIn("error", r)

    def test_add_bad_type(self):
        self.assertIn("error", ts.add_schedule({"name": "x", "target": "a", "schedule_type": "bad",
                                                "task_tag": "task", "policy_id": self._policy_id()}))

    def test_add_bad_tag(self):
        self.assertIn("error", ts.add_schedule({"name": "x", "target": "a", "schedule_type": "future_scan",
                                                "task_tag": "bad", "policy_id": self._policy_id(), "start_date": "2099-01-01 00:00:00"}))

    def test_add_bad_cron(self):
        self.assertIn("error", ts.add_schedule({"name": "x", "target": "a", "schedule_type": "recurrent_scan",
                                                "task_tag": "task", "policy_id": self._policy_id(), "cron": "garbage"}))

    def test_add_missing_target(self):
        self.assertIn("error", ts.add_schedule({"name": "x", "target": "", "schedule_type": "future_scan",
                                                "task_tag": "task", "policy_id": self._policy_id()}))

    def test_stop_recover(self):
        ts.add_schedule({"name": "s", "target": "a", "schedule_type": "recurrent_scan",
                        "task_tag": "task", "policy_id": self._policy_id(), "cron": "0 2 * * *"})
        sid = ts.list_schedules({})["items"][0]["_id"]
        self.assertEqual(ts.stop_schedules([sid])["modified"], 1)
        self.assertEqual(ts.list_schedules({})["items"][0]["status"], "stopped")
        self.assertEqual(ts.recover_schedules([sid])["modified"], 1)
        self.assertEqual(ts.list_schedules({})["items"][0]["status"], "scheduled")

    def test_delete(self):
        ts.add_schedule({"name": "s", "target": "a", "schedule_type": "future_scan",
                        "task_tag": "task", "policy_id": self._policy_id(), "start_date": "2099-01-01 00:00:00"})
        sid = ts.list_schedules({})["items"][0]["_id"]
        self.assertEqual(ts.delete_schedules([sid])["deleted"], 1)
        self.assertEqual(ts.list_schedules({})["total"], 0)

    def test_delete_empty(self):
        self.assertIn("error", ts.delete_schedules([]))

    def test_list_no_hard_cap(self):
        self.assertEqual(ts.list_schedules({"size": 99999})["size"], 99999)


if __name__ == "__main__":
    unittest.main()
