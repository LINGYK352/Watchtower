"""计划任务执行闭环单测 —— 补净室迁移丢失的执行层（run_due/run_one）。

覆盖：①future_scan 到期→建扫描任务+转stopped(一次性) ②recurrent_scan 到期→建任务+按cron推进next_run+run_number++
③未到期不跑 ④已stopped不跑 ⑤task_create缺失降级不崩+仍推进调度态(防每tick重触发)。
内存 repo + 假 task_create_service(经 registry 注入)。
"""
import unittest

from sentinel_platform.core import set_repo, get_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.modules.task_plan import task_schedule as ts


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0
    def _match(self, d, q):
        return all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict))
    def find_one(self, q, proj=None):
        for d in self.docs:
            if self._match(d, q):
                return d
        return None
    def find(self, q, proj=None):
        return [d for d in self.docs if self._match(d, q)]
    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "s%d" % self._n)
        self.docs.append(doc)
        class _R: pass
        r = _R(); r.inserted_id = doc["_id"]; return r
    def update_one(self, q, upd):
        d = self.find_one(q)
        class _R: modified_count = 0
        r = _R()
        if d:
            d.update(upd.get("$set", {}))
            for k, inc in (upd.get("$inc") or {}).items():
                d[k] = (d.get(k, 0) or 0) + inc
            r.modified_count = 1
        return r


class _Repo:
    def __init__(self):
        self._c = {}
    def collection(self, name):
        return self._c.setdefault(name, _Coll())


class _FakeTaskCreate:
    def __init__(self):
        self.calls = []
    def create_by_policy(self, name, policy_id, target, **kw):
        self.calls.append({"target": target, "policy_id": policy_id, "tag": kw.get("task_tag")})
        return {"ok": True, "created": 1}


class TestScheduleExec(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())
        self.tc = _FakeTaskCreate()
        get_registry().register("task_create_service", self.tc)

    def tearDown(self):
        set_repo(None)
        try:
            get_registry().register("task_create_service", None)
        except Exception:
            pass

    def _seed(self, **over):
        base = {"name": "计划A", "target": "example.com", "policy_id": "p1", "task_tag": "task",
                "schedule_type": "future_scan", "status": "scheduled",
                "next_run_date": "2000-01-01 00:00:00", "run_number": 0, "cron": ""}
        base.update(over)
        get_repo().collection("task_schedule").insert_one(base)
        return base

    def test_future_scan_runs_once_then_stopped(self):
        self._seed(schedule_type="future_scan")
        r = ts.run_due()
        self.assertEqual(r["ran"], 1)
        self.assertEqual(len(self.tc.calls), 1)
        self.assertEqual(self.tc.calls[0]["target"], "example.com")
        job = get_repo().collection("task_schedule").find_one({})
        self.assertEqual(job["status"], "stopped")     # 一次性→停
        self.assertEqual(job["run_number"], 1)

    def test_recurrent_scan_advances_next_run(self):
        self._seed(schedule_type="recurrent_scan", cron="0 0 * * *")
        r = ts.run_due()
        self.assertEqual(r["ran"], 1)
        self.assertEqual(len(self.tc.calls), 1)
        job = get_repo().collection("task_schedule").find_one({})
        self.assertEqual(job["status"], "scheduled")   # 周期→继续
        self.assertEqual(job["run_number"], 1)
        self.assertNotEqual(job["next_run_date"], "2000-01-01 00:00:00")   # 推进了

    def test_not_due_skipped(self):
        self._seed(next_run_date="2099-01-01 00:00:00")
        r = ts.run_due()
        self.assertEqual(r["picked"], 0)
        self.assertEqual(len(self.tc.calls), 0)

    def test_stopped_not_run(self):
        self._seed(status="stopped")
        r = ts.run_due()
        self.assertEqual(r["picked"], 0)

    def test_task_create_missing_still_advances(self):
        get_registry().register("task_create_service", None)
        self._seed(schedule_type="future_scan")
        r = ts.run_due()
        self.assertEqual(len(self.tc.calls), 0)
        # task_create 缺失也推进调度态（防每 tick 重触发）
        job = get_repo().collection("task_schedule").find_one({})
        self.assertEqual(job["run_number"], 1)
        self.assertEqual(job["status"], "stopped")


if __name__ == "__main__":
    unittest.main()
