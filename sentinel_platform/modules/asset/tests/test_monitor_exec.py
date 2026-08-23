"""资产监控执行闭环单测 —— 补净室迁移丢失的监控执行层（run_due/run_one）。

覆盖：①域名监控到期→经 task_create 建扫描任务 + 推进 next_run/run_number ②未到期不跑
③无 policy_id 跳过不崩 ④站点/WIH 监控诚实降级(pending，不伪造执行) ⑤stop 状态不跑。
内存 repo + 假 task_create_service（经 registry 注入）。
"""
import unittest

from sentinel_platform.core import set_repo, get_repo, models
from sentinel_platform.contracts import get_registry
from sentinel_platform.modules.asset import monitor as mon


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0
    def _match(self, d, q):
        for k, v in q.items():
            if isinstance(v, dict):
                continue
            if d.get(k) != v:
                return False
        return True
    def find_one(self, q, proj=None):
        for d in self.docs:
            if self._match(d, q):
                return d
        return None
    def find(self, q, proj=None):
        return [d for d in self.docs if self._match(d, q)]
    def count_documents(self, q):
        return len([d for d in self.docs if self._match(d, q)])
    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "j%d" % self._n)
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
    """假 task_create_service：记录 create_by_policy 调用，返回 created:1。"""
    def __init__(self):
        self.calls = []
    def create_by_policy(self, name, policy_id, target, **kw):
        self.calls.append({"name": name, "policy_id": policy_id, "target": target, "kw": kw})
        return {"ok": True, "created": 1}


class TestMonitorExec(unittest.TestCase):
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
        base = {"scope_type": "domain", "domain": "example.com",
                "monitor_options": {"policy_id": "p1"}, "interval": mon.MIN_INTERVAL,
                "status": models.SchedulerStatus.RUNNING, "next_run_time": 1, "run_number": 0,
                "name": "监控-example.com"}
        base.update(over)
        get_repo().collection("scheduler").insert_one(base)
        return base

    def test_domain_monitor_due_creates_scan_task(self):
        self._seed()
        r = mon.run_due()
        self.assertEqual(r["picked"], 1)
        self.assertEqual(r["ran"], 1)
        # 真调了 task_create.create_by_policy
        self.assertEqual(len(self.tc.calls), 1)
        self.assertEqual(self.tc.calls[0]["target"], "example.com")
        self.assertEqual(self.tc.calls[0]["policy_id"], "p1")
        # next_run 推进 + run_number++
        job = get_repo().collection("scheduler").find_one({"scope_type": "domain"})
        self.assertEqual(job["run_number"], 1)
        self.assertGreater(job["next_run_time"], 1)

    def test_not_due_skipped(self):
        import time as _t
        self._seed(next_run_time=_t.time() + 99999)   # 未来
        r = mon.run_due()
        self.assertEqual(r["picked"], 0)
        self.assertEqual(len(self.tc.calls), 0)

    def test_domain_no_policy_skipped_not_crash(self):
        self._seed(monitor_options={})   # 无 policy_id
        r = mon.run_due()
        self.assertEqual(r["picked"], 1)   # 到期了扫到
        self.assertEqual(len(self.tc.calls), 0)   # 但没建任务
        # 仍推进 next_run（防每 tick 重扫）
        self.assertEqual(get_repo().collection("scheduler").find_one({})["run_number"], 1)

    def test_site_monitor_honest_degrade(self):
        self._seed(scope_type="site_update_monitor", domain="", monitor_options={})
        r = mon.run_due()
        self.assertEqual(r["picked"], 1)
        self.assertEqual(len(self.tc.calls), 0)   # 不伪造执行
        # 诚实降级：run_one 返 pending
        job = get_repo().collection("scheduler").find_one({})
        self.assertEqual(job["run_number"], 1)   # 只推进调度

    def test_stopped_monitor_not_run(self):
        self._seed(status=models.SchedulerStatus.STOP)
        r = mon.run_due()
        self.assertEqual(r["picked"], 0)
        self.assertEqual(len(self.tc.calls), 0)


if __name__ == "__main__":
    unittest.main()
