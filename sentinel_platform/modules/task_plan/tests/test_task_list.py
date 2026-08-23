"""task_plan/task_list 单测 —— core 内存替身，不连真 Mongo。

覆盖：list(分页/过滤/禁硬限 size<=0 全量)、stop/resume/restart(清checkpoint)、batch_stop、
delete(级联)、sync_to_scope(经 registry 调 asset_group_service + 缺失降级)、sync_scope_candidates、
register 注册、降级。
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
        d = dict(doc); d.setdefault("_id", "t%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        out = []
        for d in self.docs:
            ok = True
            for k, v in (q or {}).items():
                if isinstance(v, dict):
                    if "$regex" in v:
                        import re
                        if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                            ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out

    def find(self, q=None, proj=None):
        return _Cursor(self._match(q))

    def update_one(self, q, update, upsert=False):
        m = self._match(q)
        if not m:
            return type("R", (), {"matched_count": 0})()
        tgt = next(d for d in self.docs if d.get("_id") == m[0].get("_id"))
        tgt.update(update.get("$set", {}))
        for k in update.get("$unset", {}):
            tgt.pop(k, None)
        return type("R", (), {"matched_count": 1})()

    def delete_one(self, q):
        before = len(self.docs); m = self._match(q)
        if m:
            self.docs = [d for d in self.docs if d.get("_id") != m[0].get("_id")]
        return type("R", (), {"deleted_count": before - len(self.docs)})()

    def delete_many(self, q):
        m = self._match(q); ids = {id(d) for d in m}
        self.docs = [d for d in self.docs if id(d) not in ids]
        return type("R", (), {"deleted_count": len(m)})()


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


class TaskListTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_register(self):
        from sentinel_platform.modules.task_plan.register import register
        reg = get_registry(); register(reg)
        self.assertIsNotNone(reg.get("task_list_service"))
        self.assertIsNotNone(reg.get("policy_service"))   # 与 policy 共存

    def _seed(self, **extra):
        from sentinel_platform.core import get_repo, models
        base = {"name": "t1", "target": "a.com", "status": models.TaskStatus.WAITING, "task_tag": "task"}
        base.update(extra)
        return str(get_repo().collection("task").insert_one(base).inserted_id)

    def test_list_filter_and_page(self):
        from sentinel_platform.modules.task_plan.task_list import list_tasks
        self._seed(name="alpha", status="done")
        self._seed(name="beta", status="waiting")
        self.assertEqual(list_tasks()["total"], 2)
        self.assertEqual(list_tasks(status="done")["total"], 1)
        self.assertEqual(list_tasks(name="alph")["total"], 1)

    def test_list_size_zero_all_no_hard_limit(self):
        from sentinel_platform.modules.task_plan.task_list import list_tasks
        for i in range(30):
            self._seed(name="t%d" % i)
        self.assertEqual(len(list_tasks(size=0)["items"]), 30)
        self.assertEqual(len(list_tasks(size=9999)["items"]), 30)

    def test_stop_resume(self):
        from sentinel_platform.modules.task_plan.task_list import stop_task, resume_task
        from sentinel_platform.core import models
        tid = self._seed()
        self.assertEqual(stop_task(tid)["status"], models.TaskStatus.STOP)
        self.assertEqual(resume_task(tid)["status"], models.TaskStatus.WAITING)

    def test_stop_nonexistent(self):
        from sentinel_platform.modules.task_plan.task_list import stop_task
        self.assertIn("error", stop_task("nope"))

    def test_restart_clears_checkpoint(self):
        from sentinel_platform.modules.task_plan.task_list import restart_task, list_tasks
        tid = self._seed(status="done", checkpoint={"done_steps": ["x"]})
        r = restart_task(tid)
        self.assertNotIn("error", r)
        doc = next(d for d in list_tasks()["items"] if d["_id"] == tid)
        self.assertNotIn("checkpoint", doc)   # checkpoint 已清（踩坑铁律）

    def test_batch_stop(self):
        from sentinel_platform.modules.task_plan.task_list import batch_stop
        ids = [self._seed(), self._seed()]
        self.assertEqual(batch_stop(ids)["stopped"], 2)

    def test_delete_with_cascade(self):
        from sentinel_platform.modules.task_plan.task_list import delete_tasks, list_tasks
        from sentinel_platform.core import get_repo
        tid = self._seed()
        get_repo().collection("site").insert_one({"task_id": tid, "site": "http://a.com"})
        get_repo().collection("domain").insert_one({"task_id": tid, "domain": "a.com"})
        r = delete_tasks([tid], del_task_data=True)
        self.assertEqual(r["deleted"], 1)
        self.assertEqual(list_tasks()["total"], 0)
        self.assertEqual(get_repo().collection("site").count_documents({"task_id": tid}), 0)  # 级联清

    def test_delete_without_cascade_keeps_results(self):
        from sentinel_platform.modules.task_plan.task_list import delete_tasks
        from sentinel_platform.core import get_repo
        tid = self._seed()
        get_repo().collection("site").insert_one({"task_id": tid, "site": "http://a.com"})
        delete_tasks([tid], del_task_data=False)
        self.assertEqual(get_repo().collection("site").count_documents({"task_id": tid}), 1)  # 保留

    # —— sync 经 registry 调 groups（闭合对接）——
    def test_sync_to_scope_via_registry(self):
        from sentinel_platform.modules.task_plan.task_list import sync_to_scope
        calls = []
        fake_groups = type("G", (), {
            "sync_task_to_scope": lambda self, t, s: calls.append((t, s)) or {"ok": True, "synced": {"domain": 3}}})()
        get_registry().register("asset_group_service", fake_groups)
        r = sync_to_scope("T1", "S1")
        self.assertTrue(r["ok"])
        self.assertEqual(calls, [("T1", "S1")])

    def test_sync_to_scope_groups_missing_degrades(self):
        from sentinel_platform.modules.task_plan.task_list import sync_to_scope
        r = sync_to_scope("T1", "S1")   # 未注册 asset_group_service
        self.assertIn("error", r)
        self.assertIn("资产分组服务未就绪", r["error"])

    def test_sync_requires_ids(self):
        from sentinel_platform.modules.task_plan.task_list import sync_to_scope
        self.assertIn("error", sync_to_scope("", "S1"))

    def test_sync_scope_candidates(self):
        from sentinel_platform.modules.task_plan.task_list import sync_scope_candidates
        from sentinel_platform.core import get_repo
        get_repo().collection("asset_scope").insert_one({"name": "G", "scope_array": ["example.com"], "scope_type": "domain"})
        r = sync_scope_candidates("www.example.com")   # 子域命中
        self.assertEqual(r["total"], 1)
        self.assertEqual(sync_scope_candidates("other.org")["total"], 0)

    def test_list_db_failure_degrades(self):
        from sentinel_platform.modules.task_plan import task_list as tl

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        self.assertEqual(tl.list_tasks()["total"], 0)


if __name__ == "__main__":
    unittest.main()
