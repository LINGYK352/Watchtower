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
        return [d for d in self.docs if self._doc_ok(d, q or {})]

    def _doc_ok(self, d, q):
        for k, v in q.items():
            if k == "$and":
                if not all(self._doc_ok(d, sub) for sub in v):
                    return False
                continue
            if isinstance(v, dict):
                if "$regex" in v and not __import__("re").search(v["$regex"], str(d.get(k, "")), __import__("re").I):
                    return False
                if "$exists" in v:
                    present = k in d
                    if present != bool(v["$exists"]):
                        return False
                if "$nin" in v:
                    # 缺失字段视为 None（与 Mongo 语义一致：$nin 命中不含该值/缺失）
                    if d.get(k) in v["$nin"]:
                        return False
                if "$in" in v:
                    if d.get(k) not in v["$in"]:
                        return False
            elif d.get(k) != v:
                return False
        return True

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

    def test_stop_task_cascades_to_sessions(self):
        """治 #8：停止任务连带停派发的渗透会话（否则子会话继续跑+产漏洞）。
        注册 fake PENTEST_DISPATCH，验证 stop_task 调 stop_sessions_by_task。"""
        from sentinel_platform.modules.task_plan.task_list import stop_task
        from sentinel_platform.contracts import ROLE
        calls = {"stopped_task": None}
        class _FakeDispatch:
            def stop_sessions_by_task(self, task_id, only_active=True):
                calls["stopped_task"] = task_id
                return {"stopped": 3, "task_id": task_id}
        get_registry().register(ROLE.PENTEST_DISPATCH, _FakeDispatch())
        tid = self._seed()
        r = stop_task(tid)
        self.assertEqual(calls["stopped_task"], tid, "停止任务必须连带调 stop_sessions_by_task")
        self.assertEqual(r.get("sessions_stopped"), 3)

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

    # —— 孤儿资产清理（core 缺陷修复：区分"查库失败假空"与"任务真为0"）——
    def test_orphan_purge_normal(self):
        """有现存任务：只删 task_id 指向已删任务的记录，存活任务的资产 + 无 task_id 资产保留。"""
        from sentinel_platform.modules.task_plan.task_list import purge_orphan_assets
        from sentinel_platform.core import get_repo
        live = self._seed(name="live")                          # 存活任务
        get_repo().collection("site").insert_one({"task_id": live, "site": "keep"})       # 存活任务资产→保留
        get_repo().collection("site").insert_one({"task_id": "gone999", "site": "orphan"})  # 指向已删任务→孤儿
        get_repo().collection("site").insert_one({"site": "manual"})                       # 无 task_id→绝不删
        get_repo().collection("site").insert_one({"task_id": "", "site": "empty"})         # 空 task_id→绝不删
        r = purge_orphan_assets()
        self.assertEqual(r["purged"], 1)                        # 只删了 1 条孤儿
        sites = [d["site"] for d in get_repo().collection("site").find({})]
        self.assertIn("keep", sites); self.assertIn("manual", sites); self.assertIn("empty", sites)
        self.assertNotIn("orphan", sites)

    def test_orphan_purge_when_no_task_still_cleans(self):
        """**核心修复**：任务全删光时不再跳过——带 task_id 的资产按定义就是孤儿，应清理；
        无/空 task_id 的合法资产仍保留。旧逻辑此处误跳过（用户质疑点）。"""
        from sentinel_platform.modules.task_plan.task_list import purge_orphan_assets, scan_orphan_assets
        from sentinel_platform.core import get_repo
        # 不 seed 任何任务（task 集合空但可查）
        get_repo().collection("site").insert_one({"task_id": "gone1", "site": "orphan1"})
        get_repo().collection("domain").insert_one({"task_id": "gone2", "domain": "orphan2"})
        get_repo().collection("site").insert_one({"site": "manual"})            # 无 task_id→保留
        # scan 与 purge 判据一致：都能看到孤儿
        scanned = scan_orphan_assets()
        self.assertTrue(scanned["purgeable"])
        self.assertEqual(scanned["total"], 2)
        self.assertEqual(scanned["live_task_count"], 0)
        r = purge_orphan_assets()
        self.assertNotIn("skipped", r)                          # 不再跳过
        self.assertEqual(r["purged"], 2)                        # 两条孤儿都清了
        self.assertEqual(get_repo().collection("site").count_documents({"site": "manual"}), 1)  # 合法资产保留

    def test_orphan_purge_skips_only_on_query_failure(self):
        """查库失败（非任务为0）：保守跳过防误删，且 scan 也不谎报孤儿（判据统一）。"""
        from sentinel_platform.modules.task_plan import task_list as tl

        real_repo = tl.get_repo()
        class _TaskBoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                if name == "task":                               # 只让任务查询失败
                    raise RuntimeError("task coll down")
                return real_repo.collection(name)
        # 先塞一条带 task_id 的资产（若误判成孤儿会被删）
        real_repo.collection("site").insert_one({"task_id": "x", "site": "should_survive"})
        set_repo(_TaskBoomRepo())
        r = tl.purge_orphan_assets()
        self.assertEqual(r.get("skipped"), "task_query_failed")  # 查库失败→跳过
        self.assertEqual(r["purged"], 0)
        scanned = tl.scan_orphan_assets()
        self.assertFalse(scanned["purgeable"])                   # scan 不谎报
        self.assertEqual(scanned["total"], 0)
        # 资产未被误删
        self.assertEqual(real_repo.collection("site").count_documents({"site": "should_survive"}), 1)

    def test_list_by_id_exact(self):
        """v1.21.157-48 item8b：详情页按 _id 取单任务（此前被忽略拿到最新任务）。"""
        from sentinel_platform.core import get_repo, models
        from sentinel_platform.modules.task_plan.task_list import list_tasks
        c = get_repo().collection(models.Collections.TASK if hasattr(models, "Collections") else "task")
        c.insert_one({"name": "老任务", "status": "done", "target": "a.com"})
        c.insert_one({"name": "新任务", "status": "running", "target": "b.com"})
        # 不传 _id → 最新(新任务)在前
        first = list_tasks()["items"][0]
        self.assertEqual(first["name"], "新任务")
        # 传老任务 _id → 精确拿老任务（不是最新）
        old_id = [d["_id"] for d in c.docs if d["name"] == "老任务"][0]
        r = list_tasks(_id=str(old_id))
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["name"], "老任务")

    def test_compute_statistic_counts_ai_findings(self):
        """v1.21.157-48 item8c：任务漏洞数含 AI 渗透漏洞（两跳 session→intel_finding），此前恒漏。"""
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.task_plan.task_list import _compute_statistic
        repo = get_repo()
        tid = "task_ai_1"
        # 该任务派发的会话 + 会话下的 AI 漏洞（intel_finding 只带 session_id 无 task_id）
        repo.collection("intel_pentest_session").insert_one({"_id": "sess_a", "source_task_id": tid})
        repo.collection("intel_finding").insert_one({"session_id": "sess_a", "status": "finding", "source": "ai"})
        repo.collection("intel_finding").insert_one({"session_id": "sess_a", "status": "finding", "source": "ai"})
        repo.collection("intel_finding").insert_one({"session_id": "sess_a", "status": "lead", "source": "ai"})  # 线索不计
        st = _compute_statistic(tid)
        self.assertEqual(st["vuln_cnt"], 2)   # 2 个 finding（lead 不计），此前恒 0


if __name__ == "__main__":
    unittest.main()
