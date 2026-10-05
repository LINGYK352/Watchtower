"""orchestration phase-2 绑定单测 —— 执行器/submit_task/run_waiting_tasks/scan handler。

不需真 celery（核心零 celery 依赖）：用同步执行器（set_executor）让投递立即执行、断言确定。
覆盖：submit_task 入队+已停止不投、run_waiting_tasks 只捡 waiting、默认 handler 驱动 RECON+缺失降级、
协作式取消不被 phase-2 破坏、OrchestrationService 门面暴露 submit_task/run_waiting_tasks、
celery 适配 delay hook 优先。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo, get_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.registry import reset_registry
from sentinel_platform.modules.kernel import orchestration as o


class _Cursor(list):
    def sort(self, key_or_spec=None, direction=None):
        if isinstance(key_or_spec, str):
            super().sort(key=lambda d: (d.get(key_or_spec) is None, d.get(key_or_spec) or 0),
                         reverse=(direction or 1) < 0)
        elif key_or_spec:
            for key, order in reversed(key_or_spec):
                super().sort(key=lambda d: d.get(key), reverse=order < 0)
        else:
            super().sort()
        return self


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0

    def find_one(self, q, proj=None):
        for d in self.docs:
            def matches(key, expected):
                value=d.get(key)
                if isinstance(expected,dict):
                    if "$in" in expected:return value in expected["$in"]
                    if "$ne" in expected:return value != expected["$ne"]
                return value == expected
            if all(matches(k,v) for k,v in q.items()):
                return d
        return None

    def find(self, q=None, proj=None):
        q = q or {}
        return _Cursor([d for d in self.docs if all(d.get(k) == v for k, v in q.items())])

    def insert_one(self, d):
        self._n += 1
        d.setdefault("_id", "t{}".format(self._n))
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def update_one(self, q, u, upsert=False):
        t = self.find_one(q)
        if t is not None:
            t.update(u.get("$set") or {})
        return type("R", (), {"modified_count": 1 if t else 0})()


class _Repo(Repository):
    def __init__(self):
        self._c = _Coll()

    def collection(self, name):
        return self._c


class OrchPhase2Test(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        set_repo(_Repo())
        o.set_executor(lambda fn: fn())        # 同步执行器：投递即跑，断言确定
        o.register_default_handlers()
        if "_celery_delay" in o.__dict__:
            del o.__dict__["_celery_delay"]     # 清 celery hook

    def tearDown(self):
        reset_repo()
        reset_registry()
        o.reset_executor()
        if "_celery_delay" in o.__dict__:
            del o.__dict__["_celery_delay"]

    def _seed(self, status="waiting", ttype="domain", target="a.com"):
        coll = get_repo().collection(o.TASK_COLL)
        r = coll.insert_one({"status": status, "type": ttype, "target": target, "options": {}})
        return str(r.inserted_id)

    # —— submit_task 入队 → 同步执行器下真跑到 done（RECON 未注册降级） ——
    def test_submit_runs_to_done(self):
        tid = self._seed()
        r = o.submit_task(tid, {"type": "domain", "options": {}})
        self.assertTrue(r["submitted"])
        doc = get_repo().collection(o.TASK_COLL).find_one({"_id": tid})
        self.assertEqual(doc["status"], "done")     # handler 降级但仍收尾

    # —— 已停止态不投 ——
    def test_submit_stopped_not_submitted(self):
        tid = self._seed(status="stop")
        r = o.submit_task(tid, {"type": "domain"})
        self.assertFalse(r["submitted"])
        self.assertEqual(r["reason"], "stopped")

    # —— run_waiting_tasks 只捡 waiting，running 不重投 ——
    def test_run_waiting_only_waiting(self):
        self._seed(status="waiting")
        self._seed(status="waiting")
        self._seed(status="running")               # 不该被捡
        self._seed(status="done")                  # 不该被捡
        r = o.run_waiting_tasks()
        self.assertEqual(r["picked"], 2)
        self.assertEqual(r["submitted"], 2)

    # —— run_waiting_tasks limit>0 分批（非硬上限，默认 0 不限） ——
    def test_run_waiting_limit(self):
        for _ in range(5):
            self._seed(status="waiting")
        # 同步执行器会把 waiting 立即跑成 done；为验证 limit 语义用不改状态的执行器
        o.set_executor(lambda fn: None)            # 只入队不执行 → status 保持 waiting
        r = o.run_waiting_tasks(limit=3)
        self.assertEqual(r["submitted"], 3)

    # —— 默认 handler：RECON 注册则被驱动 ——
    def test_recon_handler_drives_recon(self):
        called = {}

        class _Recon:
            def run_recon(self, task_type, task_id, target, **kw):
                called["type"] = task_type
                called["target"] = target
                return {"result": "done"}
        get_registry().register(ROLE.RECON, _Recon())
        tid = self._seed(ttype="domain", target="x.com")
        o.submit_task(tid, {"type": "domain"})
        self.assertEqual(called.get("target"), "x.com")

    # —— RECON 缺失：handler 降级不崩，任务仍 done ——
    def test_recon_handler_degrade(self):
        tid = self._seed(ttype="ip", target="1.1.1.1")
        r = o.submit_task(tid, {"type": "ip"})
        self.assertTrue(r["submitted"])
        self.assertEqual(get_repo().collection(o.TASK_COLL).find_one({"_id": tid})["status"], "done")

    # —— unit handler 降级（反查未接）——
    def test_unit_handler_pending(self):
        tid = self._seed(ttype="unit", target="某公司")
        # unit handler 返回 pending，但 run_task 仍收尾 done（不阻断）
        o.submit_task(tid, {"type": "unit", "options": {"unit_names": ["某公司"]}})
        self.assertEqual(get_repo().collection(o.TASK_COLL).find_one({"_id": tid})["status"], "done")

    # —— 协作式取消：waiting→stop 后 submit 不跑（phase-2 不破坏核心铁律）——
    def test_cooperative_cancel_preserved(self):
        tid = self._seed(status="stop")
        o.submit_task(tid, {"type": "domain"})
        self.assertEqual(get_repo().collection(o.TASK_COLL).find_one({"_id": tid})["status"], "stop")

    # —— 门面暴露 submit_task/run_waiting_tasks ——
    def test_service_facade(self):
        svc = o.get_service()
        self.assertTrue(hasattr(svc, "submit_task"))
        self.assertTrue(hasattr(svc, "run_waiting_tasks"))
        tid = self._seed()
        self.assertTrue(svc.submit_task(tid, {"type": "domain"})["submitted"])

    # —— celery delay hook 优先于执行器 ——
    def test_celery_delay_hook_preferred(self):
        sent = {}
        o.__dict__["_celery_delay"] = lambda tid, tt, opts: sent.update(tid=tid, tt=tt)
        o.set_executor(lambda fn: sent.update(executor_called=True))
        tid = self._seed()
        o.submit_task(tid, {"type": "domain", "options": {}})
        self.assertEqual(sent.get("tid"), tid)          # 走了 celery delay
        self.assertNotIn("executor_called", sent)        # 没走执行器
        del o.__dict__["_celery_delay"]

    # —— register_default_handlers 幂等 + 注册了 domain/ip/unit ——
    def test_default_handlers_registered(self):
        types = o.registered_types()
        for t in ("domain", "ip", "unit"):
            self.assertIn(t, types)


if __name__ == "__main__":
    unittest.main()
