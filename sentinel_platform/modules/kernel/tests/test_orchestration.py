"""orchestration 单测 —— handler 注册/生命周期/协作式取消/run_task 分发，注入内存 repo。

重点：**协作式取消**（DB status=stop → ctx.checkpoint() 抛 Stopped，run_task 返 stopped 不覆盖状态）
是本层核心正确性（记忆 dengta-stop-cooperative-cancellation 铁律）。
"""
import unittest
from unittest import mock

from sentinel_platform.core import set_repo
from sentinel_platform.modules.kernel import orchestration as orch


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find_one(self, q, proj=None):
        for d in self.docs:
            if all(str(d.get(k)) == str(v) for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def insert_one(self, doc):
        doc.setdefault("_id", "t%d" % (len(self.docs) + 1)); self.docs.append(doc)
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            class _R: modified_count = 1
            return _R()
        class _R0: modified_count = 0
        return _R0()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


class TestHandlerRegistry(unittest.TestCase):
    def setUp(self):
        orch._HANDLERS.clear()

    def test_register_get(self):
        def h(tid, ctx):
            return "ok"
        orch.register_handler("domain", h)
        self.assertIs(orch.get_handler("domain"), h)
        self.assertIn("domain", orch.registered_types())

    def test_get_missing(self):
        self.assertIsNone(orch.get_handler("nope"))


class TestLifecycleAndRun(unittest.TestCase):
    def setUp(self):
        orch._HANDLERS.clear()
        self.repo = _FakeRepo()
        set_repo(self.repo)
        self.repo.collection("task").insert_one({"_id": "t1", "task_type": "domain",
                                                 "status": "waiting", "options": {}})

    def tearDown(self):
        set_repo(None)

    def test_run_task_success_sets_done(self):
        ran = {}
        def h(tid, ctx):
            ran["called"] = tid
            ctx.checkpoint()   # 不该抛（status=running）
        orch.register_handler("domain", h)
        r = orch.run_task("t1")
        self.assertEqual(r["result"], "done")
        self.assertEqual(ran["called"], "t1")
        self.assertEqual(self.repo.collection("task").find_one({"_id": "t1"})["status"], "done")

    def test_no_handler(self):
        r = orch.run_task("t1", task_type="unknown_type")
        self.assertEqual(r["result"], "no_handler")

    def test_handler_error_sets_error(self):
        def h(tid, ctx):
            raise ValueError("boom")
        orch.register_handler("domain", h)
        r = orch.run_task("t1")
        self.assertEqual(r["result"], "error")
        self.assertIn("boom", r["error"])
        self.assertEqual(self.repo.collection("task").find_one({"_id": "t1"})["status"], "error")

    def test_cooperative_cancel_at_checkpoint(self):
        # handler 执行中被置 stop → checkpoint 抛 Stopped → result=stopped，且不覆盖 stop 状态
        def h(tid, ctx):
            self.repo.collection("task").update_one({"_id": "t1"}, {"$set": {"status": "stop"}})
            ctx.checkpoint()   # 应抛 StoppedException
            raise AssertionError("不该到这")
        orch.register_handler("domain", h)
        r = orch.run_task("t1")
        self.assertEqual(r["result"], "stopped")
        self.assertEqual(self.repo.collection("task").find_one({"_id": "t1"})["status"], "stop")

    def test_entry_guard_already_stopped(self):
        self.repo.collection("task").update_one({"_id": "t1"}, {"$set": {"status": "stop"}})
        def h(tid, ctx):
            raise AssertionError("停止态不该启动 handler")
        orch.register_handler("domain", h)
        r = orch.run_task("t1")
        self.assertEqual(r["result"], "stopped")

    def test_post_scan_calls_intel(self):
        intel = mock.Mock()
        def h(tid, ctx):
            pass
        orch.register_handler("domain", h)
        reg = mock.Mock()
        reg.get.side_effect = lambda role: intel if role == orch.ROLE.INTEL else None
        with mock.patch.object(orch, "get_registry", return_value=reg):
            orch.run_task("t1")
        intel.auto_collect_after_scan.assert_called_once_with("t1")

    def test_context_checkpoint_no_raise_when_running(self):
        ctx = orch.TaskContext("t1")
        self.repo.collection("task").update_one({"_id": "t1"}, {"$set": {"status": "running"}})
        ctx.checkpoint()   # 不抛
        self.assertFalse(ctx.is_stopped())


class TestService(unittest.TestCase):
    def test_singleton_and_facade(self):
        s = orch.get_service()
        self.assertIs(s, orch.get_service())
        self.assertTrue(hasattr(s, "run_task"))
        self.assertTrue(hasattr(s, "register_handler"))


class TestFofaHandler(unittest.TestCase):
    """FOFA 导入任务 handler：目标在 options.fofa_ip，归一剥 scheme → IP/域名分流喂 RECON。
    治「type=fofa 无 handler → 任务永卡 queued」。"""

    def test_normalize_and_is_ip(self):
        self.assertEqual(orch._normalize_fofa_target("https://1.2.3.4:9443"), "1.2.3.4:9443")
        self.assertEqual(orch._normalize_fofa_target("http://www.x.cn/a/b?q=1"), "www.x.cn")
        self.assertEqual(orch._normalize_fofa_target("Host.CN:8080"), "host.cn:8080")
        self.assertEqual(orch._normalize_fofa_target("  "), "")
        self.assertTrue(orch._is_ip_host("1.2.3.4:9443"))
        self.assertTrue(orch._is_ip_host("10.0.0.1"))
        self.assertFalse(orch._is_ip_host("www.x.cn"))
        self.assertFalse(orch._is_ip_host("999.1.1.1"))

    def _ctx(self, fofa_ip, recon=None):
        ctx = mock.Mock()
        ctx.options = {"fofa_ip": fofa_ip}
        ctx.checkpoint = mock.Mock()
        ctx.is_stopped = lambda: False
        ctx.recon = recon
        return ctx

    def test_no_targets_degrade(self):
        r = orch._fofa_handler("t1", self._ctx([]))
        self.assertEqual(r["fofa"], "no_targets")

    def test_recon_unavailable_degrade(self):
        r = orch._fofa_handler("t1", self._ctx(["https://1.2.3.4"], recon=None))
        self.assertEqual(r["fofa"], "recon_unavailable")

    def test_split_ip_and_domain_and_dedup(self):
        recon = mock.Mock()
        recon.run_recon.return_value = {"result": "done", "counts": {"site": 1}}
        targets = ["https://1.2.3.4:9443", "https://1.2.3.4:9443",  # 去重
                   "https://www.x.cn", "www.x.cn:9080", "10.0.0.1"]
        r = orch._fofa_handler("t1", self._ctx(targets, recon=recon))
        self.assertEqual(r["fofa"], "done")
        self.assertEqual(r["target_count"], 4)   # 去重后 4 个
        self.assertEqual(r["ip_count"], 2)       # 1.2.3.4:9443 + 10.0.0.1
        self.assertEqual(r["domain_count"], 2)   # www.x.cn + www.x.cn:9080
        # 两次 run_recon：ip 批 + domain 批；且强制关子域名爆破
        self.assertEqual(recon.run_recon.call_count, 2)
        for call in recon.run_recon.call_args_list:
            kwargs = call.kwargs
            self.assertFalse(kwargs.get("domain_brute"))
            self.assertFalse(kwargs.get("alt_dns"))


if __name__ == "__main__":
    unittest.main()
