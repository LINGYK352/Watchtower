"""task_plan/task_create 单测 —— core 内存替身，不需真 Mongo。

覆盖：register 字符串键、目标分类(ip/domain/无效)、SSRF 私网拒、create_by_policy(经 policy_service
展开 options + 落 WAITING + IP关域名选项)、策略不存在降级、派发降级(orchestration 未建=waiting)、
create_from_targets(FOFA/单位路径)、白名单/临时情报贯穿、禁硬限制(目标数不砍)。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo, get_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "t{}".format(self._n))
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()


class _Repo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _Coll())


class _FakePolicy:
    """假 policy_service：返回带域名/IP/site 配置的 options（模拟 get_options_by_policy_id）。"""
    def __init__(self, ok=True):
        self._ok = ok

    def get_options_by_policy_id(self, policy_id, task_tag):
        if not self._ok or policy_id == "missing":
            return {}
        return {"policy_name": "测试策略", "domain_brute": True, "port_scan": True,
                "site_identify": True, "auto_pentest": False}


class TaskCreateTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        set_repo(_Repo())
        get_registry().register("policy_service", _FakePolicy())

    def tearDown(self):
        reset_repo()
        reset_registry()

    def _impl(self):
        from sentinel_platform.modules.task_plan.task_create import TaskCreateServiceImpl
        return TaskCreateServiceImpl()

    def _tasks(self):
        from sentinel_platform.contracts import Collections
        return get_repo().collection(Collections.TASK).docs

    # —— register 字符串键 ——
    def test_register_string_key(self):
        from sentinel_platform.modules.task_plan.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get("task_create_service")
        self.assertIsNotNone(svc)
        for m in ("create_by_policy", "create_from_targets"):
            self.assertTrue(hasattr(svc, m))

    # —— 目标分类 ——
    def test_classify(self):
        from sentinel_platform.modules.task_plan.task_create import classify_targets
        ip, dom, inv = classify_targets("1.2.3.4, example.com, 8.8.8.8/24, bad_target")
        self.assertIn("1.2.3.4", ip)
        self.assertIn("8.8.8.8/24", ip)
        self.assertIn("example.com", dom)
        self.assertTrue(any("bad_target" in x for x in inv))

    # —— 内网/私网目标接受（授权内网渗透工具，2026-08-11 放开）——
    def test_internal_targets_accepted(self):
        from sentinel_platform.modules.task_plan.task_create import classify_targets
        ip, dom, inv = classify_targets("10.0.0.1, 192.168.1.1, 127.0.0.1, 172.16.5.5, 8.8.8.8")
        # 内网/环回/公网 IP 全部接受，无 invalid
        for t in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "172.16.5.5", "8.8.8.8"):
            self.assertIn(t, ip)
        self.assertEqual(len(inv), 0)

    def test_ip_octet_range(self):
        from sentinel_platform.modules.task_plan.task_create import classify_targets
        ip, dom, inv = classify_targets("999.1.1.1, 256.0.0.1, 10.0.0.1")
        self.assertIn("10.0.0.1", ip)
        self.assertTrue(any("999" in x or "超范围" in x for x in inv))

    def test_ssrf_172_boundary(self):
        from sentinel_platform.modules.task_plan.task_create import _is_private_ip
        self.assertTrue(_is_private_ip("172.16.0.1"))
        self.assertTrue(_is_private_ip("172.31.255.255"))
        self.assertFalse(_is_private_ip("172.15.0.1"))     # 边界外=公网
        self.assertFalse(_is_private_ip("172.32.0.1"))

    # —— create_by_policy 必填校验 ——
    def test_create_missing(self):
        self.assertFalse(self._impl().create_by_policy("", "p1", "x")["ok"])
        self.assertFalse(self._impl().create_by_policy("n", "", "x")["ok"])
        self.assertFalse(self._impl().create_by_policy("n", "p1", "")["ok"])

    # —— create_by_policy 主流程：域名 + IP 拆任务 + WAITING ——
    def test_create_by_policy_multi_target_single_task(self):
        """v1.21.157-48：多目标(2域名+1IP)合并成**一篇**任务（此前拆 3 篇）。"""
        r = self._impl().create_by_policy("扫描A", "p1", "a.com, b.com, 8.8.8.8", priority=1)
        self.assertTrue(r["ok"])
        self.assertEqual(r["created"], 1)                  # 多目标合一篇
        tasks = self._tasks()
        self.assertEqual(len(tasks), 1)
        t = tasks[0]
        self.assertEqual(t["status"], "waiting")
        self.assertEqual(t["priority"], 1)
        self.assertEqual(t["options"]["policy_name"], "测试策略")
        # 全量目标按 ip/domain 分类存 options.multi_targets
        mt = t["options"]["multi_targets"]
        self.assertEqual(sorted(mt["domain"]), ["a.com", "b.com"])
        self.assertEqual(mt["ip"], ["8.8.8.8"])
        self.assertEqual(t["type"], "domain")              # 有域名 → 主类型 domain

    def test_create_by_policy_single_target_unchanged(self):
        """单目标行为不变：一篇，target=该目标，无 multi_targets。"""
        r = self._impl().create_by_policy("扫描B", "p1", "only.com", priority=2)
        self.assertEqual(r["created"], 1)
        t = self._tasks()[0]
        self.assertEqual(t["target"], "only.com")
        self.assertNotIn("multi_targets", t["options"])

    # —— IP 任务关域名相关选项 ——
    def test_ip_task_disables_domain_opts(self):
        self._impl().create_by_policy("扫描", "p1", "8.8.8.8")
        ip_task = [t for t in self._tasks() if t["type"] == "ip"][0]
        self.assertFalse(ip_task["options"]["domain_brute"])   # IP 任务关域名爆破
        self.assertFalse(ip_task["options"]["alt_dns"])

    # —— 策略不存在降级 ——
    def test_policy_missing(self):
        r = self._impl().create_by_policy("扫描", "missing", "a.com")
        self.assertFalse(r["ok"])
        self.assertIn("策略不存在", r["error"])

    # —— policy 服务未注册降级 ——
    def test_policy_service_absent(self):
        reset_registry()   # 清掉 policy_service
        r = self._impl().create_by_policy("扫描", "p1", "a.com")
        self.assertFalse(r["ok"])

    # —— 派发降级：orchestration 未建 → waiting ——
    def test_dispatch_degrade_waiting(self):
        r = self._impl().create_by_policy("扫描", "p1", "a.com")
        self.assertEqual(r["items"][0]["dispatch"], "waiting")   # orchestration 未注册

    # —— 派发接通：orchestration 有 submit_task → dispatched ——
    def test_dispatch_when_orchestration_ready(self):
        called = {}

        class _Orch:
            def submit_task(self, task_id, doc):
                called["id"] = task_id
                return {"submitted": True}
        get_registry().register("orchestration_service", _Orch())
        r = self._impl().create_by_policy("扫描", "p1", "a.com")
        self.assertEqual(r["items"][0]["dispatch"], "dispatched")
        self.assertTrue(called.get("id"))

    # —— 白名单 + 临时情报贯穿 options ——
    def test_whitelist_mission_intel(self):
        self._impl().create_by_policy("扫描", "p1", "a.com",
                                      pentest_whitelist="admin.a.com,test.a.com",
                                      mission_intel='[{"text":"WAF是安恒"}]')
        opts = self._tasks()[0]["options"]
        self.assertEqual(opts["pentest_whitelist"], ["admin.a.com", "test.a.com"])
        self.assertIn("mission_intel_raw", opts)

    def test_primary_and_backup_provider_flow_to_all_task_kinds(self):
        """首要/备用模型必须贯穿普通、源查询、单位三入口；单位入口也覆盖备用出口参数。"""
        svc = self._impl()
        svc.create_by_policy("普通", "p1", "a.com",
                             pentest_provider_id="primary", pentest_backup_provider_id="backup")
        opts = self._tasks()[-1]["options"]
        self.assertEqual(opts["pentest_provider_id"], "primary")
        self.assertEqual(opts["pentest_backup_provider_id"], "backup")

        svc.create_from_targets("源", ["b.com"], "p1",
                                pentest_provider_id="primary", pentest_backup_provider_id="backup")
        self.assertEqual(self._tasks()[-1]["options"]["pentest_backup_provider_id"], "backup")

        r = svc.create_unit_task("单位", ["某公司"], "p1",
                                 pentest_provider_id="primary", pentest_backup_provider_id="backup",
                                 pentest_fallback_egress_mode="direct")
        self.assertTrue(r["ok"])
        unit_opts = self._tasks()[-1]["options"]
        self.assertEqual(unit_opts["pentest_backup_provider_id"], "backup")
        self.assertEqual(unit_opts["pentest_fallback_egress"]["mode"], "direct")

    # —— source 归档贯穿（全空不写）——
    def test_source(self):
        self._impl().create_by_policy("扫描", "p1", "a.com", source={"unit": "某公司", "platform": "butian"})
        self.assertEqual(self._tasks()[0]["source"]["unit"], "某公司")
        # 全空 source 不写字段
        get_repo().collection("task").docs.clear()
        self._impl().create_by_policy("扫描", "p1", "b.com", source={"unit": "", "platform": ""})
        self.assertNotIn("source", self._tasks()[0])

    # —— create_from_targets（FOFA 聚合任务）——
    def test_create_from_targets(self):
        r = self._impl().create_from_targets("FOFA导入", ["x.com", "y.com", "1.1.1.1"], "p1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["created"], 1)
        self.assertEqual(self._tasks()[0]["type"], "fofa")
        self.assertEqual(self._tasks()[0]["options"]["fofa_ip"], ["x.com", "y.com", "1.1.1.1"])

    def test_create_from_targets_missing(self):
        self.assertFalse(self._impl().create_from_targets("n", [], "p1")["ok"])

    def test_source_queries_archived(self):
        """源查询语句随任务归档（供详情页展示）：source.sources/queries 落库。"""
        r = self._impl().create_from_targets(
            "FOFA导入", ["x.com"], "p1",
            source={"platform": "multi_source", "sources": ["fofa", "hunter"],
                    "queries": {"fofa": 'domain="x.com"', "hunter": 'ip="1.1.1.1"', "empty": ""}})
        self.assertTrue(r["ok"])
        src = self._tasks()[0]["source"]
        self.assertEqual(src["sources"], ["fofa", "hunter"])
        self.assertEqual(src["queries"]["fofa"], 'domain="x.com"')
        self.assertEqual(src["queries"]["hunter"], 'ip="1.1.1.1"')
        self.assertNotIn("empty", src["queries"])          # 空语句过滤

    # —— 禁硬限制：大量目标全收不砍（v1.21.157-48：合一篇，200 目标全在 multi_targets 不丢）——
    def test_no_hard_limit_on_targets(self):
        many = ",".join("d{}.com".format(i) for i in range(200))
        r = self._impl().create_by_policy("批量", "p1", many)
        self.assertEqual(r["created"], 1)                 # 多目标合一篇
        tasks = self._tasks()
        self.assertEqual(len(tasks), 1)
        self.assertEqual(len(tasks[0]["options"]["multi_targets"]["domain"]), 200)  # 200 目标全收无上限

    # —— #3 上下文上限从策略移到新建任务：_apply_ctx_tokens 门控 + create_by_policy 透传 ——
    def test_apply_ctx_tokens_gated_by_auto_pentest(self):
        from sentinel_platform.modules.task_plan.task_create import TaskCreateServiceImpl as _Impl
        # 策略未绑定 AI 渗透（auto_pentest=False）→ 不写入（上下文上限只对 AI 渗透有意义）
        opts = {"auto_pentest": False}
        _Impl._apply_ctx_tokens(opts, -1)
        self.assertNotIn("max_context_tokens", opts)
        # 绑定 AI 渗透（auto_pentest=True）→ 写入（-1=拉满原生上限 / 0=跟随全局 / 正数=固定）
        opts2 = {"auto_pentest": True}
        _Impl._apply_ctx_tokens(opts2, -1)
        self.assertEqual(opts2["max_context_tokens"], -1)
        opts3 = {"auto_pentest": True}
        _Impl._apply_ctx_tokens(opts3, 256000)
        self.assertEqual(opts3["max_context_tokens"], 256000)
        # None（前端未传）→ 不覆盖策略值（向后兼容）
        opts4 = {"auto_pentest": True, "max_context_tokens": 0}
        _Impl._apply_ctx_tokens(opts4, None)
        self.assertEqual(opts4["max_context_tokens"], 0)

    def test_create_by_policy_passes_ctx_tokens(self):
        # _FakePolicy 返回 auto_pentest=False → 传了上下文上限也不落（门控生效）
        r = self._impl().create_by_policy("t", "p1", "a.com", pentest_max_context_tokens=-1)
        self.assertTrue(r["ok"])
        self.assertNotIn("max_context_tokens", self._tasks()[0]["options"])


if __name__ == "__main__":
    unittest.main()
