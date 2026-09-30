"""单位名反查执行闭环单测 —— 补净室迁移丢失的 _unit_handler + ext_source.reverse_lookup_units。

覆盖：①reverse_lookup_units 聚合种子+fld→单位映射(monkeypatch Hunter调用) ②无key/无种子返空
③_unit_handler 反查得种子→调 RECON 跑侦察 ④无种子/服务缺失 honest degrade 不伪造 ⑤无 units 早退。
monkeypatch _hunter_by_icp_name 隔离真实 Hunter API。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.modules.kernel import ext_source as es
from sentinel_platform.modules.kernel import orchestration as orch


class _Repo:
    def collection(self, name):
        class _C:
            def find_one(self, *a, **k): return None
            def update_one(self, *a, **k): pass
        return _C()


class TestReverseLookup(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())
        self._orig_hunter = es._hunter_by_icp_name
        self._orig_icp = es._icp_official_reverse
        self._orig_interval = es._ICP_REVERSE_BASE_INTERVAL
        es._ICP_REVERSE_BASE_INTERVAL = 0        # 关节流 sleep，单测不被拖慢（问题9）
        # 默认 ICP 官方源工具失效（unavailable）→ 走鹰图降级——各用例按需覆盖
        es._icp_official_reverse = lambda unit: {"status": "unavailable", "domains": set(), "ips": set()}

    def tearDown(self):
        es._hunter_by_icp_name = self._orig_hunter
        es._icp_official_reverse = self._orig_icp
        es._ICP_REVERSE_BASE_INTERVAL = self._orig_interval
        set_repo(None)

    def test_aggregate_seeds_and_unit_map(self):
        # mock Hunter（返回 dict {domains, ips}，对齐现有签名）：单位A→a.com 子域，单位B→b.com
        def _fake(unit):
            return {"domains": {"www.a.com", "api.a.com"}, "ips": set()} if unit == "单位A" \
                else {"domains": {"b.com"}, "ips": set()}
        es._hunter_by_icp_name = _fake
        r = es.reverse_lookup_units(["单位A", "单位B"])
        self.assertEqual(set(r["seeds"]), {"www.a.com", "api.a.com", "b.com"})
        self.assertEqual(r["unit_map"].get("a.com"), "单位A")
        self.assertEqual(r["unit_map"].get("b.com"), "单位B")

    def test_on_unit_streams_per_unit(self):
        # 流式回调：每个有种子的单位反查完即 on_unit 回调，含该单位 domains/ips/fld片段；
        # 累计结果与最终返回一致；无种子单位不回调。
        def _icp(unit):
            if unit == "空单位":
                return {"status": "empty", "domains": set(), "ips": set()}
            return {"status": "ok", "domains": {unit + ".com"}, "ips": {"9.9.9.9"} if unit == "甲" else set()}
        es._icp_official_reverse = _icp
        es._hunter_by_icp_name = lambda unit: (_ for _ in ()).throw(AssertionError("ICP ok/empty 不该降级鹰图"))
        emitted = []
        es.reverse_lookup_units(["甲", "空单位", "乙"],
                                on_unit=lambda u, d, ip, fm: emitted.append((u, set(d), set(ip), dict(fm))))
        # 只有"甲""乙"有种子回调（"空单位"empty 无种子不回调）
        self.assertEqual([e[0] for e in emitted], ["甲", "乙"])
        self.assertEqual(emitted[0][1], {"甲.com"}); self.assertEqual(emitted[0][2], {"9.9.9.9"})
        self.assertEqual(emitted[0][3].get("甲.com"), "甲")   # fld片段带本单位映射
        self.assertEqual(emitted[1][1], {"乙.com"}); self.assertEqual(emitted[1][2], set())

    def test_on_unit_none_backward_compat(self):
        # on_unit=None（默认）行为完全不变
        es._icp_official_reverse = lambda unit: {"status": "ok", "domains": {"x.com"}, "ips": set()}
        r = es.reverse_lookup_units(["单位"])
        self.assertEqual(set(r["seeds"]), {"x.com"})

    def test_icp_official_priority(self):
        # 状态①：ICP 官方源查到 → 用 ICP 权威种子，不降级鹰图（鹰图设为抛错，命中即失败）
        es._icp_official_reverse = lambda unit: {"status": "ok", "domains": {"abc.gov.cn"}, "ips": {"1.2.3.4"}}
        es._hunter_by_icp_name = lambda unit: (_ for _ in ()).throw(AssertionError("ICP查到不该降级鹰图"))
        r = es.reverse_lookup_units(["某某厅"])
        self.assertEqual(set(r["seeds"]), {"abc.gov.cn"})   # 原样，不上溯 gov.cn（6a）
        self.assertEqual(set(r["ip_seeds"]), {"1.2.3.4"})
        self.assertEqual(r["unit_map"].get("abc.gov.cn"), "某某厅")   # fld 对二级公共后缀安全

    def test_icp_unavailable_fallback_hunter(self):
        # 状态③：ICP 工具失效(unavailable) → 降级鹰图
        es._hunter_by_icp_name = lambda unit: {"domains": {"h.com"}, "ips": set()}
        r = es.reverse_lookup_units(["查不到单位"])
        self.assertEqual(set(r["seeds"]), {"h.com"})

    def test_icp_empty_no_fallback(self):
        # 状态②：ICP 权威判无备案(empty) → 该单位无资产，**绝不降级鹰图**（用户定调无资产结束）
        es._icp_official_reverse = lambda unit: {"status": "empty", "domains": set(), "ips": set()}
        es._hunter_by_icp_name = lambda unit: (_ for _ in ()).throw(AssertionError("ICP 判无备案不该降级鹰图"))
        r = es.reverse_lookup_units(["无备案单位"])
        self.assertEqual(r["seeds"], [])
        self.assertEqual(r["unit_status"].get("无备案单位"), "no_asset")

    def test_icp_ok_no_thirdparty_merge(self):
        # 状态①越权丢弃：ICP 有备案时，即便鹰图能返更多"关联"资产也不合并（防第三方越权归属）
        es._icp_official_reverse = lambda unit: {"status": "ok", "domains": {"real.com"}, "ips": set()}
        es._hunter_by_icp_name = lambda unit: {"domains": {"evil-unrelated.com"}, "ips": set()}
        r = es.reverse_lookup_units(["单位X"])
        self.assertEqual(set(r["seeds"]), {"real.com"})     # 只 ICP 的，不含鹰图越权域名

    def test_multi_unit_riskcontrol_skip(self):
        # 多单位风控：官方源从未成功 + 连续 unavailable → 疑似风控，后续单位跳过官方源直连鹰图
        calls = {"icp": 0}
        def _icp(unit):
            calls["icp"] += 1
            return {"status": "unavailable", "domains": set(), "ips": set()}
        es._icp_official_reverse = _icp
        es._hunter_by_icp_name = lambda unit: {"domains": {unit + ".com"}, "ips": set()}
        r = es.reverse_lookup_units(["U1", "U2", "U3", "U4", "U5"])
        self.assertTrue(r["risk_suspected"])
        # 连续 2 次失效后判风控 → 后续跳过官方源，ICP 实际调用次数 < 单位总数
        self.assertLess(calls["icp"], 5)

    def test_no_seeds(self):
        es._hunter_by_icp_name = lambda unit: {"domains": set(), "ips": set()}
        r = es.reverse_lookup_units(["空单位"])
        self.assertEqual(r["seeds"], [])
        self.assertEqual(r["unit_map"], {})

    def test_empty_units(self):
        r = es.reverse_lookup_units([])
        self.assertEqual(r["seeds"], [])


class _FakeExt:
    def __init__(self, seeds):
        self._seeds = seeds
    def reverse_lookup_units(self, units):
        return {"seeds": self._seeds, "unit_map": {"a.com": units[0]} if units else {}}


class _FakeRecon:
    def __init__(self):
        self.called_with = None      # 仅最后一次（no_seeds 用例断言 is None）
        self.calls = []              # 流式逐目标调用累积全部（v1.21.163-10 起 unit 任务逐目标 run_recon）
    def run_recon(self, ttype, task_id, target, **opts):
        self.called_with = {"ttype": ttype, "target": target, "opts": opts}
        self.calls.append({"ttype": ttype, "target": target, "opts": opts})
        return {"result": "done", "counts": {"site": 3}}
    def scanned_targets(self):
        """所有 run_recon 调用扫过的目标并集（逐目标流式模型下 target 是单元素列表）。"""
        out = set()
        for c in self.calls:
            t = c["target"]
            out.update(t if isinstance(t, (list, tuple, set)) else [t])
        return out


class _Ctx:
    """最小 TaskContext 替身。"""
    def __init__(self, options, ext=None, recon=None):
        self.task_id = "t1"
        self.options = options
        self._reg = _FakeReg(ext, recon)
    def checkpoint(self): pass
    def is_stopped(self): return False
    @property
    def recon(self): return self._reg.get("RECON_ROLE")


class _FakeReg:
    def __init__(self, ext, recon):
        self._ext = ext
        self._recon = recon
    def get(self, key):
        if key == "ext_source_service":
            return self._ext
        return self._recon   # recon role


class TestUnitHandler(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())        # 桩 repo：unit_map 写回 TASK_COLL 走内存桩，不真连 Mongo（否则超时 30s）

    def tearDown(self):
        set_repo(None)

    def test_reverse_then_recon(self):
        recon = _FakeRecon()
        ctx = _Ctx({"unit_names": ["某公司"]}, ext=_FakeExt(["www.a.com", "b.com"]), recon=recon)
        r = orch._unit_handler("t1", ctx)
        # 流式：反查得种子后逐目标喂 RECON 跑 domain 侦察（每目标一次 run_recon，非批量一次）；
        # 两个目标都必须被扫到（验证流式不丢目标）。
        self.assertTrue(recon.calls, "应至少调用一次 run_recon")
        self.assertTrue(all(c["ttype"] == "domain" for c in recon.calls))
        self.assertEqual(recon.scanned_targets(), {"www.a.com", "b.com"})
        self.assertEqual(r["seed_count"], 2)

    def test_no_seeds_honest_degrade(self):
        recon = _FakeRecon()
        ctx = _Ctx({"unit_names": ["空壳"]}, ext=_FakeExt([]), recon=recon)
        r = orch._unit_handler("t1", ctx)
        self.assertEqual(r["unit"], "no_seeds")      # 不伪造资产
        self.assertIsNone(recon.called_with)          # 没种子不跑 RECON

    def test_ext_missing_degrade(self):
        recon = _FakeRecon()
        ctx = _Ctx({"unit_names": ["x"]}, ext=None, recon=recon)
        r = orch._unit_handler("t1", ctx)
        self.assertEqual(r["unit"], "ext_source_unavailable")

    def test_empty_units(self):
        ctx = _Ctx({"unit_names": []}, ext=_FakeExt([]), recon=_FakeRecon())
        r = orch._unit_handler("t1", ctx)
        self.assertEqual(r["unit"], "no_units")


if __name__ == "__main__":
    unittest.main()
