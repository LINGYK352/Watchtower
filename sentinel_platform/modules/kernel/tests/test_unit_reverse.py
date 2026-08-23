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
        self._orig = es._hunter_by_icp_name

    def tearDown(self):
        es._hunter_by_icp_name = self._orig
        set_repo(None)

    def test_aggregate_seeds_and_unit_map(self):
        # mock Hunter：单位A→{a.com子域}，单位B→{b.com}
        def _fake(unit):
            return {"www.a.com", "api.a.com"} if unit == "单位A" else {"b.com"}
        es._hunter_by_icp_name = _fake
        r = es.reverse_lookup_units(["单位A", "单位B"])
        self.assertEqual(set(r["seeds"]), {"www.a.com", "api.a.com", "b.com"})
        # fld→单位映射
        self.assertEqual(r["unit_map"].get("a.com"), "单位A")
        self.assertEqual(r["unit_map"].get("b.com"), "单位B")

    def test_no_seeds(self):
        es._hunter_by_icp_name = lambda unit: set()
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
        self.called_with = None
    def run_recon(self, ttype, task_id, target, **opts):
        self.called_with = {"ttype": ttype, "target": target, "opts": opts}
        return {"result": "done", "counts": {"site": 3}}


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
    def test_reverse_then_recon(self):
        recon = _FakeRecon()
        ctx = _Ctx({"unit_names": ["某公司"]}, ext=_FakeExt(["www.a.com", "b.com"]), recon=recon)
        r = orch._unit_handler("t1", ctx)
        # 反查得种子 → 调 RECON 跑 domain 侦察
        self.assertEqual(recon.called_with["ttype"], "domain")
        self.assertEqual(set(recon.called_with["target"]), {"www.a.com", "b.com"})
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
