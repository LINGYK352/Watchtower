# -*- coding: utf-8 -*-
"""network_check 评分逻辑测试 —— 覆盖 v1.21.153 关键依赖"延迟梯度扣分"。

治的问题：关键依赖体检原先只看"连不连得上"、不看快慢，导致国外源(GitHub)慢到
2500ms 仍算满分把总分抬高。新逻辑：连得上但 ≥1500ms 判"慢但通"，且**按延迟梯度扣分**
（越慢扣越多、单项 floor 兜底、断=0），平滑不断崖——GitHub 2610ms 与 NVD 4593ms 得分不同。

纯函数测试（不发真实网络请求，_http_probe 用 mock）。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.system import network_check as nc


def _dep(name, reachable=True, ms=200):
    """构造单个依赖明细项（含 slow 标记，与 deps_healthcheck 输出对齐）。"""
    slow = bool(reachable and ms >= nc._DEP_SLOW_MS)
    return {"name": name, "url": "https://x/" + name, "kind": "intel",
            "reachable": reachable, "slow": slow, "status": 200 if reachable else 0, "ms": ms}


def _deps(items):
    """把明细列表包成 deps_healthcheck 输出结构。"""
    down = [d["name"] for d in items if not d["reachable"]]
    slow = [d["name"] for d in items if d.get("slow")]
    return {"deps": items, "total": len(items), "down_count": len(down), "down": down,
            "slow_count": len(slow), "slow": slow}


class TestDepItemScore(unittest.TestCase):
    """单项质量分：断=0；快=100；慢=梯度扣分且越慢越低，floor 兜底。"""

    def test_fast_full_score(self):
        self.assertEqual(nc._dep_item_score(_dep("fofa", ms=280)), 100.0)

    def test_down_zero(self):
        self.assertEqual(nc._dep_item_score(_dep("x", reachable=False, ms=8000)), 0.0)

    def test_slow_gradient_monotonic(self):
        # 越慢分越低（梯度、非一刀切）：1500 边界=100，2610 > 4593 的分
        s1500 = nc._dep_item_score(_dep("a", ms=1500))
        s2610 = nc._dep_item_score(_dep("gh", ms=2610))
        s4593 = nc._dep_item_score(_dep("nvd", ms=4593))
        self.assertEqual(s1500, 100.0)          # 刚到阈值不扣
        self.assertLess(s2610, 100.0)           # 慢了要扣
        self.assertLess(s4593, s2610)           # 越慢扣越多（梯度核心）
        self.assertGreaterEqual(s4593, nc._DEP_SLOW_FLOOR)  # 不低于 floor

    def test_slow_floor(self):
        # 极慢仍不低于 floor（只要还通就保底，比断的 0 高）
        self.assertEqual(nc._dep_item_score(_dep("veryslow", ms=999999)), float(nc._DEP_SLOW_FLOOR))


class TestDepsScoreAndGrade(unittest.TestCase):
    """维度分=各单项均值（梯度）；档位由维度分派生。"""

    def test_all_fast_good_100(self):
        d = _deps([_dep("a", ms=200), _dep("b", ms=300), _dep("c", ms=150), _dep("d", ms=250)])
        self.assertEqual(nc._deps_score(d), 100.0)
        self.assertEqual(nc._deps_grade(d), "good")

    def test_one_slight_slow_still_high(self):
        # 4 项里 1 项 GitHub 2610ms（略慢），其余快 → 维度分只略降，不断崖
        d = _deps([_dep("gh", ms=2610), _dep("b", ms=200), _dep("c", ms=200), _dep("d", ms=200)])
        s = nc._deps_score(d)
        self.assertGreater(s, 90.0)   # 只有 1/4 略慢，均分仍很高——正是"不该被拉太低"的诉求
        self.assertEqual(nc._deps_grade(d), "good")

    def test_all_down_dead(self):
        d = _deps([_dep("a", reachable=False), _dep("b", reachable=False)])
        self.assertEqual(nc._deps_grade(d), "dead")

    def test_empty_fallback(self):
        self.assertEqual(nc._deps_score({"deps": []}), 70.0)
        self.assertEqual(nc._deps_grade({"total": 0}), "fair")


class TestDepsHealthcheckSlowFlag(unittest.TestCase):
    """deps_healthcheck：连得上但慢(≥_DEP_SLOW_MS)标 slow，快的不标。"""

    def test_slow_flag_by_latency(self):
        fake_deps = [
            {"name": "国内·FOFA", "url": "https://fofa.info", "kind": "intel"},
            {"name": "GitHub", "url": "https://api.github.com", "kind": "intel"},
            {"name": "断源", "url": "https://down.example", "kind": "intel"},
        ]

        def fake_probe(url, timeout=8.0):
            if "fofa" in url:
                return {"ok": True, "status": 200, "ms": 280}
            if "github" in url:
                return {"ok": True, "status": 200, "ms": 2610}
            return {"ok": False, "status": 0, "ms": 8000, "err": "ConnectTimeout"}

        with mock.patch.object(nc, "_dep_targets", return_value=fake_deps), \
             mock.patch.object(nc, "_http_probe", side_effect=fake_probe):
            r = nc.deps_healthcheck()

        by = {d["name"]: d for d in r["deps"]}
        self.assertTrue(by["国内·FOFA"]["reachable"]);  self.assertFalse(by["国内·FOFA"]["slow"])
        self.assertTrue(by["GitHub"]["reachable"]);     self.assertTrue(by["GitHub"]["slow"])
        self.assertFalse(by["断源"]["reachable"])
        self.assertEqual(r["slow_count"], 1)
        self.assertEqual(r["down_count"], 1)


class TestGradientVsCliff(unittest.TestCase):
    """核心诉求验证：慢按梯度扣分——略慢只小降，很慢才多降，不是一刀切。"""

    def _ctx(self, deps):
        # 其余维度全 good，隔离出 deps 对总分的影响
        return nc.overall_assessment({"grade": "good"},
                                     {"targets": [{"grade": "good"}]},
                                     {"grade": "good"}, deps, {"grade": "na"})

    def test_gradient_monotonic_on_total(self):
        # 同样1项慢：2610ms 的总分 > 4593ms 的总分（梯度体现在总分上）
        d_mid = _deps([_dep("gh", ms=2610), _dep("b", ms=200), _dep("c", ms=200), _dep("d", ms=200)])
        d_slow = _deps([_dep("gh", ms=4593), _dep("b", ms=200), _dep("c", ms=200), _dep("d", ms=200)])
        s_mid = self._ctx(d_mid)["score"]
        s_slow = self._ctx(d_slow)["score"]
        self.assertGreaterEqual(s_mid, s_slow)   # 越慢总分越低（梯度）

    def test_one_slow_not_cliff(self):
        # 4项里仅1项GitHub略慢，总分应仍在"良/优"区间，不因单个慢就崩到"差"
        d = _deps([_dep("gh", ms=2610), _dep("b", ms=200), _dep("c", ms=200), _dep("d", ms=200)])
        res = self._ctx(d)
        self.assertGreaterEqual(res["score"], 90)   # 1/4 略慢，总分仍高——回应"别扣太狠"


if __name__ == "__main__":
    unittest.main()
