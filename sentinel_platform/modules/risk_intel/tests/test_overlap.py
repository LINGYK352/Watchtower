"""risk_intel/asset_intel.check_pentest_overlap 单测 —— 内存替身 _fakedb，不连真库。

覆盖：具体 host 精确匹配活跃会话 + 历史报告、模糊域名查、单位查、
无重叠返回 overlap=False、summary 文案、humanize_ago、终态会话不算活跃。
"""
import unittest

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.contracts import Collections
from ._fakedb import FakeRepo


class OverlapTest(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepo()
        set_repo(self.repo)
        # 造资产：oa.x.com 已渗透(done+report)、shop.x.com 无渗透
        self.repo.collection(Collections.INTEL_ASSET).insert_one({
            "key": "https://oa.x.com:443", "unit": "某集团", "fld": "x.com",
            "pentest_status": "done", "report_id": "rep1",
            "last_collect_date": "2026-09-01 10:00:00"})
        # 造报告
        self.repo.collection(Collections.INTEL_REPORT).insert_one({
            "_id": "rep1", "title": "oa 渗透报告", "unit": "某集团",
            "asset_key": "https://oa.x.com:443", "max_severity": "high",
            "vuln_index": [{"vuln_type": "越权", "target": "/api/user", "severity": "high"}],
            "save_date": "2026-09-02 12:00:00"})
        # 造活跃会话：oa.x.com 正在跑(running)、另一个 stopped(终态不算)
        sc = self.repo.collection(Collections.PENTEST_SESSION)
        sc.insert_one({"_id": "s1", "site": "https://oa.x.com", "asset_key": "https://oa.x.com:443",
                       "unit": "某集团", "status": "running",
                       "save_date": "2026-09-05 09:00:00", "update_date": "2026-09-05 09:30:00"})
        sc.insert_one({"_id": "s2", "site": "https://oa.x.com", "asset_key": "https://oa.x.com:443",
                       "unit": "某集团", "status": "stopped",
                       "save_date": "2026-09-04 09:00:00", "update_date": "2026-09-04 09:30:00"})

    def tearDown(self):
        reset_repo()

    def _svc(self):
        from sentinel_platform.modules.risk_intel import asset_intel
        return asset_intel

    def test_precise_full_url_hits_active_and_report(self):
        """完整 URL(https://oa.x.com) → normalize 出 https:443 精确命中资产 → scope=precise，
        命中活跃会话(仅running,不含stopped) + 历史报告。"""
        r = self._svc().check_pentest_overlap(targets=["https://oa.x.com"])
        self.assertTrue(r["overlap"])
        self.assertEqual(r["scope"], "precise")
        self.assertEqual(len(r["active_sessions"]), 1)          # 只 running，stopped 不算
        self.assertEqual(r["active_sessions"][0]["session_id"], "s1")
        self.assertEqual(len(r["last_reports"]), 1)
        self.assertEqual(r["last_reports"][0]["report_id"], "rep1")
        self.assertEqual(r["last_reports"][0]["vuln_count"], 1)
        self.assertIn("资源浪费", r["summary"])
        self.assertIn("复验", r["summary"])

    def test_bare_domain_falls_back_best_effort(self):
        """裸域名(oa.x.com)→normalize 成 http:80 匹配不到 https:443 资产→降级 host 模糊查(best_effort)，
        功能上仍能查到会话（真实产品行为：裸域名无法确定 http/https，模糊更诚实）。"""
        r = self._svc().check_pentest_overlap(targets=["oa.x.com"])
        self.assertEqual(r["scope"], "best_effort")
        self.assertTrue(any(s["session_id"] == "s1" for s in r["active_sessions"]))

    def test_no_overlap_clean_target(self):
        """无渗透过的目标 → overlap=False，空列表。"""
        r = self._svc().check_pentest_overlap(targets=["clean.other.com"])
        self.assertFalse(r["overlap"])
        self.assertEqual(r["active_sessions"], [])
        self.assertEqual(r["last_reports"], [])

    def test_fuzzy_domain_best_effort(self):
        """大域名(匹配不到精确资产) → 模糊查 site 命中，scope=best_effort。"""
        r = self._svc().check_pentest_overlap(targets=["x.com"])
        self.assertEqual(r["scope"], "best_effort")
        # 模糊按 site 子串命中 running 会话
        self.assertTrue(any(s["session_id"] == "s1" for s in r["active_sessions"]))

    def test_unit_scope(self):
        """按单位查 → best_effort，命中该单位活跃会话 + 报告。"""
        r = self._svc().check_pentest_overlap(targets=[], unit="某集团")
        self.assertEqual(r["scope"], "best_effort")
        self.assertTrue(r["overlap"])
        self.assertTrue(any(s["session_id"] == "s1" for s in r["active_sessions"]))

    def test_humanize_ago(self):
        from sentinel_platform.modules.risk_intel.asset_intel import _humanize_ago
        import time
        self.assertIn("分钟前", _humanize_ago(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 120))))
        self.assertIn("小时前", _humanize_ago(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 7200))))
        self.assertEqual(_humanize_ago(""), "")


if __name__ == "__main__":
    unittest.main()
