"""risk_intel/vuln_intel 单测 —— core 内存替身，不连真 Mongo / 不发真网络。

覆盖：Protocol 契约、register 注册、去重三键归并、别名扩展匹配、query_by_component 排序、
list 过滤分页、stat 聚合、run_feed(mock fetcher + NOTIFY 缺失/命中)、feed_status 健康、
参数与库故障降级。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.interfaces import VulnIntelService
from sentinel_platform.contracts.registry import reset_registry

from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo, FakeCollection
from sentinel_platform.modules.risk_intel import vuln_intel as vi
from sentinel_platform.modules.risk_intel import _feed


class VulnIntelPureTest(unittest.TestCase):
    """纯函数：不依赖库。"""

    def test_normalize_cve(self):
        self.assertEqual(vi.normalize_cve("cve-2026-1234"), "CVE-2026-1234")
        self.assertEqual(vi.normalize_cve("CVE_2026_42588"), "CVE-2026-42588")
        self.assertEqual(vi.normalize_cve("not a cve"), "")
        self.assertEqual(vi.normalize_cve(None), "")

    def test_dedup_key_priority(self):
        self.assertEqual(vi._dedup_key({"cve_id": "CVE-2026-0001"}), ("cve", "CVE-2026-0001"))
        self.assertEqual(vi._dedup_key({"source": "seebug", "source_raw_id": "ssv:1"}),
                         ("raw", "seebug:ssv:1"))
        k = vi._dedup_key({"title": "泛微 OA RCE"})
        self.assertEqual(k[0], "title")
        self.assertTrue(k[1])

    def test_expand_aliases(self):
        got = set(vi._expand_aliases("泛微"))
        self.assertIn("weaver", got)
        self.assertIn("ecology", got)
        # 无别名组的组件只返回自身
        self.assertEqual(vi._expand_aliases("xyzsoft"), ["xyzsoft"])

    def test_extract_products_from_title(self):
        got = vi.extract_products_from_title("Apache ActiveMQ 远程代码执行漏洞(CVE-2026-42588)")
        self.assertIn("apache activemq", got)
        self.assertIn("activemq", got)
        self.assertEqual(vi.extract_products_from_title(""), [])

    def test_norm_products(self):
        self.assertEqual(vi._norm_products(["  Weaver ", "weaver", ""]), ["weaver"])


class VulnIntelDBTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        self.repo = FakeRepo()
        set_repo(self.repo)

    def tearDown(self):
        reset_repo()
        reset_registry()

    # —— 接口契约 ——
    def test_satisfies_protocol(self):
        self.assertIsInstance(vi.VulnIntelServiceImpl(), VulnIntelService)

    def test_register_puts_vuln_intel_into_registry(self):
        from sentinel_platform.modules.risk_intel.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get(ROLE.VULN_INTEL)
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "query"))

    # —— 去重归并 ——
    def test_upsert_new_then_merge_by_cve(self):
        a = {"cve_id": "CVE-2026-0001", "title": "X RCE", "severity": "medium",
             "products": ["x"], "source": "nvd", "source_url": "u1"}
        self.assertEqual(vi.upsert_vuln(a)[0], "new")
        # 同 CVE 第二源：merged，severity 升级 high，sources 聚合，products 合并
        b = {"cve_id": "CVE-2026-0001", "title": "X RCE", "severity": "high",
             "products": ["xtra"], "in_kev": True, "source": "cisa_kev", "source_url": "u2",
             "poc_urls": ["http://poc"]}
        self.assertEqual(vi.upsert_vuln(b)[0], "merged")
        doc = self.repo.collection("vuln_intel").find_one({"dedup_key": "cve:CVE-2026-0001"})
        self.assertEqual(doc["severity"], "high")
        self.assertTrue(doc["in_kev"])
        self.assertEqual(len(doc["sources"]), 2)
        self.assertIn("xtra", doc["products"])
        self.assertIn("http://poc", doc["poc_urls"])

    def test_upsert_merge_does_not_downgrade_severity(self):
        vi.upsert_vuln({"cve_id": "CVE-2026-0002", "title": "t", "severity": "critical", "source": "a"})
        vi.upsert_vuln({"cve_id": "CVE-2026-0002", "title": "t", "severity": "low", "source": "b"})
        doc = self.repo.collection("vuln_intel").find_one({"dedup_key": "cve:CVE-2026-0002"})
        self.assertEqual(doc["severity"], "critical")

    def test_upsert_executable_upgrade_on_merge(self):
        vi.upsert_vuln({"cve_id": "CVE-2026-0003", "title": "t", "severity": "high", "source": "nvd"})
        vi.upsert_vuln({"cve_id": "CVE-2026-0003", "title": "t", "severity": "high",
                        "source": "nuclei", "executable": True, "exec_kind": "nuclei", "exec_ref": "cve-2026-3"})
        doc = self.repo.collection("vuln_intel").find_one({"dedup_key": "cve:CVE-2026-0003"})
        self.assertTrue(doc["executable"])
        self.assertEqual(doc["exec_ref"], "cve-2026-3")

    def test_upsert_skip_when_no_key(self):
        self.assertEqual(vi.upsert_vuln({})[0], "skip")

    # —— 按组件查（别名 + 排序）——
    def _seed_components(self):
        vi.upsert_vuln({"cve_id": "CVE-2026-0010", "title": "Weaver ecology RCE", "severity": "high",
                        "products": ["weaver", "ecology"], "source": "nvd"})
        vi.upsert_vuln({"cve_id": "CVE-2026-0011", "title": "泛微 OA 文件上传", "severity": "critical",
                        "products": ["泛微"], "in_kev": True, "source": "qianxin_ti"})
        vi.upsert_vuln({"cve_id": "", "title": "泛微 命令执行", "severity": "high",
                        "products": ["weaver"], "source": "nuclei", "source_raw_id": "nuclei:x",
                        "executable": True, "exec_kind": "nuclei", "exec_ref": "x"})

    def test_query_by_component_alias_and_sort(self):
        self._seed_components()
        # 查中文"泛微"经别名扩展命中英文 weaver/ecology
        res = vi.query_by_component("泛微")
        self.assertGreaterEqual(res["count"], 3)
        # 排序：可执行优先
        self.assertTrue(res["vulns"][0]["executable"])

    def test_query_missing_component(self):
        res = vi.query_by_component("")
        self.assertIn("error", res)
        self.assertEqual(res["vulns"], [])

    def test_role_query_returns_list(self):
        self._seed_components()
        out = vi.VulnIntelServiceImpl().query("weaver", limit=2)
        self.assertIsInstance(out, list)
        self.assertLessEqual(len(out), 2)

    # —— list 过滤分页 ——
    def test_list_filter_and_paging(self):
        self._seed_components()
        r = vi.list_vulns(severity="high")
        self.assertTrue(all(i["severity"] == "high" for i in r["items"]))
        r2 = vi.list_vulns(in_kev=True)
        self.assertTrue(all(i["in_kev"] for i in r2["items"]))
        r3 = vi.list_vulns(page=1, size=1)
        self.assertEqual(len(r3["items"]), 1)
        self.assertIn("source_labels", r3["items"][0])

    # —— stat 聚合 ——
    def test_stat(self):
        self._seed_components()
        s = vi.stat()
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["in_kev"], 1)
        self.assertEqual(s["executable"], 1)
        self.assertIn("nvd", s["by_source"])

    # —— 库故障降级不抛 ——
    def test_query_db_failure_degrades(self):
        reset_repo()  # 无 repo → get_repo 会尝试建真连接失败
        with mock.patch("sentinel_platform.modules.risk_intel.vuln_intel.get_repo",
                        side_effect=RuntimeError("no db")):
            res = vi.query_by_component("weaver")
        self.assertEqual(res["vulns"], [])


class FeedTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        self.repo = FakeRepo()
        set_repo(self.repo)

    def tearDown(self):
        reset_repo()
        reset_registry()

    def test_source_registry_complete(self):
        # 10 源全注册，各有平台展示信息
        self.assertEqual(set(_feed.FETCHERS), set(_feed.SOURCE_PLATFORMS))
        self.assertEqual(len(_feed.FETCHERS), 10)

    def test_source_label(self):
        self.assertIn("CISA", _feed.source_label("cisa_kev"))
        self.assertEqual(_feed.source_label("unknown_src"), "unknown_src")

    def test_run_feed_with_mock_fetcher_and_notify(self):
        # mock 一个源返回 2 条（1 条 KEV），验证入库 + NOTIFY 命中
        fake = [{"cve_id": "CVE-2026-0099", "title": "KEV vuln", "severity": "high",
                 "in_kev": True, "source": "cisa_kev", "source_url": "u"},
                {"cve_id": "CVE-2026-0098", "title": "normal", "severity": "low",
                 "source": "cisa_kev", "source_url": "u2"}]
        notify_spy = mock.Mock()
        get_registry().register(ROLE.NOTIFY, mock.Mock(notify=notify_spy))
        with mock.patch.dict(_feed.FETCHERS, {"cisa_kev": lambda: fake}):
            report = _feed.run_feed(["cisa_kev"])
        self.assertEqual(report["cisa_kev"]["fetched"], 2)
        self.assertEqual(report["cisa_kev"]["new"], 2)
        notify_spy.assert_called_once()  # 有 1 条 KEV → 推送一次

    def test_run_feed_notify_missing_degrades(self):
        # 无 NOTIFY 注册也不炸
        with mock.patch.dict(_feed.FETCHERS,
                             {"nvd": lambda: [{"cve_id": "CVE-2026-0001", "title": "t",
                                               "severity": "critical", "source": "nvd"}]}):
            report = _feed.run_feed(["nvd"])
        self.assertEqual(report["nvd"]["new"], 1)

    def test_run_feed_unknown_source(self):
        report = _feed.run_feed(["does_not_exist"])
        self.assertIn("error", report["does_not_exist"])

    def test_run_feed_transient_retry(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 2:
                raise TimeoutError("connection timed out")
            return [{"cve_id": "CVE-2026-0077", "title": "t", "severity": "high", "source": "nvd"}]

        with mock.patch.object(_feed.time, "sleep"):
            with mock.patch.dict(_feed.FETCHERS, {"nvd": flaky}):
                report = _feed.run_feed(["nvd"])
        self.assertEqual(calls["n"], 2)  # 首次超时→重试成功
        self.assertEqual(report["nvd"]["new"], 1)

    def test_run_feed_network_failure_logs_warning_not_error(self):
        """境外源网络不可达(预期常态)应记 WARNING 不刷 ERROR+堆栈；只有非预期错误才 ERROR。
        治「vuln_feed source nvd/cisa_kev failed」每轮刷 100+ 条 ERROR 污染错误日志。"""
        def dead():
            raise Exception("HTTPSConnectionPool: Max retries exceeded (Caused by ProxyError timed out)")
        with mock.patch.object(_feed.time, "sleep"):
            with mock.patch.dict(_feed.FETCHERS, {"nvd": dead}):
                with mock.patch.object(_feed.logger, "warning") as mwarn, \
                     mock.patch.object(_feed.logger, "exception") as mexc:
                    report = _feed.run_feed(["nvd"])
        self.assertIn("error", report["nvd"])
        self.assertTrue(mwarn.called)          # 网络不可达 → WARNING
        self.assertFalse(mexc.called)          # 不再 ERROR+堆栈

    def test_run_feed_real_error_still_logs_exception(self):
        """非瞬时(解析/逻辑)错误仍 ERROR+堆栈，保留真问题可见性。"""
        def broken():
            raise ValueError("unexpected schema: KeyError 'items'")
        with mock.patch.dict(_feed.FETCHERS, {"nvd": broken}):
            with mock.patch.object(_feed.logger, "warning") as mwarn, \
                 mock.patch.object(_feed.logger, "exception") as mexc:
                _feed.run_feed(["nvd"])
        self.assertTrue(mexc.called)           # 真错误 → ERROR+堆栈
        self.assertFalse(mwarn.called)

    def test_feed_interval_get_set(self):
        self.assertEqual(_feed.get_feed_interval(), _feed.DEFAULT_FEED_INTERVAL)
        self.assertEqual(_feed.set_feed_interval(100), 600)  # 下限 600
        self.assertEqual(_feed.set_feed_interval(7200), 7200)
        self.assertEqual(_feed.get_feed_interval(), 7200)

    def test_feed_status_health(self):
        with mock.patch.dict(_feed.FETCHERS, {"nvd": lambda: [
                {"cve_id": "CVE-2026-0001", "title": "t", "severity": "high", "source": "nvd"}]}):
            _feed.run_feed(["nvd"])
        st = _feed.feed_status()
        self.assertIn("sources", st)
        nvd = next(s for s in st["sources"] if s["name"] == "nvd")
        self.assertEqual(nvd["health"], "ok")
        # 没拉过的源标 unknown
        seebug = next(s for s in st["sources"] if s["name"] == "seebug")
        self.assertEqual(seebug["health"], "unknown")

    def test_fetch_arl_npoc_from_poc_collection(self):
        poc = self.repo.collection("poc")
        poc.insert_one({"app_name": "泛微OA", "vul_name": "泛微RCE", "plugin_name": "weaver_rce"})
        out = _feed.fetch_arl_npoc()
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["executable"])
        self.assertEqual(out[0]["exec_kind"], "arl_npoc")

    def test_fetch_nvd_paginates_until_source_end(self):
        pages = [
            {"totalResults": 3, "vulnerabilities": [
                {"cve": {"id": "CVE-2026-1", "descriptions": [], "metrics": {}, "configurations": []}},
                {"cve": {"id": "CVE-2026-2", "descriptions": [], "metrics": {}, "configurations": []}},
            ]},
            {"totalResults": 3, "vulnerabilities": [
                {"cve": {"id": "CVE-2026-3", "descriptions": [], "metrics": {}, "configurations": []}},
            ]},
        ]
        with mock.patch.object(_feed, "_http_json", side_effect=pages) as req:
            out = _feed.fetch_nvd_recent(limit=0)
        self.assertEqual([x["cve_id"] for x in out], ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
        self.assertEqual(req.call_args_list[1].kwargs["params"]["startIndex"], 2)

    def test_fetch_nvd_positive_limit_is_caller_choice(self):
        page = {"totalResults": 10, "vulnerabilities": [
            {"cve": {"id": "CVE-2026-1", "descriptions": [], "metrics": {}, "configurations": []}},
            {"cve": {"id": "CVE-2026-2", "descriptions": [], "metrics": {}, "configurations": []}},
        ]}
        with mock.patch.object(_feed, "_http_json", return_value=page) as req:
            out = _feed.fetch_nvd_recent(limit=2)
        self.assertEqual(len(out), 2)
        self.assertEqual(req.call_args.kwargs["params"]["resultsPerPage"], 2)


if __name__ == "__main__":
    unittest.main()
