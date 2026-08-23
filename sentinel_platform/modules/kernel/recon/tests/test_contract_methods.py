"""补契约方法单测 —— dnsx 解析 / webinfo 提取 / bridge 的 dns_query·collect_js·run_recon。

不跑真进程/真网络：dnsx 测 parse_record，webinfo 测 _extract 纯正则，bridge 用 stub。
"""
import unittest

from sentinel_platform.modules.kernel.recon.tools import Dnsx
from sentinel_platform.modules.kernel.recon.models import DomainRec, WihRec
from sentinel_platform.modules.kernel.recon.webinfo import WebInfoHunter
from sentinel_platform.modules.kernel.recon_bridge import ReconBridge


class TestDnsx(unittest.TestCase):
    def test_parse_a(self):
        rec = Dnsx().parse_record({"host": "A.com", "a": ["1.2.3.4"]})
        self.assertIsInstance(rec, DomainRec)
        self.assertEqual(rec.domain, "a.com")
        self.assertEqual(rec.type, "A")
        self.assertEqual(rec.ips, ["1.2.3.4"])

    def test_parse_cname_priority(self):
        rec = Dnsx().parse_record({"host": "x.com", "a": ["1.1.1.1"], "cname": ["c.com"]})
        self.assertEqual(rec.type, "CNAME")
        self.assertEqual(rec.record, ["c.com"])

    def test_no_resolution_dropped(self):
        self.assertIsNone(Dnsx().parse_record({"host": "x.com"}))


class TestWebInfoExtract(unittest.TestCase):
    def setUp(self):
        self.w = WebInfoHunter()
        self.hits = []
        self._add = lambda t, c: self.hits.append((t, c))

    def test_extract_path_ip_mail_mobile(self):
        blob = '"/api/user/list" "admin@corp.com" 10.0.0.1:8080 13800138000 "http://a.com/x"'
        self.w._extract(blob, self._add)
        types = {t for t, _ in self.hits}
        self.assertIn("url", types)       # /api/... 与 http://...
        self.assertIn("ip_port", types)
        self.assertIn("mail", types)
        self.assertIn("mobile", types)

    def test_secret_akia(self):
        self.w._extract('key="AKIAABCDEFGHIJKLMNOP"', self._add)
        self.assertTrue(any(t == "secret" and c.startswith("aws_ak:") for t, c in self.hits))

    def test_static_path_skipped(self):
        self.w._extract('"/assets/logo.png" "/api/real"', self._add)
        urls = [c for t, c in self.hits if t == "url"]
        self.assertIn("/api/real", urls)
        self.assertNotIn("/assets/logo.png", urls)

    def test_endpoint_with_query_string_extracted(self):
        """回归(旧简化正则漏报):带 ?query 的接口必须提取到。旧 `["'](/...)["']` 遇 ? 整体失配，
        漏掉 /acb/2.0/bossManager/listVO?page=1&size=100；换 LinkFinder 正则后应提到(含 query)。"""
        blob = 'axios.get("/acb/2.0/bossManager/listVO?page=1&size=100");$.post("/prod-api/system/user/add")'
        self.w._extract(blob, self._add)
        urls = [c for t, c in self.hits if t == "url"]
        self.assertTrue(any("/acb/2.0/bossManager/listVO" in u for u in urls),
                        "带 query 的业务接口必须被提取到（LinkFinder 正则回归）")
        self.assertIn("/prod-api/system/user/add", urls)

    def test_lib_noise_endpoint_filtered(self):
        """前端库路径(jquery/vue 等)不当业务接口。"""
        self.w._extract('"/static/jquery.min.js" "/api/biz/list"', self._add)
        urls = [c for t, c in self.hits if t == "url"]
        self.assertIn("/api/biz/list", urls)
        self.assertFalse(any("jquery" in u for u in urls))

    def test_available(self):
        self.assertTrue(WebInfoHunter().available())


class _StubResolver:
    adapter = "stub_dnsx"
    def available(self):
        return True
    def resolve(self, hosts, concurrency=200):
        return [DomainRec(domain="a.com", type="A", ips=["1.2.3.4"], record=["1.2.3.4"])]


class _StubWebinfo:
    adapter = "stub_webinfo"
    def available(self):
        return True
    def hunt(self, sites):
        return [WihRec(record_type="url", content="/api/x", site="https://a.com")]


class TestBridgeContractMethods(unittest.TestCase):
    def test_dns_query_dicts(self):
        b = ReconBridge()
        b._reg._roles["dns_resolve"].insert(0, _StubResolver())
        out = b.dns_query("a.com")
        self.assertTrue(out and isinstance(out[0], dict))
        self.assertEqual(out[0]["domain"], "a.com")

    def test_collect_js_dicts(self):
        b = ReconBridge()
        b._reg._roles["webinfo"].insert(0, _StubWebinfo())
        out = b.collect_js("https://a.com")
        self.assertEqual(out[0]["record_type"], "url")

    def test_dns_query_degrade(self):
        b = ReconBridge()
        b._reg._roles["dns_resolve"] = []
        self.assertEqual(b.dns_query("a.com"), [])

    def test_run_recon_summary_shape(self):
        b = ReconBridge()
        # 全部工具置空 → 各阶段跳过，仍返回规范摘要 dict（result=done, stages=[]）
        for role in ("dns_resolve", "port_scan", "http_probe", "vuln_scan"):
            b._reg._roles[role] = []
        r = b.run_recon("domain", "task1", "a.com")
        self.assertIn(r["result"], ("done", "error"))  # Windows 可定位到 Linux ELF 时会如实标执行错误
        self.assertIsInstance(r["stages"], list)
        self.assertEqual(r["records"], {})
        if r["result"] == "done":
            self.assertIsNone(r["error"])
        else:
            self.assertIn("failed stages", r["error"])

    def test_run_recon_delegates_to_pipeline(self):
        # P1(2026-07-05)后 run_recon 委托 recon/pipeline（替换旧最小4阶段+旧registry-role桩）。
        # 验证委托契约：run_recon 调 pipeline.run_pipeline 并透传参数、返回其摘要（数据流细节见 test_pipeline）。
        import sentinel_platform.modules.kernel.recon.pipeline as _pl
        captured = {}
        orig = _pl.run_pipeline
        def _spy(task_id, task_type, target, options=None, cancel_check=None, **_kw):
            captured.update(task_id=task_id, task_type=task_type, target=target, options=options)
            return {"result": "done", "task_id": task_id, "task_type": task_type,
                    "stages": ["subdomain"], "skipped": [], "counts": {}, "records": {"domain": [{"domain": "a.com"}]}, "error": None}
        _pl.run_pipeline = _spy
        try:
            r = ReconBridge().run_recon("domain", "t", "a.com", ports="top-100")
        finally:
            _pl.run_pipeline = orig
        self.assertEqual(captured["task_type"], "domain")
        self.assertEqual(captured["target"], "a.com")
        self.assertEqual(captured["options"].get("ports"), "top-100")   # kwargs 透传进 options
        self.assertIn("subdomain", r["stages"])
        self.assertIn("domain", r["records"])


class ScanEgressTest(unittest.TestCase):
    """scan_proxy 扫描出口代理（回归:净室迁移曾丢,scan_proxy 存了没人消费扫描恒直连）。
    移植旧 proxy_core.set_scan_egress→注入 *_proxy env 供扫描子进程/native 继承。"""

    def setUp(self):
        from sentinel_platform.contracts.registry import reset_registry
        reset_registry()

    def tearDown(self):
        import os
        from sentinel_platform.modules.kernel import recon_bridge as rb
        for k in rb._SCAN_PROXY_ENV_KEYS:
            os.environ.pop(k, None)
        from sentinel_platform.contracts.registry import reset_registry
        reset_registry()

    def _reg_proxy(self, url="http://127.0.0.1:7890"):
        from sentinel_platform.contracts import get_registry, ROLE
        class _P:
            def resolve_egress(self, prefer, source=""): return (url, False)
        get_registry().register(ROLE.PROXY, _P())

    def test_proxy_mode_injects_env(self):
        import os
        from sentinel_platform.modules.kernel import recon_bridge as rb
        for k in rb._SCAN_PROXY_ENV_KEYS: os.environ.pop(k, None)
        self._reg_proxy()
        saved = rb._apply_scan_egress({"scan_proxy": "proxy"})
        self.assertEqual(os.environ.get("HTTP_PROXY"), "http://127.0.0.1:7890")
        self.assertEqual(os.environ.get("ALL_PROXY"), "http://127.0.0.1:7890")
        rb._restore_scan_egress(saved)          # 还原后清干净
        self.assertNotIn("HTTP_PROXY", os.environ)

    def test_direct_mode_no_inject(self):
        import os
        from sentinel_platform.modules.kernel import recon_bridge as rb
        for k in rb._SCAN_PROXY_ENV_KEYS: os.environ.pop(k, None)
        self._reg_proxy()
        saved = rb._apply_scan_egress({"scan_proxy": "direct"})
        self.assertEqual(saved, {})
        self.assertNotIn("HTTP_PROXY", os.environ)   # direct 不注入

    def test_no_proxy_service_degrade(self):
        from sentinel_platform.modules.kernel import recon_bridge as rb
        saved = rb._apply_scan_egress({"scan_proxy": "proxy"})   # 无 PROXY 服务
        self.assertEqual(saved, {})                              # 降级不崩不注入


if __name__ == "__main__":
    unittest.main()
