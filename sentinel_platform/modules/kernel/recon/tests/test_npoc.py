"""recon/tools/npoc 单测 —— list 解析 / scan JSONL 解析 / 降级 / registry。

不需真装 xing：available() 依赖 xing 二进制，通过注入假路径验证；解析器直接喂样本文本/JSONL。
run_poc 的 subprocess 执行不在单测跑（只测解析与降级路径），避免依赖真 xing/真扫描。
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from sentinel_platform.modules.kernel.recon.tools.npoc import (
    Npoc, ROLE_SERVICE_POC, _as_list,
)
from sentinel_platform.modules.kernel.recon.models import VulnRec


class TestParseList(unittest.TestCase):
    def test_poc_and_brute_lines(self):
        text = (
            "[1][poc] Redis_noauth | Redis 未授权访问\n"
            "[2][brute] mysql_brute | MySQL 弱口令\n"
            "[3][sniffer-redis] redis_sniffer \n"
        )
        out = Npoc.parse_list(text)
        names = {r["plugin_name"]: r for r in out}
        self.assertIn("Redis_noauth", names)
        self.assertEqual(names["Redis_noauth"]["plugin_type"], "poc")
        self.assertEqual(names["Redis_noauth"]["vul_name"], "Redis 未授权访问")
        self.assertEqual(names["mysql_brute"]["plugin_type"], "brute")
        self.assertIn("redis_sniffer", names)   # sniffer 行(带 -scheme)也解析

    def test_dedup(self):
        text = "[1][poc] A | x\n[2][poc] A | x\n"
        self.assertEqual(len(Npoc.parse_list(text)), 1)

    def test_ignore_noise(self):
        text = "load plugin 42\nsome log line\n[1][poc] Solr_noauth | Solr 未授权\n"
        out = Npoc.parse_list(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["plugin_name"], "Solr_noauth")

    def test_empty(self):
        self.assertEqual(Npoc.parse_list(""), [])
        self.assertEqual(Npoc.parse_list(None), [])

    def test_no_vul_name(self):
        out = Npoc.parse_list("[1][poc] NoVul\n")
        self.assertEqual(out[0]["plugin_name"], "NoVul")
        self.assertEqual(out[0]["vul_name"], "")


class TestParseResults(unittest.TestCase):
    def _write(self, lines):
        f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        f.write("\n".join(lines))
        f.close()
        return f.name

    def test_jsonl_to_vulnrec(self):
        path = self._write([
            json.dumps({"plg_name": "Redis_noauth", "plg_type": "poc",
                        "vul_name": "Redis 未授权", "app_name": "Redis",
                        "target": "redis://1.2.3.4:6379", "verify_data": "keys *"}),
            json.dumps({"plg_name": "mysql_brute", "plg_type": "brute",
                        "vul_name": "MySQL 弱口令", "app_name": "MySQL",
                        "target": "1.2.3.4:3306", "verify_data": {"username": "root", "password": "123456"}}),
        ])
        try:
            out = Npoc.parse_results(path)
            self.assertEqual(len(out), 2)
            self.assertIsInstance(out[0], VulnRec)
            self.assertEqual(out[0].plg_name, "Redis_noauth")
            self.assertEqual(out[0].target, "redis://1.2.3.4:6379")
            self.assertEqual(out[0].verify_data, "keys *")
            # dict verify_data 被 json 序列化成字符串
            self.assertIn("root", out[1].verify_data)
            self.assertEqual(out[1].plg_type, "brute")
        finally:
            os.unlink(path)

    def test_skip_bad_lines(self):
        path = self._write(["not json", "", json.dumps({"plg_name": "X", "target": "t"}), "123"])
        try:
            out = Npoc.parse_results(path)
            # "not json" 跳过；"123" 是合法 json 但非 dict 跳过；只 X 有效
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0].plg_name, "X")
            self.assertEqual(out[0].plg_type, "poc")   # 缺省
        finally:
            os.unlink(path)

    def test_missing_file(self):
        self.assertEqual(Npoc.parse_results("/no/such/result.txt"), [])
        self.assertEqual(Npoc.parse_results(""), [])


class TestAvailable(unittest.TestCase):
    def test_unavailable_no_binary(self):
        n = Npoc(binary_path="/no/such/xing")
        self.assertFalse(n.available())

    def test_available_with_fake_binary(self):
        with tempfile.NamedTemporaryFile(suffix="_xing", delete=False) as f:
            fake = f.name
        try:
            n = Npoc(binary_path=fake)
            self.assertTrue(n.available())
            self.assertEqual(n.locate(), fake)
        finally:
            os.unlink(fake)


class TestRunPocDegrade(unittest.TestCase):
    def test_no_binary_returns_empty(self):
        n = Npoc(binary_path="/no/such/xing")
        self.assertEqual(n.run_poc(["Redis_noauth"], ["1.2.3.4:6379"]), [])

    def test_no_targets_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix="_xing", delete=False) as f:
            fake = f.name
        try:
            n = Npoc(binary_path=fake)
            self.assertEqual(n.run_poc(["Redis_noauth"], []), [])
            self.assertEqual(n.run_poc(["Redis_noauth"], None), [])
        finally:
            os.unlink(fake)

    def test_list_plugins_no_binary(self):
        n = Npoc(binary_path="/no/such/xing")
        self.assertEqual(n.list_plugins(), [])


class TestAsList(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(_as_list(None), [])
        self.assertEqual(_as_list("a"), ["a"])
        self.assertEqual(_as_list(["a", "b"]), ["a", "b"])
        self.assertEqual(_as_list(("a",)), ["a"])


class TestRegistryIntegration(unittest.TestCase):
    def test_npoc_registered(self):
        from sentinel_platform.modules.kernel.recon.registry import build_registry, ROLE_SERVICE_POC as R
        reg = build_registry(None)
        tool = reg.first(R)
        self.assertIsNotNone(tool)
        self.assertEqual(tool.adapter, "npoc")

    def test_role_constant(self):
        self.assertEqual(ROLE_SERVICE_POC, "service_poc")


class TestReconBridgeWiring(unittest.TestCase):
    """recon_bridge.run_poc 契约修复：有 plugins 走 service_poc，无则 nuclei 降级。"""

    def test_run_poc_uses_npoc_when_plugins(self):
        from sentinel_platform.modules.kernel import recon_bridge as rb

        class _FakeNpoc:
            adapter = "npoc"
            def available(self): return True
            def run_poc(self, plugins, targets, proxy=""):
                return [VulnRec(target=targets[0], vul_name="v", plg_name=plugins[0],
                                plg_type="poc", app_name="a", verify_data="ok")]

        bridge = rb.ReconBridge()
        bridge._reg.register(rb.ROLE_SERVICE_POC, _FakeNpoc())
        out = bridge.run_poc(["Redis_noauth"], ["redis://1.2.3.4:6379"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["plg_name"], "Redis_noauth")
        self.assertEqual(out[0]["verify_data"], "ok")

    def test_run_poc_falls_back_nuclei_no_plugins(self):
        from sentinel_platform.modules.kernel import recon_bridge as rb
        bridge = rb.ReconBridge()
        called = {}
        def _fake_nuclei(targets, **kw):
            called["t"] = targets
            return []
        bridge.nuclei_scan = _fake_nuclei
        out = bridge.run_poc(None, ["http://a.com"])
        self.assertEqual(out, [])
        self.assertEqual(called["t"], ["http://a.com"])   # 无 plugins → 走 nuclei


if __name__ == "__main__":
    unittest.main()
