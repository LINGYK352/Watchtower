"""recon_bridge 单测 —— 验证 dict 化 + 工具缺失降级，不跑真进程。

用 stub 工具替换 registry，验证 bridge 把 models dataclass 转成 list[dict]（对齐 §0.3），
以及工具 pick 返回 None 时降级为 []（不抛异常）。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.kernel import recon_bridge as _rb
from sentinel_platform.modules.kernel.recon_bridge import ReconBridge
from sentinel_platform.modules.kernel.recon.models import NucleiRec, VulnRec


class _StubNuclei:
    adapter = "stub_nuclei"
    def available(self):
        return True
    def scan(self, targets, concurrency=25):
        return [NucleiRec(target="a.com", template_id="T1", vuln_name="v", vuln_severity="high")]


class _StubBrute:
    adapter = "stub_brute"
    def available(self):
        return True
    def brute(self, host, port, scheme):
        return [VulnRec(target="ssh://h:22", plg_type="brute", verify_data="root:123")]


class TestReconBridge(unittest.TestCase):
    def setUp(self):
        self.bridge = ReconBridge()

    # 主动扫描已全局禁用(_ACTIVE_SCAN_DISABLED=True)——底层 nuclei_scan/weak_brute/run_poc 返空。
    # 下列测试验证「底层结构化转换逻辑本身」，用 mock 临时关禁用开关（将来恢复主动扫描时逻辑仍正确）。
    def test_nuclei_scan_dicts(self):
        self.bridge._reg.register("vuln_scan", _StubNuclei())
        self.bridge._reg._roles["vuln_scan"].insert(0, _StubNuclei())
        with mock.patch.object(_rb, "_ACTIVE_SCAN_DISABLED", False):
            out = self.bridge.nuclei_scan(["https://a.com"])
        self.assertTrue(out and isinstance(out[0], dict))
        self.assertEqual(out[0]["target"], "a.com")
        self.assertEqual(out[0]["vuln_severity"], "high")

    def test_weak_brute_dicts(self):
        self.bridge._reg._roles.setdefault("weak_brute", []).insert(0, _StubBrute())
        with mock.patch.object(_rb, "_ACTIVE_SCAN_DISABLED", False):
            out = self.bridge.weak_brute("h", 22, "ssh")
        self.assertTrue(out and isinstance(out[0], dict))
        self.assertEqual(out[0]["verify_data"], "root:123")

    def test_degrade_empty_when_no_tool(self):
        b = ReconBridge()
        b._reg._roles["vuln_scan"] = []          # 模拟工具全不可用
        with mock.patch.object(_rb, "_ACTIVE_SCAN_DISABLED", False):
            self.assertEqual(b.nuclei_scan(["x"]), [])

    def test_run_poc_alias(self):
        self.bridge._reg._roles["vuln_scan"].insert(0, _StubNuclei())
        with mock.patch.object(_rb, "_ACTIVE_SCAN_DISABLED", False):
            self.assertTrue(self.bridge.run_poc(targets=["https://a.com"]))

    def test_active_scan_globally_disabled_returns_empty(self):
        """全局禁用开关生效：nuclei_scan/weak_brute/run_poc 直接返空、不调工具。"""
        self.bridge._reg._roles["vuln_scan"] = [_StubNuclei()]
        self.bridge._reg._roles.setdefault("weak_brute", []).insert(0, _StubBrute())
        self.assertEqual(self.bridge.nuclei_scan(["https://a.com"]), [])
        self.assertEqual(self.bridge.weak_brute("h", 22, "ssh"), [])
        self.assertEqual(self.bridge.run_poc(targets=["https://a.com"]), [])

    def test_as_list_accepts_str(self):
        b = ReconBridge()
        b._reg._roles["http_probe"] = []
        self.assertEqual(b.http_probe("single-target"), [])


if __name__ == "__main__":
    unittest.main()
