"""vhost 单测 —— 纯标准库，mock urllib，不连真网络。

覆盖：available 恒真、基线对比判独立 vhost、与基线同状态近长度→非 vhost、状态不同→vhost、
空输入、去重、HTTPError 状态、registry 注册（build_registry 含 vhost 且可 pick）。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.kernel.recon.native.vhost import VhostFinder, ROLE_VHOST
from sentinel_platform.modules.kernel.recon.models import SiteRec


class VhostUnitTest(unittest.TestCase):
    def test_available(self):
        self.assertTrue(VhostFinder().available())

    def test_concurrency_floor(self):
        self.assertEqual(VhostFinder(concurrency=0).concurrency, 1)

    def test_empty_inputs(self):
        vf = VhostFinder()
        self.assertEqual(vf.find("", ["a.com"]), [])
        self.assertEqual(vf.find("1.2.3.4", []), [])
        self.assertEqual(vf.find("1.2.3.4", None), [])


class VhostFindTest(unittest.TestCase):
    def setUp(self):
        self.vf = VhostFinder(timeout=1.0, concurrency=4)

    def _mk_request(self, host_map, baseline=(404, 100)):
        """_request(url, host) 替身：基线 host 返 baseline；host_map[host]=(status,len)。"""
        def _req(url, host):
            if host == "sentinel-nonexist-host.invalid":
                return baseline
            return host_map.get(host, baseline)
        return _req

    def test_distinct_vhost_by_status(self):
        # a.com 状态与基线不同 → vhost；b.com 与基线相同 → 非 vhost
        hm = {"a.com": (200, 100), "b.com": (404, 100)}
        with mock.patch.object(VhostFinder, "_request", side_effect=self._mk_request(hm, (404, 100))):
            out = self.vf.find("1.2.3.4", ["a.com", "b.com"])
        self.assertEqual(len(out), 1)
        self.assertIsInstance(out[0], SiteRec)
        self.assertEqual(out[0].hostname, "a.com")
        self.assertEqual(out[0].ip, "1.2.3.4")
        self.assertEqual(out[0].url, "http://a.com/")

    def test_distinct_vhost_by_length(self):
        # 同状态但长度差 ≥64 → vhost；长度差 <64 → 非 vhost
        hm = {"big.com": (200, 500), "same.com": (200, 210)}
        with mock.patch.object(VhostFinder, "_request", side_effect=self._mk_request(hm, (200, 200))):
            out = self.vf.find("1.2.3.4", ["big.com", "same.com"])
        self.assertEqual({r.hostname for r in out}, {"big.com"})

    def test_baseline_none_collects_all(self):
        # 基线取不到（None）→ 所有响应到的 host 都收
        def _req(url, host):
            if host == "sentinel-nonexist-host.invalid":
                return None
            return (200, 100)
        with mock.patch.object(VhostFinder, "_request", side_effect=_req):
            out = self.vf.find("1.2.3.4", ["a.com", "b.com"])
        self.assertEqual(len(out), 2)

    def test_unreachable_host_skipped(self):
        def _req(url, host):
            if host == "sentinel-nonexist-host.invalid":
                return (404, 0)
            return (200, 999) if host == "up.com" else None
        with mock.patch.object(VhostFinder, "_request", side_effect=_req):
            out = self.vf.find("1.2.3.4", ["up.com", "down.com"])
        self.assertEqual([r.hostname for r in out], ["up.com"])

    def test_https_scheme(self):
        with mock.patch.object(VhostFinder, "_request",
                               side_effect=self._mk_request({"s.com": (200, 500)}, (404, 0))):
            out = self.vf.find("1.2.3.4", ["s.com"], scheme="https")
        self.assertEqual(out[0].url, "https://s.com/")

    def test_request_httperror_returns_code(self):
        import urllib.error
        err = urllib.error.HTTPError("http://1.2.3.4/", 403, "Forbidden", {}, None)
        err.read = lambda n=0: b"deny"
        with mock.patch("urllib.request.urlopen", side_effect=err):
            r = self.vf._request("http://1.2.3.4/", "x.com")
        self.assertEqual(r, (403, 4))

    def test_request_conn_error_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("refused")):
            self.assertIsNone(self.vf._request("http://1.2.3.4/", "x.com"))


class VhostRegistryTest(unittest.TestCase):
    def test_registered_and_pickable(self):
        from sentinel_platform.modules.kernel.recon.registry import build_registry, ROLE_VHOST as R
        reg = build_registry(None)
        self.assertEqual(R, ROLE_VHOST)
        tool = reg.pick(ROLE_VHOST)
        self.assertIsNotNone(tool)
        self.assertEqual(tool.adapter, "native_vhost")


if __name__ == "__main__":
    unittest.main()
