"""fileleak 单测 —— 纯标准库，mock urllib，不连真网络。

覆盖：available 恒真、命中状态过滤、基线去误报（同状态+近长度→跳过）、_extract_title、
空输入、wordlist 注入、HTTPError(403/500)仍判命中、registry 注册（build_registry 含 file_leak）。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.kernel.recon.native.fileleak import (
    FileLeakScanner, ROLE_FILE_LEAK, DEFAULT_WORDLIST, _extract_title)
from sentinel_platform.modules.kernel.recon.models import FileLeakRec


class FileLeakUnitTest(unittest.TestCase):
    def test_available(self):
        self.assertTrue(FileLeakScanner().available())

    def test_extract_title(self):
        self.assertEqual(_extract_title(b"<html><title>Index of /</title></html>"), "Index of /")
        self.assertEqual(_extract_title(b"no title here"), "")
        self.assertEqual(_extract_title(b"<title>x"), "")   # 无闭合

    def test_empty_sites(self):
        self.assertEqual(FileLeakScanner().scan([]), [])
        self.assertEqual(FileLeakScanner().scan(None), [])

    def test_default_wordlist_nonempty(self):
        self.assertIn(".git/config", DEFAULT_WORDLIST)
        self.assertIn(".env", DEFAULT_WORDLIST)

    def test_concurrency_floor(self):
        self.assertEqual(FileLeakScanner(concurrency=0).concurrency, 1)


class FileLeakScanTest(unittest.TestCase):
    def setUp(self):
        self.sc = FileLeakScanner(timeout=1.0, concurrency=4)

    def _mk_request(self, mapping, baseline=(404, 100, "")):
        """构造 _request 替身：baseline 路径返基线；mapping[path]=(status,len,title)。"""
        def _req(url):
            if "sentinel_nonexist" in url:
                return baseline
            for path, resp in mapping.items():
                if url.endswith(path):
                    return resp
            return (404, 100, "")   # 未列出的路径同基线
        return _req

    def test_hit_and_baseline_dedup(self):
        # .git/config 命中(200,长度差异大)；robots.txt 与基线同状态近长度→误报跳过
        mapping = {".git/config": (200, 500, "cfg"), "robots.txt": (404, 110, "")}
        with mock.patch.object(FileLeakScanner, "_request",
                               side_effect=self._mk_request(mapping, baseline=(404, 100, ""))):
            out = self.sc.scan(["http://t.com"], wordlist=[".git/config", "robots.txt"])
        self.assertEqual(len(out), 1)
        self.assertIsInstance(out[0], FileLeakRec)
        self.assertTrue(out[0].url.endswith(".git/config"))
        self.assertEqual(out[0].status_code, 200)

    def test_status_not_in_hit_skipped(self):
        # 302 不在命中候选(_HIT_STATUS)→跳过
        with mock.patch.object(FileLeakScanner, "_request",
                               side_effect=self._mk_request({".env": (302, 50, "")}, baseline=(404, 0, ""))):
            out = self.sc.scan(["http://t.com"], wordlist=[".env"])
        self.assertEqual(out, [])

    def test_403_500_are_hits(self):
        # 403/500 属命中候选，且与基线(404)状态不同→不被去误报
        mapping = {"admin": (403, 20, "Forbidden"), "err": (500, 30, "Error")}
        with mock.patch.object(FileLeakScanner, "_request",
                               side_effect=self._mk_request(mapping, baseline=(404, 0, ""))):
            out = self.sc.scan(["http://t.com/"], wordlist=["admin", "err"])
        self.assertEqual({r.status_code for r in out}, {403, 500})

    def test_baseline_same_status_close_length_filtered(self):
        # 命中 200 但基线也是 200 且长度相近(<32)→泛响应跳过
        with mock.patch.object(FileLeakScanner, "_request",
                               side_effect=self._mk_request({"x": (200, 1010, "")}, baseline=(200, 1000, ""))):
            out = self.sc.scan(["http://spa.com"], wordlist=["x"])
        self.assertEqual(out, [])

    def test_request_httperror_returns_code(self):
        import urllib.error
        sc = FileLeakScanner(timeout=0.5)
        err = urllib.error.HTTPError("http://t/x", 403, "Forbidden", {}, None)
        err.read = lambda n=0: b"denied"
        with mock.patch("urllib.request.urlopen", side_effect=err):
            r = sc._request("http://t/x")
        self.assertEqual(r[0], 403)
        self.assertEqual(r[1], len(b"denied"))

    def test_request_conn_error_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("refused")):
            self.assertIsNone(FileLeakScanner(timeout=0.5)._request("http://t/x"))


class FileLeakRegistryTest(unittest.TestCase):
    def test_registered_and_pickable(self):
        from sentinel_platform.modules.kernel.recon.registry import build_registry, ROLE_FILE_LEAK as R
        reg = build_registry(None)
        self.assertEqual(R, ROLE_FILE_LEAK)
        tool = reg.pick(ROLE_FILE_LEAK)
        self.assertIsNotNone(tool)
        self.assertEqual(tool.adapter, "native_fileleak")


if __name__ == "__main__":
    unittest.main()
