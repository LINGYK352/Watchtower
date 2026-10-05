"""certfetch 单测 —— 纯标准库，mock socket/ssl，不连真网络。

覆盖：_parse 各形态、available 恒真、fetch 并发聚合、取证成功→CertRec、连不上/非TLS→跳过、
空输入、registry 注册（build_registry 含 cert_fetch 角色且可 pick）。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.kernel.recon.native.certfetch import CertFetcher, ROLE_CERT_FETCH
from sentinel_platform.modules.kernel.recon.models import CertRec

_PEM = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"


class CertParseTest(unittest.TestCase):
    def test_parse_valid(self):
        self.assertEqual(CertFetcher._parse("1.2.3.4:443"), ("1.2.3.4", 443))
        self.assertEqual(CertFetcher._parse("host.example.com:8443"), ("host.example.com", 8443))

    def test_parse_invalid(self):
        for bad in ("noport", "1.2.3.4", "1.2.3.4:abc", "1.2.3.4:0", "1.2.3.4:70000", ":443", "", None):
            self.assertIsNone(CertFetcher._parse(bad))

    def test_available_always_true(self):
        self.assertTrue(CertFetcher().available())

    def test_concurrency_floor(self):
        self.assertEqual(CertFetcher(concurrency=0).concurrency, 1)


class CertFetchTest(unittest.TestCase):
    def setUp(self):
        self.cf = CertFetcher(timeout=1.0, concurrency=5)

    def test_empty_targets(self):
        self.assertEqual(self.cf.fetch([]), [])
        self.assertEqual(self.cf.fetch(None), [])
        self.assertEqual(self.cf.fetch(["nonsense", "no-port"]), [])   # 全非法 → []

    def test_fetch_success(self):
        # mock _fetch_one 返回 CertRec（隔离网络，验证聚合/解析链路）
        with mock.patch.object(CertFetcher, "_fetch_one",
                               side_effect=lambda ip, port: CertRec(ip=ip, port=port, cert=_PEM)):
            out = self.cf.fetch(["1.2.3.4:443", "5.6.7.8:8443"])
        self.assertEqual(len(out), 2)
        self.assertTrue(all(isinstance(x, CertRec) and x.cert == _PEM for x in out))
        self.assertEqual({x.port for x in out}, {443, 8443})

    def test_fetch_skips_unreachable(self):
        # 一个成功一个失败（None）→ 只返回成功的
        def _one(ip, port):
            return CertRec(ip=ip, port=port, cert=_PEM) if port == 443 else None
        with mock.patch.object(CertFetcher, "_fetch_one", side_effect=_one):
            out = self.cf.fetch(["1.2.3.4:443", "5.6.7.8:9999"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].port, 443)

    def test_fetch_one_der_to_pem(self):
        # mock socket + ssl：getpeercert(binary_form=True) 返 der → DER_cert_to_PEM_cert
        fake_ssock = mock.MagicMock()
        fake_ssock.getpeercert.return_value = b"DERBYTES"
        fake_ctx = mock.MagicMock()
        fake_ctx.wrap_socket.return_value.__enter__.return_value = fake_ssock
        with mock.patch("ssl.create_default_context", return_value=fake_ctx), \
             mock.patch("socket.create_connection"), \
             mock.patch("ssl.DER_cert_to_PEM_cert", return_value=_PEM) as m_pem:
            rec = self.cf._fetch_one("1.2.3.4", 443)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.cert, _PEM)
        m_pem.assert_called_once_with(b"DERBYTES")

    def test_fetch_one_no_cert_returns_none(self):
        fake_ssock = mock.MagicMock()
        fake_ssock.getpeercert.return_value = None       # 无证书
        fake_ctx = mock.MagicMock()
        fake_ctx.wrap_socket.return_value.__enter__.return_value = fake_ssock
        with mock.patch("ssl.create_default_context", return_value=fake_ctx), \
             mock.patch("socket.create_connection"):
            self.assertIsNone(self.cf._fetch_one("1.2.3.4", 443))

    def test_fetch_one_connection_error_returns_none(self):
        with mock.patch("socket.create_connection", side_effect=OSError("refused")):
            self.assertIsNone(self.cf._fetch_one("1.2.3.4", 443))


class CertRegistryTest(unittest.TestCase):
    def test_registered_and_pickable(self):
        from sentinel_platform.modules.kernel.recon.registry import build_registry, ROLE_CERT_FETCH as R
        reg = build_registry(None)
        self.assertEqual(R, ROLE_CERT_FETCH)
        tool = reg.pick(ROLE_CERT_FETCH)          # native 恒 available → pick 到
        self.assertIsNotNone(tool)
        self.assertEqual(tool.adapter, "native_certfetch")


if __name__ == "__main__":
    unittest.main()
