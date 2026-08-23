"""recon/enrich 单测 —— 纯函数 + GeoIP(mock) + 批量富化 + 降级。

不需真装 maxminddb、不需真 mmdb：GeoIP 通过注入假 reader（鸭子类型 .get(ip)）验证。
"""
from __future__ import annotations

import os
import unittest

from sentinel_platform.modules.kernel.recon.enrich import (
    classify_ip, extract_fld, auto_tag, detect_cdn, default_geolite_dir,
    GeoIPResolver, Enricher, build_enricher, _host_from_url,
)


class _FakeReader:
    """假 mmdb reader：按注入的 dict 返回，模拟 maxminddb open_database().get(ip)。"""
    def __init__(self, table):
        self._t = table
        self.closed = False
    def get(self, ip):
        return self._t.get(ip)
    def close(self):
        self.closed = True


class TestClassifyIP(unittest.TestCase):
    def test_public(self):
        self.assertEqual(classify_ip("8.8.8.8"), "PUBLIC")
        self.assertEqual(classify_ip("1.1.1.1"), "PUBLIC")
        self.assertEqual(classify_ip("114.114.114.114"), "PUBLIC")

    def test_private(self):
        for ip in ("10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1",
                   "169.254.1.1", "100.64.0.1"):
            self.assertEqual(classify_ip(ip), "PRIVATE", ip)

    def test_ipv6(self):
        self.assertEqual(classify_ip("2001:4860:4860::8888"), "PUBLIC")
        self.assertEqual(classify_ip("::1"), "PRIVATE")
        self.assertEqual(classify_ip("fe80::1"), "PRIVATE")

    def test_non_ip(self):
        self.assertEqual(classify_ip("example.com"), "")
        self.assertEqual(classify_ip(""), "")
        self.assertEqual(classify_ip("999.1.1.1"), "")
        self.assertEqual(classify_ip(None), "")


class TestExtractFld(unittest.TestCase):
    def test_two_level(self):
        self.assertEqual(extract_fld("www.example.com"), "example.com")
        self.assertEqual(extract_fld("a.b.c.example.com"), "example.com")

    def test_three_level_suffix(self):
        self.assertEqual(extract_fld("www.example.com.cn"), "example.com.cn")
        self.assertEqual(extract_fld("shop.example.gov.cn"), "example.gov.cn")
        self.assertEqual(extract_fld("x.y.example.co.uk"), "example.co.uk")

    def test_bare_and_short(self):
        self.assertEqual(extract_fld("example.com"), "example.com")
        self.assertEqual(extract_fld("localhost"), "localhost")

    def test_ip_passthrough(self):
        self.assertEqual(extract_fld("8.8.8.8"), "8.8.8.8")

    def test_empty(self):
        self.assertEqual(extract_fld(""), "")
        self.assertEqual(extract_fld(None), "")

    def test_normalize_case_dots(self):
        self.assertEqual(extract_fld("WWW.Example.COM."), "example.com")


class TestAutoTag(unittest.TestCase):
    def test_4xx_5xx_invalid(self):
        self.assertEqual(auto_tag({"status": 404, "title": "Something"}), ["无效"])
        self.assertEqual(auto_tag({"status": 502}), ["无效"])

    def test_container_title_invalid(self):
        self.assertEqual(auto_tag({"status": 200, "title": "Welcome to nginx!"}), ["无效"])
        self.assertEqual(auto_tag({"status": 200, "title": "Apache Tomcat/8.5"}), ["无效"])

    def test_small_body_no_title_invalid(self):
        self.assertEqual(auto_tag({"status": 200, "title": "", "body_length": 50}), ["无效"])

    def test_entry(self):
        self.assertEqual(auto_tag({"status": 200, "title": "后台管理系统", "body_length": 5000}), ["入口"])
        # 200 + 无标题但 body 够大 → 入口
        self.assertEqual(auto_tag({"status": 200, "title": "", "body_length": 5000}), ["入口"])

    def test_dirty_values(self):
        # 非数字 status/body 不炸
        self.assertEqual(auto_tag({"status": "x", "title": "登录", "body_length": "y"}), ["入口"])


class TestDetectCDN(unittest.TestCase):
    def test_hit(self):
        self.assertEqual(detect_cdn(["x.cloudfront.net"]), "cloudfront")
        self.assertEqual(detect_cdn(["foo.aliyuncs.com"]), "aliyuncs")

    def test_miss(self):
        self.assertEqual(detect_cdn(["www.example.com"]), "")
        self.assertEqual(detect_cdn([]), "")
        self.assertEqual(detect_cdn(None), "")


class TestGeoIPResolver(unittest.TestCase):
    def test_degrade_no_lib(self):
        # 指向不存在的文件 → reader None → 全 {}
        r = GeoIPResolver(city_db="/no/such/city.mmdb", asn_db="/no/such/asn.mmdb")
        self.assertEqual(r.city("8.8.8.8"), {})
        self.assertEqual(r.asn("8.8.8.8"), {})

    def test_city_via_fake_reader(self):
        r = GeoIPResolver()
        r._city_tried = True
        r._city_reader = _FakeReader({
            "8.8.8.8": {"country": {"names": {"en": "United States"}},
                        "city": {"names": {"en": "Mountain View"}}},
        })
        self.assertEqual(r.city("8.8.8.8"), {"country": "United States", "city": "Mountain View"})
        self.assertEqual(r.city("1.2.3.4"), {})   # 表里没有 → {}

    def test_asn_via_fake_reader(self):
        r = GeoIPResolver()
        r._asn_tried = True
        r._asn_reader = _FakeReader({
            "8.8.8.8": {"autonomous_system_number": 15169,
                        "autonomous_system_organization": "GOOGLE"},
        })
        self.assertEqual(r.asn("8.8.8.8"), {"number": 15169, "org": "GOOGLE"})
        self.assertEqual(r.asn("1.2.3.4"), {})

    def test_partial_fields(self):
        r = GeoIPResolver()
        r._city_tried = True
        r._city_reader = _FakeReader({"5.5.5.5": {"country": {"names": {"en": "Germany"}}}})
        self.assertEqual(r.city("5.5.5.5"), {"country": "Germany"})   # 无 city 只返 country

    def test_reader_exception_degrades(self):
        class _Boom:
            def get(self, ip):
                raise RuntimeError("corrupt")
        r = GeoIPResolver()
        r._city_tried = True
        r._city_reader = _Boom()
        self.assertEqual(r.city("8.8.8.8"), {})


class TestEnricherIP(unittest.TestCase):
    def test_ip_type_and_cdn(self):
        enr = Enricher(geoip=None)
        rec = {"ip": "192.168.1.1", "domain": ["x.cloudflare.net"]}
        enr.enrich_ip(rec)
        self.assertEqual(rec["ip_type"], "PRIVATE")
        self.assertEqual(rec["cdn_name"], "cloudflare")

    def test_cdn_hint_priority(self):
        enr = Enricher(geoip=None)
        rec = {"ip": "1.2.3.4"}
        enr.enrich_ip(rec, cdn_hint=["target.akamai.net"])
        self.assertEqual(rec["cdn_name"], "akamai")

    def test_geoip_only_public(self):
        r = GeoIPResolver()
        r._city_tried = r._asn_tried = True
        r._city_reader = _FakeReader({"8.8.8.8": {"country": {"names": {"en": "US"}}}})
        r._asn_reader = _FakeReader({"8.8.8.8": {"autonomous_system_number": 15169,
                                                 "autonomous_system_organization": "GOOGLE"}})
        enr = Enricher(geoip=r)
        pub = {"ip": "8.8.8.8"}
        enr.enrich_ip(pub)
        self.assertEqual(pub["geo_city"], {"country": "US"})
        self.assertEqual(pub["geo_asn"], {"number": 15169, "org": "GOOGLE"})
        # 私网不查 geo
        priv = {"ip": "10.0.0.1"}
        enr.enrich_ip(priv)
        self.assertNotIn("geo_city", priv)
        self.assertNotIn("geo_asn", priv)

    def test_no_overwrite_existing(self):
        enr = Enricher(geoip=None)
        rec = {"ip": "8.8.8.8", "ip_type": "PUBLIC", "cdn_name": "preset"}
        enr.enrich_ip(rec)
        self.assertEqual(rec["cdn_name"], "preset")   # 未覆盖已有

    def test_batch_ips_with_hint(self):
        enr = Enricher(geoip=None)
        recs = [{"ip": "10.0.0.1"}, {"ip": "1.1.1.1"}]
        enr.enrich_ips(recs, cdn_hint={"1.1.1.1": ["a.fastly.net"]})
        self.assertEqual(recs[0]["ip_type"], "PRIVATE")
        self.assertEqual(recs[1]["cdn_name"], "fastly")

    def test_batch_empty(self):
        self.assertEqual(Enricher().enrich_ips([]), [])
        self.assertEqual(Enricher().enrich_ips(None), None)


class TestEnricherSite(unittest.TestCase):
    def test_tag_and_fld(self):
        enr = Enricher()
        rec = {"hostname": "www.example.com", "status": 200, "title": "登录", "body_length": 4000}
        enr.enrich_site(rec)
        self.assertEqual(rec["tag"], ["入口"])
        self.assertEqual(rec["fld"], "example.com")

    def test_fld_from_url(self):
        enr = Enricher()
        rec = {"site": "https://shop.example.com.cn/path", "status": 200,
               "title": "商城", "body_length": 4000}
        enr.enrich_site(rec)
        self.assertEqual(rec["fld"], "example.com.cn")

    def test_invalid_site_tag(self):
        enr = Enricher()
        rec = {"hostname": "a.example.com", "status": 404}
        enr.enrich_site(rec)
        self.assertEqual(rec["tag"], ["无效"])

    def test_no_overwrite_tag(self):
        enr = Enricher()
        rec = {"hostname": "a.example.com", "status": 200, "title": "x",
               "body_length": 9999, "tag": ["自定义"]}
        enr.enrich_site(rec)
        self.assertEqual(rec["tag"], ["自定义"])

    def test_batch_sites(self):
        enr = Enricher()
        recs = [{"hostname": "www.a.com", "status": 200, "title": "t", "body_length": 5000},
                {"hostname": "b.cn", "status": 500}]
        enr.enrich_sites(recs)
        self.assertEqual(recs[0]["tag"], ["入口"])
        self.assertEqual(recs[1]["tag"], ["无效"])


class TestHostFromUrl(unittest.TestCase):
    def test_with_scheme(self):
        self.assertEqual(_host_from_url("https://www.Example.com/x"), "www.example.com")

    def test_without_scheme(self):
        self.assertEqual(_host_from_url("www.example.com:8080/x"), "www.example.com")

    def test_empty(self):
        self.assertEqual(_host_from_url(""), "")
        self.assertEqual(_host_from_url(None), "")


class TestBuildEnricher(unittest.TestCase):
    def test_default(self):
        enr = build_enricher()
        self.assertIsInstance(enr, Enricher)
        self.assertIsNotNone(enr.geoip)
        # 默认路径指向 external/geolite2（可能存在也可能不在，不强求文件）
        self.assertTrue(enr.geoip.city_db.endswith("GeoLite2-City.mmdb"))

    def test_config_dir(self):
        class _Cfg:
            geolite_dir = "/custom/geo"
        enr = build_enricher(_Cfg())
        self.assertEqual(enr.geoip.city_db, os.path.join("/custom/geo", "GeoLite2-City.mmdb"))
        self.assertEqual(enr.geoip.asn_db, os.path.join("/custom/geo", "GeoLite2-ASN.mmdb"))

    def test_config_explicit_paths(self):
        class _Cfg:
            geolite_city_db = "/a/city.mmdb"
            geolite_asn_db = "/a/asn.mmdb"
        enr = build_enricher(_Cfg())
        self.assertEqual(enr.geoip.city_db, "/a/city.mmdb")
        self.assertEqual(enr.geoip.asn_db, "/a/asn.mmdb")


class TestDefaultGeoliteDir(unittest.TestCase):
    def test_points_to_external_geolite2(self):
        d = default_geolite_dir()
        self.assertTrue(d.replace("\\", "/").endswith("external/geolite2"))


if __name__ == "__main__":
    unittest.main()
