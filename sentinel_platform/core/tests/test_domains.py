"""core/domains 共享 fld 提取单测 —— 治「三套后缀表分叉 → 单位回填失灵 / *.mil.cn 打歪」缺陷4。"""
import unittest

from sentinel_platform.core.domains import extract_fld


class DomainsTest(unittest.TestCase):
    def test_second_level_no_uplift(self):
        # 二级公共后缀取三段，绝不上溯根域（防打歪政府/教育网段）
        self.assertEqual(extract_fld("abc.gov.cn"), "abc.gov.cn")
        self.assertEqual(extract_fld("www.xxx.edu.cn"), "xxx.edu.cn")
        self.assertEqual(extract_fld("a.b.com.cn"), "b.com.cn")
        self.assertEqual(extract_fld("abc.mil.cn"), "abc.mil.cn")   # 缺陷4：不被削成 mil.cn
        self.assertEqual(extract_fld("x.com.au"), "x.com.au")       # 缺陷4：enrick/unit_map 曾分叉
        self.assertEqual(extract_fld("sub.gov.hk"), "sub.gov.hk")

    def test_ordinary_domain(self):
        self.assertEqual(extract_fld("foo.bar.example.com"), "example.com")
        self.assertEqual(extract_fld("example.com"), "example.com")

    def test_url_and_port_stripped(self):
        self.assertEqual(extract_fld("https://www.a.com:8443/path?x=1"), "a.com")

    def test_ip_and_edge(self):
        self.assertEqual(extract_fld("1.2.3.4"), "1.2.3.4")
        self.assertEqual(extract_fld(""), "")
        self.assertEqual(extract_fld("localhost"), "localhost")


if __name__ == "__main__":
    unittest.main()
