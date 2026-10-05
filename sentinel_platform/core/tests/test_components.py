"""core/components 共享组件归一器单测 —— 治「三套词汇不通」+「短别名子串误匹配」。

覆盖：跨源同组件归一（缺陷1）、短别名不子串误命中（缺陷3）、长别名词边界匹配、
expand_aliases 扩展全组、alias_match 归一比较。
"""
import unittest

from sentinel_platform.core.components import (
    canonical_component, expand_aliases, alias_match)


class ComponentsTest(unittest.TestCase):
    # —— 缺陷1：跨源同组件归一到同一规范名 ——
    def test_cross_source_canonical(self):
        self.assertEqual(canonical_component("spring boot"), canonical_component("springboot"))
        self.assertEqual(canonical_component("spring-boot"), canonical_component("spring boot"))
        self.assertEqual(canonical_component("Apache Tomcat"), "tomcat")
        self.assertEqual(canonical_component("apache shiro"), "shiro")
        self.assertEqual(canonical_component("yonyounc"), "用友")
        self.assertTrue(alias_match("spring boot", "springboot"))
        self.assertTrue(alias_match("Apache Tomcat", "tomcat"))

    # —— 缺陷3：短别名（tp/u8/c6/nc）绝不子串误命中 ——
    def test_short_alias_no_substring_falsematch(self):
        self.assertEqual(canonical_component("http"), "http")     # 不该归 thinkphp（tp∈http）
        self.assertEqual(canonical_component("httpd"), "httpd")
        self.assertEqual(canonical_component("sftp"), "sftp")     # tp∈sftp 不该命中
        # tp 作为别名仍在 thinkphp 组里（查 thinkphp 扩展得到），只是不反向吞并
        self.assertIn("tp", expand_aliases("thinkphp"))
        self.assertFalse(alias_match("http", "thinkphp"))
        self.assertFalse(alias_match("nc", "用友"))               # nc 短别名不误配用友

    # —— 长别名词边界匹配（版本后缀不影响归一）——
    def test_long_alias_word_boundary(self):
        self.assertEqual(canonical_component("nginx/1.20.1"), "nginx")
        self.assertEqual(canonical_component("apache tomcat 9.0"), "tomcat")
        # 词内嵌入不误命中（tomcat 不该匹配 "tomcatalog" 之类）
        self.assertEqual(canonical_component("tomcatalog"), "tomcatalog")

    def test_expand_aliases(self):
        exp = set(expand_aliases("泛微"))
        self.assertIn("weaver", exp)
        self.assertIn("ecology", exp)
        # 无别名组返回自身
        self.assertEqual(expand_aliases("xyzsoft"), ["xyzsoft"])
        self.assertEqual(expand_aliases(""), [])

    def test_no_alias_returns_lower(self):
        self.assertEqual(canonical_component("SomeRandomTech"), "somerandomtech")
        self.assertEqual(canonical_component("  "), "")


if __name__ == "__main__":
    unittest.main()
