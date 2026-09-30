"""回归②：临时情报 scope DNS 边界匹配 _target_scope_match（session.py:650，AUD-03）。

事故：修复前用 `m_target in host_l` 子串匹配 → example.com 误命中 evil-example.com /
example.com.attacker.invalid，把凭证等临时情报注入无关目标。修=DNS 标签边界(精确或 .scope 结尾)。
红线：绝不能退回子串匹配。
"""
import unittest

from sentinel_platform.modules.ai_pentest.session import _target_scope_match as m


class ScopeMatchRegression(unittest.TestCase):
    def test_exact_and_subdomain_match(self):
        self.assertTrue(m("example.com", "example.com"))
        self.assertTrue(m("example.com", "api.example.com"))
        self.assertTrue(m("example.com", "a.b.example.com"))

    def test_substring_lookalikes_must_not_match(self):
        """红线：子串型仿冒/后缀附加域绝不命中（修复前 bug）。"""
        self.assertFalse(m("example.com", "evil-example.com"))
        self.assertFalse(m("example.com", "example.com.attacker.invalid"))
        self.assertFalse(m("example.com", "example.company.com"))
        self.assertFalse(m("example.com", "notexample.com"))

    def test_normalize_port_dot_case(self):
        self.assertTrue(m("example.com", "API.EXAMPLE.COM"))     # 大小写
        self.assertTrue(m("example.com", "example.com."))         # 尾点
        self.assertTrue(m("example.com", "api.example.com:8443")) # 端口

    def test_empty_inputs_false(self):
        self.assertFalse(m("example.com", ""))
        self.assertFalse(m("", "example.com"))


if __name__ == "__main__":
    unittest.main()
