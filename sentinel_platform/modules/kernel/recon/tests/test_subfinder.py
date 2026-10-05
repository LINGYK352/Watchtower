"""subfinder 对接单测 —— 只测 parse_record/structure/归属过滤/去重，不需真装工具。

覆盖：正常发现结构化为 DomainRec(type=SUBDOMAIN,无解析)、越界子域名归属过滤丢弃、
杂行/非法/缺 host 跳过、enumerate 去重 + scope 多主域过滤、build_argv -all 开关。
"""
import os
import unittest
from unittest import mock

from sentinel_platform.modules.kernel.recon.tools import Subfinder
from sentinel_platform.modules.kernel.recon.tools.subfinder import _belongs
from sentinel_platform.modules.kernel.recon.models import DomainRec


class TestSubfinder(unittest.TestCase):
    def test_parse_basic(self):
        rec = Subfinder().parse_record({"host": "api.example.com", "input": "example.com",
                                        "source": "crtsh"})
        self.assertIsInstance(rec, DomainRec)
        self.assertEqual(rec.domain, "api.example.com")
        self.assertEqual(rec.type, "SUBDOMAIN")
        self.assertEqual(rec.record, [])              # 被动枚举不解析
        self.assertEqual(rec.ips, [])
        self.assertEqual(rec.source, "subfinder")

    def test_parse_lowercase_strip_dot(self):
        rec = Subfinder().parse_record({"host": "API.Example.COM.", "input": "example.com"})
        self.assertEqual(rec.domain, "api.example.com")   # 小写 + 去尾点

    def test_parse_out_of_scope_dropped(self):
        # host 不属 input 主域（CNAME 到第三方）→ 归属过滤丢弃
        self.assertIsNone(Subfinder().parse_record(
            {"host": "cdn.akamai.net", "input": "example.com"}))

    def test_parse_no_input_no_filter(self):
        # 无 input 时不做归属过滤（放行，交 enumerate 的 scope 兜底）
        rec = Subfinder().parse_record({"host": "x.other.com"})
        self.assertEqual(rec.domain, "x.other.com")

    def test_parse_missing_host(self):
        self.assertIsNone(Subfinder().parse_record({"input": "example.com"}))
        self.assertIsNone(Subfinder().parse_record({"host": ""}))
        self.assertIsNone(Subfinder().parse_record({"host": "  "}))

    def test_structure_skips_junk(self):
        out = "\n".join([
            '{"host":"a.example.com","input":"example.com"}',
            'not-json-line',
            '["not","dict"]',
            '{"host":"b.example.com","input":"example.com"}',
        ])
        recs = list(Subfinder().structure(out))
        self.assertEqual(len(recs), 2)
        self.assertEqual({r.domain for r in recs}, {"a.example.com", "b.example.com"})

    def test_belongs(self):
        self.assertTrue(_belongs("a.example.com", "example.com"))
        self.assertTrue(_belongs("example.com", "example.com"))
        self.assertTrue(_belongs("a.b.example.com", "example.com"))
        self.assertFalse(_belongs("notexample.com", "example.com"))   # 防后缀误判
        self.assertFalse(_belongs("evil.com", "example.com"))
        self.assertTrue(_belongs("anything.com", ""))                  # root 空放行

    def test_build_argv_all_switch(self):
        self.assertNotIn("-all", Subfinder().build_argv())
        self.assertIn("-all", Subfinder().build_argv(all_sources=True))
        self.assertIn("-json", Subfinder().build_argv())
        self.assertIn("-silent", Subfinder().build_argv())

    def test_available_no_binary_on_path(self):
        self.assertFalse(Subfinder(binary_path="/definitely/missing/subfinder").available())

    def test_enumerate_dedup_and_scope(self):
        # 用 fake run 注入两条重复 + 一条越界，验证去重 + scope 过滤
        sf = Subfinder()
        sf.run = lambda stdin_lines=None, **kw: [
            DomainRec(domain="a.example.com", type="SUBDOMAIN", source="subfinder"),
            DomainRec(domain="a.example.com", type="SUBDOMAIN", source="subfinder"),  # 重复
            DomainRec(domain="x.other.com", type="SUBDOMAIN", source="subfinder"),    # 越界
        ]
        out = sf.enumerate(["example.com"], scope={"example.com"})
        self.assertEqual(len(out), 1)                 # 去重 + 越界过滤
        self.assertEqual(out[0].domain, "a.example.com")

    def test_build_argv_selected_sources_and_provider_config(self):
        argv = Subfinder().build_argv(
            sources=["hunter", "securitytrails"], provider_config="/tmp/providers.yaml")
        self.assertIn("-s", argv)
        self.assertIn("hunter,securitytrails", argv)
        self.assertIn("-pc", argv)
        self.assertIn("/tmp/providers.yaml", argv)

    def test_enumerate_sources_uses_temporary_secret_file_and_deletes_it(self):
        sf = Subfinder()
        observed = {}

        def fake_run(stdin_lines=None, **kwargs):
            path = kwargs["provider_config"]
            observed["path"] = path
            with open(path, "r", encoding="utf-8") as fp:
                observed["content"] = fp.read()
            observed["sources"] = kwargs["sources"]
            return [DomainRec(domain="api.example.com"), DomainRec(domain="outside.test")]

        with mock.patch.object(sf, "run", side_effect=fake_run):
            out = sf.enumerate_sources(
                ["example.com"], {"hunter": "secret:key", "chaos": "token"},
                scope={"example.com"})
        self.assertEqual([r.domain for r in out], ["api.example.com"])
        self.assertEqual(observed["sources"], ["hunter", "chaos"])
        self.assertIn('"secret:key"', observed["content"])
        self.assertFalse(os.path.exists(observed["path"]))


if __name__ == "__main__":
    unittest.main()
