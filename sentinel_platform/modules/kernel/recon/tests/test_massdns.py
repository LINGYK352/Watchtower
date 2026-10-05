"""massdns 对接单测 —— 只测 parse_line/structure/候选生成/泛解析·归属过滤/合并，不需真装工具。

覆盖：`-o S` 文本行解析为 DomainRec、非三段行跳过、泛解析 IP 过滤、gen_candidates(word.root/{fuzz}/主域自身/去重)、
brute 去重合并 IP + 归属过滤 + scope、build_argv(resolvers/并发/stdin)、available 降级。
"""
import unittest

from sentinel_platform.modules.kernel.recon.tools import Massdns
from sentinel_platform.modules.kernel.recon.tools.massdns import gen_candidates, _belongs
from sentinel_platform.modules.kernel.recon.models import DomainRec


class TestMassdns(unittest.TestCase):
    # —— parse_line：标准三段 A 记录 ——
    def test_parse_a_record(self):
        rec = Massdns().parse_line("api.example.com. A 1.2.3.4")
        self.assertIsInstance(rec, DomainRec)
        self.assertEqual(rec.domain, "api.example.com")
        self.assertEqual(rec.type, "A")
        self.assertEqual(rec.record, ["1.2.3.4"])
        self.assertEqual(rec.ips, ["1.2.3.4"])
        self.assertEqual(rec.source, "domain_brute")

    def test_parse_cname_no_ip(self):
        rec = Massdns().parse_line("www.example.com. CNAME example.com")
        self.assertEqual(rec.type, "CNAME")
        self.assertEqual(rec.record, ["example.com"])
        self.assertEqual(rec.ips, [])              # 非 A 不填 ips

    def test_parse_bad_lines(self):
        self.assertIsNone(Massdns().parse_line("only two"))
        self.assertIsNone(Massdns().parse_line("a. A "))       # 空 record → 拆成 2 段
        self.assertIsNone(Massdns().parse_line(""))

    def test_parse_wildcard_filtered(self):
        # 命中泛解析 IP → 丢弃
        self.assertIsNone(Massdns().parse_line("rand.example.com. A 9.9.9.9",
                                               wildcard_ips={"9.9.9.9"}))

    def test_structure_text_lines(self):
        out = "a.example.com. A 1.1.1.1\njunk line here now\nb.example.com. A 2.2.2.2\n"
        recs = list(Massdns().structure(out))
        self.assertEqual(len(recs), 2)
        self.assertEqual({r.domain for r in recs}, {"a.example.com", "b.example.com"})

    # —— gen_candidates ——
    def test_gen_candidates_word_root(self):
        c = gen_candidates("example.com", ["www", "api", ""])
        self.assertIn("www.example.com", c)
        self.assertIn("api.example.com", c)
        self.assertIn("example.com", c)            # 主域自身
        self.assertEqual(len([x for x in c if x == "www.example.com"]), 1)  # 去重

    def test_gen_candidates_fuzz(self):
        c = gen_candidates("{fuzz}.example.com", ["a", "b"])
        self.assertIn("a.example.com", c)
        self.assertIn("b.example.com", c)
        self.assertNotIn("example.com", c)         # fuzz 模式不加主域自身

    def test_gen_candidates_empty_root(self):
        self.assertEqual(gen_candidates("", ["a"]), [])

    # —— _belongs ——
    def test_belongs(self):
        self.assertTrue(_belongs("a.example.com", "example.com"))
        self.assertFalse(_belongs("notexample.com", "example.com"))
        self.assertTrue(_belongs("x", ""))

    # —— brute：去重合并 IP + 归属 + scope（注入 fake run）——
    def test_brute_merge_and_filter(self):
        m = Massdns()
        m.run = lambda stdin_lines=None, **kw: [
            DomainRec(domain="a.example.com", record=["1.1.1.1"], type="A", ips=["1.1.1.1"], source="domain_brute"),
            DomainRec(domain="a.example.com", record=["2.2.2.2"], type="A", ips=["2.2.2.2"], source="domain_brute"),  # 同域另IP
            DomainRec(domain="evil.com", record=["3.3.3.3"], type="A", ips=["3.3.3.3"], source="domain_brute"),        # 越界
            DomainRec(domain="w.example.com", record=["9.9.9.9"], type="A", ips=["9.9.9.9"], source="domain_brute"),   # 泛解析
        ]
        out = m.brute("example.com", ["a", "w"], resolvers="/tmp/r.txt",
                      wildcard_ips={"9.9.9.9"})
        by = {r.domain: r for r in out}
        self.assertIn("a.example.com", by)
        self.assertEqual(sorted(by["a.example.com"].ips), ["1.1.1.1", "2.2.2.2"])  # 合并去重
        self.assertNotIn("evil.com", by)           # 归属过滤
        self.assertNotIn("w.example.com", by)      # 泛解析过滤

    def test_brute_no_resolvers(self):
        # resolvers 缺失 → 不跑返 []（massdns 依赖 resolver 文件）
        self.assertEqual(Massdns().brute("example.com", ["a"], resolvers=""), [])

    def test_brute_scope(self):
        m = Massdns()
        m.run = lambda stdin_lines=None, **kw: [
            DomainRec(domain="a.example.com", record=["1.1.1.1"], type="A", ips=["1.1.1.1"]),
        ]
        # scope 不含 example.com → 过滤掉
        self.assertEqual(m.brute("example.com", ["a"], resolvers="/tmp/r", scope={"other.com"}), [])

    # —— build_argv ——
    def test_build_argv(self):
        argv = Massdns().build_argv(resolvers="/etc/resolvers.txt", concurrency=500)
        self.assertIn("/etc/resolvers.txt", argv)
        self.assertIn("500", argv)
        self.assertIn("-", argv)                   # stdin
        self.assertIn("S", argv)                   # -o S

    def test_available_no_binary(self):
        self.assertFalse(Massdns(binary_path="/definitely/missing/massdns").available())


if __name__ == "__main__":
    unittest.main()
