"""katana 对接单测 —— 只测 parse_record/structure/crawl 去重/argv，不需真装工具。

覆盖：嵌套 request/response 结构解析、扁平 endpoint、response 元信息回填(title/status/clen)、
缺 endpoint 跳过、杂行跳过、crawl 按 url 去重、build_argv(-jc/-c/-d 深度非写死)、available 降级。
"""
import unittest

from sentinel_platform.modules.kernel.recon.tools import Katana
from sentinel_platform.modules.kernel.recon.models import UrlRec


class TestKatana(unittest.TestCase):
    def test_parse_nested(self):
        obj = {"request": {"endpoint": "https://a.com/x"},
               "response": {"status_code": 200, "title": "首页", "content_length": 1234}}
        rec = Katana().parse_record(obj)
        self.assertIsInstance(rec, UrlRec)
        self.assertEqual(rec.url, "https://a.com/x")
        self.assertEqual(rec.site, "https://a.com/x")
        self.assertEqual(rec.status_code, 200)
        self.assertEqual(rec.title, "首页")
        self.assertEqual(rec.content_length, 1234)
        self.assertEqual(rec.source, "site_spider")

    def test_parse_flat_endpoint(self):
        rec = Katana().parse_record({"endpoint": "https://a.com/api"})
        self.assertEqual(rec.url, "https://a.com/api")
        self.assertEqual(rec.status_code, 0)          # 无响应元信息降 0

    def test_parse_request_url_fallback(self):
        rec = Katana().parse_record({"request": {"url": "https://a.com/y"}})
        self.assertEqual(rec.url, "https://a.com/y")

    def test_parse_missing_endpoint(self):
        self.assertIsNone(Katana().parse_record({"response": {"status_code": 200}}))
        self.assertIsNone(Katana().parse_record({"endpoint": ""}))
        self.assertIsNone(Katana().parse_record({"endpoint": "  "}))

    def test_parse_bad_status_safe(self):
        rec = Katana().parse_record({"endpoint": "https://a.com", "response": {"status_code": "bad"}})
        self.assertEqual(rec.status_code, 0)          # 非法状态码降 0 不崩

    def test_structure_skips_junk(self):
        out = "\n".join([
            '{"endpoint":"https://a.com/1"}',
            'not json',
            '["arr"]',
            '{"endpoint":"https://a.com/2"}',
        ])
        recs = list(Katana().structure(out))
        self.assertEqual(len(recs), 2)
        self.assertEqual({r.url for r in recs}, {"https://a.com/1", "https://a.com/2"})

    def test_crawl_dedup(self):
        k = Katana()
        k.run = lambda stdin_lines=None, **kw: [
            UrlRec(site="https://a.com/x", url="https://a.com/x"),
            UrlRec(site="https://a.com/x", url="https://a.com/x"),   # 重复
            UrlRec(site="https://a.com/y", url="https://a.com/y"),
        ]
        out = k.crawl(["https://a.com"])
        self.assertEqual(len(out), 2)                 # 按 url 去重
        self.assertEqual({r.url for r in out}, {"https://a.com/x", "https://a.com/y"})

    def test_build_argv(self):
        argv = Katana().build_argv()
        self.assertIn("-silent", argv)
        self.assertIn("-json", argv)
        self.assertIn("-jc", argv)                    # 默认爬 JS
        self.assertIn("-c", argv)
        self.assertNotIn("-d", argv)                  # depth=0 不写死上限
        argv2 = Katana().build_argv(crawl_js=False, depth=3)
        self.assertNotIn("-jc", argv2)
        self.assertIn("-d", argv2)
        self.assertIn("3", argv2)

    def test_available_no_binary(self):
        self.assertFalse(Katana(binary_path="/definitely/missing/katana").available())


if __name__ == "__main__":
    unittest.main()
