"""risk_intel/_hazard_table 单测 —— 漏洞名规范化 + 单条模板查询（需求3）。

覆盖：别名映射(sqli→SQL注入)、后缀剥除(ssrf漏洞→SSRF)、垃圾名识别(表头/竖线/纯符号)、
CVE 保留、未知类型保留、query_template 单条返回不含整表、record_finding 落库归一 + name_quality。
不需真 Mongo（canonicalize/query_template 纯读 dicts json）；落库测试用 core 内存替身。
"""
import unittest

from sentinel_platform.modules.risk_intel import _hazard_table as h


class HazardCanonicalizeTest(unittest.TestCase):
    def setUp(self):
        h.reload_table()

    def test_alias_maps_to_standard(self):
        for raw, exp in [("sqli", "SQL注入"), ("SQL injection", "SQL注入"),
                         ("sql注入", "SQL注入"), ("xss", "XSS"),
                         ("未授权", "未授权访问"), ("越权", "越权访问"),
                         ("Swagger泄露", "接口文档暴露")]:
            name, matched, garbage = h.canonicalize(raw)
            self.assertEqual(name, exp, raw)
            self.assertTrue(matched, raw)
            self.assertFalse(garbage, raw)

    def test_suffix_stripped_before_match(self):
        # "ssrf漏洞"/"XSS攻击" 带后缀也能命中标准名
        self.assertEqual(h.canonicalize("ssrf漏洞")[0], "SSRF")
        self.assertEqual(h.canonicalize("XSS攻击")[0], "XSS")

    def test_garbage_names_flagged(self):
        # 表头/竖线表头/纯符号/空 → is_garbage=True
        for raw in ["类型", "目标", "证据", "目标|等级|证据", "类型|目标|等级|证据",
                    "", "---", "—"]:
            name, matched, garbage = h.canonicalize(raw)
            self.assertFalse(matched, raw)
            self.assertTrue(garbage, "expected garbage: %r" % raw)

    def test_cve_preserved_not_garbage(self):
        name, matched, garbage = h.canonicalize("CVE-2021-44228")
        self.assertEqual(name, "CVE-2021-44228")
        self.assertFalse(matched)
        self.assertFalse(garbage)          # CVE 优先保留，绝不当垃圾

    def test_unknown_type_preserved_as_custom(self):
        name, matched, garbage = h.canonicalize("某种新型洞XYZ")
        self.assertEqual(name, "某种新型洞XYZ")
        self.assertFalse(matched)
        self.assertFalse(garbage)          # 未知但非垃圾 → 保留原名兜底

    def test_query_template_single_row_no_full_table(self):
        r = h.query_template("sqli")
        self.assertTrue(r["matched"])
        self.assertEqual(r["canonical_type"], "SQL注入")
        self.assertIn("level_range", r)
        self.assertIn("hazard_template", r)
        # 关键：单条返回绝不含整表 types 列表
        self.assertNotIn("types", r)
        self.assertNotIn("standard_types", r)   # 命中时不返清单

    def test_query_template_requirement_carried(self):
        # 短信轰炸带"1分钟20条"这类收录要求，须透出供 AI 参考
        r = h.query_template("短信轰炸")
        self.assertTrue(r["matched"])
        self.assertIn("20", r.get("requirement", ""))

    def test_query_template_miss_returns_names_only(self):
        r = h.query_template("完全不存在的洞ABC")
        self.assertFalse(r["matched"])
        self.assertIn("standard_types", r)
        self.assertTrue(all(isinstance(x, str) for x in r["standard_types"]))
        # 清单只含名字，不含模板正文
        self.assertNotIn("hazard_template", r)


class RecordFindingCanonicalizeTest(unittest.TestCase):
    """落库归一：record_finding 存入 sqli → vuln_type 归一为 SQL注入 + raw 留痕 + name_quality。"""

    def setUp(self):
        from sentinel_platform.core.db import set_repo, reset_repo
        from sentinel_platform.contracts.registry import reset_registry
        # 复用 test_vuln_center 的内存替身（同目录 helper）
        from sentinel_platform.modules.risk_intel.tests.test_vuln_center import _Repo, _http_call
        reset_repo()
        reset_registry()
        set_repo(_Repo())
        self._http_call = _http_call
        from sentinel_platform.modules.risk_intel.vuln_center import FindingServiceImpl
        self.im = FindingServiceImpl()

    def tearDown(self):
        from sentinel_platform.core.db import reset_repo
        from sentinel_platform.contracts.registry import reset_registry
        reset_repo()
        reset_registry()

    def _get_one(self):
        from sentinel_platform.core.db import get_repo
        return get_repo().collection("intel_finding").find_one({})

    def test_record_canonicalizes_and_keeps_raw(self):
        tgt = "http://t.com/x"
        self.im.record_finding({"vuln_type": "sqli", "target": tgt,
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "tool_log": [self._http_call(tgt, 200, "id=1 union select" * 5)]})
        doc = self._get_one()
        self.assertEqual(doc["vuln_type"], "SQL注入")
        self.assertEqual(doc["raw_vuln_type"], "sqli")
        self.assertEqual(doc["name_quality"], "standard")

    def test_record_garbage_name_flagged(self):
        tgt = "http://t.com/y"
        self.im.record_finding({"vuln_type": "目标|等级|证据", "target": tgt,
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                "tool_log": [self._http_call(tgt, 200, "x" * 60)]})
        doc = self._get_one()
        self.assertEqual(doc["name_quality"], "garbage")


if __name__ == "__main__":
    unittest.main()
