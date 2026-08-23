"""core/query 纯函数单测 —— 锁定 REST→Mongo 查询语义。

query.py 的 one_clause/build_query/serialize_items 被 asset/search、asset/monitor、
risk_intel/scan_result 三个叶子 + BaseResource 共用，其运算符语义是列表查询的口径基准，
故独立锁定，防未来改动破坏任一消费方。
"""
import re
import unittest
from datetime import datetime

from sentinel_platform.core.query import (
    one_clause, build_query, serialize_items, to_object_id,
    EQUAL_FIELDS, BASE_QUERY_KEYS,
)


class TestOneClause(unittest.TestCase):
    def test_date_range_dgt_dlt(self):
        self.assertEqual(
            one_clause("save_date__dgt", "2026-01-01 00:00:00"),
            {"save_date": {"$gt": datetime(2026, 1, 1)}},
        )
        self.assertEqual(
            one_clause("save_date__dlt", "2026-01-01 00:00:00"),
            {"save_date": {"$lt": datetime(2026, 1, 1)}},
        )

    def test_neq(self):
        self.assertEqual(one_clause("status__neq", "done"), {"status": {"$ne": "done"}})

    def test_not_is_regex_negation_escaped(self):
        out = one_clause("name__not", "a.b")
        self.assertIn("name", out)
        self.assertIn("$not", out["name"])
        # 值被 re.escape（. 不当通配），是编译后的正则
        self.assertTrue(out["name"]["$not"].pattern, r"a\.b")

    def test_int_gt_lt_only_for_int(self):
        self.assertEqual(one_clause("port__gt", 80), {"port": {"$gt": 80}})
        self.assertEqual(one_clause("port__lt", 80), {"port": {"$lt": 80}})
        # 非 int 的 __gt 不触发数值分支，落到默认字符串正则
        out = one_clause("port__gt", "80")
        self.assertIn("port__gt", out)  # 整个键当字段名走正则

    def test_string_default_is_case_insensitive_regex_escaped(self):
        out = one_clause("title", "a+b")
        self.assertEqual(out, {"title": {"$regex": re.escape("a+b"), "$options": "i"}})

    def test_equal_fields_exact_match(self):
        for f in ("task_id", "task_tag", "ip_type", "scope_id", "type"):
            self.assertEqual(one_clause(f, "v"), {f: "v"}, f"{f} 应走等值不走正则")

    def test_non_string_passthrough(self):
        self.assertEqual(one_clause("cnt", 5), {"cnt": 5})
        self.assertEqual(one_clause("flag", True), {"flag": True})


class TestBuildQuery(unittest.TestCase):
    def test_skips_pagination_keys(self):
        q = build_query({"page": 2, "size": 50, "order": "-_id", "title": "x"})
        self.assertNotIn("page", q)
        self.assertNotIn("size", q)
        self.assertNotIn("order", q)
        self.assertIn("title", q)

    def test_skips_none(self):
        self.assertEqual(build_query({"a": None}), {})

    def test_empty_id_skipped(self):
        self.assertEqual(build_query({"_id": ""}), {})

    def test_id_present_maps_to_id_key(self):
        q = build_query({"_id": "deadbeef"})
        self.assertIn("_id", q)  # 无 bson 环境下 to_object_id 原值兜底

    def test_base_query_keys_constant(self):
        self.assertEqual(BASE_QUERY_KEYS, {"page", "size", "order"})
        self.assertIn("task_id", EQUAL_FIELDS)


class TestSerializeItems(unittest.TestCase):
    def test_serializes_special_fields_to_str(self):
        out = serialize_items([{"_id": 123, "save_date": 456, "update_date": 789, "x": 1}])
        self.assertEqual(out[0]["_id"], "123")
        self.assertEqual(out[0]["save_date"], "456")
        self.assertEqual(out[0]["update_date"], "789")
        self.assertEqual(out[0]["x"], 1)  # 非特殊字段不动

    def test_empty(self):
        self.assertEqual(serialize_items([]), [])


class TestToObjectId(unittest.TestCase):
    def test_no_bson_falls_back_to_original(self):
        # 无 bson 环境（本地/离线）返回原值，不抛
        self.assertEqual(to_object_id("not-an-oid"), "not-an-oid")


class TestDelegationEquivalence(unittest.TestCase):
    """BaseResource 委托后必须与纯函数行为一致（向后兼容硬保证）。"""

    def test_baseresource_delegates_identically(self):
        from sentinel_platform.core.web import BaseResource
        for k, v in [("title", "x"), ("port__gt", 3), ("type", "domain"),
                     ("name__neq", "y"), ("save_date__dgt", "2026-01-01 00:00:00")]:
            self.assertEqual(str(BaseResource._one_clause(k, v)), str(one_clause(k, v)))


if __name__ == "__main__":
    unittest.main()
