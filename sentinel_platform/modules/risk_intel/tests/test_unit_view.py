"""unit_view 叶子单测 —— 聚合/详情/级联删除，注入内存 repo（按集合名分开）。

覆盖：①unit_overview 按 unit 聚合多集合 + 倒序 ②unit_detail 明细 + 空 unit 拒
③delete_unit 级联 + 空 unit 拒（防全删）④未知单位归并。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import unit_view as uv


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find(self, q=None, proj=None):
        q = q or {}
        self._r = [d for d in self.docs if self._match(d, q)]
        return self
    def _match(self, d, q):
        for k, v in q.items():
            if k == "$or":                       # 支持 _unit_filter 的空 unit $or 查询（BUG-011）
                if not any(self._match(d, sub) for sub in v):
                    return False
            elif isinstance(v, dict):
                if "$exists" in v:               # {"$exists": False} → 字段缺失才匹配
                    present = k in d and d.get(k) is not None
                    if present == v["$exists"]:
                        continue
                    return False
                # 其他 dict 操作符（如 $ne）宽松跳过（本 fake 未用到）
                continue
            elif d.get(k) != v:
                return False
        return True
    def sort(self, *a):
        return self
    def __iter__(self):
        return iter(self._r)
    def insert_one(self, doc):
        self.docs.append(doc)
    def delete_many(self, q):
        keep, removed = [], 0
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                removed += 1
            else:
                keep.append(d)
        self.docs = keep
        class _R: deleted_count = removed
        return _R()
    def update_many(self, q, upd):
        class _R: modified_count = 0
        return _R()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


def _seed(repo):
    repo.collection("intel_asset").insert_one({"unit": "A公司", "subdomain": "a.com", "system_id": "s1"})
    repo.collection("intel_asset").insert_one({"unit": "A公司", "subdomain": "b.a.com", "system_id": "s1"})
    repo.collection("intel_asset").insert_one({"unit": "B公司", "fld": "b.com"})
    repo.collection("intel_finding").insert_one({"source": "ai", "unit": "A公司", "verified": True, "severity": "high"})
    repo.collection("intel_finding").insert_one({"source": "ai", "unit": "A公司", "verified": False, "severity": "low"})
    repo.collection("intel_report").insert_one({"unit": "A公司", "save_date": "2026-07-01", "vuln_index": [1, 2]})
    repo.collection("intel_attack_chain").insert_one({"unit": "A公司", "title": "链1", "step_count": 3})


class TestUnitOverview(unittest.TestCase):
    def setUp(self):
        self.repo = _FakeRepo(); set_repo(self.repo); _seed(self.repo)

    def tearDown(self):
        set_repo(None)

    def test_aggregate(self):
        cards = {c["unit"]: c for c in uv.unit_overview()}
        self.assertIn("A公司", cards)
        a = cards["A公司"]
        self.assertEqual(a["asset_count"], 2)
        self.assertEqual(a["subdomain_count"], 2)
        self.assertEqual(a["system_count"], 1)
        self.assertEqual(a["vuln_count"], 1)
        self.assertEqual(a["lead_count"], 1)
        self.assertEqual(a["report_count"], 1)
        self.assertEqual(a["chain_count"], 1)

    def test_unknown_unit_grouped(self):
        self.repo.collection("intel_asset").insert_one({"subdomain": "x.com"})  # 无 unit
        cards = {c["unit"]: c for c in uv.unit_overview()}
        self.assertIn("未知单位", cards)

    def test_empty(self):
        set_repo(_FakeRepo())
        self.assertEqual(uv.unit_overview(), [])


class TestUnitDetail(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo()); _seed(__import__("sentinel_platform.core", fromlist=["get_repo"]).get_repo())

    def tearDown(self):
        set_repo(None)

    def test_detail(self):
        d = uv.unit_detail("A公司")
        self.assertEqual(d["unit"], "A公司")
        self.assertEqual(d["vuln_count"], 1)
        self.assertEqual(d["lead_count"], 1)
        self.assertEqual(len(d["reports"]), 1)
        self.assertEqual(len(d["chains"]), 1)

    def test_empty_unit_rejected(self):
        self.assertIn("error", uv.unit_detail(""))

    def test_unknown_unit_detail_matches_empty_unit_records(self):
        """BUG-011：列表把空 unit 分桶「未知单位」，详情按「未知单位」查询必须反解为空 unit 记录
        （而非字面匹配→恒0）。这里 seed 空 unit 的 finding/asset/report，详情应查得到。"""
        repo = __import__("sentinel_platform.core", fromlist=["get_repo"]).get_repo()
        repo.collection("intel_finding").insert_one({"source": "ai", "unit": "", "verified": True, "severity": "high"})
        repo.collection("intel_asset").insert_one({"unit": "", "subdomain": "orphan.com"})
        repo.collection("intel_report").insert_one({"unit": "", "save_date": "2026-07-02", "vuln_index": [1]})
        d = uv.unit_detail("未知单位")
        self.assertEqual(d["unit"], "未知单位")
        self.assertEqual(d["vuln_count"], 1, "未知单位详情应查到空 unit 的 finding（BUG-011 核心）")
        self.assertEqual(len(d["reports"]), 1, "未知单位详情应查到空 unit 的 report")
        self.assertTrue(d["subdomain_count"] >= 1)

    def test_unit_filter_pure(self):
        """_unit_filter：普通单位=等值；未知单位=空 unit 的 $or。"""
        self.assertEqual(uv._unit_filter("A公司"), {"unit": "A公司"})
        f = uv._unit_filter(uv._UNKNOWN)
        self.assertIn("$or", f)


class TestDeleteUnit(unittest.TestCase):
    def setUp(self):
        self.repo = _FakeRepo(); set_repo(self.repo); _seed(self.repo)

    def tearDown(self):
        set_repo(None)

    def test_cascade_delete(self):
        r = uv.delete_unit("A公司")
        self.assertNotIn("error", r)
        self.assertEqual(r["deleted"]["intel_asset"], 2)
        self.assertEqual(r["deleted"]["intel_finding"], 2)
        # B公司数据不受影响
        self.assertEqual(len(self.repo.collection("intel_asset").docs), 1)

    def test_empty_unit_never_deletes_all(self):
        r = uv.delete_unit("")
        self.assertIn("error", r)
        self.assertEqual(len(self.repo.collection("intel_asset").docs), 3)   # 一条没删


if __name__ == "__main__":
    unittest.main()
