"""save_pentest_report 单测 —— 写 intel_report + 从 intel_finding 派生 vuln 统计 + 幂等。

治审计头条「intel_report 只读零写」:会话收尾写往期报告,供三层情报联动第二层借鉴。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import asset_intel


class _Coll:
    def __init__(self):
        self.docs = []
    def find(self, q=None):
        q = q or {}
        return [d for d in self.docs if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict))]
    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def insert_one(self, doc):
        doc.setdefault("_id", "r%d" % (len(self.docs) + 1)); self.docs.append(doc)
        class _R: inserted_id = doc["_id"]
        return _R()
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))


class _Repo:
    def __init__(self):
        self.c = {}
    def collection(self, n):
        return self.c.setdefault(n, _Coll())


class TestSaveReport(unittest.TestCase):
    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        # 种 2 条本会话 finding（high + low）
        fc = self.repo.collection("intel_finding")
        fc.insert_one({"_id": "f1", "session_id": "s1", "severity": "high"})
        fc.insert_one({"_id": "f2", "session_id": "s1", "severity": "low"})

    def tearDown(self):
        set_repo(None)

    def test_writes_report_with_derived_stats(self):
        r = asset_intel.save_pentest_report({"session_id": "s1", "unit": "U公司",
                                             "site": "https://a.com", "content": "## 漏洞\n..."})
        self.assertTrue(r["ok"])
        self.assertEqual(r["vuln_count"], 2)
        self.assertFalse(r["updated"])
        doc = self.repo.collection("intel_report").find_one({"source_session": "s1"})
        self.assertEqual(doc["max_severity"], "high")        # 派生取最高
        self.assertEqual(len(doc["vuln_index"]), 2)
        self.assertEqual(doc["unit"], "U公司")
        self.assertIn("a.com", doc["title"])                 # 默认标题含站点

    def test_idempotent_update(self):
        asset_intel.save_pentest_report({"session_id": "s1", "content": "v1"})
        r2 = asset_intel.save_pentest_report({"session_id": "s1", "content": "v2"})
        self.assertTrue(r2["updated"])                       # 同会话更新不重复建
        reports = self.repo.collection("intel_report").find({"source_session": "s1"})
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["content"], "v2")

    def test_no_session_id_rejected(self):
        self.assertIn("error", asset_intel.save_pentest_report({"unit": "U"}))

    def test_no_findings_empty_index(self):
        r = asset_intel.save_pentest_report({"session_id": "s_none", "content": "x"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["vuln_count"], 0)


if __name__ == "__main__":
    unittest.main()
