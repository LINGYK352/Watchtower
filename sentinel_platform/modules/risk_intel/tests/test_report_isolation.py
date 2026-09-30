"""报告隔离单测 —— 人看成品报告 pentest_report 与 AI 情报报告 intel_report 物理隔离。

核心断言：
1. 会话收尾 save_pentest_report 只进 intel_report，pentest_report 计数为 0；
2. 人工 build_task_report 只进 pentest_report，intel_report 无新增 task 文档；
3. 人工 regenerate_session_report 只进 pentest_report，且 intel_asset.report_id 未被改
   （_mark_asset_pentested 未触发，AI 借鉴指针不被污染）；
4. AI 借鉴链 get_pentest_report/query_unit_reports 仍只命中 intel_report；
5. get_report 双集合：默认 intel_report，传 pentest_report 命中成品；
6. delete_records 白名单接受 pentest_report、拒绝未知集合；
7. 迁移脚本：task/edited 迁入 pentest_report，普通会话报告不迁，原文档全留，重跑无重复。
LLM/provider 用 monkeypatch 屏蔽，不发真网络。
"""
import unittest
from unittest import mock

from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import asset_intel
from sentinel_platform.modules.risk_intel import migrate_pentest_report as migrate


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0

    def _match(self, d, q):
        for k, v in (q or {}).items():
            if k == "$or":
                if not any(self._match(d, sub) for sub in v):
                    return False
                continue
            if isinstance(v, dict):
                if "$ne" in v and d.get(k) == v["$ne"]:
                    return False
                if "$in" in v and d.get(k) not in v["$in"]:
                    return False
            elif d.get(k) != v:
                return False
        return True

    def find(self, q=None, *a, **k):
        return _Cursor([d for d in self.docs if self._match(d, q or {})])

    def find_one(self, q, *a, **k):
        for d in self.docs:
            if self._match(d, q or {}):
                return d
        return None

    def count_documents(self, q=None, **k):
        return len([d for d in self.docs if self._match(d, q or {})])

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "x%d" % self._n)
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            return type("R", (), {"matched_count": 1, "modified_count": 1, "upserted_id": None})()
        if upsert:
            self._n += 1
            nd = dict(q)
            nd.update(upd.get("$set", {}))
            nd.update(upd.get("$setOnInsert", {}))
            nd.setdefault("_id", "x%d" % self._n)
            self.docs.append(nd)
            return type("R", (), {"matched_count": 0, "modified_count": 0, "upserted_id": nd["_id"]})()
        return type("R", (), {"matched_count": 0, "modified_count": 0, "upserted_id": None})()

    def delete_many(self, q):
        before = len(self.docs)
        self.docs = [d for d in self.docs if not self._match(d, q or {})]
        return type("R", (), {"deleted_count": before - len(self.docs)})()


class _Cursor(list):
    def sort(self, *a, **k):
        return _Cursor(list(reversed(self)))

    def skip(self, n):
        return _Cursor(self[n:])

    def limit(self, n):
        return _Cursor(self[:n])


class _Repo:
    def __init__(self):
        self.c = {}

    def collection(self, n):
        return self.c.setdefault(n, _Coll())


class ReportIsolationTest(unittest.TestCase):
    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        # 会话 s1 的漏洞 + 资产（带 report_id 指针，验证 regenerate 不污染它）
        self.repo.collection("intel_finding").insert_one(
            {"_id": "f1", "session_id": "s1", "severity": "high", "vuln_type": "SQLi", "target": "a.com"})
        self.repo.collection("intel_asset").insert_one(
            {"_id": "a1", "key": "https://a.com", "report_id": "ORIGINAL_PTR", "pentest_status": "done"})

    def tearDown(self):
        set_repo(None)

    def test_save_pentest_report_only_intel(self):
        """会话收尾 save_pentest_report 只进 intel_report，pentest_report 计数 0。"""
        r = asset_intel.save_pentest_report(
            {"session_id": "s1", "unit": "U", "asset_key": "https://a.com", "content": "## 自动报告"})
        self.assertTrue(r["ok"])
        self.assertEqual(self.repo.collection("intel_report").count_documents({"source_session": "s1"}), 1)
        self.assertEqual(self.repo.collection("pentest_report").count_documents({}), 0)

    def test_build_task_report_only_pentest(self):
        """人工 build_task_report 只进 pentest_report，intel_report 无新增 task 文档。"""
        # 种一条会话情报报告作聚合源
        self.repo.collection("intel_report").insert_one(
            {"_id": "ir1", "report_type": "session", "source_session": "s1", "source_task_id": "t1",
             "asset_key": "https://a.com", "content": "## a", "vuln_index": ["f1"], "max_severity": "high"})
        self.repo.collection("task").insert_one({"_id": "t1", "name": "任务甲"})
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=None):
            r = asset_intel.build_task_report("t1")
        self.assertTrue(r["ok"])
        self.assertEqual(self.repo.collection("pentest_report").count_documents({"report_type": "task"}), 1)
        self.assertEqual(self.repo.collection("intel_report").count_documents({"report_type": "task"}), 0)

    def test_regenerate_only_pentest_no_pointer_pollution(self):
        """人工 regenerate 只进 pentest_report，且 intel_asset.report_id 未被改（未触发 _mark_asset_pentested）。"""
        # 种一条 intel_report 会话报告作元数据源
        self.repo.collection("intel_report").insert_one(
            {"_id": "ir1", "report_type": "session", "source_session": "s1", "source_task_id": "t1",
             "unit": "U", "asset_key": "https://a.com", "content": "## 旧自动报告", "site": "https://a.com"})
        fake = {"api_key": "x", "name": "p", "model": "m"}
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=fake):
            with mock.patch("sentinel_platform.modules.ai_pentest._llm.chat",
                            return_value={"ok": True, "content": "# 重生成成品报告"}):
                r = asset_intel.regenerate_session_report("s1")
        self.assertTrue(r["ok"])
        # 只进 pentest_report
        pr = self.repo.collection("pentest_report").find_one({"report_key": "session:s1"})
        self.assertIsNotNone(pr)
        self.assertIn("重生成成品报告", pr["content"])
        self.assertEqual(pr["asset_key"], "https://a.com")   # 元数据继承自 intel_report
        self.assertEqual(pr["max_severity"], "high")          # 从 intel_finding 派生
        # intel_report 原自动报告 content 未变
        self.assertEqual(self.repo.collection("intel_report").find_one({"_id": "ir1"})["content"], "## 旧自动报告")
        # 关键不变量：intel_asset.report_id 未被污染
        self.assertEqual(self.repo.collection("intel_asset").find_one({"_id": "a1"})["report_id"], "ORIGINAL_PTR")

    def test_ai_borrow_reads_intel_only(self):
        """AI 借鉴 get_pentest_report/query_unit_reports 仍只命中 intel_report。"""
        self.repo.collection("intel_report").insert_one(
            {"_id": "ir1", "report_type": "session", "source_session": "s1", "unit": "U",
             "asset_key": "https://a.com", "title": "情报报告", "vuln_index": ["f1"], "max_severity": "high"})
        # pentest_report 里放一条同 unit 成品，验证 query_unit_reports 不会捞它
        self.repo.collection("pentest_report").insert_one(
            {"_id": "pr1", "report_type": "task", "unit": "U", "title": "成品报告", "vuln_index": []})
        got = asset_intel.get_pentest_report("ir1", mode="index")
        self.assertEqual(got["report_id"], "ir1")
        ur = asset_intel.query_unit_reports("U")
        titles = {x["title"] for x in ur["reports"]}
        self.assertIn("情报报告", titles)
        self.assertNotIn("成品报告", titles)   # 成品报告不进 AI 借鉴

    def test_get_report_dual_collection(self):
        """get_report 默认 intel_report；传 pentest_report 命中成品。"""
        self.repo.collection("intel_report").insert_one({"_id": "ir1", "title": "情报"})
        self.repo.collection("pentest_report").insert_one({"_id": "pr1", "title": "成品"})
        self.assertEqual(asset_intel.get_report("ir1")["title"], "情报")                     # 默认
        self.assertIsNone(asset_intel.get_report("pr1"))                                       # 默认集合找不到成品
        self.assertEqual(asset_intel.get_report("pr1", collection="pentest_report")["title"], "成品")

    def test_delete_records_whitelist(self):
        """delete_records 接受 pentest_report、拒绝未知集合。"""
        self.repo.collection("pentest_report").insert_one({"_id": "pr1", "title": "x"})
        self.assertEqual(asset_intel.delete_records("pentest_report", ["pr1"])["deleted"], 1)
        self.assertIn("error", asset_intel.delete_records("no_such_coll", ["y"]))

    def test_migration(self):
        """迁移：task/edited 迁入 pentest_report，普通会话报告不迁，原文档全留，重跑无重复。"""
        rc = self.repo.collection("intel_report")
        rc.insert_one({"_id": "ir_task", "report_type": "task", "source_task_id": "t1", "content": "任务报告"})
        rc.insert_one({"_id": "ir_edited", "report_type": "session", "source_session": "s1",
                       "edited": True, "content": "人工改过的会话报告"})
        rc.insert_one({"_id": "ir_auto", "report_type": "session", "source_session": "s2", "content": "自动会话报告"})
        n_before = rc.count_documents({})

        res = migrate.migrate(dry_run=False)
        self.assertEqual(res["migrated_task"], 1)
        self.assertEqual(res["migrated_session_edited"], 1)
        # 只迁前两类
        self.assertEqual(self.repo.collection("pentest_report").count_documents({}), 2)
        self.assertIsNotNone(self.repo.collection("pentest_report").find_one({"report_key": "task:t1"}))
        self.assertIsNotNone(self.repo.collection("pentest_report").find_one({"report_key": "session:s1"}))
        # 自动会话报告不迁
        self.assertIsNone(self.repo.collection("pentest_report").find_one({"report_key": "session:s2"}))
        # 原文档全留
        self.assertEqual(rc.count_documents({}), n_before)
        # 重跑幂等：pentest_report 仍 2 条
        migrate.migrate(dry_run=False)
        self.assertEqual(self.repo.collection("pentest_report").count_documents({}), 2)


if __name__ == "__main__":
    unittest.main()
