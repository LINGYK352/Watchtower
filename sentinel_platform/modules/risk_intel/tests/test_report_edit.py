"""报告编辑单测（#4）—— 任务级报告聚合/幂等、update_report、docx 导出、会话级重生成守卫。

覆盖：build_task_report（无 LLM 走模板拼接 + 幂等更新）、update_report（改正文标记 edited）、
export_report_docx（md→docx 字节流，本地有 python-docx 才实测渲染）、regenerate 无 provider 拒绝。
LLM/provider 用 monkeypatch 屏蔽，不发真网络。
"""
import unittest
from unittest import mock

from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import asset_intel


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0

    def _match(self, d, q):
        for k, v in (q or {}).items():
            if isinstance(v, dict):
                if "$ne" in v and d.get(k) == v["$ne"]:
                    return False
                if "$in" in v and d.get(k) not in v["$in"]:
                    return False
            elif d.get(k) != v:
                return False
        return True

    def find(self, q=None):
        res = [d for d in self.docs if self._match(d, q or {})]
        return _Cursor(res)

    def find_one(self, q):
        for d in self.docs:
            if self._match(d, q or {}):
                return d
        return None

    def count_documents(self, q=None):
        return len([d for d in self.docs if self._match(d, q or {})])

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "r%d" % self._n)
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            return type("R", (), {"matched_count": 1, "upserted_id": None})()
        if upsert:
            self._n += 1
            nd = dict(q)
            nd.update(upd.get("$set", {}))
            nd.update(upd.get("$setOnInsert", {}))
            nd.setdefault("_id", "r%d" % self._n)
            self.docs.append(nd)
            return type("R", (), {"matched_count": 0, "upserted_id": nd["_id"]})()
        return type("R", (), {"matched_count": 0, "upserted_id": None})()


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


class ReportEditTest(unittest.TestCase):
    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        # 任务 t1 下两个会话级报告 + 对应 finding
        fc = self.repo.collection("intel_finding")
        fc.insert_one({"_id": "f1", "session_id": "s1", "severity": "high", "vuln_type": "SQLi", "target": "a.com"})
        fc.insert_one({"_id": "f2", "session_id": "s2", "severity": "low", "vuln_type": "XSS", "target": "b.com"})
        rc = self.repo.collection("intel_report")
        rc.insert_one({"_id": "rep1", "report_type": "session", "source_session": "s1",
                       "source_task_id": "t1", "asset_key": "https://a.com", "content": "## a 报告",
                       "vuln_index": ["f1"], "max_severity": "high", "title": "a 报告"})
        rc.insert_one({"_id": "rep2", "report_type": "session", "source_session": "s2",
                       "source_task_id": "t1", "asset_key": "https://b.com", "content": "## b 报告",
                       "vuln_index": ["f2"], "max_severity": "low", "title": "b 报告"})
        self.repo.collection("task").insert_one({"_id": "t1", "name": "测试任务甲"})

    def tearDown(self):
        set_repo(None)

    def test_build_task_report_template_fallback(self):
        """无 LLM provider → 走模板拼接，聚合两会话报告 + 漏洞统计，落 report_type=task。"""
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=None):
            r = asset_intel.build_task_report("t1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["session_count"], 2)
        self.assertEqual(r["vuln_total"], 2)
        # 任务级成品报告落 pentest_report（与 intel_report 情报报告物理隔离）
        doc = self.repo.collection("pentest_report").find_one({"source_task_id": "t1", "report_type": "task"})
        self.assertIsNotNone(doc)
        self.assertEqual(doc["report_key"], "task:t1")    # 幂等键
        self.assertIn("测试任务甲", doc["content"])       # 任务名进正文
        self.assertIn("a 报告", doc["content"])           # 会话报告被堆叠进去
        self.assertIn("b 报告", doc["content"])
        self.assertEqual(doc["max_severity"], "high")     # 取最高危

    def test_build_task_report_idempotent(self):
        """重复生成同任务 → 更新不重建。"""
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=None):
            asset_intel.build_task_report("t1")
            r2 = asset_intel.build_task_report("t1")
        self.assertTrue(r2["updated"])
        tasks = self.repo.collection("pentest_report").find({"source_task_id": "t1", "report_type": "task"})
        self.assertEqual(len(list(tasks)), 1)

    def test_build_task_report_uses_llm_when_available(self):
        """有 provider → 用 LLM content（mock chat 返回固定文本）。"""
        fake_prov = {"api_key": "x", "name": "p", "model": "m"}
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=fake_prov):
            with mock.patch("sentinel_platform.modules.ai_pentest._llm.chat",
                            return_value={"ok": True, "content": "# LLM 整合报告正文"}):
                r = asset_intel.build_task_report("t1")
        self.assertTrue(r["ok"])
        doc = self.repo.collection("pentest_report").find_one({"source_task_id": "t1", "report_type": "task"})
        self.assertIn("LLM 整合报告", doc["content"])

    def test_build_task_report_llm_fail_falls_back(self):
        """LLM 返回失败 → 降级模板，不崩、有产出。"""
        fake_prov = {"api_key": "x", "name": "p", "model": "m"}
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=fake_prov):
            with mock.patch("sentinel_platform.modules.ai_pentest._llm.chat",
                            return_value={"ok": False, "error": "boom"}):
                r = asset_intel.build_task_report("t1")
        self.assertTrue(r["ok"])
        doc = self.repo.collection("pentest_report").find_one({"source_task_id": "t1", "report_type": "task"})
        self.assertIn("测试任务甲", doc["content"])       # 降级模板仍有内容

    def test_update_report(self):
        # update_report 现只作用于 pentest_report（人看成品），种一条成品报告
        self.repo.collection("pentest_report").insert_one(
            {"_id": "pr1", "report_type": "task", "content": "原正文", "title": "原标题"})
        r = asset_intel.update_report("pr1", content="改后的正文", title="新标题")
        self.assertTrue(r["ok"])
        doc = self.repo.collection("pentest_report").find_one({"_id": "pr1"})
        self.assertEqual(doc["content"], "改后的正文")
        self.assertEqual(doc["title"], "新标题")
        self.assertTrue(doc["edited"])

    def test_update_report_not_found(self):
        self.assertIn("error", asset_intel.update_report("nope", content="x"))

    def test_regenerate_session_no_provider_rejected(self):
        """无 provider → 明确拒绝，不覆盖已有报告。"""
        with mock.patch.object(asset_intel, "_report_llm_provider", return_value=None):
            r = asset_intel.regenerate_session_report("s1")
        self.assertIn("error", r)
        # 原报告未被动过
        self.assertEqual(self.repo.collection("intel_report").find_one({"_id": "rep1"})["content"], "## a 报告")

    def test_export_report_docx(self):
        """md→docx：本地有 python-docx 才实测渲染，返回非空 bytes + 文件名。"""
        try:
            import docx  # noqa
        except Exception:
            self.skipTest("no python-docx locally")
        md = "# 标题\n\n正文 **加粗** 段落\n\n- 列表项1\n- 列表项2\n\n| 严重 | 高危 |\n|---|---|\n| 1 | 2 |\n"
        self.repo.collection("intel_report").insert_one(
            {"_id": "repd", "title": "导出测试", "content": md})
        r = asset_intel.export_report_docx("repd")
        self.assertTrue(r["ok"])
        self.assertTrue(r["filename"].endswith(".docx"))
        self.assertGreater(len(r["data"]), 500)           # docx zip 至少几百字节
        self.assertTrue(r["data"][:2] == b"PK")           # docx 是 zip，magic=PK

    def test_export_report_docx_not_found(self):
        self.assertIn("error", asset_intel.export_report_docx("nope"))

    def test_list_report_type_filter(self):
        """#4 报告编辑分栏：report_type=task 只返任务级；session 返会话级（含存量无字段）。"""
        rc = self.repo.collection("intel_report")
        rc.insert_one({"_id": "rept", "report_type": "task", "source_task_id": "t1",
                       "title": "任务甲总结", "content": "# 任务报告"})
        # 存量会话报告：无 report_type 字段，session 档应用 $ne task 兜住
        rc.insert_one({"_id": "rep_legacy", "source_session": "s9",
                       "title": "旧会话报告", "content": "旧"})

        task_only = asset_intel.list_collection("intel_report", size=0, report_type="task")
        self.assertEqual({d["_id"] for d in task_only["items"]}, {"rept"})

        session_only = asset_intel.list_collection("intel_report", size=0, report_type="session")
        ids = {d["_id"] for d in session_only["items"]}
        self.assertIn("rep1", ids)          # 显式 report_type=session
        self.assertIn("rep_legacy", ids)    # 存量无字段，$ne task 命中
        self.assertNotIn("rept", ids)       # 任务级不混入

        # 不传 report_type → 全量（task + session 都在）
        all_rep = asset_intel.list_collection("intel_report", size=0)
        self.assertEqual(all_rep["total"], len(rc.docs))


if __name__ == "__main__":
    unittest.main()
