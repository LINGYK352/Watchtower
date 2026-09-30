"""报告模板学习单测 —— 结构读取/占位符注入(跨 run)/schema 学习/确定性生成/图表/.wps 拒绝。

依赖 python-docx + docxtpl(纯 py)本地可用才实测渲染；matplotlib 本地有则测图表。
LLM 用 mock 屏蔽（学习是唯一 LLM 调用点，mock 返固定 schema）。
"""
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import report_template as rt


def _has(mod):
    try:
        __import__(mod)
        return True
    except Exception:
        return False


HAS_DOCX = _has("docx")
HAS_DOCXTPL = _has("docxtpl")


# ---- 内存 repo（支持 $push / upsert / sort / skip / limit）----
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

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "t%d" % self._n)
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def find(self, q=None, *a, **k):
        return _Cur([d for d in self.docs if self._match(d, q or {})])

    def find_one(self, q=None, *a, **k):
        for d in self.docs:
            if self._match(d, q or {}):
                return d
        return None

    def count_documents(self, q=None, **k):
        return len([d for d in self.docs if self._match(d, q or {})])

    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            for kk, vv in (upd.get("$push") or {}).items():
                d.setdefault(kk, []).append(vv)
            for kk, vv in (upd.get("$inc") or {}).items():   # refine_count 累加需 $inc
                d[kk] = (d.get(kk) or 0) + vv
            return type("R", (), {"matched_count": 1, "upserted_id": None})()
        if upsert:
            self._n += 1
            nd = dict(q)
            nd.update(upd.get("$set", {}))
            nd.update(upd.get("$setOnInsert", {}))
            nd.setdefault("_id", "t%d" % self._n)
            self.docs.append(nd)
            return type("R", (), {"matched_count": 0, "upserted_id": nd["_id"]})()
        return type("R", (), {"matched_count": 0, "upserted_id": None})()

    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)
        return type("R", (), {"deleted_count": 1 if d else 0})()


class _Cur(list):
    def sort(self, *a, **k):
        return _Cur(list(reversed(self)))

    def skip(self, n):
        return _Cur(self[n:])

    def limit(self, n):
        return _Cur(self[:n])


class _Repo:
    def __init__(self):
        self.c = {}

    def collection(self, n):
        return self.c.setdefault(n, _Coll())


def _make_sample_docx(path):
    """造一份带【多 run 段落】+【漏洞表格】的样例模板 docx。"""
    from docx import Document
    doc = Document()
    doc.add_heading("XX单位渗透测试报告", level=0)          # p? 标题
    p = doc.add_paragraph()                                  # 多 run 段落：模拟 Word 拆 run
    p.add_run("测试时间：")
    p.add_run("2024")
    p.add_run("年3月")
    doc.add_paragraph("本报告共发现漏洞 12 个。")            # 概述(含可变数字)
    tbl = doc.add_table(rows=2, cols=3)                      # 漏洞表：表头 + 1 数据行
    hdr = tbl.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text = "序号", "漏洞名称", "危害等级"
    dr = tbl.rows[1].cells
    dr[0].text, dr[1].text, dr[2].text = "1", "SQL注入", "高危"
    doc.save(path)


def _fake_schema():
    """模拟 AI 学出的 schema（对应 _make_sample_docx 的结构）。"""
    return {
        "version": 1,
        "scalars": [
            {"idx": "p0", "placeholder": "report_title", "semantic": "report.title", "sample_text": ""},
            {"idx": "p1", "placeholder": "test_period", "semantic": "report.period", "sample_text": "2024年3月"},
            {"idx": "p2", "placeholder": "vuln_total", "semantic": "stat.total", "sample_text": "12"},
        ],
        "loops": [
            {"idx": "t0", "data_row": 1, "columns": [
                {"col": 0, "placeholder": "item.seq", "semantic": "seq"},
                {"col": 1, "placeholder": "item.vuln_type", "semantic": "finding.vuln_type"},
                {"col": 2, "placeholder": "item.severity_cn", "semantic": "finding.severity_cn"}]}],
        "images": [],
        "fixed_kept": [],
    }


class ReportTemplateTest(unittest.TestCase):
    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        self.tmp = tempfile.mkdtemp(prefix="tpltest-")
        # 把模板根指到临时目录，避免污染项目 template/
        self._patch_dir = mock.patch.object(rt, "template_dir", return_value=self.tmp)
        self._patch_dir.start()

    def tearDown(self):
        self._patch_dir.stop()
        set_repo(None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    @unittest.skipUnless(HAS_DOCX, "no python-docx")
    def test_read_structure(self):
        p = os.path.join(self.tmp, "s.docx")
        _make_sample_docx(p)
        items = rt._read_docx_structure(p)
        idxs = {i["idx"] for i in items}
        self.assertTrue(any(i["kind"] == "table" for i in items))
        self.assertTrue(any(i["kind"] == "paragraph" for i in items))
        # 表格带表头
        tbl = next(i for i in items if i["kind"] == "table")
        self.assertEqual(tbl["header"], ["序号", "漏洞名称", "危害等级"])

    @unittest.skipUnless(HAS_DOCX, "no python-docx")
    def test_merge_runs_and_inject(self):
        """多 run 段落合并后注入占位符：标签落单 run（docxtpl 前提）。"""
        from docx import Document
        d = Document()
        p = d.add_paragraph()
        p.add_run("测试时间："); p.add_run("2024"); p.add_run("年3月")
        self.assertGreater(len(p.runs), 1)
        rt._inject_scalar(p, "test_period", "2024年3月")
        # 合并后仅首 run 有文本，且占位符完整落在单 run
        nonempty = [r for r in p.runs if r.text]
        self.assertEqual(len(nonempty), 1)
        self.assertIn("{{ test_period }}", nonempty[0].text)
        self.assertIn("测试时间：", nonempty[0].text)   # 固定前缀保留

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_learn_and_generate_e2e(self):
        """端到端：mock LLM 学 schema → 注入 → 自检 ready → 生成填充 docx 断言含数据。"""
        origin = os.path.join(self.tmp, "origin_up.docx")
        _make_sample_docx(origin)
        # 种 finding + 会话报告（task 数据源）
        self.repo.collection("intel_finding").insert_one(
            {"_id": "f1", "session_id": "s1", "severity": "high", "vuln_type": "SQL注入", "target": "a.com"})
        self.repo.collection("intel_finding").insert_one(
            {"_id": "f2", "session_id": "s1", "severity": "low", "vuln_type": "XSS", "target": "b.com"})
        self.repo.collection("intel_report").insert_one(
            {"report_type": "session", "source_task_id": "task1", "source_session": "s1",
             "vuln_index": ["f1", "f2"], "unit": "XX单位", "title": "会话报告"})
        self.repo.collection("task").insert_one({"_id": "task1", "name": "XX项目"})

        # mock LLM 返回 tool_call schema
        fake_tc = {"ok": True, "tokens": 100,
                   "tool_calls": [{"name": "emit_template_schema", "arguments": _fake_schema()}]}
        with mock.patch("sentinel_platform.modules.ai_pentest._llm.resolve_provider",
                        return_value={"api_key": "x", "model": "m", "name": "p"}):
            with mock.patch("sentinel_platform.modules.ai_pentest._llm.chat", return_value=fake_tc):
                r = rt.learn_template("测试模板", origin, source_filename="origin_up.docx",
                                      need_review=False, sync=True)
        self.assertTrue(r.get("ok"), r)
        self.assertEqual(r["status"], "ready")
        tid = r["template_id"]

        # 生成（task 源）→ 落 pentest_report，产 docx
        g = rt.generate_from_template(tid, "task", "task1")
        self.assertTrue(g.get("ok"), g)
        self.assertEqual(g["vuln_total"], 2)
        docx_abs = os.path.join(self.tmp, g["docx_path"])
        self.assertTrue(os.path.isfile(docx_abs))
        # 读回渲染结果：标题填充 + 表格两行漏洞
        from docx import Document
        out = Document(docx_abs)
        alltext = "\n".join(p.text for p in out.paragraphs)
        self.assertIn("XX项目", alltext)              # report.title 填充
        self.assertNotIn("{{", alltext)               # 无标签外泄
        # 表格：表头 + 2 条漏洞行（循环生效）
        vt = "\n".join(c.text for t in out.tables for row in t.rows for c in row.cells)
        self.assertIn("SQL注入", vt)
        self.assertIn("XSS", vt)
        # pentest_report 落库 gen_mode=template
        pr = self.repo.collection("pentest_report").find_one({"report_key": "tpl:task1:{}".format(tid)})
        self.assertIsNotNone(pr)
        self.assertEqual(pr["gen_mode"], "template")

    def test_collect_findings_excludes_false_positive(self):
        """v1.21.157-48 item6：报告采集排除误报漏洞；降级已自动生效（读 severity=降后值）。"""
        # session 源：3 条 finding，1 条标误报 + 1 条被降级
        self.repo.collection("intel_finding").insert_one(
            {"_id": "g1", "session_id": "sx", "severity": "high", "vuln_type": "SQL注入", "target": "a"})
        self.repo.collection("intel_finding").insert_one(
            {"_id": "g2", "session_id": "sx", "severity": "high", "vuln_type": "误报洞", "target": "b",
             "handle_status": "false_positive"})
        self.repo.collection("intel_finding").insert_one(
            {"_id": "g3", "session_id": "sx", "severity": "low", "vuln_type": "降级洞", "target": "c",
             "manual_severity": "low", "downgraded_from": "high"})
        out = rt._collect_findings("session", "sx")
        names = [f["vuln_type"] for f in out]
        self.assertIn("SQL注入", names)
        self.assertNotIn("误报洞", names)              # 误报排除
        self.assertIn("降级洞", names)                 # 降级仍在，按降后等级
        g3 = next(f for f in out if f["vuln_type"] == "降级洞")
        self.assertEqual(g3["severity"], "low")        # 读 severity=降后值

    def test_severity_stat_and_evidence(self):
        finds = [{"severity": "high"}, {"severity": "high"}, {"severity": "low"}]
        st = rt._severity_stat(finds)
        self.assertEqual(st["high"], 2)
        self.assertEqual(st["total"], 3)
        # evidence: list of dicts → text
        txt = rt._evidence_text([{"tool": "http_request", "result": "200 OK body"}])
        self.assertIn("http_request", txt)
        self.assertIn("200 OK", txt)

    def test_chart_severity_empty(self):
        """无漏洞（全 0）→ 不产图（返 False），不崩。"""
        p = os.path.join(self.tmp, "c.png")
        ok = rt._chart_severity({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}, p)
        self.assertFalse(ok)

    # ========== 新增：模型可选 + 人在回路迭代精修 ==========

    def _mock_learn(self, schema=None):
        """返回 (patch_resolve, patch_chat) 上下文管理器组：mock 掉 LLM 学习。"""
        fake_tc = {"ok": True, "tokens": 100,
                   "tool_calls": [{"name": "emit_template_schema", "arguments": schema or _fake_schema()}]}
        return (mock.patch("sentinel_platform.modules.ai_pentest._llm.resolve_provider",
                           return_value={"api_key": "x", "model": "m", "name": "p"}),
                mock.patch("sentinel_platform.modules.ai_pentest._llm.chat", return_value=fake_tc))

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_need_review_lands_review_not_ready(self):
        """勾选 need_review → 学成落 review 态（非 ready）；生成端点拒绝 review 态。"""
        origin = os.path.join(self.tmp, "o1.docx")
        _make_sample_docx(origin)
        pr, pc = self._mock_learn()
        with pr, pc:
            r = rt.learn_template("T", origin, need_review=True, sync=True)
        self.assertTrue(r.get("ok"), r)
        self.assertEqual(r["status"], "review")           # 红线：勾选复核 → review 而非 ready
        g = rt.generate_from_template(r["template_id"], "task", "task1")
        self.assertIn("error", g)                          # review 态不可生成
        self.assertIn("未就绪", g["error"])

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_default_no_review_stays_ready(self):
        """不勾 need_review（默认）→ 直接 ready（向后兼容，存量行为不变）。"""
        origin = os.path.join(self.tmp, "o2.docx")
        _make_sample_docx(origin)
        pr, pc = self._mock_learn()
        with pr, pc:
            r = rt.learn_template("T", origin, need_review=False, sync=True)
        self.assertEqual(r["status"], "ready")

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_refine_confirm_state_machine(self):
        """review → refine（重学仍 review + refine_count++）→ confirm → ready → 可生成。"""
        origin = os.path.join(self.tmp, "o3.docx")
        _make_sample_docx(origin)
        pr, pc = self._mock_learn()
        with pr, pc:
            r = rt.learn_template("T", origin, need_review=True, sync=True)
        tid = r["template_id"]
        # confirm 前生成被拒
        self.assertIn("error", rt.generate_from_template(tid, "task", "task1"))
        # refine：重学，仍 review，refine_count=1
        pr2, pc2 = self._mock_learn()
        with pr2, pc2:
            rf = rt.refine_template(tid, feedback="第2段是固定文案不要当可变")
        self.assertTrue(rf.get("ok"), rf)
        self.assertEqual(rf["status"], "review")
        doc = self.repo.collection("report_template").find_one({"_id": rt._oid(tid)})
        self.assertEqual(doc.get("refine_count"), 1)
        # confirm → ready
        cf = rt.confirm_template(tid)
        self.assertTrue(cf.get("ok"))
        self.assertEqual(cf["status"], "ready")
        # confirm 非 review 态拒绝（幂等保护）：再 confirm 已 ready → note 已定稿
        self.assertEqual(rt.confirm_template(tid).get("status"), "ready")

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_provider_id_recorded_and_bad_id_degrades(self):
        """provider_id 记录进 learn_provider_name；无效 id 降级到场景默认不炸。"""
        origin = os.path.join(self.tmp, "o4.docx")
        _make_sample_docx(origin)
        # 无效 provider_id：get_provider 返 {} → 降级 _llm.resolve_provider（被 mock）
        pr, pc = self._mock_learn()
        with pr, pc, mock.patch("sentinel_platform.modules.ai_pentest.ai_config.get_provider",
                                return_value={}):
            r = rt.learn_template("T", origin, provider_id="deadbeef", sync=True)
        self.assertTrue(r.get("ok"), r)                    # 降级不炸
        doc = self.repo.collection("report_template").find_one({"_id": rt._oid(r["template_id"])})
        self.assertEqual(doc.get("learn_provider_name"), "p")   # 记录降级后实际用的 provider

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_async_learn_returns_learning_then_completes(self):
        """异步（默认）：learn 秒回 status=learning + 起后台线程；线程跑完落 review。"""
        import time
        origin = os.path.join(self.tmp, "async.docx")
        _make_sample_docx(origin)
        pr, pc = self._mock_learn()
        with pr, pc:
            r = rt.learn_template("异步模板", origin)   # 默认 sync=False + need_review=True
            self.assertTrue(r.get("ok"), r)
            self.assertEqual(r["status"], "learning")     # 秒回 learning（不阻塞）
            self.assertTrue(r.get("async"))
            tid = r["template_id"]
            # 等后台线程跑完（mock LLM 很快）
            for _ in range(50):
                d = self.repo.collection("report_template").find_one({"_id": rt._oid(tid)})
                if d and d.get("status") != "learning":
                    break
                time.sleep(0.05)
        d = self.repo.collection("report_template").find_one({"_id": rt._oid(tid)})
        self.assertEqual(d.get("status"), "review")       # 默认 need_review=True → review
        self.assertEqual(d.get("learn_progress"), 100)

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_empty_schema_falls_to_failed(self):
        """空 schema 兜底：LLM 产出 scalars/loops/images 全空 → 落 failed（非 review）+ 提示换强模型。"""
        origin = os.path.join(self.tmp, "empty.docx")
        _make_sample_docx(origin)
        empty = {"version": 1, "scalars": [], "loops": [], "images": [], "fixed_kept": ["p0", "p1"]}
        pr, pc = self._mock_learn(empty)
        with pr, pc:
            r = rt.learn_template("空schema", origin, need_review=True, sync=True)
        self.assertFalse(r.get("ok"))
        self.assertEqual(r["status"], "failed")
        self.assertIn("换更强模型", r.get("error", ""))

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_get_template_docx_origin_and_template(self):
        """在线对比取字节：which=origin/template 都返回真实文件路径；非法 which 由端点拦（此处测服务层）。"""
        origin = os.path.join(self.tmp, "docx.docx")
        _make_sample_docx(origin)
        pr, pc = self._mock_learn()
        with pr, pc:
            r = rt.learn_template("对比模板", origin, need_review=True, sync=True)
        tid = r["template_id"]
        ro = rt.get_template_docx(tid, "origin")
        rt2 = rt.get_template_docx(tid, "template")
        self.assertTrue(ro.get("ok") and os.path.isfile(ro["path"]))
        self.assertTrue(rt2.get("ok") and os.path.isfile(rt2["path"]))
        self.assertTrue(ro["path"].endswith("origin.docx"))
        self.assertTrue(rt2["path"].endswith("template.docx"))

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_loop_col_bad_varname_still_renders(self):
        """回归 VM E2E 缺陷：弱模型把循环列 placeholder 填成 row.x（≠循环变量 item）。
        修复后注入侧强制 item.<字段>（按 semantic 派生），自检渲染不再 'row' is undefined。"""
        origin = os.path.join(self.tmp, "bad.docx")
        _make_sample_docx(origin)
        bad_schema = {
            "version": 1, "scalars": [], "images": [], "fixed_kept": ["p0", "p1", "p2"],
            "loops": [{"idx": "t0", "data_row": 1, "columns": [
                {"col": 0, "placeholder": "row.seq", "semantic": "seq"},
                {"col": 1, "placeholder": "row.name", "semantic": "finding.vuln_type"},
                {"col": 2, "placeholder": "row.lvl", "semantic": "finding.severity_cn"}]}],
        }
        pr, pc = self._mock_learn(bad_schema)
        with pr, pc:
            r = rt.learn_template("坏变量名", origin, need_review=True, sync=True)
        self.assertTrue(r.get("ok"), r)              # 不再因 'row' undefined 落 failed
        self.assertEqual(r["status"], "review")
        # 派生字段名正确（semantic → finding 键）
        self.assertEqual(rt._loop_field_name({"semantic": "finding.vuln_type", "placeholder": "row.name"}), "vuln_type")
        self.assertEqual(rt._loop_field_name({"semantic": "finding.severity_cn"}), "severity_cn")

    @unittest.skipUnless(HAS_DOCX, "no python-docx")
    def test_template_diff_marks_verdicts(self):
        """并排对比：schema 判定映射回 origin 每段（可变/循环/未识别）。"""
        origin = os.path.join(self.tmp, "o5.docx")
        _make_sample_docx(origin)
        pr, pc = self._mock_learn()
        with pr, pc:
            r = rt.learn_template("T", origin, need_review=True, sync=True)
        d = rt.template_diff(r["template_id"])
        self.assertTrue(d.get("ok"), d)
        verdicts = {row["idx"]: row["verdict"] for row in d["rows"]}
        self.assertEqual(verdicts.get("p1"), "可变字段")   # 测试时间段判可变
        self.assertEqual(verdicts.get("t0"), "循环表格")   # 漏洞表判循环
        self.assertIn("total", d["summary"])


from sentinel_platform.modules.risk_intel import report_template_builtin as rtb


class BuiltinTemplateTest(unittest.TestCase):
    """内置默认模板（会话级/任务级）：播种幂等、autoescape 保 POC、任务级分系统分组。"""

    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        self.tmp = tempfile.mkdtemp(prefix="tplbuiltin-")
        # rtb 与 rt 都从 core.template_dir 取根；两处都指到临时目录
        self._p1 = mock.patch.object(rtb, "template_dir", return_value=self.tmp)
        self._p2 = mock.patch.object(rt, "template_dir", return_value=self.tmp)
        self._p1.start(); self._p2.start()

    def tearDown(self):
        self._p1.stop(); self._p2.stop()
        set_repo(None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_seed_idempotent(self):
        """首次播种 3 个（会话级+任务级+漏洞级）；再播种 0（幂等，不重复）。"""
        n1 = rtb.seed_builtin_templates()
        self.assertEqual(n1, len(rtb.BUILTIN_IDS))
        coll = rt.repo_coll()
        self.assertIsNotNone(coll.find_one({"_id": rtb.BUILTIN_SESSION_ID}))
        self.assertIsNotNone(coll.find_one({"_id": rtb.BUILTIN_TASK_ID}))
        # 两个都 ready + builtin 标记 + 磁盘 template.docx 存在
        for tid in rtb.BUILTIN_IDS:
            d = coll.find_one({"_id": tid})
            self.assertEqual(d["status"], "ready")
            self.assertTrue(d["builtin"])
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, d["template_path"])))
        n2 = rtb.seed_builtin_templates()
        self.assertEqual(n2, 0)

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_seed_reheals_missing_disk(self):
        """库有 doc 但磁盘目录被清 → 重播补齐（存量实例目录丢失自愈）。"""
        rtb.seed_builtin_templates()
        shutil.rmtree(os.path.join(self.tmp, rtb.BUILTIN_SESSION_ID), ignore_errors=True)
        n = rtb.seed_builtin_templates()
        self.assertGreaterEqual(n, 1)
        d = rt.repo_coll().find_one({"_id": rtb.BUILTIN_SESSION_ID})
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, d["template_path"])))

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_builtin_not_deletable(self):
        """内置模板不可删（delete_template 拒绝）。"""
        rtb.seed_builtin_templates()
        r = rt.delete_template(rtb.BUILTIN_SESSION_ID)
        self.assertIn("error", r)
        self.assertIsNotNone(rt.repo_coll().find_one({"_id": rtb.BUILTIN_SESSION_ID}))

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_poc_special_chars_preserved(self):
        """autoescape=True：POC 里的 < > & 不被 docxtpl 当 XML 吞掉（携带 POC 铁律）。"""
        from docx import Document
        from docxtpl import DocxTemplate
        tp = os.path.join(self.tmp, "t.docx")
        rtb._build_session_docx(tp)
        tpl = DocxTemplate(tp)
        payload = "kw=<script>alert(1)</script> & id=1&size=2"
        ctx = {"report_title": "T", "report_unit": "U", "report_period": "2026", "report_system": "S",
               "report_summary": "s", "chart_severity": "",
               "stat": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
               "findings": [{"seq": 1, "vuln_type": "XSS", "target": "t", "severity_cn": "高危",
                             "cvss_score": "6.1", "impact": "i", "verify_method": "v",
                             "poc": payload, "evidence": "e"}]}
        tpl.render(ctx, autoescape=True)
        op = os.path.join(self.tmp, "o.docx")
        tpl.save(op)
        full = "\n".join(p.text for p in Document(op).paragraphs)
        self.assertIn("<script>", full)
        self.assertIn("size=2", full)   # & 后内容不丢

    @unittest.skipUnless(HAS_DOCX and HAS_DOCXTPL, "need python-docx + docxtpl")
    def test_task_grouping_multi_system(self):
        """任务级分组：不同 system_name 分桶，组内 seq 从 1 重排。"""
        findings = [
            {"seq": 1, "system_name": "OA", "vuln_type": "a", "severity_cn": "高危"},
            {"seq": 2, "system_name": "门户", "vuln_type": "b", "severity_cn": "中危"},
            {"seq": 3, "system_name": "OA", "vuln_type": "c", "severity_cn": "低危"},
        ]
        groups = rt._group_findings_by_system("task", findings)
        names = [g["name"] for g in groups]
        self.assertEqual(names, ["OA", "门户"])           # 保序
        oa = next(g for g in groups if g["name"] == "OA")
        self.assertEqual([f["seq"] for f in oa["findings"]], [1, 2])   # 组内重排
        self.assertEqual(oa["stat"]["total"], 2)

    def test_session_grouping_single(self):
        """会话级分组：始终单组（组名取 meta_system）。"""
        groups = rt._group_findings_by_system("session", [{"seq": 1, "severity_cn": "高危"}], meta_system="OA系统")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["name"], "OA系统")


if __name__ == "__main__":
    unittest.main()
