"""risk_intel/vuln_center 单测 —— core 内存替身，不需真 Mongo / 不发真网络 / 不需 pymongo。

覆盖：接口契约（FindingService 结构化子类型）、is_identify_poc 判定、CVSS 定级 + triage 校准、
证据强制（confirmed→verified / none→lead / 5xx 不误判）、record_finding 幂等 + lead 升级、
md 批量登记、出洞经 registry 调 NOTIFY（阈值 + 降级）、三来源混排查询/标记、register 注册。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.interfaces import FindingService
from sentinel_platform.contracts.registry import reset_registry


# —— 富内存 Mongo 替身：支持 vuln_center 用到的 $ne/$nor/$in/$gte/$lte/$regex + 投影 + delete/update_many ——
def _match(doc, query):
    import re as _re
    for k, cond in (query or {}).items():
        if k == "$nor":
            if any(_match(doc, sub) for sub in cond):
                return False
            continue
        val = doc.get(k)
        if isinstance(cond, dict):
            if "$regex" in cond:
                flags = _re.I if "i" in cond.get("$options", "") else 0
                if not (isinstance(val, str) and _re.search(cond["$regex"], val, flags)):
                    return False
            elif "$ne" in cond:
                if val == cond["$ne"]:
                    return False
            elif "$in" in cond:
                if val not in cond["$in"]:
                    return False
            elif "$nin" in cond:
                if val in cond["$nin"]:
                    return False
            elif "$gte" in cond or "$lte" in cond:
                if val is None:
                    return False
                if "$gte" in cond and str(val) < str(cond["$gte"]):
                    return False
                if "$lte" in cond and str(val) > str(cond["$lte"]):
                    return False
            else:
                return False
        else:
            if val != cond:
                return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=None):
        if isinstance(key, list):
            for k, d in reversed(key):
                self._docs.sort(key=lambda x: (x.get(k) is None, x.get(k)), reverse=(d < 0))
        else:
            self._docs.sort(key=lambda x: (x.get(key) is None, x.get(key)), reverse=(direction < 0))
        return self

    def skip(self, n):
        self._docs = self._docs[n:]
        return self

    def limit(self, n):
        if n:
            self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)


class _Coll:
    def __init__(self):
        self.docs = []
        self._seq = 0

    def _next_id(self):
        self._seq += 1
        return "oid{}".format(self._seq)

    def find_one(self, query, projection=None):
        for d in self.docs:
            if _match(d, query):
                return d
        return None

    def find(self, query=None, projection=None):
        return _Cursor([d for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        doc.setdefault("_id", self._next_id())
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def update_one(self, query, update, upsert=False):
        t = self.find_one(query)
        if t is None and upsert:
            t = dict(query)
            t.setdefault("_id", self._next_id())
            self.docs.append(t)
        if t is not None:
            t.update(update.get("$set") or {})
        return type("R", (), {"modified_count": 1 if t else 0})()

    def update_many(self, query, update):
        n = 0
        for d in self.docs:
            if _match(d, query):
                d.update(update.get("$set") or {})
                n += 1
        return type("R", (), {"modified_count": n})()

    def delete_many(self, query):
        keep = [d for d in self.docs if not _match(d, query)]
        n = len(self.docs) - len(keep)
        self.docs = keep
        return type("R", (), {"deleted_count": n})()

    def count_documents(self, query):
        return sum(1 for d in self.docs if _match(d, query or {}))


class _Repo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _Coll())


# —— 工具调用日志构造 helper（模拟 http_request 命中证据）——
def _http_call(url, status_code=200, body="x" * 60, **extra):
    import json as _j
    res = {"status_code": status_code, "body": body}
    res.update(extra)
    return {"name": "http_request", "arguments": {"url": url}, "result": _j.dumps(res)}


class VulnCenterTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        set_repo(_Repo())

    def tearDown(self):
        reset_repo()
        reset_registry()

    def _impl(self):
        from sentinel_platform.modules.risk_intel.vuln_center import FindingServiceImpl
        return FindingServiceImpl()

    # —— 接口契约 ——
    def test_satisfies_protocol(self):
        self.assertIsInstance(self._impl(), FindingService)

    def test_register_puts_finding_into_registry(self):
        from sentinel_platform.modules.risk_intel.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get(ROLE.FINDING)
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "record_finding"))
        self.assertTrue(hasattr(svc, "is_identify_poc"))

    # —— is_identify_poc 纯判定 ——
    def test_is_identify_poc(self):
        im = self._impl()
        self.assertTrue(im.is_identify_poc("Nacos_Identify", ""))
        self.assertTrue(im.is_identify_poc("x", "发现 Nacos 服务"))
        self.assertFalse(im.is_identify_poc("x", "发现Host碰撞漏洞"))   # 含"漏洞"不算识别类
        self.assertFalse(im.is_identify_poc("sqli_check", "SQL注入"))

    # —— CVSS 定级 + triage 校准 ——
    def test_cvss_grading(self):
        from sentinel_platform.modules.risk_intel import _cvss
        score, sev = _cvss.score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(sev, "high")
        self.assertAlmostEqual(score, 7.5, places=1)

    def test_triage_calibrate_info_leak_downgrade(self):
        from sentinel_platform.modules.risk_intel import _cvss
        # 版本泄露：base medium(5.3) → 校准 info
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        s, sev = _cvss.score_from_vector(vec)
        cal, basis = _cvss.calibrate_severity(sev, s, "Jira 版本号泄露", "暴露版本", vector=vec)
        self.assertEqual(cal, "info")
        self.assertTrue(basis)

    def test_triage_vector_hard_gate_no_downgrade(self):
        from sentinel_platform.modules.risk_intel import _cvss
        # 名字像信息泄露但向量 C:H(真脱库) → 硬闸保原级不降
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        s, sev = _cvss.score_from_vector(vec)
        cal, _ = _cvss.calibrate_severity(sev, s, "数据库备份泄露", "可下载完整备份", vector=vec)
        self.assertEqual(cal, "high")   # 未降

    # —— 证据强制：confirmed → verified ——
    def test_record_confirmed_verified(self):
        im = self._impl()
        f = {"vuln_type": "SQL注入", "target": "http://t.com/api/x",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "tool_log": [_http_call("http://t.com/api/x", 200, "database error near line 1" * 3)]}
        r = im.record_finding(f)
        self.assertTrue(r["ok"])
        self.assertTrue(r["verified"])
        self.assertEqual(r["evidence_level"], "confirmed")

    # —— 证据强制：无证据 → lead 降级(不静默丢) ——
    def test_record_no_evidence_lead(self):
        im = self._impl()
        f = {"vuln_type": "SQL注入", "target": "http://t.com/api/x",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "tool_log": []}
        r = im.record_finding(f)
        self.assertTrue(r["ok"])
        self.assertFalse(r["verified"])
        self.assertEqual(r["evidence_level"], "none")

    # —— 证据强制：5xx 不误判 verified(旧坑) ——
    def test_record_5xx_not_verified(self):
        im = self._impl()
        f = {"vuln_type": "SQL注入", "target": "http://t.com/api/x",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "tool_log": [_http_call("http://t.com/api/x", 503, "gateway error")]}
        r = im.record_finding(f)
        self.assertFalse(r["verified"])   # 503=unknown 不算证据

    # —— 参数校验 ——
    def test_record_missing_fields(self):
        r = self._impl().record_finding({"vuln_type": "", "target": "x"})
        self.assertFalse(r["ok"])
        r2 = self._impl().record_finding("nope")
        self.assertFalse(r2["ok"])

    # —— 幂等 + lead 升级 ——
    def test_idempotent_and_lead_upgrade(self):
        im = self._impl()
        tgt = "http://t.com/api/x"
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        r1 = im.record_finding({"vuln_type": "SQL注入", "target": tgt, "cvss_vector": vec, "tool_log": []})
        self.assertFalse(r1["verified"])                 # 先落 lead
        # 同 key 再报，这次带正向证据 → 升级
        r2 = im.record_finding({"vuln_type": "SQL注入", "target": tgt, "cvss_vector": vec,
                                "tool_log": [_http_call(tgt, 200, "error in your SQL syntax" * 3)]})
        self.assertTrue(r2.get("upgraded"))
        # 第三次同 key 无新证据 → dup skip
        r3 = im.record_finding({"vuln_type": "SQL注入", "target": tgt, "cvss_vector": vec, "tool_log": []})
        self.assertTrue(r3["dup"])

    # —— md 批量登记 ——
    def test_ingest_md_batch(self):
        im = self._impl()
        md = (
            "## 漏洞\n"
            "### 2026-07-05 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | SQL注入\n"
            "- 目标: http://t.com/api/x\n- 危害: 脱库\n"
            "```bash\ncurl http://t.com/api/x\n```\n"
        )
        r = im.record_finding({"md_text": md,
                               "tool_log": [_http_call("http://t.com/api/x", 200, "sql error" * 20)]})
        self.assertTrue(r["ok"])
        self.assertEqual(r["ingested"], 1)

    # —— 出洞经 registry 调 NOTIFY(阈值达标推) ——
    def test_notify_on_verified(self):
        from sentinel_platform.modules.risk_intel import vuln_center as vc
        # 注册一个 fake NOTIFY
        sent = {}
        class _Notify:
            def notify(self, message, **kw):
                sent["msg"] = message
                sent["kw"] = kw
                return {"ok": True, "sent": ["feishu"]}
        get_registry().register(ROLE.NOTIFY, _Notify())
        im = self._impl()
        im.record_finding({"vuln_type": "RCE", "target": "http://t.com/rce",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_http_call("http://t.com/rce", 200, "uid=0(root)" * 10)]})
        self.assertIn("msg", sent)              # 已推
        self.assertEqual(sent["kw"].get("channel"), "feishu")

    # —— NOTIFY 未注册：降级不崩 ——
    def test_notify_absent_degrades(self):
        im = self._impl()   # 未注册 NOTIFY
        r = im.record_finding({"vuln_type": "RCE", "target": "http://t.com/rce",
                               "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                               "tool_log": [_http_call("http://t.com/rce", 200, "root" * 30)]})
        self.assertTrue(r["verified"])          # 登记成功，推送降级静默不影响

    # —— 出洞低于阈值不推 ——
    def test_notify_below_threshold_skipped(self):
        from sentinel_platform.modules.risk_intel import vuln_center as vc
        sent = {}
        class _Notify:
            def notify(self, message, **kw):
                sent["msg"] = message
                return {"ok": True}
        get_registry().register(ROLE.NOTIFY, _Notify())
        # min_severity 默认 medium；info 级漏洞不推
        im = self._impl()
        im.record_finding({"vuln_type": "版本泄露", "target": "http://t.com/v",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                           "impact": "暴露版本号",
                           "tool_log": [_http_call("http://t.com/v", 200, "Server: nginx/1.2" * 5)]})
        self.assertNotIn("msg", sent)           # info 校准后 < medium 阈值，不推

    # —— 三来源混排：AI verified 进列表，lead 默认不进 ——
    def test_unified_list_only_verified(self):
        im = self._impl()
        tgt = "http://t.com/a"
        im.record_finding({"vuln_type": "RCE", "target": tgt,
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_http_call(tgt, 200, "root" * 30)]})
        im.record_finding({"vuln_type": "XSS", "target": "http://t.com/b",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                           "tool_log": []})   # lead
        from sentinel_platform.modules.risk_intel.vuln_center import list_unified_findings
        r = list_unified_findings(source="ai")
        names = [x["name"] for x in r["items"]]
        self.assertIn("RCE", names)
        self.assertNotIn("XSS", names)         # lead 默认不进漏洞中心

    # —— min_severity 阈值：默认 low 隐藏 info，但绝不误杀缺失/unknown 等级的 PoC 命中 ——
    def test_min_severity_hides_info_keeps_unknown_poc(self):
        im = self._impl()
        # AI: 一条 info（版本泄露校准）+ 一条 high（RCE），均 verified
        im.record_finding({"vuln_type": "版本泄露", "target": "http://t.com/ver",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                           "tool_log": [_http_call("http://t.com/ver", 200, "Server: nginx" * 10)]})
        im.record_finding({"vuln_type": "RCE", "target": "http://t.com/rce",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_http_call("http://t.com/rce", 200, "root" * 30)]})
        # PoC 命中：无 vuln_severity 字段（NPoC 插件常见）——绝不能被 min_severity 误杀
        from sentinel_platform.core.db import get_repo
        get_repo().collection("vuln").insert_one(
            {"plg_name": "struts2_rce", "vul_name": "Struts2 命令执行", "target": "http://t.com/s2",
             "save_date": "2026-07-08 10:00:00"})
        from sentinel_platform.modules.risk_intel.vuln_center import list_unified_findings
        # 默认 min_severity=low：info 版本泄露被隐藏
        r = list_unified_findings(min_severity="low")
        names = [x["name"] for x in r["items"]]
        self.assertIn("RCE", names)
        self.assertIn("Struts2 命令执行", names)   # 无 severity 字段的 PoC 命中保留（$nin 不误杀）
        self.assertNotIn("版本泄露", names)         # info 被 low 阈值隐藏
        # min_severity=info（“全部”）：info 也回来
        r2 = list_unified_findings(min_severity="info")
        self.assertIn("版本泄露", [x["name"] for x in r2["items"]])

    # —— 标记误报后默认列表隐藏 ——
    def test_mark_false_positive_hidden(self):
        im = self._impl()
        tgt = "http://t.com/a"
        r = im.record_finding({"vuln_type": "RCE", "target": tgt,
                               "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                               "tool_log": [_http_call(tgt, 200, "root" * 30)]})
        from sentinel_platform.modules.risk_intel.vuln_center import mark_unified, list_unified_findings
        n = mark_unified("ai", [r["id"]], "false_positive", handle_by="tester")
        self.assertEqual(n, 1)
        self.assertEqual(list_unified_findings(source="ai")["total"], 0)   # 默认藏误报

    # —— 统计：verified vs leads 分开计 ——
    def test_finding_stat(self):
        im = self._impl()
        im.record_finding({"vuln_type": "RCE", "target": "http://t.com/a",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_http_call("http://t.com/a", 200, "root" * 30)]})
        im.record_finding({"vuln_type": "XSS", "target": "http://t.com/b",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "tool_log": []})
        from sentinel_platform.modules.risk_intel.vuln_center import finding_stat
        st = finding_stat()
        self.assertEqual(st["ai"]["verified"], 1)
        self.assertEqual(st["ai"]["leads"], 1)


if __name__ == "__main__":
    unittest.main()
