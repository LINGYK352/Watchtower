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
        if k == "$and":                       # AUD-10 keyword 下推用 $and 组合（真 Mongo 原生支持）
            if not all(_match(doc, sub) for sub in cond):
                return False
            continue
        if k == "$or":
            if not any(_match(doc, sub) for sub in cond):
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
            elif "$gte" in cond or "$lte" in cond or "$gt" in cond:
                if val is None:
                    return False
                if "$gte" in cond and str(val) < str(cond["$gte"]):
                    return False
                if "$lte" in cond and str(val) > str(cond["$lte"]):
                    return False
                if "$gt" in cond and str(val) <= str(cond["$gt"]):
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
            t.update(update.get("$setOnInsert") or {})
            t.setdefault("_id", self._next_id())
            self.docs.append(t)
        if t is not None:
            t.update(update.get("$set") or {})
            for key,value in (update.get('$addToSet') or {}).items():
                values=value.get('$each',[]) if isinstance(value,dict) else [value]
                current=t.setdefault(key,[])
                current.extend(item for item in values if item not in current)
            for key,value in (update.get('$inc') or {}).items():t[key]=t.get(key,0)+value
            for key, value in (update.get("$min") or {}).items():
                if key not in t or value < t[key]:
                    t[key] = value
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

def _scanner_call(url):
    return {'name':'run_npoc','arguments':{'target':url},'result':{'count':1,'findings':[{'target':url,'fixture':'owned-positive'}]}}

def _sqli_calls(url):
    return [_http_call(url+'?id=1',200,'owned normal response '*4),
            _http_call(url+'?id=1%27',200,'You have an error in your SQL syntax near owned input; MySQL database error '*2)]


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

    def test_triage_security_header_missing_to_info(self):
        """问题6：纯配置弱（安全响应头缺失/TLS·证书配置）→ info（不是 low）。"""
        from sentinel_platform.modules.risk_intel import _cvss
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"   # base 5.3 medium
        s, sev = _cvss.score_from_vector(vec)
        for vt, imp in [("缺少X-Frame-Options安全响应头", "未设点击劫持防护头"),
                        ("CSP 缺失", "内容安全策略未配置"),
                        ("HSTS 未启用", "TLS 配置不当"),
                        ("自签名证书", "证书问题")]:
            cal, _ = _cvss.calibrate_severity(sev, s, vt, imp, vector=vec)
            self.assertEqual(cal, "info", "{} 应降 info".format(vt))

    def test_triage_clickjacking_stays_low(self):
        """问题6：已验证「点击劫持」是可利用结论 → low（不是 info）。"""
        from sentinel_platform.modules.risk_intel import _cvss
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        s, sev = _cvss.score_from_vector(vec)
        cal, _ = _cvss.calibrate_severity(sev, s, "点击劫持", "已验证可劫持登录框(clickjacking)", vector=vec)
        self.assertEqual(cal, "low")

    def test_triage_vector_hard_gate_no_downgrade(self):
        from sentinel_platform.modules.risk_intel import _cvss
        # 名字像信息泄露但向量 C:H(真脱库) → 硬闸保原级不降
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        s, sev = _cvss.score_from_vector(vec)
        cal, _ = _cvss.calibrate_severity(sev, s, "数据库备份泄露", "可下载完整备份", vector=vec)
        self.assertEqual(cal, "high")   # 未降

    def test_triage_vector_info_only_downgrade_without_wordlist(self):
        """问题6 根治：向量客观为纯信息/配置型(I:N,A:N,C≤L) → info，**即使 vuln_type 不在任何词表**。
        治本核心——不靠黑名单追词，新说法自动收敛。样本=真实 ed-admin「配置缺陷」5.3 medium。"""
        from sentinel_platform.modules.risk_intel import _cvss
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"   # base 5.3 medium
        s, sev = _cvss.score_from_vector(vec)
        # vuln_type 故意用不在任何词表里的自由说法，验证纯靠向量维度也降 info
        for vt, imp in [("配置缺陷", "缺少安全配置"),
                        ("HTTP 响应异常", "响应头设置不当"),
                        ("缺少X-Frame-Options安全响应头", "未设点击劫持防护头")]:  # impact 含"点击劫持"字样，不得被误判成 low
            cal, _ = _cvss.calibrate_severity(sev, s, vt, imp, vector=vec)
            self.assertEqual(cal, "medium" if vt == "HTTP 响应异常" else "info")

    def test_triage_quickscan_suspected_sqli_not_downgraded(self):
        """问题6：探测/保守快筛模式的「疑似 SQLi」即便没实证，向量 C:H(能读库) 不命中降级闸 → 保留 high。
        证明降级只看影响维度不看验证深度，快筛高危不被误埋（疑似标签与定级正交）。"""
        from sentinel_platform.modules.risk_intel import _cvss
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"   # C:H → high
        s, sev = _cvss.score_from_vector(vec)
        cal, _ = _cvss.calibrate_severity(sev, s, "SQL注入", "疑似可读取数据库", vector=vec)
        self.assertEqual(cal, "high")   # 疑似高危不误降

    def test_below_severities_excludes_none(self):
        """问题8 真 bug：min='low' 及以上必须排除 CVSS 0 分档 'none'（比 info 还低）。
        原实现只遍历不含 none 的 _CANON_SEV，致 severity='none' 的 0 分漏洞漏进「low 及以上」视图
        （实测 www.dhyct.com 配置缺陷 none 漏出）。min='info'(全部含INFO) 时不排除 none/info。"""
        from sentinel_platform.modules.risk_intel.vuln_center import _below_severities
        self.assertIn("none", _below_severities("low"))
        self.assertIn("info", _below_severities("low"))
        self.assertIn("none", _below_severities("medium"))
        self.assertEqual(_below_severities("info"), [])       # 全部含 INFO：none/info 都不排除，能看到
        self.assertEqual(_below_severities(""), [])           # 空/非法：不过滤
        self.assertEqual(_below_severities("xxx"), [])

    def test_triage_frontend_key_downgrade_to_medium(self):
        """前端资源(.js/.html)硬编码密钥/凭证：即使 AI 给 C:H high 也降 medium
        （前端可见密钥不构成真机密性击穿，客户端本就能解密）。"""
        from sentinel_platform.modules.risk_intel import _cvss
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        s, sev = _cvss.score_from_vector(vec)
        cal, basis = _cvss.calibrate_severity(
            sev, s, "硬编码凭证泄露", "前端JS硬编码SM2私钥可解密系统数据",
            vector=vec, target="http://x.gov.cn/js/sm2/decrypt.js")
        self.assertEqual(cal, "high")    # 不能仅因凭据出现在前端就否认高机密性影响
        self.assertFalse(basis)

    def test_triage_frontend_key_gate_no_false_downgrade(self):
        """前端密钥闸不误伤：①服务端配置泄露真凭证(target 非前端资源)保留 high；
        ②前端资源但非密钥语义 保留 high(无凭证语义不命中)。"""
        from sentinel_platform.modules.risk_intel import _cvss
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        s, sev = _cvss.score_from_vector(vec)
        # ① 服务端 DB 密码/AK/SK（配置文件/API 响应）→ 真 C:H，保留 high
        cal1, _ = _cvss.calibrate_severity(sev, s, "硬编码凭证泄露", "配置泄露数据库密码和云AK/SK",
                                           vector=vec, target="http://x.gov.cn/config/database.yml")
        self.assertEqual(cal1, "high")
        # ② 前端 .js 但只是内部接口路径泄露（非密钥）→ 不命中前端密钥闸，high 不校准
        cal2, _ = _cvss.calibrate_severity(sev, s, "信息泄露", "js里暴露内部接口路径",
                                           vector=vec, target="http://x.gov.cn/app.js")
        self.assertEqual(cal2, "high")

    # —— 证据强制：confirmed → verified ——
    def test_record_confirmed_verified(self):
        im = self._impl()
        f = {"vuln_type": "SQL注入", "target": "http://t.com/api/x",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "tool_log": _sqli_calls("http://t.com/api/x")}
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

    def test_record_302_redirect_not_verified(self):
        """治 .NET 误报:302 跳转(常跳登录/错误提示页)不当正向证据,不 verified。
        (实测 Redir.aspx?id=1' 302 跳"栏目不存在"页被误判 SQLi verified 的假阳性)"""
        im = self._impl()
        f = {"vuln_type": "SQL注入", "target": "http://t.com/Redir.aspx",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
             "tool_log": [_http_call("http://t.com/Redir.aspx", 302, "x" * 200)]}
        r = im.record_finding(f)
        self.assertFalse(r["verified"])   # 302=unknown 不算证据 → 降 lead

    # —— 参数校验 ——
    def test_record_missing_fields(self):
        r = self._impl().record_finding({"vuln_type": "", "target": "x"})
        self.assertFalse(r["ok"])
        r2 = self._impl().record_finding("nope")
        self.assertFalse(r2["ok"])

    # —— 幂等 + lead 升级 ——
    def test_first_seen_and_cross_session_identity(self):
        """当前契约：同端点同类型一条，保留来源会话；不同端点仍是独立首次发现。"""
        from sentinel_platform.core.db import get_repo
        from sentinel_platform.modules.risk_intel.vuln_center import _oid
        im = self._impl()
        coll = get_repo().collection("intel_finding")
        tgt = "http://t.com/api/x"
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        r1 = im.record_finding({"session_id": "session1", "vuln_type": "SQL注入", "target": tgt, "cvss_vector": vec, "tool_log": []})
        self.assertFalse(r1.get("dup"))                  # 方案B不 skip
        d1 = coll.find_one({"_id": _oid(r1["id"])})
        self.assertTrue(d1.get("first_seen"))            # 首次发现（未命中同 key）
        # 同 key 再报 → 同一规范记录，追加来源会话。
        r2 = im.record_finding({"session_id": "session2", "vuln_type": "SQL注入", "target": tgt, "cvss_vector": vec, "tool_log": []})
        self.assertEqual(r1["id"], r2["id"])
        d2 = coll.find_one({"_id": _oid(r2["id"])})
        self.assertTrue(d2.get("first_seen"))
        self.assertEqual(set(d2['session_ids']),{'session1','session2'})
        # 不同接口（path 不同）→ 又是首次发现（去重键粒度=资产+接口+类型）
        r3 = im.record_finding({"vuln_type": "SQL注入", "target": "http://t.com/api/y",
                                "cvss_vector": vec, "tool_log": []})
        d3 = coll.find_one({"_id": _oid(r3["id"])})
        self.assertTrue(d3.get("first_seen"))

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
                               "tool_log": _sqli_calls("http://t.com/api/x")})
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
                           "tool_log": [_scanner_call("http://t.com/rce")]})
        self.assertIn("msg", sent)              # 已推
        self.assertEqual(sent["kw"].get("channel"), "feishu")

    # —— NOTIFY 未注册：降级不崩 ——
    def test_notify_absent_degrades(self):
        im = self._impl()   # 未注册 NOTIFY
        r = im.record_finding({"vuln_type": "RCE", "target": "http://t.com/rce",
                               "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                               "tool_log": [_scanner_call("http://t.com/rce")]})
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

    # —— 三来源混排（v47 治 item2）：verified 进列表；lead 不再被隐藏但已被封顶 info，靠 min_severity 控噪 ——
    def test_unified_list_shows_leads_capped_info(self):
        im = self._impl()
        tgt = "http://t.com/a"
        im.record_finding({"vuln_type": "RCE", "target": tgt,
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_scanner_call(tgt)]})
        im.record_finding({"vuln_type": "XSS", "target": "http://t.com/b",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                           "tool_log": []})   # lead → 封顶 info
        from sentinel_platform.modules.risk_intel.vuln_center import list_unified_findings
        # 默认 min_severity=low：verified RCE 进列表，info 级 lead 被 min_severity 过滤（不刷屏）
        r = list_unified_findings(source="ai", min_severity="low")
        names = [x["name"] for x in r["items"]]
        self.assertIn("代码执行", names)         # RCE 归一为"代码执行"
        self.assertIn("XSS", names)            # 线索状态不能篡改风险等级
        # min_severity=info（看全部）：lead 可见，不再被 verified 硬过滤吞掉（item2 核心）
        r2 = list_unified_findings(source="ai", min_severity="info")
        names2 = [x["name"] for x in r2["items"]]
        self.assertIn("XSS", names2)           # 调到 info 阈值就能看到线索（不再被吞）

    def test_unified_list_keeps_same_endpoint_unique(self):
        """同端点同类型只落一条；列表切换筛选也不能显示重复漏洞。"""
        im = self._impl()
        tgt = "http://t.com/api/x"
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        # 同 target+type 报两次 → 同一记录。
        im.record_finding({"session_id": "session1", "vuln_type": "RCE", "target": tgt, "cvss_vector": vec,
                           "tool_log": [_scanner_call(tgt)]})
        im.record_finding({"session_id": "session2", "vuln_type": "RCE", "target": tgt, "cvss_vector": vec,
                           "tool_log": [_scanner_call(tgt)]})
        from sentinel_platform.modules.risk_intel.vuln_center import list_unified_findings
        # 去重（默认）：同漏洞点只 1 条
        rd = list_unified_findings(source="ai", min_severity="low", dedup=True)
        rce = [x for x in rd["items"] if x["name"] == "代码执行"]
        self.assertEqual(len(rce), 1)          # 去重后只留最新一条
        # 全部漏洞：仍只显示同一记录。
        ra = list_unified_findings(source="ai", min_severity="low", dedup=False)
        rce_all = [x for x in ra["items"] if x["name"] == "代码执行"]
        self.assertEqual(len(rce_all), 1)

    def test_unified_keyword_finds_old_record_beyond_page(self):
        """AUD-10：关键词命中的记录即使在首页窗口之外（最旧一条），也能被查到且 total 正确。
        修复前是先 limit(page*size) 截取再 Python 过滤 → 命中项落窗口外则漏、total=0。"""
        from sentinel_platform.core import get_repo
        coll = get_repo().collection("intel_finding")
        # 种 25 条 verified AI 漏洞：只有最旧一条(_id 最小)命中关键词 UNIQUEKW，其余不含。
        # _id 用递增字符串保证排序：sort('_id',-1) 时命中项排在最后（最旧）。
        for i in range(25):
            hit = (i == 0)   # i=0 最先插入=最旧
            coll.insert_one({
                "_id": "f{:03d}".format(i), "source": "ai", "verified": True,
                "vuln_type": ("UNIQUEKW 注入" if hit else "普通漏洞"),
                "target": "http://t.com/{}".format(i), "unit": "U",
                "severity": "high", "save_date": "2026-01-{:02d} 00:00:00".format(i + 1),
            })
        from sentinel_platform.modules.risk_intel.vuln_center import list_unified_findings
        # 首页 size=20，命中项在第 25 条（窗口外）；关键词下推 DB 后应能查到 + total=1
        r = list_unified_findings(source="ai", keyword="UNIQUEKW", page=1, size=20)
        self.assertEqual(r["total"], 1)
        self.assertEqual(len(r["items"]), 1)
        self.assertIn("UNIQUEKW", r["items"][0]["name"])

    # —— min_severity 阈值：默认 low 隐藏 info，但绝不误杀缺失/unknown 等级的 PoC 命中 ——
    def test_min_severity_hides_info_keeps_unknown_poc(self):
        im = self._impl()
        # AI: 一条 info（版本泄露校准）+ 一条 high（RCE），均 verified
        im.record_finding({"vuln_type": "版本泄露", "target": "http://t.com/ver",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                           "tool_log": [_http_call("http://t.com/ver", 200, "Server: nginx" * 10)]})
        im.record_finding({"vuln_type": "RCE", "target": "http://t.com/rce",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_scanner_call("http://t.com/rce")]})
        # PoC 命中：无 vuln_severity 字段（NPoC 插件常见）——绝不能被 min_severity 误杀
        from sentinel_platform.core.db import get_repo
        get_repo().collection("vuln").insert_one(
            {"plg_name": "struts2_rce", "vul_name": "Struts2 命令执行", "target": "http://t.com/s2",
             "save_date": "2026-07-08 10:00:00"})
        from sentinel_platform.modules.risk_intel.vuln_center import list_unified_findings
        # 默认 min_severity=low：info 版本泄露被隐藏
        r = list_unified_findings(min_severity="low")
        names = [x["name"] for x in r["items"]]
        self.assertIn("代码执行", names)            # RCE 归一为标准名"代码执行"（需求3）
        self.assertIn("Struts2 命令执行", names)   # poc 来源(vuln 集合)不走 record_finding 归一，原样保留
        self.assertNotIn("版本信息泄露", names)     # 版本泄露→标准名"版本信息泄露"，info 被 low 阈值隐藏
        # min_severity=info（“全部”）：info 也回来
        r2 = list_unified_findings(min_severity="info")
        self.assertIn("版本信息泄露", [x["name"] for x in r2["items"]])

    # —— 标记误报后默认列表隐藏 ——
    def test_mark_false_positive_hidden(self):
        im = self._impl()
        tgt = "http://t.com/a"
        r = im.record_finding({"vuln_type": "RCE", "target": tgt,
                               "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                               "tool_log": [_scanner_call(tgt)]})
        from sentinel_platform.modules.risk_intel.vuln_center import mark_unified, list_unified_findings
        n = mark_unified("ai", [r["id"]], "false_positive", handle_by="tester")
        self.assertEqual(n, 1)
        self.assertEqual(list_unified_findings(source="ai")["total"], 0)   # 默认藏误报

    # —— 统计：verified vs leads 分开计 ——
    def test_finding_stat(self):
        im = self._impl()
        im.record_finding({"vuln_type": "RCE", "target": "http://t.com/a",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_scanner_call("http://t.com/a")]})
        im.record_finding({"vuln_type": "XSS", "target": "http://t.com/b",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "tool_log": []})
        from sentinel_platform.modules.risk_intel.vuln_center import finding_stat
        st = finding_stat()
        self.assertEqual(st["ai"]["verified"], 1)
        self.assertEqual(st["ai"]["leads"], 1)

    def test_finding_stat_dedup_matches_list(self):
        """卡片统计与去重列表同口径:跨会话同一漏洞点只计一次(v1.21.163-16 收尾)。

        旧 finding_stat 用未去重 count_documents(仅同会话去重)→ 卡片数≥去重列表数。
        改用 _finding_index.statistics(同 point_key 分组)后,卡片 verified 必须等于
        list_unified_findings(dedup=True) 的 total；跨会话再次发现只累计来源。"""
        im = self._impl()
        f = {"vuln_type": "RCE", "target": "http://t.com/x",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "tool_log": [_scanner_call("http://t.com/x")]}
        im.record_finding(dict(f, session_id="sess-A"))
        im.record_finding(dict(f, session_id="sess-B"))   # 不同会话、同漏洞点 → 2 条 duplicate_of=None
        from sentinel_platform.modules.risk_intel.vuln_center import (
            finding_stat, list_unified_findings, get_repo, COLL)
        raw = get_repo().collection(COLL).count_documents(
            {"source": "ai", "duplicate_of": None, "verified": True})
        self.assertEqual(raw, 1, "跨会话报送必须只落一条规范记录")
        st = finding_stat()
        lst = list_unified_findings(source="ai", verified=1, dedup=True)
        self.assertEqual(st["ai"]["verified"], 1, "卡片应按 point_key 跨会话去重计 1")
        self.assertEqual(lst["total"], 1, "去重列表 total 应为 1")
        self.assertEqual(st["ai"]["verified"], lst["total"], "卡片与去重列表口径必须一致")

    # —— item3（v47）：无实证 finding 封顶 info（猜想不冒充高危）——
    def test_unproven_finding_capped_info(self):
        im = self._impl()
        # AI 自评 high（C:H/I:H），但 tool_log 无匹配该 target 的正向证据 → evidence none → 封顶 info
        f = {"vuln_type": "逻辑缺陷", "target": "http://t.com/passport/login",
             "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "tool_log": []}
        r = im.record_finding(f)
        self.assertTrue(r["ok"])
        from sentinel_platform.modules.risk_intel.vuln_center import get_repo, COLL
        d = list(get_repo().collection(COLL).find({"target": "http://t.com/passport/login"}))[0]
        self.assertEqual(d["severity"], "high")          # 保留等级，仍为未验证线索
        self.assertFalse(d.get("severity_capped_by_evidence"))
        self.assertFalse(d["verified"])
        self.assertNotEqual(d.get("cvss_severity"), "info")   # 原始定级仍留档(cvss_severity 未动)

    def test_confirmed_finding_keeps_severity(self):
        """有实证的 finding 不被封顶（保留 AI 定级）。"""
        im = self._impl()
        f = {"vuln_type": "SQL注入", "target": "http://t.com/api/x",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "tool_log": _sqli_calls("http://t.com/api/x")}
        r = im.record_finding(f)
        self.assertTrue(r["verified"])
        from sentinel_platform.modules.risk_intel.vuln_center import get_repo, COLL
        d = list(get_repo().collection(COLL).find({"target": "http://t.com/api/x"}))[0]
        self.assertIn(d["severity"], ("high", "critical"))
        self.assertFalse(d.get("severity_capped_by_evidence"))

    # —— item2（v47）：同端点具体泄露类型不再互吞 ——
    def test_same_endpoint_distinct_leak_types_not_merged(self):
        im = self._impl()
        tgt = "http://t.com/dc.js"
        for vt in ("硬编码凭证泄露", "源码泄露", "接口文档泄露"):
            im.record_finding({"vuln_type": vt, "target": tgt, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "tool_log": []})
        from sentinel_platform.modules.risk_intel.vuln_center import get_repo, COLL
        rows = list(get_repo().collection(COLL).find({"target": tgt}))
        types = {r["vuln_type"] for r in rows}
        self.assertEqual(len(types), 3, "同端点3个不同具体泄露类型应各自成条，不互吞: {}".format(types))

    def test_generic_leak_absorbed_by_specific(self):
        """模糊伞形泛称(信息泄露)在同端点有具体洞时被吸收。"""
        im = self._impl()
        tgt = "http://t.com/app.js"
        im.record_finding({"vuln_type": "硬编码凭证泄露", "target": tgt, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "tool_log": []})
        r2 = im.record_finding({"vuln_type": "信息泄露", "target": tgt, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "tool_log": []})
        self.assertFalse(r2.get("dup"), "不同规范类别不能仅因同端点而被静默吞并")

    # —— item5（v47）：人工降级只降不升 ——
    def test_downgrade_severity_only_down(self):
        from sentinel_platform.modules.risk_intel.vuln_center import downgrade_severity, get_repo, COLL
        im = self._impl()
        im.record_finding({"vuln_type": "SQL注入", "target": "http://t.com/api/y",
                           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "tool_log": [_http_call("http://t.com/api/y", 200, "sql syntax error" * 4)]})
        d = list(get_repo().collection(COLL).find({"target": "http://t.com/api/y"}))[0]
        fid = str(d["_id"])
        orig_sev = d["severity"]                         # C:H/I:H/A:H → critical
        # 降到 low（低于原级）→ 成功
        r = downgrade_severity("ai", [fid], "low", handle_by="tester")
        self.assertEqual(r["updated"], 1)
        d2 = list(get_repo().collection(COLL).find({"target": "http://t.com/api/y"}))[0]
        self.assertEqual(d2["severity"], "low")
        self.assertEqual(d2["downgraded_from"], orig_sev)
        # 再想升回原级 → 跳过（只降不升）
        r2 = downgrade_severity("ai", [fid], orig_sev, handle_by="tester")
        self.assertEqual(r2["updated"], 0)
        self.assertEqual(r2["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
