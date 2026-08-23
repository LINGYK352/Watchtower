"""risk_intel/asset_intel 单测 —— core 内存替身，不连真 Mongo。

覆盖：normalize_asset_key 去重铁律（剥www/补端口/剥path）、collect 幂等、upsert 二次叠加、
auto_collect 派发降级(PENTEST_DISPATCH 未建)/派发(注册假 dispatcher)、SYSTEM_TAGS 消费、
stat/list(禁硬限)/match/context、register 注册、降级。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        d = dict(doc); d.setdefault("_id", "o%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        out = []
        for d in self.docs:
            if self._ok(d, q):
                out.append(d)
        return out

    def _ok(self, d, q):
        for k, v in (q or {}).items():
            if k == "$or":
                if not any(self._ok(d, sub) for sub in v):
                    return False
            elif isinstance(v, dict):
                if "$gt" in v and not (d.get(_dig(d, k), 0) if False else _nested(d, k)) > v["$gt"]:
                    return False
                if "$in" in v and d.get(k) not in v["$in"]:
                    return False
                if "$regex" in v:
                    import re
                    if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                        return False
            elif "." in k:
                if _nested(d, k) != v:
                    return False
            elif d.get(k) != v:
                return False
        return True

    def find(self, q=None, proj=None):
        return _Cursor(self._match(q))

    def find_one(self, q):
        m = self._match(q)
        return dict(m[0]) if m else None

    def update_one(self, q, update, upsert=False):
        m = self._match(q)
        if m:
            tgt = next(d for d in self.docs if d.get("_id") == m[0].get("_id"))
            tgt.update(update.get("$set", {}))
            for k, v in update.get("$addToSet", {}).items():
                tgt.setdefault(k, [])
                if v not in tgt[k]:
                    tgt[k].append(v)

    def delete_many(self, q):
        m = self._match(q)
        ids = {d.get("_id") for d in m}
        self.docs = [d for d in self.docs if d.get("_id") not in ids]
        return type("R", (), {"deleted_count": len(ids)})()


def _nested(d, dotted):
    cur = d
    for p in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


class _Cursor(list):
    def sort(self, *a, **k):
        return _Cursor(reversed(self))

    def skip(self, n):
        return _Cursor(list(self)[n:])

    def limit(self, n):
        return _Cursor(list(self)[:n])


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _MemColl())


class AssetIntelTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_register(self):
        from sentinel_platform.modules.risk_intel.register import register
        reg = get_registry(); register(reg)
        self.assertIsNotNone(reg.get(ROLE.INTEL))

    # —— 去重铁律 ——
    def test_normalize_asset_key(self):
        from sentinel_platform.modules.risk_intel.asset_intel import normalize_asset_key as nk
        self.assertEqual(nk("http://a.com/Home/Login"), "http://a.com:80")   # 剥 path
        self.assertEqual(nk("http://a.com"), "http://a.com:80")              # 补默认端口
        self.assertEqual(nk("https://a.com"), "https://a.com:443")
        self.assertEqual(nk("http://www.example.com"), "http://example.com:80")  # 剥 www
        self.assertEqual(nk("http://a.com:8080"), "http://a.com:8080")       # 非默认端口保留
        self.assertEqual(nk("mail.x.com"), "http://mail.x.com:80")           # 非 www 子域不剥
        self.assertEqual(nk(""), "")

    def _seed_task_sites(self, task_id="T1", n=2):
        from sentinel_platform.core import get_repo
        get_repo().collection("task").insert_one({"_id": task_id, "name": "任务A", "source": {"unit": "ACME"}})
        for i in range(n):
            get_repo().collection("site").insert_one({
                "task_id": task_id, "site": "http://s%d.a.com" % i, "hostname": "s%d.a.com" % i,
                "fld": "a.com", "title": "站点%d" % i, "finger": [{"name": "nginx"}], "status": 200})

    def test_collect_and_idempotent(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task, list_collection
        self._seed_task_sites(n=2)
        r1 = collect_from_task("T1")
        self.assertEqual(r1["site_total"], 2)
        self.assertEqual(r1["new_asset"], 2)
        self.assertEqual(len(r1["asset_keys"]), 2)
        # 再归集：幂等，不新增（same asset_key）
        r2 = collect_from_task("T1")
        self.assertEqual(r2["new_asset"], 0)
        self.assertEqual(list_collection("intel_asset")["total"], 2)   # 仍 2 条

    def test_collect_carries_unit(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task, list_collection
        self._seed_task_sites(n=1)
        collect_from_task("T1")
        asset = list_collection("intel_asset")["items"][0]
        self.assertEqual(asset["unit"], "ACME")   # 从 task.source.unit 带入

    def test_collect_missing_task_id(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task
        self.assertIn("error", collect_from_task(""))

    # —— SYSTEM_TAGS 消费 ——
    def test_system_name_via_system_tags(self):
        from sentinel_platform.modules.risk_intel.asset_intel import _pick_sys_name
        fake = type("S", (), {"pick_system_name": lambda self, a: "致远OA",
                              "extract_tags": lambda self, a: ["致远"]})()
        get_registry().register(ROLE.SYSTEM_TAGS, fake)
        self.assertEqual(_pick_sys_name(["seeyon"], "OA"), "致远OA")

    def test_system_name_degrades_without_tags_svc(self):
        from sentinel_platform.modules.risk_intel.asset_intel import _pick_sys_name
        self.assertEqual(_pick_sys_name(["nginx"], "t"), "nginx")   # 无 SYSTEM_TAGS → 首指纹
        self.assertEqual(_pick_sys_name([], ""), "未知系统")

    def test_report_tree(self):
        """BUG-014：report_tree 按 任务名>单位>资产 三级聚合，task_name 由 source_task_id 反查。"""
        from sentinel_platform.modules.risk_intel.asset_intel import report_tree
        from sentinel_platform.core import get_repo
        repo = get_repo()
        repo.collection("task").insert_one({"_id": "t1", "name": "任务A"})
        repo.collection("intel_report").insert_one({"_id": "r1", "source_task_id": "t1", "unit": "U1",
                                                     "asset_key": "http://a.com:80", "save_date": "2026-08-01"})
        repo.collection("intel_report").insert_one({"_id": "r2", "source_task_id": "t1", "unit": "U1",
                                                     "asset_key": "http://a.com:80", "save_date": "2026-08-02"})
        repo.collection("intel_report").insert_one({"_id": "r3", "source_task_id": "", "unit": "",
                                                     "asset_key": "", "save_date": "2026-08-03"})
        tree = report_tree()["tree"]
        by_name = {t["task_name"]: t for t in tree}
        self.assertIn("任务A", by_name)                              # task_id 反查出 name
        ta = by_name["任务A"]
        self.assertEqual(ta["report_cnt"], 2)
        self.assertEqual(ta["units"][0]["unit"], "U1")
        self.assertEqual(ta["units"][0]["assets"][0]["report_cnt"], 2)  # 同资产 2 份报告聚在一起
        self.assertIn("未分类任务", by_name)                          # 无 task_id → 未分类任务
        self.assertEqual(by_name["未分类任务"]["units"][0]["unit"], "未知单位")  # 空 unit → 未知单位

    # —— auto_collect 派发 ——
    def test_auto_collect_dispatch_degrades_without_pentest(self):
        from sentinel_platform.modules.risk_intel.asset_intel import auto_collect_after_scan
        from sentinel_platform.core import get_repo
        get_repo().collection("task").insert_one({"_id": "T2", "name": "x", "options": {"auto_pentest": True}})
        get_repo().collection("site").insert_one({"task_id": "T2", "site": "http://b.com", "hostname": "b.com", "fld": "b.com"})
        r = auto_collect_after_scan("T2")
        self.assertIsNone(r["dispatched"])
        self.assertIn("skipped", r)   # PENTEST_DISPATCH 未建，只归集不派发

    def test_auto_collect_dispatches_when_registered(self):
        from sentinel_platform.modules.risk_intel.asset_intel import auto_collect_after_scan
        from sentinel_platform.core import get_repo
        get_repo().collection("task").insert_one({"_id": "T3", "name": "x", "options": {"auto_pentest": True}})
        get_repo().collection("site").insert_one({"task_id": "T3", "site": "http://c.com", "hostname": "c.com", "fld": "c.com"})
        calls = []
        fake = type("D", (), {"batch_create_from_assets": lambda self, **kw: calls.append(kw) or {"created": 1}})()
        get_registry().register(ROLE.PENTEST_DISPATCH, fake)
        r = auto_collect_after_scan("T3")
        self.assertEqual(r["dispatched"], {"created": 1})
        self.assertEqual(len(calls), 1)

    def test_auto_collect_no_pentest_when_flag_off(self):
        from sentinel_platform.modules.risk_intel.asset_intel import auto_collect_after_scan
        from sentinel_platform.core import get_repo
        get_repo().collection("task").insert_one({"_id": "T4", "name": "x", "options": {"auto_pentest": False}})
        r = auto_collect_after_scan("T4")
        self.assertIsNone(r["dispatched"])

    # —— stat / list / match / context ——
    def test_stat(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task, stat
        self._seed_task_sites(n=2)
        collect_from_task("T1")
        s = stat()
        self.assertEqual(s["asset_total"], 2)
        self.assertGreaterEqual(s["system_total"], 1)

    def test_list_size_zero_all_no_hard_limit(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task, list_collection
        self._seed_task_sites(n=15)
        collect_from_task("T1")
        self.assertEqual(len(list_collection("intel_asset", size=0)["items"]), 15)

    def test_list_unknown_collection(self):
        from sentinel_platform.modules.risk_intel.asset_intel import list_collection
        self.assertIn("error", list_collection("intel_evil"))

    def test_match_and_context(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task, match_asset, build_pentest_context
        self._seed_task_sites(n=1)
        collect_from_task("T1")
        m = match_asset("http://s0.a.com/whatever")   # path 不影响匹配（去重键）
        self.assertIsNotNone(m)
        ctx = build_pentest_context(m["key"])
        self.assertEqual(ctx["identity"]["asset_key"], m["key"])
        # 不存在资产 → 身份空壳
        self.assertEqual(build_pentest_context("http://none:80")["identity"]["asset_key"], "http://none:80")

    def test_list_db_failure_degrades(self):
        from sentinel_platform.modules.risk_intel import asset_intel as ai

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        self.assertEqual(ai.list_collection("intel_asset")["total"], 0)
        self.assertEqual(ai.stat()["asset_total"], 0)



    # —— 指纹分层打法库 match/write/mark（intel_playbook，核心链路 §6.2）——
    def test_playbook_write_match_two_layer(self):
        from sentinel_platform.modules.risk_intel.asset_intel import (
            write_playbook, match_playbook)
        # Layer1 单组件 + Layer2 组合
        r1 = write_playbook(["spring-boot"], "actuator_unauth", method="/actuator/env 未授权", unit="U1")
        self.assertTrue(r1.get("ok"))
        self.assertFalse(r1.get("dup"))
        r2 = write_playbook(["spring-boot", "shiro"], "shiro_deser", method="rememberMe 反序列化", unit="U1")
        self.assertTrue(r2.get("ok"))
        # 重复写累计 seen_count
        self.assertTrue(write_playbook(["spring-boot"], "actuator_unauth", method="/actuator/env 未授权").get("dup"))
        # 目标指纹含 spring-boot + shiro → 两条都匹配（Layer2 组合基础分更高排前）
        pb = match_playbook(["spring-boot", "shiro", "nginx"])
        self.assertEqual(pb["count"], 2)
        self.assertIn("note", pb)
        self.assertEqual(pb["playbooks"][0]["vuln_type"], "shiro_deser")  # Layer2 基础分20 > Layer1 基础分10
        # 目标只有 spring-boot → 只匹配 Layer1（Layer2 要求 shiro 不满足）
        pb2 = match_playbook(["spring-boot"])
        self.assertEqual(pb2["count"], 1)
        self.assertEqual(pb2["playbooks"][0]["vuln_type"], "actuator_unauth")

    def test_playbook_effective_score_sort(self):
        from sentinel_platform.modules.risk_intel.asset_intel import (
            write_playbook, match_playbook, mark_playbook_useful)
        write_playbook(["tomcat"], "A", method="打法A")
        r = write_playbook(["tomcat"], "B", method="打法B")
        pid_b = r["playbook_id"]
        # B 出高危 +5 → 有效分升 → 排前
        mark_playbook_useful(playbook_id=pid_b, out_high=True)
        pb = match_playbook(["tomcat"])
        self.assertEqual(pb["playbooks"][0]["vuln_type"], "B")  # 有效分高排首

    def test_playbook_score_only_high_adds(self):
        """有效分（核心链路 §6.2）：只有出高危及以上 +5，其余一律不加分（不减）。"""
        from sentinel_platform.modules.risk_intel.asset_intel import (
            write_playbook, mark_playbook_useful)
        r = write_playbook(["nginx"], "V", method="M")
        pid = r["playbook_id"]
        # 高危：+5 且 useful_count+1
        res_high = mark_playbook_useful(playbook_id=pid, out_high=True)
        self.assertEqual(res_high["delta"], 5)
        self.assertEqual(res_high["effective_score"], 5)
        # 非高危：0 不加不减（不是负分）
        res_other = mark_playbook_useful(playbook_id=pid, out_high=False)
        self.assertEqual(res_other["delta"], 0)
        self.assertEqual(res_other["effective_score"], 5)   # 维持 5，不减

    def test_playbook_title_bonus(self):
        from sentinel_platform.modules.risk_intel.asset_intel import write_playbook, match_playbook
        write_playbook(["custom-cms"], "rce", method="上传", title="用友NC")
        # title 吻合 → 推荐分 +5
        pb = match_playbook(["custom-cms"], title="用友NC 后台管理系统")
        self.assertEqual(pb["count"], 1)
        base = 10  # Layer1
        self.assertEqual(pb["playbooks"][0]["recommend_score"], base + 5)  # +title辅助

    def test_playbook_empty_guards(self):
        from sentinel_platform.modules.risk_intel.asset_intel import (
            match_playbook, write_playbook, mark_playbook_useful)
        self.assertEqual(match_playbook([])["count"], 0)
        self.assertFalse(write_playbook([], "X").get("ok"))     # 无组件不能归档
        self.assertFalse(write_playbook(["a"], "").get("ok"))   # 无 vuln_type
        self.assertFalse(mark_playbook_useful(playbook_id="").get("ok"))

    # —— 报告情报查询 ——
    def test_query_unit_reports(self):
        from sentinel_platform.modules.risk_intel.asset_intel import save_pentest_report, query_unit_reports
        from sentinel_platform.core import get_repo
        get_repo().collection("intel_finding").insert_one(
            {"session_id": "S1", "target": "a.com", "vuln_type": "SQLi", "verified": True, "severity": "high"})
        save_pentest_report({"session_id": "S1", "unit": "U9", "asset_key": "http://a.com:80", "content": "## 漏洞"})
        r = query_unit_reports("U9")
        self.assertGreaterEqual(r["count"], 1)
        self.assertEqual(query_unit_reports("")["count"], 0)



    # —— 新 pipeline 写 SiteRec.url(非 site)也能归集(修字段不匹配漏归集全链路断) ——
    def test_collect_site_url_field(self):
        from sentinel_platform.modules.risk_intel.asset_intel import collect_from_task
        from sentinel_platform.core import get_repo
        # 模拟新 recon pipeline 落库的 site：只有 url 无 site 字段
        get_repo().collection("site").insert_one(
            {"task_id": "TU", "url": "http://45.33.32.156:80", "hostname": "45.33.32.156",
             "status": 200, "title": "ScanMe"})
        get_repo().collection("task").insert_one({"_id": __import__("bson").ObjectId() if False else "TU", "name": "t"})
        r = collect_from_task("TU")
        self.assertEqual(r["site_total"], 1)
        self.assertEqual(r["new_asset"], 1)                 # url 字段也归集成资产
        self.assertTrue(r["asset_keys"])                     # asset_key 非空(修前为空→0派发)


    def test_save_report_backfills_asset_pentested(self):
        from sentinel_platform.modules.risk_intel.asset_intel import save_pentest_report
        from sentinel_platform.core import get_repo
        repo=get_repo()
        repo.collection("intel_asset").insert_one({"key":"http://mk.com:80","pentest_status":"none","report_id":""})
        repo.collection("intel_finding").insert_one({"session_id":"SM","target":"mk.com","vuln_type":"X","verified":True,"severity":"high"})
        r=save_pentest_report({"session_id":"SM","unit":"U","asset_key":"http://mk.com:80","content":"## report"})
        self.assertTrue(r.get("ok"))
        a=repo.collection("intel_asset").find_one({"key":"http://mk.com:80"})
        self.assertEqual(a["pentest_status"],"done")     # 回填生效(治重复派发)
        self.assertTrue(a["report_id"])


class ReportDetailAndDeleteTest(unittest.TestCase):
    """#4/#5：渗透报告详情 get_report + 情报记录批量删除 delete_records（原缺→404）。"""
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_get_report_hit_and_miss(self):
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.risk_intel.asset_intel import get_report
        rid = get_repo().collection("intel_report").insert_one(
            {"title": "报告A", "content": "..."}).inserted_id
        d = get_report(str(rid))
        self.assertIsNotNone(d)
        self.assertEqual(d["title"], "报告A")
        self.assertIsNone(get_report("nonexistent-id-000"))
        self.assertIsNone(get_report(""))

    def test_delete_records(self):
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.risk_intel.asset_intel import delete_records
        coll = get_repo().collection("intel_asset")
        id1 = str(coll.insert_one({"key": "a"}).inserted_id)
        id2 = str(coll.insert_one({"key": "b"}).inserted_id)
        r = delete_records("intel_asset", [id1, id2])
        self.assertEqual(r.get("deleted"), 2)

    def test_delete_rejects_empty_and_unknown(self):
        from sentinel_platform.modules.risk_intel.asset_intel import delete_records
        self.assertIn("error", delete_records("intel_asset", []))        # 空 ids 拒绝
        self.assertIn("error", delete_records("bad_coll", ["x"]))         # 未知集合拒绝

    def test_is_valid_host(self):
        """host 校验：合法域名/IP 通过，中文单位名/FOFA 语句/含空格 拒绝（防被拼 http:// 造垃圾资产）。"""
        from sentinel_platform.modules.risk_intel.asset_intel import _is_valid_host
        for ok in ["www.example.com", "example.com", "http://oa.x.com",
                   "https://a.b.cn:8443/p", "1.2.3.4", "1.2.3.4:9090"]:
            self.assertTrue(_is_valid_host(ok), ok)
        for bad in ["上海禾赛科技有限公司", "http://上海禾赛科技有限公司",
                    'icp.name="上海禾赛科技有限公司"', "FOFA 目标 33", "", "  ", "has space here"]:
            self.assertFalse(_is_valid_host(bad), bad)

    def test_ensure_target_skips_non_host(self):
        """_ensure_target_as_asset 对中文单位名/FOFA 语句不归集（honest degrade），真域名/IP 正常归集。
        mock upsert_asset 记录被归集的 site（隔离 normalize_asset_key 的补端口细节）。"""
        from sentinel_platform.modules.risk_intel import asset_intel as ai
        collected = []
        orig = ai.upsert_asset
        ai.upsert_asset = lambda site_doc, **kw: (collected.append(site_doc.get("site")),
                                                  {"asset_key": site_doc.get("site"), "system_id": "", "is_new": True})[1]
        try:
            self.assertEqual(ai._ensure_target_as_asset("上海禾赛科技有限公司", "t1", {"name": "禾赛", "type": "unit"}), [])
            self.assertEqual(ai._ensure_target_as_asset('icp.name="x"', "t2", {"name": "f", "type": "fofa"}), [])
            self.assertEqual(collected, [])                               # 非 host 一个都没归集
            keys = ai._ensure_target_as_asset("oa.example.com", "t3", {"name": "d", "type": "domain"})
            self.assertEqual(keys, ["http://oa.example.com"])            # 真域名正常归集
            collected.clear()
            mixed = ai._ensure_target_as_asset("good.com\n上海禾赛科技有限公司\n1.2.3.4", "t4", {"name": "d", "type": "domain"})
            self.assertEqual(set(mixed), {"http://good.com", "http://1.2.3.4"})  # 混合只留合法 host
        finally:
            ai.upsert_asset = orig

    def test_auto_collect_unit_type_no_garbage_asset(self):
        """unit 任务归集 0 资产 + auto_pentest=True → 不把单位名当 host 造资产（本次负优化根治）。"""
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.risk_intel.asset_intel import auto_collect_after_scan
        repo = get_repo()
        tid = str(repo.collection("task").insert_one({
            "name": "禾赛", "type": "unit", "target": "上海禾赛科技有限公司",
            "options": {"auto_pentest": True}}).inserted_id)
        out = auto_collect_after_scan(tid)
        self.assertIsNone(out.get("dispatched"))                          # 未派发假目标
        self.assertIn("honest degrade", out.get("skipped", ""))           # 明确 honest degrade
        garbage = repo.collection("intel_asset").count_documents({"key": "http://上海禾赛科技有限公司"})
        self.assertEqual(garbage, 0)                                      # 无垃圾资产落库


if __name__ == "__main__":
    unittest.main()
