"""risk_intel/attack_chain 单测 —— core 内存替身，不需真 Mongo / 不需 bson。

覆盖：register 字符串键、record_step 新建/追加/幂等去重/跨会话标记、P6 证据约束（无实打拒绝/
有实打放行/空 tool_log 跳过）、read_chains 接力简表、list 分页禁硬限制、get/delete/stat、
链危害回传 best-effort（FINDING 无门面跳过不崩）。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.registry import reset_registry


def _match(doc, query):
    for k, v in (query or {}).items():
        if k == "_id" and isinstance(v, dict) and "$in" in v:
            if doc.get("_id") not in v["$in"]:
                return False
        elif doc.get(k) != v:
            return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
        self._docs.sort(key=lambda d: d.get(key, 0), reverse=(direction < 0))
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
        self._n = 0

    def find_one(self, query, projection=None):
        for d in self.docs:
            if _match(d, query):
                return d
        return None

    def find(self, query=None, projection=None):
        return _Cursor([d for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "c{}".format(self._n))
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    def update_one(self, query, update, upsert=False):
        t = self.find_one(query)
        if t is not None:
            t.update(update.get("$set") or {})
        return type("R", (), {"modified_count": 1 if t else 0})()

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


def _tl(url):
    """构造一条命中该 url 的 tool_log（P6 实打证据）。"""
    return [{"name": "http_request", "arguments": {"url": url}, "result": "{}"}]


class AttackChainTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        set_repo(_Repo())

    def tearDown(self):
        reset_repo()
        reset_registry()

    def _impl(self):
        from sentinel_platform.modules.risk_intel.attack_chain import AttackChainServiceImpl
        return AttackChainServiceImpl()

    # —— register 字符串键 ——
    def test_register_string_key(self):
        from sentinel_platform.modules.risk_intel.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get("attack_chain_service")
        self.assertIsNotNone(svc)
        for m in ("record_step", "read_chains", "list_chains", "get_chain", "delete_chains", "stat"):
            self.assertTrue(hasattr(svc, m))

    # —— record_step 必填校验 ——
    def test_record_missing(self):
        self.assertIn("error", self._impl().record_step("", "t", "a"))
        self.assertIn("error", self._impl().record_step("u", "", "a"))
        self.assertIn("error", self._impl().record_step("u", "t", ""))

    # —— 新建链 ——
    def test_record_create(self):
        r = self._impl().record_step("ACME", "链A", "JS泄露内网域名", result="found intranet", severity="low")
        self.assertEqual(r["action"], "created")
        self.assertEqual(r["step_count"], 1)

    # —— 追加环节 + max_severity 取高 ——
    def test_record_append_and_maxsev(self):
        im = self._impl()
        im.record_step("ACME", "链A", "step1", severity="low")
        r = im.record_step("ACME", "链A", "step2 SSRF打内网", severity="high")
        self.assertEqual(r["action"], "appended")
        self.assertEqual(r["step_count"], 2)
        d = im.get_chain(r["chain_id"])
        self.assertEqual(d["max_severity"], "high")   # 取高

    # —— 幂等去重：同 action+target 不重复追加 ——
    def test_record_dedup(self):
        im = self._impl()
        im.record_step("ACME", "链A", "step1", target="http://a.com/x")
        r = im.record_step("ACME", "链A", "step1", target="http://a.com/x")
        self.assertEqual(r["action"], "skipped(dup)")
        self.assertEqual(r["step_count"], 1)

    # —— 跨会话延续标记 ——
    def test_cross_session(self):
        im = self._impl()
        im.record_step("ACME", "链A", "s1", session_id="sess1")
        r = im.record_step("ACME", "链A", "s2", session_id="sess2")
        d = im.get_chain(r["chain_id"])
        self.assertTrue(d["cross_session"])
        self.assertEqual(sorted(d["sessions"]), ["sess1", "sess2"])

    # —— P6 证据约束：声明 target + tool_log 无实打 → 拒绝 ——
    def test_p6_no_evidence_rejected(self):
        r = self._impl().record_step("ACME", "链A", "打后台", target="http://a.com/admin",
                                     tool_log=_tl("http://b.com/other"))   # tool_log 打的是别的 host
        self.assertIn("error", r)
        self.assertIn("实打证据", r["error"])

    # —— P6：有实打证据 → 放行 ——
    def test_p6_with_evidence_ok(self):
        r = self._impl().record_step("ACME", "链A", "打后台", target="http://a.com/admin",
                                     tool_log=_tl("http://a.com/admin"))
        self.assertEqual(r["action"], "created")

    # —— P6：空 tool_log 跳过校验（其他入口）——
    def test_p6_empty_toollog_skips(self):
        r = self._impl().record_step("ACME", "链A", "打后台", target="http://a.com/admin", tool_log=None)
        self.assertEqual(r["action"], "created")

    # —— read_chains 接力简表 ——
    def test_read_chains(self):
        im = self._impl()
        im.record_step("ACME", "链A", "step1 泄露", severity="low")
        im.record_step("ACME", "链B", "step1 越权", severity="high")
        r = im.read_chains("ACME")
        self.assertEqual(r["count"], 2)
        self.assertIn("outline", r["chains"][0])
        # 另一单位不串
        self.assertEqual(im.read_chains("OTHER")["count"], 0)

    # —— list 分页 + 禁硬限制（size 透传大值不砍）——
    def test_list_no_hard_limit(self):
        im = self._impl()
        for i in range(25):
            im.record_step("ACME", "链{}".format(i), "step")
        r = im.list_chains(size=1000)
        self.assertEqual(r["size"], 1000)
        self.assertEqual(r["total"], 25)
        self.assertEqual(len(r["items"]), 25)

    def test_list_filter_unit(self):
        im = self._impl()
        im.record_step("ACME", "链A", "s")
        im.record_step("OTHER", "链B", "s")
        self.assertEqual(im.list_chains(unit="ACME")["total"], 1)

    # —— stat ——
    def test_stat(self):
        im = self._impl()
        im.record_step("ACME", "链A", "s1", session_id="x")
        im.record_step("ACME", "链A", "s2", session_id="y", severity="critical")  # 跨会话
        im.record_step("ACME", "链B", "s", severity="low")
        st = im.stat("ACME")
        self.assertEqual(st["total"], 2)
        self.assertEqual(st["cross_session"], 1)
        self.assertEqual(st["by_severity"]["critical"], 1)

    # —— delete 批量 ——
    def test_delete(self):
        im = self._impl()
        c1 = im.record_step("ACME", "链A", "s")["chain_id"]
        c2 = im.record_step("ACME", "链B", "s")["chain_id"]
        r = im.delete_chains([c1, c2])
        self.assertTrue(r["ok"])
        self.assertEqual(r["deleted"], 2)
        self.assertEqual(im.list_chains()["total"], 0)

    def test_delete_empty(self):
        r = self._impl().delete_chains([])
        self.assertFalse(r["ok"])

    # —— 链危害回传 best-effort：FINDING 无 apply_chain_severity 门面 → 跳过不崩 ——
    def test_propagate_finding_no_method_ok(self):
        # 注册一个没有 apply_chain_severity 的 FINDING（模拟当前 vuln_center）
        get_registry().register(ROLE.FINDING, object())
        r = self._impl().record_step("ACME", "链A", "s", severity="high")
        self.assertEqual(r["action"], "created")   # 不因 finding 无门面而崩

    # —— 链危害回传 best-effort：FINDING 有门面 → 被调 ——
    def test_propagate_finding_with_method(self):
        called = {}

        class _F:
            def apply_chain_severity(self, title, chain_severity, steps):
                called["title"] = title
                called["sev"] = chain_severity
                return 3
        get_registry().register(ROLE.FINDING, _F())
        self._impl().record_step("ACME", "链A", "越权读全量", severity="critical")
        self.assertEqual(called.get("sev"), "critical")


if __name__ == "__main__":
    unittest.main()
