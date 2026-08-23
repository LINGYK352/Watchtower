"""task_plan/policy 单测 —— core 内存替身，不需真 Mongo / 不需 bson。

覆盖：register 字符串键、add(校验插件/端口/归一模式)、edit 深合并、delete、
list 分页(禁硬限制:size 透传)、get_options_by_policy_id 展开(task_tag 分支)、
端口语法校验、模式归一、缺字段错误。
"""
import re
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


def _match(doc, query):
    for k, cond in (query or {}).items():
        if k == "_id":
            if isinstance(cond, dict) and "$in" in cond:
                if doc.get("_id") not in cond["$in"]:
                    return False
            elif doc.get("_id") != cond:
                return False
        elif isinstance(cond, dict) and "$regex" in cond:
            flags = re.I if "i" in cond.get("$options", "") else 0
            if not re.search(cond["$regex"], str(doc.get(k, "")), flags):
                return False
        elif doc.get(k) != cond:
            return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
        self._docs.sort(key=lambda d: str(d.get(key, "")), reverse=(direction < 0))
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

    def _nid(self):
        self._n += 1
        return "pid{}".format(self._n)

    def find_one(self, query, projection=None):
        for d in self.docs:
            if _match(d, query):
                return d
        return None

    def find(self, query=None, projection=None):
        return _Cursor([d for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        doc.setdefault("_id", self._nid())
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


class PolicyTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        self.repo = _Repo()
        set_repo(self.repo)
        # seed 两个 poc 插件（add 校验插件存在用）
        self.repo.collection("poc").insert_one({"plugin_name": "weblogic_rce", "vul_name": "Weblogic RCE"})
        self.repo.collection("poc").insert_one({"plugin_name": "struts2_017", "vul_name": "Struts2 017"})

    def tearDown(self):
        reset_repo()
        reset_registry()

    def _impl(self):
        from sentinel_platform.modules.task_plan.policy import PolicyServiceImpl
        return PolicyServiceImpl()

    # —— register 字符串键 ——
    def test_register_string_key(self):
        from sentinel_platform.modules.task_plan.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get("policy_service")
        self.assertIsNotNone(svc)
        for m in ("list_policies", "add_policy", "edit_policy", "delete_policy", "get_options_by_policy_id"):
            self.assertTrue(hasattr(svc, m))

    # —— add：缺 name / 非法 policy ——
    def test_add_missing_name(self):
        self.assertFalse(self._impl().add_policy("", {})["ok"])

    # —— add：默认值填充 + 归一模式 ——
    def test_add_defaults_and_normalize(self):
        im = self._impl()
        r = im.add_policy("基础策略", {"pentest_mode": "REDTEAM", "scan_proxy": "proxy",
                                    "collect_mode": "single", "pentest_proxy": "on"})
        self.assertTrue(r["ok"])
        doc = self.repo.collection("policy").find_one({"_id": r["policy_id"]})
        pol = doc["policy"]
        self.assertEqual(pol["pentest_mode"], "redteam")
        self.assertEqual(pol["collect_mode"], "single")
        # 代理4模式重构：旧 scan_proxy=proxy → scan_egress.mode=global；pentest_proxy=on → pentest_egress.mode=global
        self.assertEqual(pol["scan_egress"]["mode"], "global")
        self.assertEqual(pol["pentest_egress"]["mode"], "global")
        self.assertNotIn("scan_proxy", pol)                 # 旧字段已废除
        self.assertNotIn("pentest_proxy", pol)
        self.assertTrue(pol["domain_config"]["domain_brute"])  # 默认值填充
        self.assertEqual(pol["ip_config"]["port_parallelism"], 32)  # 缺省透传

    # —— add：非法模式回落默认 ——
    def test_add_bad_mode_fallback(self):
        im = self._impl()
        r = im.add_policy("x", {"pentest_mode": "hacker", "collect_mode": "weird"})
        pol = self.repo.collection("policy").find_one({"_id": r["policy_id"]})["policy"]
        self.assertEqual(pol["pentest_mode"], "src")
        self.assertEqual(pol["collect_mode"], "multi_brute")

    # —— add：插件不存在报错 ——
    def test_add_unknown_plugin(self):
        r = self._impl().add_policy("x", {"poc_config": [{"plugin_name": "nonexist", "enable": True}]})
        self.assertFalse(r["ok"])
        self.assertIn("nonexist", r["error"])

    # —— add：插件存在则带出 vul_name + 去重 ——
    def test_add_valid_plugin_dedup(self):
        im = self._impl()
        r = im.add_policy("x", {"poc_config": [
            {"plugin_name": "weblogic_rce", "enable": True},
            {"plugin_name": "weblogic_rce", "enable": True},  # 重复
        ]})
        pol = self.repo.collection("policy").find_one({"_id": r["policy_id"]})["policy"]
        self.assertEqual(len(pol["poc_config"]), 1)
        self.assertEqual(pol["poc_config"][0]["vul_name"], "Weblogic RCE")

    # —— add：自定义端口非法 ——
    def test_add_bad_custom_port(self):
        r = self._impl().add_policy("x", {"ip_config": {"port_scan_type": "custom", "port_custom": "80,abc"}})
        self.assertFalse(r["ok"])
        self.assertIn("abc", r["error"])

    # —— add：排除端口非法 ——
    def test_add_bad_exclude_ports(self):
        r = self._impl().add_policy("x", {"ip_config": {"exclude_ports": "99999"}})
        self.assertFalse(r["ok"])

    # —— 端口语法工具 ——
    def test_port_helpers(self):
        from sentinel_platform.modules.task_plan.policy import build_port_custom, is_valid_exclude_ports
        self.assertEqual(build_port_custom("80,443,8000-9000"), ["80", "443", "8000-9000"])
        self.assertEqual(build_port_custom("80,bad"), "bad")
        self.assertTrue(is_valid_exclude_ports("22,3306,8000-9000"))
        self.assertFalse(is_valid_exclude_ports("9000-8000"))   # start>end
        self.assertFalse(is_valid_exclude_ports("70000"))       # 越界

    # —— list 分页：禁硬限制（size 透传大值不砍）——
    def test_list_pagination_no_hard_limit(self):
        im = self._impl()
        for i in range(25):
            im.add_policy("策略{}".format(i), {})
        r = im.list_policies(page=1, size=1000)    # 传大 size
        self.assertEqual(r["size"], 1000)          # 透传不砍
        self.assertEqual(r["total"], 25)
        self.assertEqual(len(r["items"]), 25)      # 全返（无硬上限）

    def test_list_name_filter(self):
        im = self._impl()
        im.add_policy("补天激进", {})
        im.add_policy("普通侦察", {})
        r = im.list_policies(name="补天")
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["name"], "补天激进")

    # —— edit：深合并 policy 子字段 ——
    def test_edit_merge(self):
        im = self._impl()
        pid = im.add_policy("x", {"auto_pentest": False})["policy_id"]
        r = im.edit_policy(pid, {"policy": {"auto_pentest": True}, "desc": "改了"})
        self.assertTrue(r["ok"])
        doc = self.repo.collection("policy").find_one({"_id": pid})
        self.assertTrue(doc["policy"]["auto_pentest"])
        self.assertEqual(doc["desc"], "改了")

    def test_edit_not_found(self):
        self.assertFalse(self._impl().edit_policy("nope", {"desc": "x"})["ok"])

    # —— delete 批量 ——
    def test_delete(self):
        im = self._impl()
        p1 = im.add_policy("a", {})["policy_id"]
        p2 = im.add_policy("b", {})["policy_id"]
        r = im.delete_policy([p1, p2])
        self.assertTrue(r["ok"])
        self.assertEqual(r["deleted"], 2)
        self.assertEqual(im.list_policies()["total"], 0)

    # —— get_options_by_policy_id：TASK 带域名/IP 配置 ——
    def test_get_options_task_tag(self):
        from sentinel_platform.core import models
        im = self._impl()
        pid = im.add_policy("x", {"file_leak": True, "auto_pentest": True,
                                  "scope_config": {"scope_id": "s1"}})["policy_id"]
        opts = im.get_options_by_policy_id(pid, models.TaskTag.TASK)
        self.assertEqual(opts["policy_name"], "x")
        self.assertIn("domain_brute", opts)      # 资产发现任务带域名配置
        self.assertIn("port_scan", opts)         # 带 IP 配置
        self.assertIn("site_identify", opts)     # 带 site 配置
        self.assertTrue(opts["file_leak"])       # 顶层项
        self.assertEqual(opts["related_scope_id"], "s1")

    # —— get_options：非 TASK tag 不带域名/IP，但带 site + 顶层 ——
    def test_get_options_non_task_tag(self):
        im = self._impl()
        pid = im.add_policy("x", {})["policy_id"]
        opts = im.get_options_by_policy_id(pid, "monitor")
        self.assertNotIn("domain_brute", opts)   # 非资产发现任务不带域名配置
        self.assertIn("site_identify", opts)     # 仍带 site

    # —— get_options：策略不存在降级 {} ——
    def test_get_options_missing(self):
        self.assertEqual(self._impl().get_options_by_policy_id("nope", ""), {})


if __name__ == "__main__":
    unittest.main()
