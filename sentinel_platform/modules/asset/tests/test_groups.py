"""asset/groups 单测 —— core 内存替身，不连真 Mongo。

覆盖：域名/IP 校验、scope 建/列/删(级联)/加范围/删范围、组内资产 list(禁硬限)/delete/add/export、
site tag、sync_task_to_scope、降级、register 注册。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        d = dict(doc); d.setdefault("_id", "oid%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        out = []
        for d in self.docs:
            ok = True
            for k, v in (q or {}).items():
                if isinstance(v, dict):
                    if "$regex" in v:
                        import re
                        if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                            ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out

    def find(self, q=None, proj=None):
        return _Cursor(self._match(q))

    def find_one(self, q):
        m = self._match(q)
        return dict(m[0]) if m else None

    def update_one(self, q, update, upsert=False):
        m = self._match(q)
        if m:
            tgt = next(d for d in self.docs if d is m[0] or d.get("_id") == m[0].get("_id"))
            tgt.update(update.get("$set", {}))
            for k, v in update.get("$addToSet", {}).items():
                tgt.setdefault(k, [])
                if v not in tgt[k]:
                    tgt[k].append(v)
            for k, v in update.get("$pull", {}).items():
                if k in tgt and v in tgt[k]:
                    tgt[k].remove(v)
        elif upsert:
            nd = dict(q); nd.update(update.get("$set", {})); nd.setdefault("_id", "up%d" % (len(self.docs) + 1))
            self.docs.append(nd)

    def delete_one(self, q):
        before = len(self.docs)
        m = self._match(q)
        if m:
            self.docs = [d for d in self.docs if d.get("_id") != m[0].get("_id")]
        return type("R", (), {"deleted_count": before - len(self.docs)})()

    def delete_many(self, q):
        m = self._match(q); ids = {d.get("_id") for d in m}
        self.docs = [d for d in self.docs if d.get("_id") not in ids]
        return type("R", (), {"deleted_count": len(ids)})()


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


class GroupsTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_register(self):
        from sentinel_platform.modules.asset.register import register
        reg = get_registry(); register(reg)
        self.assertIsNotNone(reg.get("asset_group_service"))

    # —— 校验器 ——
    def test_validators(self):
        from sentinel_platform.modules.asset.groups import is_valid_domain, normalize_ip_scope
        self.assertTrue(is_valid_domain("example.com"))
        self.assertFalse(is_valid_domain("not a domain"))
        self.assertEqual(normalize_ip_scope("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize_ip_scope("10.0.0.0/8"), "10.0.0.0/8")
        self.assertIsNone(normalize_ip_scope("999.999.0.0"))

    # —— scope CRUD ——
    def test_add_list_scope(self):
        from sentinel_platform.modules.asset.groups import add_scope_group, list_scopes
        r = add_scope_group({"name": "G1", "scope": "a.com, b.com", "scope_type": "domain"})
        self.assertIn("scope_id", r)
        lst = list_scopes()
        self.assertEqual(lst["total"], 1)
        self.assertEqual(lst["items"][0]["scope_array"], ["a.com", "b.com"])

    def test_add_scope_invalid_domain(self):
        from sentinel_platform.modules.asset.groups import add_scope_group
        self.assertIn("error", add_scope_group({"name": "x", "scope": "bad domain", "scope_type": "domain"}))

    def test_add_scope_ip(self):
        from sentinel_platform.modules.asset.groups import add_scope_group, list_scopes
        add_scope_group({"name": "ipg", "scope": "10.0.0.0/24", "scope_type": "ip"})
        self.assertEqual(list_scopes()["items"][0]["scope_array"], ["10.0.0.0/24"])

    def test_add_delete_scope_range(self):
        from sentinel_platform.modules.asset.groups import add_scope_group, add_scope_range, delete_scope_range, list_scopes
        sid = add_scope_group({"name": "g", "scope": "a.com"})["scope_id"]
        add_scope_range(sid, "b.com c.com")
        self.assertEqual(set(list_scopes()["items"][0]["scope_array"]), {"a.com", "b.com", "c.com"})
        delete_scope_range(sid, "b.com")
        self.assertNotIn("b.com", list_scopes()["items"][0]["scope_array"])

    def test_delete_scope_cascades(self):
        from sentinel_platform.modules.asset import groups as g
        sid = g.add_scope_group({"name": "g", "scope": "a.com"})["scope_id"]
        # 塞组内资产
        set_repo_coll = g.get_repo().collection
        set_repo_coll("asset_domain").insert_one({"scope_id": sid, "domain": "a.com"})
        set_repo_coll("asset_site").insert_one({"scope_id": sid, "site": "http://a.com"})
        r = g.delete_scope_groups([sid])
        self.assertEqual(r["deleted"], 1)
        # 级联清空
        self.assertEqual(g.list_assets("asset_domain", scope_id=sid)["total"], 0)
        self.assertEqual(g.list_assets("asset_site", scope_id=sid)["total"], 0)

    # —— 组内资产 ——
    def test_asset_add_list_delete(self):
        from sentinel_platform.modules.asset.groups import add_asset, list_assets, delete_assets
        r = add_asset("asset_domain", {"scope_id": "S1", "domain": "x.com"})
        self.assertIn("_id", r)
        lst = list_assets("asset_domain", scope_id="S1")
        self.assertEqual(lst["total"], 1)
        self.assertEqual(delete_assets("asset_domain", [r["_id"]])["deleted"], 1)

    def test_asset_add_requires_scope_and_key(self):
        from sentinel_platform.modules.asset.groups import add_asset
        self.assertIn("error", add_asset("asset_domain", {"domain": "x.com"}))   # 缺 scope_id
        self.assertIn("error", add_asset("asset_domain", {"scope_id": "S1"}))    # 缺 domain

    def test_unknown_collection_rejected(self):
        from sentinel_platform.modules.asset.groups import list_assets, add_asset
        self.assertIn("error", add_asset("asset_evil", {"scope_id": "S1"}))
        self.assertEqual(list_assets("asset_evil")["total"], 0)

    def test_export_size_zero_all_no_hard_limit(self):
        """禁硬限制参数：export 全量不 limit。"""
        from sentinel_platform.modules.asset.groups import add_asset, export_assets, list_assets
        for i in range(25):
            add_asset("asset_site", {"scope_id": "S1", "site": "http://x%d.com" % i})
        self.assertEqual(len(export_assets("asset_site", scope_id="S1")), 25)
        self.assertEqual(len(list_assets("asset_site", scope_id="S1", size=0)["items"]), 25)

    def test_site_tag(self):
        from sentinel_platform.modules.asset.groups import add_asset, add_site_tag, delete_site_tag, list_assets
        aid = add_asset("asset_site", {"scope_id": "S1", "site": "http://t.com"})["_id"]
        add_site_tag("asset_site", aid, "important")
        self.assertIn("important", list_assets("asset_site", scope_id="S1")["items"][0].get("tag", []))
        delete_site_tag("asset_site", aid, "important")
        self.assertNotIn("important", list_assets("asset_site", scope_id="S1")["items"][0].get("tag", []))

    # —— sync ——
    def test_sync_task_to_scope(self):
        from sentinel_platform.modules.asset import groups as g
        # 造任务侦察结果
        g.get_repo().collection("domain").insert_one({"task_id": "T1", "domain": "a.com"})
        g.get_repo().collection("site").insert_one({"task_id": "T1", "site": "http://a.com"})
        r = g.sync_task_to_scope("T1", "S9")
        self.assertTrue(r["ok"])
        self.assertEqual(r["synced"]["domain"], 1)
        self.assertEqual(r["synced"]["site"], 1)
        # 落入资产库带 scope_id
        self.assertEqual(g.list_assets("asset_domain", scope_id="S9")["total"], 1)

    def test_sync_requires_ids(self):
        from sentinel_platform.modules.asset.groups import sync_task_to_scope
        self.assertIn("error", sync_task_to_scope("", "S1"))

    # —— 降级 ——
    def test_list_db_failure_degrades(self):
        from sentinel_platform.modules.asset import groups as g

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        self.assertEqual(g.list_scopes()["total"], 0)
        self.assertEqual(g.list_assets("asset_domain")["total"], 0)


if __name__ == "__main__":
    unittest.main()
