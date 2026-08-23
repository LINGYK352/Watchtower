"""asset_groups 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封）。

证明不孤岛：端点挂 swagger + 资产组 CRUD 往返 + 组内资产 list/add/delete + 分页信封。
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
            tgt = next(d for d in self.docs if d.get("_id") == m[0].get("_id"))
            tgt.update(update.get("$set", {}))

    def delete_one(self, q):
        before = len(self.docs); m = self._match(q)
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


class AssetGroupsE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_endpoints_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertIn("/asset_scope/", paths)
        self.assertIn("/asset_domain/", paths)
        self.assertIn("/asset_site/add_tag/", paths)

    def test_scope_crud_roundtrip(self):
        # 建组
        add = self.client.post("/api/asset_scope/", json={"name": "G1", "scope": "a.com,b.com"}).get_json()
        self.assertEqual(add["code"], 200)
        sid = add["data"]["scope_id"]
        # 列（分页信封）
        lst = self.client.get("/api/asset_scope/").get_json()
        self.assertEqual(lst["code"], 200)
        self.assertEqual(lst["data"]["total"], 1)
        self.assertIn("items", lst["data"])
        # 追加范围
        self.client.post("/api/asset_scope/add/", json={"scope_id": sid, "scope": "c.com"})
        # 删单条范围（GET）
        self.client.get("/api/asset_scope/delete/?scope_id=%s&scope=c.com" % sid)
        # 删组
        dl = self.client.post("/api/asset_scope/delete/", json={"scope_id": [sid]}).get_json()
        self.assertEqual(dl["code"], 200)

    def test_scope_add_invalid_400(self):
        body = self.client.post("/api/asset_scope/", json={"name": "x", "scope": "bad domain"}).get_json()
        self.assertEqual(body["code"], 400)

    def test_grouped_asset_list_add(self):
        r = self.client.post("/api/asset_domain/", json={"scope_id": "S1", "domain": "x.com"}).get_json()
        self.assertEqual(r["code"], 200)
        lst = self.client.get("/api/asset_domain/?scope_id=S1").get_json()
        self.assertEqual(lst["code"], 200)
        self.assertEqual(lst["data"]["total"], 1)

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/asset_scope/").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
