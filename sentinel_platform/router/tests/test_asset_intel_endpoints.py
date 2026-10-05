"""asset_intel 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封）。

证明不孤岛：端点挂 swagger（与 vuln_intel 同 /intel path 共存）+ stat/list/collect/match/context 走 INTEL。
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
        d = dict(doc); d.setdefault("_id", "o%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        return [d for d in self.docs if self._ok(d, q)]

    def _ok(self, d, q):
        for k, v in (q or {}).items():
            if k == "$or":
                if not any(self._ok(d, s) for s in v):
                    return False
            elif isinstance(v, dict):
                if "$gt" in v:
                    return False
                if "$in" in v and d.get(k) not in v["$in"]:
                    return False
                if "$regex" in v:
                    import re
                    if not re.search(v["$regex"], str(d.get(k, "")), re.I):
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


class AssetIntelE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_endpoints_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertIn("/intel/stat/", paths)
        self.assertIn("/intel/asset/", paths)
        self.assertIn("/intel/collect/", paths)
        # 与 vuln_intel 同 /intel path 共存（vuln_feed 仍在）
        self.assertIn("/intel/vuln_feed/stat/", paths)

    def test_stat_envelope(self):
        body = self.client.get("/api/intel/stat/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("asset_total", body["data"])

    def test_collect_and_list(self):
        from sentinel_platform.core import get_repo
        get_repo().collection("task").insert_one({"_id": "T1", "name": "x", "source": {"unit": "U"}})
        get_repo().collection("site").insert_one({"task_id": "T1", "site": "http://a.com", "hostname": "a.com", "fld": "a.com", "finger": [{"name": "nginx"}]})
        c = self.client.post("/api/intel/collect/", json={"task_id": "T1"}).get_json()
        self.assertEqual(c["code"], 200)
        self.assertEqual(c["data"]["new_asset"], 1)
        lst = self.client.get("/api/intel/asset/").get_json()
        self.assertEqual(lst["code"], 200)
        self.assertEqual(lst["data"]["total"], 1)

    def test_collect_missing_task_id_400(self):
        body = self.client.post("/api/intel/collect/", json={}).get_json()
        self.assertEqual(body["code"], 400)

    def test_match_envelope(self):
        body = self.client.get("/api/intel/match/?site=http://none.com").get_json()
        self.assertEqual(body["code"], 200)
        self.assertFalse(body["data"]["matched"])

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/intel/stat/").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
