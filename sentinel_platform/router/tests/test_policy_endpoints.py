"""policy 端点 e2e —— 真起 app，test_client 打 /api/policy/*，验证不孤岛。

链路：前端(Policy.vue/api policy.ts) → 网关 → endpoint(policy ns) → registry 取
"policy_service"（字符串键）→ policy 叶子 → 信封 {code,message,data}。
用内存 Mongo 替身 seed poc 插件，验证 CRUD 全链路 + 禁硬限制(size 透传)。
"""
import re
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.contracts import Collections


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

    def find_one(self, query, projection=None):
        for d in self.docs:
            if _match(d, query):
                return d
        return None

    def find(self, query=None, projection=None):
        return _Cursor([d for d in self.docs if _match(d, query or {})])

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "pid{}".format(self._n))
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


class PolicyEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = _Repo()
        set_repo(self.repo)
        self.repo.collection(Collections.POC).insert_one(
            {"plugin_name": "weblogic_rce", "vul_name": "Weblogic RCE"})

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    def test_swagger_contains_policy_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/policy/" in p or p.endswith("/policy") for p in spec["paths"]),
                        "policy 端点应进 OpenAPI 规范")

    def test_add_list_edit_delete_flow(self):
        # add
        d = self._data(self.client.post("/api/policy/add/",
                                        json={"name": "补天激进", "policy": {"auto_pentest": True}}))
        pid = d["policy_id"]
        self.assertTrue(pid)
        # list
        lst = self._data(self.client.get("/api/policy/"))
        self.assertEqual(lst["total"], 1)
        self.assertEqual(lst["items"][0]["name"], "补天激进")
        # edit
        e = self._data(self.client.post("/api/policy/edit/",
                                        json={"policy_id": pid, "policy_data": {"desc": "改了"}}))
        self.assertEqual(e["data"]["desc"], "改了")
        # delete
        de = self._data(self.client.post("/api/policy/delete/", json={"policy_id": [pid]}))
        self.assertEqual(de["deleted"], 1)
        self.assertEqual(self._data(self.client.get("/api/policy/"))["total"], 0)

    def test_add_unknown_plugin_400(self):
        resp = self.client.post("/api/policy/add/",
                                json={"name": "x", "policy": {"poc_config": [{"plugin_name": "ghost", "enable": True}]}})
        self.assertEqual(resp.status_code, 400)

    def test_add_missing_name_400(self):
        resp = self.client.post("/api/policy/add/", json={"policy": {}})
        self.assertEqual(resp.status_code, 400)

    def test_edit_not_found_404(self):
        resp = self.client.post("/api/policy/edit/", json={"policy_id": "nope", "policy_data": {"desc": "x"}})
        self.assertEqual(resp.status_code, 404)

    def test_delete_empty_400(self):
        resp = self.client.post("/api/policy/delete/", json={"policy_id": []})
        self.assertEqual(resp.status_code, 400)

    # —— 禁硬限制：list size 传大值透传不砍 ——
    def test_list_no_hard_limit(self):
        for i in range(15):
            self.client.post("/api/policy/add/", json={"name": "p{}".format(i), "policy": {}})
        data = self._data(self.client.get("/api/policy/?size=500"))
        self.assertEqual(data["size"], 500)
        self.assertEqual(data["total"], 15)
        self.assertEqual(len(data["items"]), 15)


if __name__ == "__main__":
    unittest.main()
