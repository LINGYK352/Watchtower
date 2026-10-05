"""attack_chain 端点 e2e —— 真起 app，test_client 打 /api/intel/chain/*，验证不孤岛。

链路：前端(AttackChain.vue/api intel.ts) → 网关 → endpoint(attack_chain ns) → registry 取
"attack_chain_service"（字符串键）→ attack_chain 叶子 → 信封 {code,message,data}。
用内存 Mongo 替身 seed 攻击链，验证 list/detail/stat/delete 全链路 + 禁硬限制(size 透传)。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.contracts import Collections


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


class AttackChainEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = _Repo()
        set_repo(self.repo)
        from sentinel_platform.modules.risk_intel.attack_chain import AttackChainServiceImpl
        g = AttackChainServiceImpl()
        g.record_step("ACME", "链A", "JS泄露内网", severity="low", session_id="s1")
        g.record_step("ACME", "链A", "SSRF打内网拿凭证", severity="high", session_id="s2")  # 跨会话+提级
        g.record_step("OTHER", "链B", "越权", severity="critical")

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    def test_swagger_contains_chain_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/intel/chain" in p for p in spec["paths"]),
                        "attack_chain 端点应进 OpenAPI 规范")

    def test_list(self):
        data = self._data(self.client.get("/api/intel/chain/?unit=ACME"))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["title"], "链A")
        self.assertTrue(data["items"][0]["cross_session"])
        self.assertEqual(data["items"][0]["max_severity"], "high")

    def test_detail(self):
        lst = self._data(self.client.get("/api/intel/chain/?unit=ACME"))
        cid = lst["items"][0]["_id"]
        d = self._data(self.client.get("/api/intel/chain/{}".format(cid)))
        self.assertEqual(d["title"], "链A")
        self.assertEqual(len(d["steps"]), 2)

    def test_detail_not_found_404(self):
        resp = self.client.get("/api/intel/chain/nope")
        self.assertEqual(resp.status_code, 404)

    def test_stat(self):
        data = self._data(self.client.get("/api/intel/chain/stat/"))
        self.assertEqual(data["total"], 2)          # ACME链A + OTHER链B
        self.assertEqual(data["cross_session"], 1)   # 仅链A跨会话
        self.assertEqual(data["by_severity"]["critical"], 1)

    def test_delete(self):
        lst = self._data(self.client.get("/api/intel/chain/?unit=ACME"))
        cid = lst["items"][0]["_id"]
        d = self._data(self.client.post("/api/intel/chain/delete/", json={"_id": [cid]}))
        self.assertEqual(d["deleted"], 1)
        self.assertEqual(self._data(self.client.get("/api/intel/chain/?unit=ACME"))["total"], 0)

    def test_delete_empty_400(self):
        resp = self.client.post("/api/intel/chain/delete/", json={"_id": []})
        self.assertEqual(resp.status_code, 400)

    # —— 禁硬限制：list size 传大值透传不砍 ——
    def test_list_no_hard_limit(self):
        from sentinel_platform.modules.risk_intel.attack_chain import AttackChainServiceImpl
        g = AttackChainServiceImpl()
        for i in range(30):
            g.record_step("BIG", "链{}".format(i), "step")
        data = self._data(self.client.get("/api/intel/chain/?unit=BIG&size=500"))
        self.assertEqual(data["size"], 500)
        self.assertEqual(data["total"], 30)
        self.assertEqual(len(data["items"]), 30)


if __name__ == "__main__":
    unittest.main()
