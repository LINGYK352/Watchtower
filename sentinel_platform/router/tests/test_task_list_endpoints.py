"""task_list 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封）。

证明不孤岛：端点挂 swagger + 列表分页信封 + stop/delete 往返 + sync 经 registry 调 asset_group_service（闭合 groups 对接）。
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
        d = dict(doc); d.setdefault("_id", "t%d" % self._n)
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

    def update_one(self, q, update, upsert=False):
        m = self._match(q)
        if not m:
            return type("R", (), {"matched_count": 0})()
        tgt = next(d for d in self.docs if d.get("_id") == m[0].get("_id"))
        tgt.update(update.get("$set", {}))
        return type("R", (), {"matched_count": 1})()

    def delete_one(self, q):
        before = len(self.docs); m = self._match(q)
        if m:
            self.docs = [d for d in self.docs if d.get("_id") != m[0].get("_id")]
        return type("R", (), {"deleted_count": before - len(self.docs)})()

    def delete_many(self, q):
        m = self._match(q); ids = {id(d) for d in m}
        self.docs = [d for d in self.docs if id(d) not in ids]
        return type("R", (), {"deleted_count": len(m)})()


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


class TaskListE2E(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        for name in ("auth_enabled", "activation_enforced"):
            p = patch("sentinel_platform.router.gateway." + name, return_value=False)
            p.start()
            self.addCleanup(p.stop)
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def _seed(self):
        from sentinel_platform.core import get_repo
        return str(get_repo().collection("task").insert_one(
            {"name": "t1", "target": "a.com", "status": "waiting", "task_tag": "task"}).inserted_id)

    def test_endpoints_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertIn("/task/", paths)
        self.assertIn("/task/sync/", paths)

    def test_list_envelope(self):
        self._seed()
        body = self.client.get("/api/task/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["data"]["total"], 1)
        self.assertIn("items", body["data"])

    def test_stop_delete_roundtrip(self):
        tid = self._seed()
        s = self.client.get("/api/task/stop/%s" % tid).get_json()
        self.assertEqual(s["code"], 200)
        self.assertEqual(s["data"]["status"], "stop")
        d = self.client.post("/api/task/delete/", json={"task_id": [tid]}).get_json()
        self.assertEqual(d["code"], 200)
        self.assertEqual(self.client.get("/api/task/").get_json()["data"]["total"], 0)

    def test_sync_via_registry(self):
        """/api/task/sync 经 registry 调 asset_group_service（闭合 groups 对接，不孤岛）。"""
        fake = type("G", (), {"sync_task_to_scope": lambda self, t, s: {"ok": True, "synced": {"domain": 2}}})()
        get_registry().register("asset_group_service", fake)
        body = self.client.post("/api/task/sync/", json={"task_id": "T1", "scope_id": "S1"}).get_json()
        self.assertEqual(body["code"], 200)
        self.assertTrue(body["data"]["ok"])

    def test_sync_real_groups_empty_ok(self):
        """create_app 已注册真 asset_group_service：同步无结果的任务返 200 ok synced 0（不孤岛，真链路）。
        （groups 服务缺失的降级路径由叶子单测 test_sync_to_scope_groups_missing_degrades 覆盖。）"""
        body = self.client.post("/api/task/sync/", json={"task_id": "T1", "scope_id": "S1"}).get_json()
        self.assertEqual(body["code"], 200)
        self.assertTrue(body["data"]["ok"])

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/task/").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
