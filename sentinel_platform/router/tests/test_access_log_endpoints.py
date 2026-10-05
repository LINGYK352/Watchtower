"""access_log 端点 + gateway 审计钩子 e2e —— 真 Flask test_client 走完整链路。

证明不孤岛：① 端点 GET /api/access_log/{,stat} 走网关→registry→信封；
② **gateway after_request 真记审计**——发一个业务请求后，access_log 里能查到该请求（闭合交接待办③）。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemCollection:
    def __init__(self):
        self._docs = []
        self._auto = 0

    def insert_one(self, doc):
        self._auto += 1
        d = dict(doc); d.setdefault("_id", "id%d" % self._auto)
        self._docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        out = []
        for d in self._docs:
            ok = True
            for k, v in (q or {}).items():
                if isinstance(v, dict):
                    if "$gte" in v and not (d.get(k, 0) >= v["$gte"]):
                        ok = False
                    if "$regex" in v:
                        import re as _re
                        if not _re.search(v["$regex"], str(d.get(k, "")), _re.I):
                            ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out

    def find(self, q):
        return _Cursor(self._match(q))


class _Cursor(list):
    def sort(self, *a, **k):
        return _Cursor(reversed(self))

    def skip(self, n):
        return _Cursor(list(self)[n:])

    def limit(self, n):
        return _Cursor(list(self)[:n])


class _MemRepo(Repository):
    def __init__(self):
        self._coll = _MemCollection()

    def collection(self, name):
        return self._coll


class AccessLogE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_endpoints_in_swagger(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertIn("/access_log/", spec.get("paths", {}))
        self.assertIn("/access_log/stat/", spec.get("paths", {}))

    def test_stat_envelope(self):
        body = self.client.get("/api/access_log/stat/").get_json()
        self.assertEqual(body["code"], 200)
        for k in ("total", "writes", "today", "errors"):
            self.assertIn(k, body["data"])

    def test_list_envelope(self):
        body = self.client.get("/api/access_log/").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("items", body["data"])

    def test_gateway_records_audit(self):
        """核心：发一个业务请求 → gateway after_request 应记一条审计，list 能查到（闭合待办③）。"""
        # 先发一个会被记录的业务请求（meta/modules 是 /api 且非 skip 前缀）
        self.client.get("/api/meta/modules")
        # 再查审计列表，应含刚才那条
        body = self.client.get("/api/access_log/").get_json()
        paths = [i["path"] for i in body["data"]["items"]]
        self.assertIn("/api/meta/modules", paths)
        # access_log 自身查询不被记录（防递归刷屏）
        self.assertNotIn("/api/access_log/", paths)

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/access_log/stat/").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
