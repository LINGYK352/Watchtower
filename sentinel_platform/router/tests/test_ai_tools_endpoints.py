"""ai_tools 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封）。

证明不孤岛：/api/pentest/tools 挂 swagger（与 ai_config 的 /ai_config、其他 /pentest 命名空间共存）+ 走 ai_tools_service。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        class _C:
            def find_one(self, q): return None
            def find(self, q=None, proj=None): return []
            def count_documents(self, q): return 0
            def insert_one(self, d): return type("R", (), {"inserted_id": "x"})()
            def update_one(self, *a, **k): return type("R", (), {"matched_count": 0})()
        return self._colls.setdefault(name, _C())


class AiToolsE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_endpoint_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertIn("/pentest/tools", paths)

    def test_tools_envelope(self):
        body = self.client.get("/api/pentest/tools").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("tools", body["data"])
        self.assertGreater(body["data"]["total"], 20)
        # 每条含前端渲染必需字段
        t0 = body["data"]["tools"][0]
        for f in ("name", "category", "summary", "params"):
            self.assertIn(f, t0)

    def test_core_tool_present_via_http(self):
        body = self.client.get("/api/pentest/tools").get_json()
        names = {t["name"] for t in body["data"]["tools"]}
        self.assertIn("http_request", names)
        self.assertIn("report_finding", names)

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/pentest/tools").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
