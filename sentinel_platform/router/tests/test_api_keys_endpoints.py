"""api_keys 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封），证明不孤岛。

AUTH 默认关（缺省安全）故不需 token 即可过网关；重点验：端点挂载进 swagger、
GET/POST 走 registry 调 api_keys_service、响应是 {code,message,data} 信封、掩码生效。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemCollection:
    def __init__(self):
        self._doc = None

    def find_one(self, query):
        return dict(self._doc) if self._doc else None

    def insert_one(self, doc):
        self._doc = dict(doc)
        return type("R", (), {"inserted_id": "mem1"})()

    def update_one(self, query, update, upsert=False):
        if self._doc is None:
            self._doc = {"name": "default"}
        self._doc.update(update.get("$set", {}))


class _MemRepo(Repository):
    def __init__(self):
        self._coll = _MemCollection()

    def collection(self, name):
        return self._coll


class ApiKeysEndpointE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry()
        set_repo(_MemRepo())
        from sentinel_platform.modules.system import api_keys
        self._validators = mock.patch.dict(
            api_keys._VALIDATORS,
            {name: (lambda _key, _sub: (True, "")) for name in api_keys._VALIDATORS},
            clear=False)
        self._validators.start()
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        self._validators.stop()
        reset_repo(); reset_registry()

    def test_endpoint_mounted_in_swagger(self):
        resp = self.client.get("/api/swagger.json")
        self.assertEqual(resp.status_code, 200)
        spec = resp.get_json()
        self.assertIn("/api_keys/", spec.get("paths", {}))

    def test_get_list_envelope(self):
        resp = self.client.get("/api/api_keys/")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        # 统一信封
        self.assertEqual(body["code"], 200)
        self.assertIn("data", body)
        self.assertIn("items", body["data"])
        ids = {i["id"] for i in body["data"]["items"]}
        self.assertIn("fofa", ids)

    def test_post_save_and_mask_roundtrip(self):
        # 保存 fofa key → 再 GET 应掩码
        resp = self.client.post("/api/api_keys/", json={"fofa": {"key": "MYKEY12345678", "enabled": True}})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["code"], 200)
        fofa = next(i for i in body["data"]["items"] if i["id"] == "fofa")
        self.assertTrue(fofa["enabled"])
        self.assertTrue(fofa["key"].endswith("5678"))
        self.assertNotIn("MYKEY", fofa["key"])   # 明文不经 HTTP 泄露

    def test_post_bad_body(self):
        resp = self.client.post("/api/api_keys/", data="notjson", content_type="text/plain")
        body = resp.get_json()
        self.assertEqual(body["code"], 400)

    def test_service_missing_degrades_500(self):
        # 清掉 registry 里的 api_keys_service，端点应降级 500 信封（不崩）
        reset_registry()
        resp = self.client.get("/api/api_keys/")
        body = resp.get_json()
        self.assertEqual(body["code"], 500)
        self.assertIn("未就绪", body["message"])


if __name__ == "__main__":
    unittest.main()
