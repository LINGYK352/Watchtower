"""proxy 端点 e2e —— 真 Flask test_client 走完整链路，证明解 ProxySetting.vue 孤岛。

验：契约核心端点(status/config/exit_ip/health)走 ROLE.PROXY 真响应 + phase-2 端点优雅降级(200+phase2,不404崩页) + swagger 含 /proxy。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self._doc = None

    def find_one(self, q):
        return dict(self._doc) if self._doc else None

    def find(self, q=None):
        # 空可排序游标：本 fake 存单配置文档，无流量账本行→traffic_stats 返空账本(200)。
        class _Cur(list):
            def sort(self, *a, **k):
                return self
        return _Cur()

    def insert_one(self, doc):
        self._doc = dict(doc)
        return type("R", (), {"inserted_id": "x"})()

    def update_one(self, q, u, upsert=False):
        if self._doc is None:
            self._doc = {"name": "default"}
        self._doc.update(u.get("$set", {}))
        return type("R", (), {"matched_count": 1})()


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}   # 按集合名分实例（真 Mongo 语义；避免 gateway 审计写 access_log 污染 proxy_config）

    def collection(self, name):
        return self._colls.setdefault(name, _MemColl())


class ProxyEndpointsE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertIn("/proxy/status", paths)
        self.assertIn("/proxy/config", paths)
        self.assertIn("/proxy/exit_ip", paths)

    def test_status_envelope(self):
        body = self.client.get("/api/proxy/status").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("config", body["data"])
        self.assertIn("running", body["data"])   # phase-2 内核未跑，running=False

    def test_config_get_and_save(self):
        got = self.client.get("/api/proxy/config").get_json()
        self.assertEqual(got["code"], 200)
        self.assertEqual(got["data"]["mode"], "rule")   # 默认配置
        saved = self.client.post("/api/proxy/config", json={"enabled": True, "http_port": 18080}).get_json()
        self.assertEqual(saved["code"], 200)
        self.assertTrue(saved["data"]["enabled"])
        self.assertEqual(saved["data"]["http_port"], 18080)

    def test_config_bad_mode_400(self):
        body = self.client.post("/api/proxy/config", json={"mode": "weird"}).get_json()
        self.assertEqual(body["code"], 400)

    def test_mihomo_endpoints_real(self):
        """mihomo 端点已从 phase-2 毕业为真实（v1.21.94 system/_mihomo 落地）：
        profiles/proxies/traffic/logs 返 200 真实数据，不再是 phase2 桩（无 phase2 标记）。"""
        for path in ("/api/proxy/profiles", "/api/proxy/proxies", "/api/proxy/traffic",
                     "/api/proxy/logs"):
            body = self.client.get(path).get_json()
            self.assertEqual(body["code"], 200, path)
            self.assertFalse(body["data"].get("phase2"), path)   # 已毕业，无 phase2 标记

    def test_pool_endpoints_real(self):
        """pool/list、pool/stats 已转真实（proxy_pool_service）：返 200 真实数据，不再是 phase-2 桩。"""
        for path in ("/api/proxy/pool/list", "/api/proxy/pool/stats"):
            body = self.client.get(path).get_json()
            self.assertEqual(body["code"], 200, path)
            self.assertFalse(body["data"].get("phase2"), path)   # 已毕业，无 phase2 标记

    def test_core_action_real(self):
        """core/start 已真实（v1.21.94）：调 mihomo 启停。测试环境无 mihomo 二进制→返 400+error
        （FileNotFoundError），不再是 phase2 桩。断言：非 phase2、code 为 200 或 400（真实执行结果）。"""
        body = self.client.post("/api/proxy/core/start").get_json()
        self.assertIn(body["code"], (200, 400))
        self.assertFalse((body.get("data") or {}).get("phase2"))   # 已毕业，无 phase2 标记

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/proxy/status").get_json()
        self.assertEqual(body["code"], 500)


if __name__ == "__main__":
    unittest.main()
