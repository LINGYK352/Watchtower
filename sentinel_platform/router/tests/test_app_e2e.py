"""端到端集成测试 —— 真起 Flask app，用 test_client 发请求，验证前端能真正调到后端。

这是「不孤岛」的硬证明：请求经核心路由 → 网关 → endpoint → registry → 信封返回，
响应结构与前端 request.ts 契约一致（{code,message,data}）。也验证 swagger.json 可生成。
"""
import unittest

from sentinel_platform.router import create_app


class TestAppEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_health_envelope(self):
        resp = self.client.get("/api/meta/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        # 前端契约：{code,message,data}
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["message"], "ok")
        self.assertEqual(body["data"]["status"], "up")

    def test_version(self):
        body = self.client.get("/api/meta/version").get_json()
        self.assertEqual(body["code"], 200)
        self.assertIn("哨兵", body["data"]["name"])

    def test_modules_readiness_reports_kernel(self):
        """经 registry 探模块就绪度：kernel 已注册的能力应为 True（证明 registry 装配生效）。"""
        body = self.client.get("/api/meta/modules").get_json()
        mods = body["data"]["modules"]
        # kernel 已完成的 recon/notify/exploit_clue/system_tags 应就绪
        self.assertTrue(mods.get("recon"), "RECON 应已注册(kernel register 生效)")
        self.assertTrue(mods.get("notify"))
        self.assertTrue(mods.get("system_tags"))
        # 未建模块为 False（不崩，降级）
        self.assertIn("proxy", mods)

    def test_swagger_json_generated(self):
        """/api/swagger.json 可生成且含 meta 端点（§5 硬约束：路由必须进 OpenAPI 规范）。"""
        resp = self.client.get("/api/swagger.json")
        self.assertEqual(resp.status_code, 200)
        spec = resp.get_json()
        self.assertIn("paths", spec)
        self.assertTrue(any("/meta/health" in p for p in spec["paths"]),
                        "meta/health 应出现在 swagger paths")

    def test_unknown_api_404_not_crash(self):
        resp = self.client.get("/api/nonexistent/x")
        self.assertIn(resp.status_code, (404,))


if __name__ == "__main__":
    unittest.main()
