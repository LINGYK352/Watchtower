"""AI 配置中心端点 e2e —— 真起 app，test_client 打 /api/ai_config/*，验证不孤岛。

链路：前端(aiConfig.ts) → 网关 → endpoint(ns) → registry 取 ai_config_service 门面
→ ai_config 叶子 → 信封 {code,message,data}。用内存 Mongo 替身，覆盖
config GET/POST、provider CRUD+掩码回显+掩码不覆盖、presets、prompt CRUD+内置禁删、
usage_stat、test_provider(mock LLM)。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo
from sentinel_platform.modules.ai_pentest import ai_config as ac


_PROVIDER_JSON = ('{"name":"DeepSeek","base_url":"https://api.deepseek.com",'
                  '"api_key":"sk-abcdefgh1234","model":"deepseek-chat"}')


class AIConfigEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        set_repo(FakeRepo())

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    def _add_provider(self):
        return self._data(self.client.post("/api/ai_config/provider",
                                           json={"config": _PROVIDER_JSON}))["_id"]

    # —— registry 装配 + swagger ——
    def test_service_registered(self):
        from sentinel_platform.contracts import get_registry
        self.assertIsNotNone(get_registry().get("ai_config_service"))

    def test_swagger_contains_ai_config(self):
        spec = self.client.get("/api/swagger.json").get_json()
        for p in ("/ai_config/config", "/ai_config/provider", "/ai_config/prompt"):
            self.assertTrue(any(pp == p for pp in spec["paths"]), "缺 {}".format(p))

    # —— 全局参数 ——
    def test_config_get_and_save(self):
        d = self._data(self.client.get("/api/ai_config/config"))
        self.assertIn("recommend_concurrency", d)
        self.assertIn("effective_concurrency", d)
        d2 = self._data(self.client.post("/api/ai_config/config", json={"max_context_tokens": 500000}))
        self.assertEqual(d2["max_context_tokens"], 500000)

    def test_config_no_hard_cap_on_context(self):
        # 禁止硬限制：超大上下文上限透传不被砍
        d = self._data(self.client.post("/api/ai_config/config", json={"max_context_tokens": 99999999}))
        self.assertEqual(d["max_context_tokens"], 99999999)

    # —— Provider CRUD + 掩码 ——
    def test_provider_add_list_masked(self):
        pid = self._add_provider()
        self.assertTrue(pid)
        items = self._data(self.client.get("/api/ai_config/provider"))["items"]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["api_key"].endswith("1234"))
        self.assertIn("*", items[0]["api_key"])           # 掩码回显

    def test_provider_masked_update_preserves_key(self):
        pid = self._add_provider()
        masked = self._data(self.client.get("/api/ai_config/provider"))["items"][0]["api_key"]
        # 传掩码值 + 改 model → key 应保留原值
        self._data(self.client.post("/api/ai_config/provider/{}".format(pid),
                                    json={"api_key": masked, "model": "deepseek-reasoner"}))
        self.assertEqual(ac.get_provider(pid)["api_key"], "sk-abcdefgh1234")
        self.assertEqual(ac.get_provider(pid)["model"], "deepseek-reasoner")

    def test_provider_real_key_update(self):
        pid = self._add_provider()
        self._data(self.client.post("/api/ai_config/provider/{}".format(pid),
                                    json={"api_key": "sk-newkey5678"}))
        self.assertEqual(ac.get_provider(pid)["api_key"], "sk-newkey5678")

    def test_provider_delete_clears_active(self):
        pid = self._add_provider()
        self._data(self.client.post("/api/ai_config/config", json={"active_provider_id": pid}))
        self._data(self.client.post("/api/ai_config/provider/{}/delete".format(pid)))
        self.assertEqual(self._data(self.client.get("/api/ai_config/config"))["active_provider_id"], "")

    def test_add_provider_invalid_json_400(self):
        r = self.client.post("/api/ai_config/provider", json={"config": "not-json{"})
        self.assertEqual(r.status_code, 400)

    def test_presets(self):
        items = self._data(self.client.get("/api/ai_config/presets"))["items"]
        self.assertTrue(any(p["key"] == "claude" for p in items))
        self.assertIn("template", items[0])

    def test_provider_test_endpoint(self):
        pid = self._add_provider()
        with mock.patch("sentinel_platform.modules.ai_pentest._client.test_provider",
                        return_value={"ok": True, "content": "hi", "model": "deepseek-chat",
                                      "total_tokens": 12, "proxy_enabled": False, "error": ""}):
            d = self._data(self.client.post("/api/ai_config/provider/{}/test".format(pid),
                                            json={"message": "ping"}))
        self.assertTrue(d["ok"])
        self.assertEqual(d["total_tokens"], 12)

    # —— Prompt CRUD ——
    def test_prompt_seed_list_and_builtin_protect(self):
        ac.seed_prompts()
        items = self._data(self.client.get("/api/ai_config/prompt"))["items"]
        self.assertGreaterEqual(len(items), 5)
        builtin = next(p for p in items if p["builtin"])
        # 内置禁删 → 400
        r = self.client.post("/api/ai_config/prompt/{}/delete".format(builtin["_id"]))
        self.assertEqual(r.status_code, 400)

    def test_prompt_add_update_delete_custom(self):
        pid = self._data(self.client.post("/api/ai_config/prompt",
                                          json={"scene": "custom", "name": "X", "content": "hi"}))["_id"]
        self._data(self.client.post("/api/ai_config/prompt/{}".format(pid), json={"content": "hello"}))
        d = self._data(self.client.post("/api/ai_config/prompt/{}/delete".format(pid)))
        self.assertTrue(d.get("ok"))

    def test_usage_stat(self):
        d = self._data(self.client.get("/api/ai_config/usage_stat"))
        self.assertIn("overall", d)
        self.assertIn("by_provider", d)


if __name__ == "__main__":
    unittest.main()
