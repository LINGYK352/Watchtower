"""risk_intel 端点 e2e —— 真起 app，test_client 打 /api/intel/vuln_feed/*，验证不孤岛。

链路：前端请求 → 网关(鉴权/RBAC，AUTH 默认关→放行) → endpoint → registry 取 VULN_INTEL 门面
→ vuln_intel/_feed → 信封 {code,message,data} 返回（前端 request.ts 契约）。
用内存 Mongo 替身 seed 数据，验证载荷真实经 registry 链路取到，非空壳。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.contracts.registry import reset_registry
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel import vuln_intel as vi
from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo


class RiskIntelEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()          # 注册 kernel + risk_intel，挂 meta + intel 端点
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = FakeRepo()
        set_repo(self.repo)
        # seed 两条情报（1 KEV 可执行 / 1 普通）
        vi.upsert_vuln({"cve_id": "CVE-2026-0001", "title": "Weaver ecology RCE", "severity": "high",
                        "products": ["weaver"], "in_kev": True, "executable": True,
                        "exec_kind": "nuclei", "exec_ref": "cve-2026-0001", "source": "nuclei"})
        vi.upsert_vuln({"cve_id": "CVE-2026-0002", "title": "Nginx 信息泄露", "severity": "low",
                        "products": ["nginx"], "source": "nvd"})

    def tearDown(self):
        reset_repo()

    def _assert_envelope(self, resp):
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["code"], 200)      # 前端契约 {code,message,data}
        self.assertIn("data", body)
        return body["data"]

    # —— registry 装配：risk_intel 已注册（不再孤岛）——
    def test_modules_readiness_reports_vuln_intel(self):
        data = self.client.get("/api/meta/modules").get_json()["data"]
        self.assertTrue(data["modules"].get("vuln_intel"), "VULN_INTEL 应经 risk_intel.register 就绪")

    def test_stat(self):
        data = self._assert_envelope(self.client.get("/api/intel/vuln_feed/stat/"))
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["in_kev"], 1)
        self.assertEqual(data["executable"], 1)

    def test_list_and_filter(self):
        data = self._assert_envelope(self.client.get("/api/intel/vuln_feed/list/"))
        self.assertEqual(data["total"], 2)
        self.assertTrue(all("source_labels" in i for i in data["items"]))
        # 过滤 in_kev
        d2 = self._assert_envelope(self.client.get("/api/intel/vuln_feed/list/?in_kev=1"))
        self.assertEqual(d2["total"], 1)

    def test_query_by_component_alias(self):
        # 中文"泛微"经别名扩展命中英文 weaver
        data = self._assert_envelope(self.client.get("/api/intel/vuln_feed/query/?component=泛微"))
        self.assertGreaterEqual(data["count"], 1)
        self.assertEqual(data["vulns"][0]["executable"], True)  # 可执行优先排序

    def test_query_missing_component_400(self):
        resp = self.client.get("/api/intel/vuln_feed/query/")
        # RequestParser required=True → flask_restx 自身 400；或空值端点返 400
        self.assertIn(resp.status_code, (400,))

    def test_status(self):
        data = self._assert_envelope(self.client.get("/api/intel/vuln_feed/status/"))
        self.assertIn("sources", data)
        self.assertEqual(len(data["sources"]), 10)   # 10 源

    def test_run_async_submitted(self):
        # run 用后台线程；patch run_feed 避免真发网络，验证端点即时返 submitted
        with mock.patch.object(vi._service, "run_feed", return_value={}) as m:
            data = self._assert_envelope(self.client.post("/api/intel/vuln_feed/run/", json={}))
        self.assertEqual(data["status"], "submitted")

    def test_interval_set(self):
        data = self._assert_envelope(
            self.client.post("/api/intel/vuln_feed/interval/", json={"seconds": 7200}))
        self.assertEqual(data["interval_seconds"], 7200)

    def test_interval_missing_seconds_400(self):
        resp = self.client.post("/api/intel/vuln_feed/interval/", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], 400)

    def test_swagger_contains_vuln_feed(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/intel/vuln_feed/stat/" in p for p in spec["paths"]),
                        "vuln_feed 端点应进 OpenAPI 规范(§5 硬约束)")


if __name__ == "__main__":
    unittest.main()
