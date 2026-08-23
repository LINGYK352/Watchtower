"""资产监控端点 e2e —— 真起 app，test_client 打 /api/scheduler/*，验证不孤岛。

链路：前端(scheduler.ts) → 网关 → endpoint(scheduler ns) → registry 取 monitor_service 门面 →
asset/monitor → 信封。用内存 Mongo 替身 seed asset_scope，覆盖 list/分页(禁止硬限制)、
新增(域名/站点/去重/间隔下限/未知范围)、删除(空 400)、停止→恢复。
"""
import unittest

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo
from sentinel_platform.contracts import Collections


class AssetMonitorEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = FakeRepo()
        set_repo(self.repo)
        # seed 资产范围
        self.repo.collection(Collections.ASSET_SCOPE).insert_one(
            {"_id": "sc1", "name": "测试组", "scope_type": "domain", "scope_array": ["a.com"]})

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    # —— registry 装配：monitor_service 就绪（不孤岛）——
    def test_service_registered(self):
        from sentinel_platform.contracts import get_registry
        self.assertIsNotNone(get_registry().get("monitor_service"))

    def test_swagger_contains_scheduler(self):
        spec = self.client.get("/api/swagger.json").get_json()
        for p in ("/scheduler/", "/scheduler/add/site_monitor/"):
            self.assertTrue(any(pp.endswith(p) or pp == p for pp in spec["paths"]),
                            "scheduler 端点 {} 应进 OpenAPI".format(p))

    def test_add_domain_job(self):
        d = self._data(self.client.post("/api/scheduler/add/", json={
            "scope_id": "sc1", "domain": "a.com", "interval": 3600 * 24, "name": "m1"}))
        self.assertTrue(d["ok"])
        self.assertEqual(len(d["jobs"]), 1)
        self.assertGreaterEqual(self._data(self.client.get("/api/scheduler/"))["total"], 1)

    def test_add_interval_floor_rejected(self):
        r = self.client.post("/api/scheduler/add/", json={
            "scope_id": "sc1", "domain": "a.com", "interval": 60})
        self.assertEqual(r.status_code, 400)

    def test_add_site_monitor_and_dup(self):
        d = self._data(self.client.post("/api/scheduler/add/site_monitor/", json={
            "scope_id": "sc1", "interval": 3600 * 24}))
        self.assertIn("schedule_id", d)
        # 同资产范围重复建站点监控 → 400
        r = self.client.post("/api/scheduler/add/site_monitor/", json={
            "scope_id": "sc1", "interval": 3600 * 24})
        self.assertEqual(r.status_code, 400)

    def test_list_no_hard_size_cap(self):
        self.client.post("/api/scheduler/add/", json={
            "scope_id": "sc1", "domain": "a.com", "interval": 3600 * 24})
        data = self._data(self.client.get("/api/scheduler/?size=100000"))
        self.assertEqual(data["size"], 100000)

    def test_stop_then_recover(self):
        self.client.post("/api/scheduler/add/", json={
            "scope_id": "sc1", "domain": "a.com", "interval": 3600 * 24})
        jid = self._data(self.client.get("/api/scheduler/"))["items"][0]["_id"]
        s = self._data(self.client.post("/api/scheduler/stop/", json={"job_id": jid}))
        self.assertTrue(s["ok"])
        r = self._data(self.client.post("/api/scheduler/recover/", json={"job_id": jid}))
        self.assertTrue(r["ok"])

    def test_delete(self):
        self.client.post("/api/scheduler/add/", json={
            "scope_id": "sc1", "domain": "a.com", "interval": 3600 * 24})
        jid = self._data(self.client.get("/api/scheduler/"))["items"][0]["_id"]
        d = self._data(self.client.post("/api/scheduler/delete/", json={"job_id": [jid]}))
        self.assertGreaterEqual(d["deleted"], 1)

    def test_delete_empty_400(self):
        r = self.client.post("/api/scheduler/delete/", json={"job_id": []})
        self.assertEqual(r.status_code, 400)

    def test_add_unknown_scope_400(self):
        r = self.client.post("/api/scheduler/add/", json={
            "scope_id": "nope", "domain": "x.com", "interval": 3600 * 24})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
