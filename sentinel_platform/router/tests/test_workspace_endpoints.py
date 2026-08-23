"""workspace 端点 e2e —— 真起 app，test_client 打 /api/console/*，验证不孤岛。

链路：前端(Dashboard.vue/api console.ts) → 网关 → endpoint(console ns) → registry 取
"dashboard_service"（字符串键，无 ROLE）→ dashboard 叶子 → 信封 {code,message,data}。
用内存 Mongo 替身 seed resource_history，验证载荷真经 registry 链路取到（非空壳）。
"""
import time
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.contracts import Collections


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
        self._docs.sort(key=lambda d: d.get(key, 0), reverse=(direction < 0))
        return self

    def __iter__(self):
        return iter(self._docs)


class _Coll:
    def __init__(self, docs):
        self.docs = docs

    def find(self, query=None):
        since = 0
        if query and isinstance(query.get("ts"), dict):
            since = query["ts"].get("$gte", 0)
        return _Cursor([d for d in self.docs if d.get("ts", 0) >= since])


class _Repo(Repository):
    def __init__(self, history):
        self._history = history

    def collection(self, name):
        return _Coll(self._history if name == Collections.RESOURCE_HISTORY else [])


class WorkspaceEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()          # 注册 workspace(dashboard_service) + 挂 console 端点
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        now = int(time.time())
        hist = [{"ts": now - i * 300, "cpu": 10 + i, "memory": 20 + i, "disk": 30 + i} for i in range(20)]
        set_repo(_Repo(hist))

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)          # 前端契约 {code,message,data}
        return body["data"]

    # —— 装配：dashboard 端点进 swagger（不孤岛）——
    def test_swagger_contains_console_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/console/info" in p for p in spec["paths"]),
                        "console/info 端点应进 OpenAPI 规范")
        self.assertTrue(any("/console/resource_history" in p for p in spec["paths"]))

    # —— /api/console/info：走完整链路返设备信息扁平字段 ——
    def test_console_info(self):
        data = self._data(self.client.get("/api/console/info"))
        self.assertIn("device_info", data)
        di = data["device_info"]
        for k in ("cpu_percent", "memory_percent", "disk_percent"):
            self.assertIn(k, di)
            self.assertNotIsInstance(di[k], dict)     # 扁平字段（旧坑防回归）

    # —— /api/console/resource_history：经 registry 取到 seed 的采样点 ——
    def test_resource_history(self):
        data = self._data(self.client.get("/api/console/resource_history?days=7"))
        self.assertEqual(data["days"], 7)
        self.assertTrue(data["count"] > 0, "应从 resource_history 集合取到采样点")
        self.assertEqual(data["count"], len(data["points"]))
        for p in data["points"]:
            self.assertIn("cpu", p)
            self.assertIn("ts", p)

    # —— days 非法 → 兜底 1，不 500 ——
    def test_resource_history_bad_days(self):
        data = self._data(self.client.get("/api/console/resource_history?days=abc"))
        self.assertEqual(data["days"], 1)


if __name__ == "__main__":
    unittest.main()
