"""task_create 端点 e2e —— 真起 app，test_client 打 /api/task/policy/ + /api/task_fofa/*。

链路：前端(TaskCreate.vue/api task.ts) → 网关 → endpoint → registry 取 task_create_service +
policy_service → 叶子 → 信封。FOFA 路径 monkeypatch kernel.ext_source.fofa_query（不发真网络）。
验证：policy 下发 / FOFA test 预览 / FOFA submit 解析建任务 / 单位名 WAITING / 必填 400 / 禁硬限制。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo, get_repo
from sentinel_platform.router import create_app
from sentinel_platform.contracts import get_registry, Collections


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "t{}".format(self._n))
        self.docs.append(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()


class _Repo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _Coll())


class _FakePolicy:
    def get_options_by_policy_id(self, policy_id, task_tag):
        if policy_id == "missing":
            return {}
        return {"policy_name": "P", "domain_brute": True, "port_scan": True}


class TaskCreateEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        set_repo(_Repo())
        # 覆盖 registry 里真实 policy_service 为可控假实现（app 已在 setUpClass 注册真实的，这里重注册覆盖）
        get_registry().register("policy_service", _FakePolicy())

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    def _tasks(self):
        return get_repo().collection(Collections.TASK).docs

    def test_swagger_contains_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/task/policy/" in p for p in spec["paths"]))
        self.assertTrue(any("/task_fofa/submit" in p for p in spec["paths"]))

    # —— /api/task/policy/ 下发 ——
    def test_policy_dispatch(self):
        d = self._data(self.client.post("/api/task/policy/",
                                        json={"name": "扫描A", "policy_id": "p1",
                                              "target": "a.com, b.com, 8.8.8.8", "task_tag": "task"}))
        self.assertEqual(d["created"], 3)
        self.assertTrue(all(t["status"] == "waiting" for t in self._tasks()))

    def test_policy_missing_400(self):
        resp = self.client.post("/api/task/policy/", json={"name": "x", "policy_id": "p1"})
        self.assertEqual(resp.status_code, 400)

    def test_policy_not_found_400(self):
        resp = self.client.post("/api/task/policy/",
                                json={"name": "x", "policy_id": "missing", "target": "a.com"})
        self.assertEqual(resp.status_code, 400)

    # —— /api/task_fofa/test 预览 ——
    def test_fofa_test(self):
        with mock.patch("sentinel_platform.modules.kernel.ext_source.fofa_query",
                        return_value=[["a.com", "1.1.1.1", "80"], ["b.com", "2.2.2.2", "443"]]):
            d = self._data(self.client.post("/api/task_fofa/test", json={"query": 'domain="x.com"'}))
        self.assertEqual(d["size"], 2)

    def test_fofa_test_missing_400(self):
        resp = self.client.post("/api/task_fofa/test", json={})
        self.assertEqual(resp.status_code, 400)

    # —— /api/task_fofa/submit 解析建任务（同步可用）——
    def test_fofa_submit(self):
        with mock.patch("sentinel_platform.modules.kernel.ext_source.fofa_query",
                        return_value=[["a.com", "1.1.1.1", "80"], ["b.com", "2.2.2.2", "443"], ["", "9.9.9.9", "80"]]):
            d = self._data(self.client.post("/api/task_fofa/submit",
                                            json={"query": 'domain="x"', "name": "FOFA导入", "policy_id": "p1"}))
        self.assertEqual(d["fofa_size"], 3)          # a.com/b.com/9.9.9.9
        self.assertEqual(d["created"], 1)            # FOFA 结果聚合成一个任务，真实目标在 options.fofa_ip

    def test_fofa_submit_zero_hit_400(self):
        with mock.patch("sentinel_platform.modules.kernel.ext_source.fofa_query", return_value=[]):
            resp = self.client.post("/api/task_fofa/submit",
                                    json={"query": "q", "name": "n", "policy_id": "p1"})
        self.assertEqual(resp.status_code, 400)

    # —— /api/task_fofa/submit_by_unit 单位名 WAITING ——
    def test_submit_by_unit(self):
        d = self._data(self.client.post("/api/task_fofa/submit_by_unit",
                                        json={"name": "单位任务", "units": "某某公司\n另一公司", "policy_id": "p1"}))
        self.assertEqual(d["unit_count"], 2)
        self.assertTrue(d["task_id"])
        ut = [t for t in self._tasks() if t.get("type") == "unit"]
        self.assertEqual(len(ut), 1)
        self.assertEqual(ut[0]["status"], "waiting")
        self.assertEqual(ut[0]["unit_names"], ["某某公司", "另一公司"])

    def test_submit_by_unit_missing_400(self):
        resp = self.client.post("/api/task_fofa/submit_by_unit", json={"name": "x", "policy_id": "p1"})
        self.assertEqual(resp.status_code, 400)

    # —— 禁硬限制：FOFA 大量结果全建 ——
    def test_no_hard_limit(self):
        many = [["d{}.com".format(i), "1.2.3.4", "80"] for i in range(150)]
        with mock.patch("sentinel_platform.modules.kernel.ext_source.fofa_query", return_value=many):
            d = self._data(self.client.post("/api/task_fofa/submit",
                                            json={"query": "q", "name": "批量", "policy_id": "p1"}))
        self.assertEqual(d["created"], 1)
        self.assertEqual(len(self._tasks()[0]["options"]["fofa_ip"]), 150)  # 全量目标保留，无上限


if __name__ == "__main__":
    unittest.main()
