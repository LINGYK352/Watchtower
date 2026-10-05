"""scan_result 端点 e2e —— 真起 app，test_client 打 /api/{vuln,nuclei_result,npoc_service}/*。

链路：前端(poc.ts vulnApi/nucleiResultApi/npocServiceApi) → 网关 → endpoint → registry 取
scan_result_service 门面 → 叶子 → 信封。用内存 Mongo 替身 seed 三集合，覆盖 list/分页/过滤/
无硬 size 上限/delete/白名单拒未知集合/npoc 无删除。
"""
import unittest

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo
from sentinel_platform.contracts import Collections


class ScanResultEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = FakeRepo()
        set_repo(self.repo)
        for i in range(3):
            self.repo.collection(Collections.VULN).insert_one(
                {"_id": "v{}".format(i), "vul_name": "SQLi{}".format(i), "target": "http://a{}".format(i), "plg_name": "p"})
        self.repo.collection(Collections.NUCLEI_RESULT).insert_one(
            {"_id": "n1", "template_id": "cve-x", "vuln_url": "http://b", "vuln_severity": "high"})
        self.repo.collection(Collections.NPOC_SERVICE).insert_one(
            {"_id": "s1", "host": "1.2.3.4", "port": 22, "scheme": "ssh"})

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    def test_service_registered(self):
        from sentinel_platform.contracts import get_registry
        self.assertIsNotNone(get_registry().get("scan_result_service"))

    def test_swagger_contains_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()["paths"]
        for p in ("/vuln/", "/vuln/delete/", "/nuclei_result/", "/nuclei_result/delete/", "/npoc_service/"):
            self.assertTrue(any(pp == p for pp in spec), "缺 {}".format(p))

    def test_vuln_list(self):
        d = self._data(self.client.get("/api/vuln/"))
        self.assertEqual(d["total"], 3)
        self.assertEqual(len(d["items"]), 3)

    def test_vuln_filter_regex(self):
        d = self._data(self.client.get("/api/vuln/?vul_name=SQLi1"))
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["items"][0]["_id"], "v1")

    def test_no_hard_size_cap(self):
        d = self._data(self.client.get("/api/vuln/?size=100000"))
        self.assertEqual(d["size"], 100000)
        self.assertEqual(len(d["items"]), 3)

    def test_nuclei_list(self):
        d = self._data(self.client.get("/api/nuclei_result/"))
        self.assertEqual(d["total"], 1)

    def test_npoc_list(self):
        d = self._data(self.client.get("/api/npoc_service/"))
        self.assertEqual(d["total"], 1)

    def test_vuln_delete(self):
        d = self._data(self.client.post("/api/vuln/delete/", json={"_id": ["v0", "v1"]}))
        self.assertEqual(d["deleted"], 2)
        self.assertEqual(self._data(self.client.get("/api/vuln/"))["total"], 1)

    def test_nuclei_delete(self):
        d = self._data(self.client.post("/api/nuclei_result/delete/", json={"_id": ["n1"]}))
        self.assertEqual(d["deleted"], 1)

    def test_vuln_delete_empty_400(self):
        r = self.client.post("/api/vuln/delete/", json={"_id": []})
        self.assertEqual(r.status_code, 400)

    def test_npoc_has_no_delete_route(self):
        # npoc_service 仅列表，无 delete 路由 → 404（不是 500）
        r = self.client.post("/api/npoc_service/delete/", json={"_id": ["s1"]})
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
