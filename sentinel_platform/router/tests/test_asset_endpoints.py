"""资产检索端点 e2e —— 真起 app，test_client 打 /api/{集合}/*，验证不孤岛。

链路：前端(assets.ts collectionApi) → 网关 → endpoint(工厂 ns) → registry 取
asset_search_service 门面 → asset/search → 信封/文本流。用内存 Mongo 替身 seed 侦察集合，
覆盖 list/分页/过滤/order、site dedup(域名+端口聚合)、delete、add_tag/delete_tag、export、
禁止硬限制(size 超大不被砍)。
"""
import unittest

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel.tests._fakedb import FakeRepo
from sentinel_platform.contracts import Collections


class AssetEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = FakeRepo()
        set_repo(self.repo)
        # seed domain
        for i in range(3):
            self.repo.collection(Collections.DOMAIN).insert_one(
                {"_id": "d{}".format(i), "domain": "a{}.acme.com".format(i),
                 "task_id": "t1", "type": "A"})
        # seed site：同 host 不同 scheme/path/task → dedup 应折叠成 1 组
        self.repo.collection(Collections.SITE).insert_one(
            {"_id": "s1", "site": "http://x.acme.com", "hostname": "x.acme.com",
             "title": "", "task_id": "t1", "tag": []})
        self.repo.collection(Collections.SITE).insert_one(
            {"_id": "s2", "site": "https://x.acme.com/admin", "hostname": "x.acme.com",
             "title": "后台", "task_id": "t1", "tag": []})
        self.repo.collection(Collections.SITE).insert_one(
            {"_id": "s3", "site": "http://y.acme.com", "hostname": "y.acme.com",
             "title": "Y", "task_id": "t1", "tag": []})

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)
        return body["data"]

    # —— registry 装配：asset_search_service 就绪（不孤岛）——
    def test_asset_service_registered(self):
        from sentinel_platform.contracts import get_registry
        self.assertIsNotNone(get_registry().get("asset_search_service"))

    def test_swagger_contains_asset_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        for p in ("/domain/", "/site/dedup/", "/ip/export/", "/wih/"):
            self.assertTrue(any(pp.endswith(p) or pp == p for pp in spec["paths"]),
                            "asset 端点 {} 应进 OpenAPI".format(p))

    def test_domain_list(self):
        data = self._data(self.client.get("/api/domain/"))
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["items"]), 3)
        self.assertIn("domain", data["items"][0])

    def test_domain_filter_regex(self):
        data = self._data(self.client.get("/api/domain/?domain=a1"))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["domain"], "a1.acme.com")

    def test_pagination_and_no_hard_size_cap(self):
        # size 请求超大不被砍（禁止硬限制）：total=3，一页全出
        data = self._data(self.client.get("/api/domain/?page=1&size=100000"))
        self.assertEqual(data["size"], 100000)
        self.assertEqual(len(data["items"]), 3)

    def test_site_dedup_groups_by_host_port(self):
        data = self._data(self.client.get("/api/site/dedup/"))
        # x.acme.com 的 http/https+path 折叠成 1 组，y.acme.com 1 组 → 共 2
        self.assertEqual(data["total"], 2)
        xrep = next(r for r in data["items"] if "x.acme.com" in r["site"])
        self.assertEqual(xrep["_group_count"], 2)          # s1+s2 同组
        self.assertEqual(set(xrep["_group_ids"]), {"s1", "s2"})
        self.assertEqual(xrep["title"], "后台")            # 优先有 title 的代表行

    def test_site_add_then_delete_tag(self):
        d = self._data(self.client.post("/api/site/add_tag/", json={"_id": "s3", "tag": "重点"}))
        self.assertIn("重点", d["tags"])
        # 重复加 → 400
        r = self.client.post("/api/site/add_tag/", json={"_id": "s3", "tag": "重点"})
        self.assertEqual(r.status_code, 400)
        # 删标签
        d2 = self._data(self.client.post("/api/site/delete_tag/", json={"_id": "s3", "tag": "重点"}))
        self.assertNotIn("重点", d2.get("tags", []))

    def test_delete_by_ids(self):
        d = self._data(self.client.post("/api/domain/delete/", json={"_id": ["d0", "d1"]}))
        self.assertEqual(d["deleted"], 2)
        self.assertEqual(self._data(self.client.get("/api/domain/"))["total"], 1)

    def test_delete_empty_ids_400(self):
        r = self.client.post("/api/domain/delete/", json={"_id": []})
        self.assertEqual(r.status_code, 400)

    def test_export_returns_textfile(self):
        resp = self.client.get("/api/domain/export/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        body = resp.get_data(as_text=True)
        # 3 个 domain 一行一个
        self.assertEqual(set(body.split("\r\n")), {"a0.acme.com", "a1.acme.com", "a2.acme.com"})

    def test_unknown_collection_not_mounted(self):
        # 未白名单集合无端点（如 /api/policy/ 不由本模块提供）→ 404 或其它模块处理，不 500
        resp = self.client.get("/api/notacoll/")
        self.assertIn(resp.status_code, (404,))


if __name__ == "__main__":
    unittest.main()
