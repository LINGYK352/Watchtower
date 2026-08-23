"""端到端：unit_view 端点经核心路由（信封 + 跨模块 ext_source 复用 + 前端可调）。

真 Flask app + 内存 repo（按集合名分开）。验证 units/detail/delete + resolve_icp 复用
kernel/ext_source.icp_query（跨模块经暴露层，非孤岛）。
"""
import unittest
from unittest import mock

from sentinel_platform.core import set_repo


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find(self, q=None, proj=None):
        q = q or {}
        self._r = [d for d in self.docs
                   if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict))]
        return self
    def sort(self, *a):
        return self
    def __iter__(self):
        return iter(self._r)
    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def insert_one(self, doc):
        doc.setdefault("_id", "x%d" % (len(self.docs) + 1)); self.docs.append(doc)
    def delete_many(self, q):
        keep, n = [], 0
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                n += 1
            else:
                keep.append(d)
        self.docs = keep
        class _R: deleted_count = n
        return _R()
    def update_many(self, q, upd):
        class _R: modified_count = 0
        return _R()


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


class TestUnitViewE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(_FakeRepo())
        from sentinel_platform.router import create_app
        cls.client = create_app().test_client()

    def setUp(self):
        r = _FakeRepo()
        r.collection("intel_asset").insert_one({"unit": "A公司", "subdomain": "a.com", "system_id": "s1"})
        r.collection("intel_finding").insert_one({"source": "ai", "unit": "A公司", "verified": True, "severity": "high"})
        set_repo(r)

    @classmethod
    def tearDownClass(cls):
        set_repo(None)

    def test_units_envelope(self):
        body = self.client.get("/api/intel/units/").get_json()
        self.assertEqual(body["code"], 200)
        units = {u["unit"]: u for u in body["data"]["units"]}
        self.assertEqual(units["A公司"]["vuln_count"], 1)

    def test_unit_detail(self):
        body = self.client.get("/api/intel/unit/A%E5%85%AC%E5%8F%B8").get_json()  # A公司 urlencoded
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["data"]["unit"], "A公司")

    def test_unit_delete_cascade(self):
        body = self.client.post("/api/intel/unit/delete/", json={"unit": "A公司"}).get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["data"]["deleted"]["intel_asset"], 1)

    def test_unit_delete_empty_rejected(self):
        body = self.client.post("/api/intel/unit/delete/", json={"unit": ""}).get_json()
        self.assertEqual(body["code"], 400)

    def test_resolve_icp_reuses_ext_source(self):
        # 跨模块复用证明：patch kernel/ext_source.icp_query，验证 endpoint 调到它
        with mock.patch("sentinel_platform.modules.kernel.ext_source.icp_query",
                        return_value={"unit": "某公司", "icp_no": "京ICP备1号", "source": "hunter"}) as m:
            body = self.client.post("/api/intel/resolve_icp/", json={"domain": "a.com"}).get_json()
        self.assertEqual(body["code"], 200)
        self.assertEqual(body["data"]["unit"], "某公司")
        m.assert_called_once_with("a.com")

    def test_resolve_icp_no_domain_400(self):
        body = self.client.post("/api/intel/resolve_icp/", json={"domain": ""}).get_json()
        self.assertEqual(body["code"], 400)


if __name__ == "__main__":
    unittest.main()
