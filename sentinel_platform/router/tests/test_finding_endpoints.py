"""漏洞中心端点 e2e —— 真起 app，test_client 打 /api/pentest/finding/*，验证不孤岛。

链路：前端(VulnCenter.vue/api pentest.ts) → 网关 → endpoint(ns_finding) → registry 取
FINDING 门面 → vuln_center → 信封 {code,message,data}。用内存 Mongo 替身 seed intel_finding，
验证载荷真实经 registry 链路取到（非空壳），覆盖 stat/unified/detail/delete/mark。
"""
import unittest
from unittest.mock import patch

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.router import create_app
from sentinel_platform.modules.risk_intel.tests.test_vuln_center import _Repo as FakeRepo
from sentinel_platform.contracts import Collections


def _seed_finding(repo, _id, target, sev="high", verified=True, unit="ACME",
                  handle_status="", vtype="SQL注入"):
    repo.collection(Collections.INTEL_FINDING).insert_one({
        "_id": _id, "source": "ai", "vuln_type": vtype, "target": target,
        "severity": sev, "cvss_severity": sev, "cvss_score": 8.1, "verified": verified,
        "unit": unit, "handle_status": handle_status, "save_date": "2026-07-05 10:00:00",
        "norm_target": target, "norm_type": vtype, "impact": "x", "poc": "curl x",
    })


class FindingEndpointE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This in-memory endpoint suite has no signed activation file. Actual gates
        # are separately tested against the installed, activated QA services.
        gate = patch('sentinel_platform.router.gateway.activation_enforced', return_value=False)
        gate.start(); cls.addClassCleanup(gate.stop)
        set_repo(FakeRepo())
        cls.app = create_app()          # 注册 risk_intel(含 FINDING)，挂 intel + pentest_finding 端点
        cls.client = cls.app.test_client()

    def setUp(self):
        reset_repo()
        self.repo = FakeRepo()
        set_repo(self.repo)
        _seed_finding(self.repo, "f1", "http://a.acme.com/x", sev="high", verified=True)
        _seed_finding(self.repo, "f2", "http://b.acme.com/y", sev="critical", verified=True)
        _seed_finding(self.repo, "f3", "http://c.acme.com/z", sev="info", verified=False)  # 无证据的线索已被既有闸刀降为INFO
        # 空的 poc/nuclei 集合（三来源混排另两源为空）
        self.repo.collection(Collections.VULN)
        self.repo.collection(Collections.NUCLEI_RESULT)

    def tearDown(self):
        reset_repo()

    def _data(self, resp, code=200):
        self.assertEqual(resp.status_code, code)
        body = resp.get_json()
        self.assertEqual(body["code"], code)     # 前端契约 {code,message,data}
        return body["data"]

    # —— registry 装配：FINDING 已注册（不孤岛）——
    def test_modules_readiness_reports_finding(self):
        data = self.client.get("/api/meta/modules").get_json()["data"]
        self.assertTrue(data["modules"].get("finding"), "FINDING 应经 risk_intel.register 就绪")

    def test_swagger_contains_finding_paths(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/pentest/finding/unified" in p for p in spec["paths"]),
                        "finding 端点应进 OpenAPI 规范")

    def test_stat(self):
        data = self._data(self.client.get("/api/pentest/finding/stat"))
        # 2 verified + 1 lead；AI verified 计入
        self.assertGreaterEqual(data["ai"]["verified"], 2)
        self.assertIn("combined_total", data)

    def test_unified_list_default_hides_leads(self):
        data = self._data(self.client.get("/api/pentest/finding/unified?source=ai"))
        # 既有契约：默认最低等级low；无证据INFO线索f3隐藏，不再强制verified=True
        self.assertEqual(data["total"], 2)
        ids = {i["_id"] for i in data["items"]}
        self.assertEqual(ids, {"f1", "f2"})

    def test_unified_filter_severity(self):
        data = self._data(self.client.get("/api/pentest/finding/unified?source=ai&severity=critical"))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["_id"], "f2")

    def test_unified_detail(self):
        data = self._data(self.client.get("/api/pentest/finding/unified/detail?source=ai&id=f1"))
        self.assertEqual(data["target"], "http://a.acme.com/x")

    def test_unified_detail_missing_params_400(self):
        resp = self.client.get("/api/pentest/finding/unified/detail?source=ai")
        self.assertIn(resp.status_code, (400,))

    def test_unified_detail_not_found_404(self):
        resp = self.client.get("/api/pentest/finding/unified/detail?source=ai&id=nope")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()["code"], 404)

    def test_unified_mark_then_hidden(self):
        # 标记 f1 误报 → 默认列表应只剩 f2
        d = self._data(self.client.post("/api/pentest/finding/unified/mark",
                                        json={"source": "ai", "ids": ["f1"], "handle_status": "false_positive"}))
        self.assertEqual(d["modified"], 1)
        data = self._data(self.client.get("/api/pentest/finding/unified?source=ai"))
        self.assertEqual({i["_id"] for i in data["items"]}, {"f2"})

    def test_unified_mark_invalid_status_400(self):
        resp = self.client.post("/api/pentest/finding/unified/mark",
                                json={"source": "ai", "ids": ["f1"], "handle_status": "bogus"})
        self.assertEqual(resp.status_code, 400)

    def test_unified_delete(self):
        d = self._data(self.client.post("/api/pentest/finding/unified/delete",
                                        json={"source": "ai", "ids": ["f1", "f2"]}))
        self.assertEqual(d["deleted"], 2)
        data = self._data(self.client.get("/api/pentest/finding/unified?source=ai"))
        self.assertEqual(data["total"], 0)

    def test_delete_missing_ids_400(self):
        resp = self.client.post("/api/pentest/finding/unified/delete", json={"source": "ai", "ids": []})
        self.assertEqual(resp.status_code, 400)


    def test_revision_increases_after_mark_and_delete(self):
        before = self._data(self.client.get('/api/pentest/finding/revision'))
        self._data(self.client.post('/api/pentest/finding/unified/mark', json={'source':'ai','ids':['f1'],'handle_status':'submitted'}))
        marked = self._data(self.client.get('/api/pentest/finding/revision'))
        self.assertEqual(marked['revision'], before['revision'] + 1)
        self.assertNotEqual(marked['stamp'], before['stamp'])
        self._data(self.client.post('/api/pentest/finding/unified/delete', json={'source':'ai','ids':['f1']}))
        self.assertEqual(self._data(self.client.get('/api/pentest/finding/revision'))['revision'], marked['revision'] + 1)

    def test_watch_checks_presence_independent_of_filter(self):
        data = self._data(self.client.get('/api/pentest/finding/unified', query_string={'keyword':'no matching rows','watch':'{"ai":["f1","missing"]}'}))
        self.assertEqual(data['items'], [])
        self.assertEqual(data['present_ids'], ['f1'])

    def test_watch_unknown_collection_rejected(self):
        response = self.client.get('/api/pentest/finding/unified', query_string={'watch':'{"user":["x"]}'})
        self.assertEqual(response.status_code, 400)

    def test_watch_operator_injection_rejected(self):
        response = self.client.get('/api/pentest/finding/unified', query_string={'watch':'{"ai":[{"$ne":""}]}'})
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
