"""回归⑤：证据强制端点精确匹配 match_evidence（vuln_center.py:289）。

事故（记忆 sentinel-finding-quality-fixes P1）：父路径误挂子路径（/api 误挂 /api/user/list）。
规则：VERIFY_TOOLS 调用的 url 归一化端点(host+path)**精确相等**才算命中；host 不同不匹配。
返回 (level, evidence)：confirmed(有正向证据)/attempted(打过但否定)/none(没打)。

R-02 可追溯锚（纯加法层，plan rustling-conjuring-river）：每条 positive hit 补
observation_id/req_hash/resp_hash/method/status_code/complete/partial/truncated。
红线：锚字段恒在、内容散列稳定、非 http 工具降级不炸、complete 如实反映 truncated。
"""
import unittest

from sentinel_platform.modules.risk_intel.vuln_center import match_evidence


def _http(url, status, body=""):
    return {"name": "http_request", "arguments": {"url": url},
            "result": {"status_code": status, "body": body, "body_length": len(body)}}


class MatchEvidenceRegression(unittest.TestCase):
    def test_empty_or_no_target_none(self):
        self.assertEqual(match_evidence({"target": ""}, [])[0], "none")
        self.assertEqual(match_evidence({"target": "http://t.com/a"}, [])[0], "none")

    def test_parent_path_not_matched_to_child(self):
        """红线：finding target=/api，工具只打过 /api/user/list（子路径）→ 不算该 finding 的证据。"""
        log = [_http("http://t.com/api/user/list", 200, "x" * 300)]
        lvl, _ = match_evidence({"target": "http://t.com/api"}, log)
        self.assertNotEqual(lvl, "confirmed")

    def test_exact_endpoint_positive_confirmed(self):
        log = [_http("http://t.com/api/x", 200, "root" * 80)]
        lvl, ev = match_evidence({"target": "http://t.com/api/x"}, log)
        self.assertEqual(lvl, "confirmed")
        self.assertTrue(ev)

    def test_different_host_not_matched(self):
        log = [_http("http://other.com/api/x", 200, "x" * 300)]
        lvl, _ = match_evidence({"target": "http://t.com/api/x"}, log)
        self.assertEqual(lvl, "none")

    def test_attempted_when_negative(self):
        """精确端点打过但响应否定(404)→ attempted 而非 confirmed（不能凭'打过'判真）。"""
        log = [_http("http://t.com/api/x", 404, "not found")]
        lvl, ev = match_evidence({"target": "http://t.com/api/x"}, log)
        self.assertEqual(lvl, "attempted")
        self.assertEqual(ev, [])


class EvidenceAnchorRegression(unittest.TestCase):
    """R-02 可追溯锚：positive hit 每条带全锚字段，散列稳定，降级不炸。"""

    _ANCHOR_KEYS = ("observation_id", "req_hash", "resp_hash", "method",
                    "status_code", "complete", "partial", "truncated")

    def test_anchor_fields_present(self):
        """positive http hit → 含全部锚字段，method=GET、status_code=200、complete=True。"""
        log = [_http("http://t.com/api/x", 200, "root" * 80)]
        lvl, ev = match_evidence({"target": "http://t.com/api/x"}, log)
        self.assertEqual(lvl, "confirmed")
        self.assertTrue(ev)
        hit = ev[0]
        for k in self._ANCHOR_KEYS:
            self.assertIn(k, hit, "锚字段缺失: {}".format(k))
        self.assertEqual(hit["method"], "GET")
        self.assertEqual(hit["status_code"], 200)
        self.assertIs(hit["complete"], True)
        self.assertIs(hit["partial"], False)
        self.assertIs(hit["truncated"], False)
        # 散列恒可算、非空、十六进制
        self.assertEqual(len(hit["resp_hash"]), 64)
        self.assertEqual(len(hit["observation_id"]), 16)
        self.assertTrue(hit["req_hash"])

    def test_complete_flag_on_truncated(self):
        """关键坑：partial=True 会被 _positive_signal 判 unknown 进不了 hits；
        测 complete=False 必须用 truncated（signal 仍 positive → 进 hits）。"""
        log = [{"name": "http_request", "arguments": {"url": "http://t.com/api/x"},
                "result": {"status_code": 200, "body": "root" * 80,
                           "body_length": 320, "truncated": True}}]
        lvl, ev = match_evidence({"target": "http://t.com/api/x"}, log)
        self.assertEqual(lvl, "confirmed")
        self.assertTrue(ev)
        hit = ev[0]
        self.assertIs(hit["truncated"], True)
        self.assertIs(hit["complete"], False)

    def test_hash_stable(self):
        """同一 result 两次 match_evidence → resp_hash/observation_id 相等（内容散列稳定，非序号）。"""
        finding = {"target": "http://t.com/api/x"}
        log = [_http("http://t.com/api/x", 200, "root" * 80)]
        _, ev1 = match_evidence(finding, log)
        _, ev2 = match_evidence(finding, [dict(log[0])])
        self.assertEqual(ev1[0]["resp_hash"], ev2[0]["resp_hash"])
        self.assertEqual(ev1[0]["observation_id"], ev2[0]["observation_id"])

    def test_nuclei_anchor_degrade(self):
        """run_nuclei hit（url 命中 + count>0）→ method 空串、status_code None、complete True（降级不炸）。"""
        log = [{"name": "run_nuclei", "arguments": {"url": "http://t.com/api/x"},
                "result": {"count": 2, "hits": [{"template": "cve-x"}]}}]
        lvl, ev = match_evidence({"target": "http://t.com/api/x"}, log)
        self.assertEqual(lvl, "confirmed")
        self.assertTrue(ev)
        hit = ev[0]
        self.assertEqual(hit["method"], "")
        self.assertIsNone(hit["status_code"])
        self.assertIs(hit["complete"], True)
        self.assertTrue(hit["resp_hash"])


if __name__ == "__main__":
    unittest.main()
