"""AI report assistance uses mocked models and never mutates saved evidence."""
import copy
import unittest
from unittest.mock import patch
from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import report_assist as assist
from sentinel_platform.modules.risk_intel.tests.test_report_template import _Repo


class ReportAssistTest(unittest.TestCase):
    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        self.addCleanup(set_repo, None)
        self.data = {"source": "finding", "source_id": "f1", "report": {"title": "样例"}, "findings": [{
            "finding_id": "f1", "vuln_type": "权限校验缺失", "evidence": "测试账号读取了另一测试账号的订单信息",
            "root_cause": "", "impact": "人工填写的影响", "poc": "原始请求", "reproduction_steps": [{"text": "原步骤"}], "screenshots": []}]}
        self.report = {"_id": "r1", "gen_mode": "template", "report_data": copy.deepcopy(self.data)}
        self.repo.collection("pentest_report").insert_one(self.report)
        p = patch("sentinel_platform.modules.risk_intel.report_template._resolve_learn_provider", return_value={"api_key": "fixture", "name": "mock-model"})
        self.provider = p.start(); self.addCleanup(p.stop)
        p = patch("sentinel_platform.modules.ai_pentest._llm.chat")
        self.chat = p.start(); self.addCleanup(p.stop)

    def response(self, changes):
        self.chat.return_value = {"ok": True, "tokens": 42, "tool_calls": [{"name": "propose_report_edits", "arguments": {"changes": changes, "warnings": []}}]}

    def change(self, **kw):
        result = {"finding_id": "f1", "field": "root_cause", "text": "订单读取缺少资源归属校验。",
            "source_field": "evidence", "source_quote": "测试账号读取了另一测试账号的订单信息", "reason": "根据现有响应整理原因"}
        result.update(kw)
        return result

    def test_grounded_proposals_are_read_only(self):
        original = copy.deepcopy(self.report)
        self.response([self.change()])
        result = assist.propose("r1", self.data)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["changes"][0]["before"], "")
        self.assertEqual(result["provider_name"], "mock-model")
        self.assertEqual(self.report, original)
        self.assertEqual(self.chat.call_args.kwargs["scene"], "template_learn")

    def test_protected_fields_and_invalid_quotes_are_rejected(self):
        self.response([self.change(field=field) for field in ("poc", "severity", "verification_status", "screenshots")]
                      + [self.change(source_quote="不存在的证据"), self.change(finding_id="other"), self.change(finding_id=[])])
        result = assist.propose("r1", self.data)
        self.assertEqual(result["changes"], [])
        self.assertEqual(len(result["warnings"]), 7)

    def test_only_empty_does_not_overwrite_manual_text(self):
        self.response([self.change(field="impact")])
        self.assertEqual(assist.propose("r1", self.data)["changes"], [])
        result = assist.propose("r1", self.data, only_empty=False)
        self.assertEqual(result["changes"][0]["before"], "人工填写的影响")

    def test_step_proposal_must_refer_to_existing_step(self):
        self.response([self.change(field="step_text", step_index=99)])
        self.assertEqual(assist.propose("r1", self.data, only_empty=False)["changes"], [])

    def test_unconfigured_or_invalid_model_output_is_an_error(self):
        self.provider.return_value = None
        self.assertIn("error", assist.propose("r1", self.data))
        self.chat.assert_not_called()
        self.provider.return_value = {"api_key": "fixture"}
        self.chat.return_value = {"ok": True, "content": "unstructured answer"}
        self.assertIn("error", assist.propose("r1", self.data))


if __name__ == "__main__":
    unittest.main()
