"""Report editor transport contract; no Mongo, document creation or network."""
import unittest
from unittest.mock import Mock, patch
from flask import Flask
from flask_restx import Api
from sentinel_platform.router.endpoints import asset_intel as endpoint


class ReportEditorEndpointsTest(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        Api(app).add_namespace(endpoint.ns, path="/api/intel")
        self.client = app.test_client()
        self.service = Mock()
        p = patch.object(endpoint, "_svc", return_value=self.service)
        p.start()
        self.addCleanup(p.stop)

    def test_save_forwards_structured_report_data(self):
        self.service.update_report.return_value = {"ok": True}
        data = {"report": {"title": "edited"}, "findings": []}
        response = self.client.put("/api/intel/pentest_report/report-1", json={"title": "edited", "report_data": data})
        self.assertEqual(response.status_code, 200)
        self.service.update_report.assert_called_once_with("report-1", content=None, title="edited", report_data=data)

    def test_template_detail_includes_editor_snapshot(self):
        self.service.get_report.return_value = {"_id": "report-1", "gen_mode": "template"}
        data = {"report": {"title": "original"}, "findings": []}
        with patch("sentinel_platform.modules.risk_intel.report_template.editor_data", return_value=data):
            response = self.client.get("/api/intel/pentest_report/report-1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["report_data"], data)

    def test_failed_render_is_reported_as_save_failure(self):
        self.service.update_report.return_value = {"error": "missing evidence image"}
        response = self.client.put("/api/intel/pentest_report/report-1", json={"report_data": {}})
        self.assertEqual(response.status_code, 400)
        self.assertIn("missing evidence", response.json["message"])

    def test_ai_assist_only_returns_proposals(self):
        self.service.assist_report.return_value = {"ok": True, "changes": [], "warnings": []}
        response = self.client.post("/api/intel/pentest_report/report-1/assist", json={"instruction": "完善文字"})
        self.assertEqual(response.status_code, 200)
        self.service.assist_report.assert_called_once_with("report-1", draft=None, instruction="完善文字", provider_id="", only_empty=True)
        self.service.update_report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
