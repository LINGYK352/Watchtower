"""Autonomous report assembly from saved evidence; no target access or model calls."""
import copy
import json
import os
import unittest
from unittest.mock import Mock, patch
from docx import Document
from sentinel_platform.modules.risk_intel import report_evidence as ev
from sentinel_platform.modules.risk_intel import report_template as rt
from sentinel_platform.modules.risk_intel import report_template_ncc as ncc
from sentinel_platform.modules.risk_intel.tests import test_report_document as fixtures
png = fixtures.png


def record(body='{"case":"local fixture","records":1}'):
    from datetime import datetime, timezone
    return {"tool": "http_request", "arguments": {"url": "https://example.invalid/api/item", "method": "GET"},
        "result": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": body,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "http_version": "HTTP/1.1", "request_meta": {"method": "GET", "url": "https://example.invalid/api/item",
                "path": "/api/item", "headers": {"Authorization": "secret-fixture"}, "body": ""}}}


class AutoEvidenceTest(unittest.TestCase):
    def setUp(self):
        fixtures.ReportDocumentTest.setUp(self)
        p = patch('sentinel_platform.core.image_dir', return_value=self.root)
        p.start(); self.addCleanup(p.stop)

    def finding(self, rec=None):
        return {"finding_id": "fixture", "target": "https://example.invalid/api/item",
                "reproduction_steps": [], "evidence_records": [rec or record()]}

    def test_packets_are_generated_and_inserted_without_upload(self):
        f = self.finding()
        before = copy.deepcopy(f["evidence_records"])
        self.assertEqual(ev.prepare(f), [])
        self.assertTrue(f["screenshots"])
        self.assertEqual(f["screenshots"][0]["section"], "steps")
        self.assertIn('状态码为 200', f["reproduction_steps"][0]["text"])
        self.assertIn('非现场工具截图', f["screenshots"][0]["caption"])
        self.assertEqual(before, f["evidence_records"])
        self.assertNotIn('secret-fixture', ev._headers({'Authorization': 'secret-fixture'}))

    def test_invalid_response_does_not_invent_success(self):
        bad = record(); bad['result'] = {'error': 'timeout'}
        self.assertEqual(ev.packet_images(bad), [])
        bad['result'] = {'status_code': True}
        self.assertEqual(ev.packet_images(bad), [])

    def test_http_tool_preserves_the_prepared_request(self):
        from types import SimpleNamespace
        from sentinel_platform.modules.ai_pentest import _tools
        response = Mock(status_code=200, headers={'Content-Length': '2'}, encoding='utf-8')
        response.iter_content.return_value = iter([b'{}'])
        response.raw.version = 11
        response.request = SimpleNamespace(method='GET', url='https://example.invalid/actual',
            path_url='/actual', headers={'X-Sent': 'recorded'}, body=None)
        with patch('sentinel_platform.core.http.http_req', return_value=response), patch.object(_tools, '_svc', return_value=None):
            result = _tools._t_http_request({'url': 'https://example.invalid/input'}, {'mode': 'conservative'})
        self.assertEqual(result['request_meta']['url'], 'https://example.invalid/actual')
        self.assertEqual(result['request_meta']['headers'], {'X-Sent': 'recorded'})
        self.assertEqual(result['http_version'], 'HTTP/1.1')
        self.assertIn('observed_at', result)

    def test_browser_capture_is_immutable_and_does_not_navigate(self):
        folder = os.path.join(self.root, 'console_s1'); os.makedirs(folder)
        path = os.path.join(folder, 'latest.png')
        original = png((320, 200))
        with open(path, 'wb') as stream: stream.write(original)
        worker = Mock()
        worker.call.return_value = {'url': 'https://example.invalid/api/item', 'shot': '/image/console_s1/latest.png?t=1'}
        with patch('sentinel_platform.modules.ai_pentest._browser_session._worker_for', return_value=worker):
            result = ev.capture_browser('fixture', 's1', 'https://example.invalid/api/item')
        worker.call.assert_called_once_with('screenshot', {})
        with open(path, 'wb') as stream: stream.write(png((10, 10)))
        from PIL import Image
        stored = os.path.join(rt._finding_shots_dir('fixture'), result['name'])
        with Image.open(stored) as image:
            self.assertEqual(image.size, (320, 200))

    def test_action_archive_survives_latest_overwrite(self):
        folder = os.path.join(self.root, 'console_s1'); os.makedirs(folder)
        path = os.path.join(folder, 'latest.png')
        with open(path, 'wb') as stream: stream.write(png((320, 200)))
        url = ev.archive_session_shot('s1', {'url': 'https://example.invalid/api/item', 'shot': '/image/console_s1/latest.png'})
        os.remove(path)
        self.repo.collection('intel_pentest_session').insert_one({'_id': 's1', 'tool_log': [
            {'name': 'browser_goto', 'result': {'report_shot': url}}]})
        f = self.finding(); f['session_id'] = 's1'
        ev.prepare(f)
        self.assertTrue(any(s['provenance'].get('kind') == 'browser_capture' for s in f['screenshots']))

    def test_stale_packet_figures_are_not_reused_for_changed_evidence(self):
        first = self.finding(); ev.prepare(first)
        second = self.finding(record('{"case":"new observation"}')); ev.prepare(second)
        old = {s['name'] for s in first['screenshots']}
        self.assertFalse(old.intersection(s['name'] for s in second['screenshots']))

    def test_one_click_generation_includes_icp_packets_and_ai_text(self):
        self.repo.collection('icp_cache').insert_one({'domain': 'example.invalid', 'unit': '示例单位', 'icp_no': '本地测试记录', 'source': 'fixture'})
        finding = self.repo.collection('intel_finding').find_one({'_id': 'fixture'})
        finding.update(target='https://example.invalid/api/item', evidence=[record()], impact='本地测试记录展示权限问题', affected_ip='192.0.2.10')
        proposal = {'ok': True, 'warnings': [], 'changes': [
            {'finding_id': 'fixture', 'field': 'root_cause', 'after': '根据本地记录整理的原因'},
            {'finding_id': 'fixture', 'field': 'remediation', 'after': '建议补充资源归属校验'}]}
        with patch('sentinel_platform.modules.risk_intel.report_assist.propose_data', return_value=proposal) as ai:
            result = rt.generate_from_template(ncc.TEMPLATE_ID, 'finding', 'fixture')
        self.assertTrue(result.get('ok'), result)
        ai.assert_called_once()
        doc = Document(os.path.join(self.root, result['docx_path']))
        self.assertGreaterEqual(len(doc.inline_shapes), 2)
        text = '\n'.join(p.text for p in doc.paragraphs)
        self.assertIn('资源归属校验', text)
        self.assertIn('原始数据重建', text)
        self.assertTrue(result['delivery_ready'], result)


if __name__ == '__main__': unittest.main()
