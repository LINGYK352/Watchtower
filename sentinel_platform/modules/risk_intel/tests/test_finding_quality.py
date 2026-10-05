import copy
import json
import unittest
from unittest import mock
from bson import ObjectId
from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.contracts.registry import reset_registry
from sentinel_platform.contracts import Collections
from sentinel_platform.modules.risk_intel import vuln_center as vc, _finding_quality as q, _cvss
from sentinel_platform.modules.risk_intel.tests.test_vuln_center import _Repo, _http_call


class FindingQualityTests(unittest.TestCase):
    def setUp(self):
        self.repo = _Repo()
        set_repo(self.repo)
        reset_registry()
        self.addCleanup(reset_repo)
        self.addCleanup(reset_registry)
        self.service = vc.FindingServiceImpl()
        self.sid = str(ObjectId())
        self.repo.collection(Collections.PENTEST_SESSION).insert_one({'_id': ObjectId(self.sid), 'tool_log': []})
        self.finding = {'session_id': self.sid, 'target': 'https://example.test/api/users',
                        'vuln_type': '未授权访问', 'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}

    def confirmed_call(self):
        call=_http_call(self.finding['target'])
        result=json.loads(call['result']) if isinstance(call['result'],str) else call['result']
        result['body']='{"passwordHash":"FAKEHASHFOROWNEDTEST1234567890","internalData":["owned-fixture"]}'
        call['result']=json.dumps(result)
        return call

    def test_high_lead_does_not_become_info(self):
        result = self.service.record_finding(self.finding)
        self.assertEqual(result['severity'], 'high')
        self.assertFalse(result['verified'])

    def test_manual_severity_survives_repair_and_evidence_upgrade(self):
        row = dict(self.finding, _id=ObjectId(), severity='low', manual_severity='low', verified=False,
                   poc='', source='ai', save_date='2026-09-22', severity_basis='人工复核')
        coll = self.repo.collection(Collections.INTEL_FINDING)
        coll.insert_one(row)
        vc.reconcile_session_findings(self.sid)
        self.assertEqual(row['severity'], 'low')
        with mock.patch.object(vc, '_adversarial_review', return_value={'verdict': 'confirmed'}):
            result = self.service.record_finding(dict(self.finding, tool_log=[self.confirmed_call()]))
        self.assertTrue(result['verified'])
        self.assertEqual(result['severity'], 'low')

    def test_minor_confidentiality_is_not_no_impact(self):
        vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
        self.assertEqual(_cvss.calibrate_severity('medium', 5.3, '未授权访问', '业务数据', vector)[0], 'medium')
        vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
        self.assertEqual(_cvss.calibrate_severity('medium', 5.3, '未授权访问', 'version 配置被修改', vector)[0], 'medium')

    def test_alias_session_parameter_and_method_changes_keep_same_endpoint_type_unique(self):
        one = self.service.record_finding(self.finding)
        two = self.service.record_finding(dict(self.finding, vuln_type='未授权访问-管理员信息及密码哈希泄露'))
        self.assertEqual(one['id'], two['id'])
        self.assertTrue(two['dup'])
        self.assertEqual(one['id'], self.service.record_finding(dict(self.finding, session_id=str(ObjectId())))['id'])
        self.assertEqual(one['id'], self.service.record_finding(dict(self.finding, parameter='other'))['id'])
        get = self.service.record_finding(dict(self.finding, method='GET'))
        post = self.service.record_finding(dict(self.finding, method='POST'))
        self.assertEqual(get['id'], post['id'])

    def test_post_cannot_borrow_get_evidence(self):
        result = self.service.record_finding(dict(self.finding, method='POST', tool_log=[_http_call(self.finding['target'])]))
        self.assertFalse(result['verified'])

    def test_other_endpoint_case_and_vulnerability_are_distinct(self):
        self.assertNotEqual(q.identity('s', 'https://x.test/API', '未授权访问'), q.identity('s', 'https://x.test/api', '未授权访问'))
        self.assertNotEqual(q.identity('s', 'https://x.test/a', '未授权访问'), q.identity('s', 'https://x.test/a', 'SQL注入'))

    def test_repeat_can_upgrade_evidence_without_creating_another_row(self):
        one = self.service.record_finding(self.finding)
        finding = dict(self.finding, tool_log=[self.confirmed_call()])
        with mock.patch.object(vc, '_adversarial_review', return_value={'verdict': 'confirmed'}):
            two = self.service.record_finding(finding)
            three = self.service.record_finding(self.finding)
        self.assertEqual(one['id'], two['id'])
        self.assertTrue(two['upgraded'])
        self.assertTrue(three['verified'])
        self.assertEqual(self.repo.collection(Collections.INTEL_FINDING).count_documents({}), 1)

    def test_description_becomes_notes_and_only_current_endpoint_becomes_request(self):
        finding = dict(self.finding, poc='信息查询类：\n1. GET /api/users → 管理员信息\n2. GET /api/dicts → 字典')
        value = q.reproduction(finding, [])
        self.assertTrue(value['poc'].startswith('GET /api/users HTTP/1.1'))
        self.assertNotIn('/api/dicts', value['poc'])
        self.assertIn('/api/dicts', value['poc_notes'])
        self.assertEqual(value['poc_quality'], 'needs_review')

    def test_prose_never_becomes_an_invented_request(self):
        value = q.reproduction(dict(self.finding, poc='浏览器能访问，存在严重漏洞'), [])
        self.assertEqual(value['poc'], '')
        self.assertEqual(value['poc_quality'], 'missing_request')

    def test_reported_post_without_http_version_preserves_body(self):
        finding = dict(self.finding, poc='POST /api/users\nContent-Type: application/json\n\n{"name":"测试","password":"secretvalue"}')
        value = q.reproduction(finding, [])
        self.assertTrue(value['poc'].startswith('POST /api/users HTTP/1.1'))
        self.assertIn('Content-Type: application/json', value['poc'])
        self.assertNotIn('secretvalue', value['poc'])
        headers, body = value['poc'].split('\n\n', 1)
        self.assertIn('Content-Length: '+str(len(body.encode('utf-8'))), headers)

    def test_explicit_host_header_is_preserved(self):
        request = q.http_request_text({'url':'https://example.test/api/users','headers':{'Host':'alternate.test'}})
        self.assertIn('Host: alternate.test', request)

    def test_captured_request_preserves_method_body_query_and_redacts_credentials(self):
        log = {'name': 'http_request', 'arguments': {'url': self.finding['target'] + '?page=2&token=testsecret',
               'method': 'POST', 'headers': {'Authorization': 'Bearer testsecret', 'Content-Type': 'application/json'},
               'body': {'password': 'testsecret', 'limit': 10}}, 'result': {'status_code': 200}}
        value = q.reproduction(self.finding, [log])
        self.assertTrue(value['poc'].startswith('POST /api/users?page=2&token='))
        self.assertNotIn('testsecret', value['poc'])
        self.assertIn('"limit": 10', value['poc'])
        self.assertEqual(value['poc_source'], 'tool_log')

    def test_reported_curl_quotes_remain_valid_after_redaction(self):
        import shlex
        finding = dict(self.finding, poc="curl 'https://example.test/api/users' -H 'Authorization: Bearer secretvalue' --data '{\"password\":\"secretvalue\",\"n\":1}'")
        value = q.reproduction(finding, [])
        self.assertNotIn('secretvalue', value['poc'])
        self.assertEqual(shlex.split(value['poc'])[0], 'curl')

    def test_script_print_is_not_confirmed_http_evidence(self):
        log = {'name': 'run_script', 'arguments': {'code': "print('/api/users success')"},
               'result': {'exit_code': 0, 'stdout': '/api/users success'}}
        result = self.service.record_finding(dict(self.finding, tool_log=[log]))
        self.assertFalse(result['verified'])
        stored = self.repo.collection(Collections.INTEL_FINDING).find_one({'_id': ObjectId(result['id'])})
        self.assertEqual(stored['supporting_evidence'][0]['tool_log_index'], 0)

    def test_markdown_response_block_is_not_selected_as_poc(self):
        text = '### 1. 未授权访问 | ' + self.finding['cvss_vector'] + '\n- 目标: ' + self.finding['target'] + '\n- 危害: test\n```json\n{"state":0}\n```\n```bash\ncurl https://example.test/api/users\n```'
        findings, _ = vc.parse_findings_md(text)
        self.assertTrue(findings[0]['poc'].startswith('curl '))

    def test_legacy_repair_is_idempotent_and_keeps_duplicate_history(self):
        coll = self.repo.collection(Collections.INTEL_FINDING)
        for i, title in enumerate(['未授权访问', '未授权访问-管理员信息泄露']):
            row = dict(self.finding, _id=ObjectId(), vuln_type=title, severity='info', verified=False,
                       source='ai', severity_capped_by_evidence=True, save_date='2026-09-22 00:00:0' + str(i),
                       poc='GET /api/users → 管理员信息')
            coll.insert_one(row)
        preview = vc.reconcile_session_findings(self.sid, dry_run=True)
        self.assertEqual(len(preview['duplicates']), 1)
        self.assertTrue(all(row['severity'] == 'info' for row in coll.docs))
        vc.reconcile_session_findings(self.sid)
        self.assertEqual(coll.count_documents({}), 3)  # 原始两条保留为历史别名，规范 ID 一条。
        self.assertEqual(coll.count_documents({'duplicate_of': None}), 1)
        self.assertEqual(coll.find_one({'duplicate_of':None})['severity'],'high')
        self.assertEqual(coll.count_documents({'duplicate_of':None}),1)
        self.assertFalse(vc.reconcile_session_findings(self.sid)['updates'])
