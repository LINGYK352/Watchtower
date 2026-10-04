import unittest
from unittest import mock
from bson import ObjectId
from sentinel_platform.contracts import Collections
from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.contracts.registry import reset_registry
from sentinel_platform.modules.risk_intel import _finding_index as index, vuln_center as vc
from sentinel_platform.modules.risk_intel.tests.test_vuln_center import _Repo


class FindingIndexTests(unittest.TestCase):
    def setUp(self):
        self.repo=_Repo(); set_repo(self.repo); reset_registry()
        self.addCleanup(reset_repo);self.addCleanup(reset_registry)
        self.coll=self.repo.collection(Collections.INTEL_FINDING)

    def add(self, target, date, **extra):
        row={'_id':ObjectId(),'source':'ai','vuln_type':'未授权访问','target':target,'save_date':date,
             'severity':'high','verified':False,'poc':'GET '+target+' HTTP/1.1',**extra}
        self.coll.insert_one(row)
        return row

    def test_legacy_missing_flags_have_exactly_one_first_per_point(self):
        a=self.add('https://example.test/a','2026-01-01')
        b=self.add('https://example.test/a','2026-01-02',first_seen=True)
        rows=vc.list_unified_findings(source='ai',dedup=False,size=100)['items']
        self.assertEqual(sum(row['first_seen'] is True for row in rows),1)
        self.assertEqual(next(row for row in rows if row['first_seen'])['_id'],str(a['_id']))
        self.assertFalse(next(row for row in rows if row['_id']==str(b['_id']))['first_seen'])

    def test_dedup_happens_before_pagination_and_total_is_global(self):
        for n in range(30): self.add('https://example.test/repeated','2026-03-%02d'%(n+1))
        for n in range(4): self.add('https://example.test/unique'+str(n),'2026-01-01')
        one=vc.list_unified_findings(source='ai',size=2,page=1)
        two=vc.list_unified_findings(source='ai',size=2,page=2)
        three=vc.list_unified_findings(source='ai',size=2,page=3)
        self.assertEqual([one['total'],two['total'],three['total']],[5,5,5])
        self.assertEqual([len(one['items']),len(two['items']),len(three['items'])],[2,2,1])
        ids=[r['_id'] for page in (one,two,three) for r in page['items']]
        self.assertEqual(len(set(ids)),5)
        self.assertEqual(next(r for r in one['items'] if '/repeated' in r['target'])['occurrence_count'],30)

    def test_same_timestamp_does_not_allow_later_hash_id_to_steal_first(self):
        first=self.add('https://example.test/a','2026-01-01',_id=ObjectId('ffffffffffffffffffffffff'),observed_at_ns=1)
        later=self.add('https://example.test/a','2026-01-01',_id=ObjectId('000000000000000000000001'),observed_at_ns=1)
        index.index_one(self.repo,first);index.index_one(self.repo,later)
        index.annotate(self.repo,[first,later])
        self.assertTrue(first['first_seen']);self.assertFalse(later['first_seen'])

    def test_older_backfill_replaces_first_atomically(self):
        later=self.add('https://example.test/a','2026-03-01');index.index_one(self.repo,later)
        older=self.add('https://example.test/a','2026-01-01');index.index_one(self.repo,older)
        index.annotate(self.repo,[later,older])
        self.assertFalse(later['first_seen']);self.assertTrue(older['first_seen'])

    def test_methods_and_parameters_merge_but_distinct_targets_stay_separate(self):
        self.add('https://example.test/a','2026-01-01',method='GET')
        self.add('https://example.test/a','2026-01-01',method='POST')
        self.add('https://example.test/a','2026-01-01',method='GET',parameter='id')
        self.add('https://other.test/a','2026-01-01',method='GET')
        self.assertEqual(vc.list_unified_findings(source='ai',size=10)['total'],2)

    def test_index_failure_does_not_report_successful_insert_as_failed(self):
        with mock.patch.object(index,'index_one',side_effect=RuntimeError('index offline')):
            result=vc.FindingServiceImpl().record_finding({'session_id':'s','target':'https://example.test/a','vuln_type':'未授权访问',
                'cvss_vector':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'})
        self.assertTrue(result['ok']);self.assertIsNone(result['first_seen'])
        self.assertEqual(self.coll.count_documents({}),1)
        self.assertEqual(index.ensure_legacy_index(self.repo),1)
