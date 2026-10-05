from pathlib import Path
import json,tempfile,unittest
from unittest.mock import Mock
from sentinel_platform.modules.about import _changelog

def row(version):return {'ver':version,'date':'2026-10-03','summary':'owned changelog fixture'}
class ChangelogCacheTest(unittest.TestCase):
    def setUp(self):self.directory=tempfile.TemporaryDirectory();self.root=Path(self.directory.name);(self.root/'version.txt').write_text('v1.21.168');self.path=self.root/'changelog.json'
    def tearDown(self):self.directory.cleanup()
    def test_old_present_log_refreshes_and_persists_for_legacy_hotupdated_users(self):
        self.path.write_text(json.dumps([row('v1.21.165')]))
        fetched=_changelog.current(self.root,lambda:[row('v1.21.168'),row('v1.21.167')])
        self.assertEqual(fetched[0]['ver'],'v1.21.168');self.assertEqual(json.loads(self.path.read_text()),fetched)
        self.assertEqual(_changelog.current(self.root,Mock(side_effect=AssertionError('Offline local read should not fetch'))),fetched)
    def test_rollback_does_not_show_future_versions(self):
        (self.root/'version.txt').write_text('v1.21.167');self.path.write_text(json.dumps([row('v1.21.168'),row('v1.21.167'),row('v1.21.166')]))
        self.assertEqual(_changelog.current(self.root,Mock())[0]['ver'],'v1.21.167')
    def test_missing_target_or_network_failure_retains_old_log(self):
        self.path.write_text(json.dumps([row('v1.21.165')]))
        self.assertEqual(_changelog.current(self.root,lambda:None),[row('v1.21.165')])
    def test_other_worker_version_change_does_not_write_stale_cache(self):
        self.path.write_text(json.dumps([row('v1.21.165')]))
        def fetch():(self.root/'version.txt').write_text('v1.21.169-1');return [row('v1.21.168')]
        _changelog.current(self.root,fetch)
        self.assertEqual(json.loads(self.path.read_text())[0]['ver'],'v1.21.165')

if __name__=='__main__':unittest.main()
