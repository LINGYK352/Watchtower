import tempfile, unittest
from unittest.mock import patch
from flask import Flask
from sentinel_platform.router.endpoints import about


class UpdateOptionsTest(unittest.TestCase):
    def test_rollback_full_flag_and_default_preserve_contract(self):
        app=Flask(__name__)
        for extra, expected in [({},False),({'full':True},True)]:
            with app.test_request_context(json=dict(version='v1.21.166',**extra)), \
                 patch.object(about,'_get_progress',return_value={'phase':'idle'}), \
                 patch.object(about,'_read_update_key',return_value='test-only'), \
                 patch.object(about,'_source_url',return_value='http://example.invalid'), \
                 patch.object(about,'_project_root',return_value='/test-only'), \
                 patch.object(about,'_launch_updater') as launch:
                result=about._Rollback().post()
                self.assertEqual(result['code'],200)
                launch.assert_called_once_with('http://example.invalid','test-only','/test-only','v1.21.166',full=expected)

    def test_non_boolean_full_is_rejected_before_launch(self):
        app=Flask(__name__)
        with app.test_request_context(json={'version':'v1.21.166','full':'false'}),patch.object(about,'_launch_updater') as launch:
            result,status=about._Rollback().post();self.assertNotEqual(result['code'],200);launch.assert_not_called()

    def test_detached_process_receives_full_mode(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(about,'_set_progress'),patch.object(about.subprocess,'Popen') as launch:
            about._launch_updater('http://example.invalid','test-only',folder,'v1.21.166',full=True)
            args=launch.call_args[0][0]
            self.assertEqual(args[-2:],['v1.21.166','--full'])
            self.assertEqual(launch.call_args[1]['cwd'],folder)

if __name__=='__main__':unittest.main()
