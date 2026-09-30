import unittest
from unittest.mock import Mock, patch
from flask import Flask
from flask_restx import Api
from sentinel_platform.router import gateway
from sentinel_platform.router.endpoints import session as routes
from sentinel_platform.modules.system import rbac


class AuditOwnershipTest(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        Api(app, prefix='/api').add_namespace(routes.ns)
        gateway.install_gateway(app)
        self.client = app.test_client()
        self.user = {'username': 'bob', 'role': 'operator', 'permissions': []}
        self.svc = Mock()
        self.svc.get_session.side_effect = lambda sid, **kw: {'_id': sid, 'owner': 'alice' if sid == 'alice' else 'bob'}
        self.svc.get_session_messages.return_value = {'messages': []}
        for action in ('stop_session', 'resume_session', 'delete_session', 'run_session', 'delete_sessions', 'update_session_provider'):
            getattr(self.svc, action).return_value = {'ok': True}
        ps = [patch.object(routes, '_svc', return_value=self.svc),
              patch.object(gateway, 'verify_token', side_effect=lambda _: self.user),
              patch.object(gateway, 'auth_enabled', return_value=True),
              patch.object(gateway, 'activation_enforced', return_value=False),
              patch.object(gateway, 'check_rbac', side_effect=rbac.check_permission),
              patch('sentinel_platform.modules.honeypot_defense.attack_alert.is_banned', return_value=False)]
        for p in ps:
            p.start(); self.addCleanup(p.stop)

    def test_all_id_endpoints_reject_other_owner(self):
        for suffix, method in (('', 'get'), ('/messages', 'get'), ('/start', 'post'),
                               ('/resume', 'post'), ('/stop', 'post'), ('/delete', 'post'), ('/set_provider', 'post')):
            self.assertEqual(getattr(self.client, method)('/api/pentest/session/alice' + suffix, json={}).status_code, 403)
        for action in ('stop_session', 'resume_session', 'delete_session', 'run_session', 'update_session_provider'):
            getattr(self.svc, action).assert_not_called()

    def test_mixed_batch_rejects_before_deleting_own(self):
        r = self.client.post('/api/pentest/session/delete', json={'ids': ['bob', 'alice']})
        self.assertEqual(r.status_code, 403)
        self.svc.delete_sessions.assert_not_called()

    def test_owner_and_explicit_view_all_and_admin(self):
        self.assertEqual(self.client.get('/api/pentest/session/bob').status_code, 200)
        self.assertEqual(self.client.post('/api/pentest/session/bob/stop').status_code, 200)
        self.user['permissions'] = ['pentest:view_all']
        self.assertEqual(self.client.get('/api/pentest/session/alice').status_code, 200)
        self.user.update(role='admin', permissions=[])
        self.assertEqual(self.client.post('/api/pentest/session/alice/stop').status_code, 200)

    def test_auth_disabled_keeps_single_user_access(self):
        with patch.object(gateway, 'auth_enabled', return_value=False):
            self.assertEqual(self.client.get('/api/pentest/session/alice').status_code, 200)
