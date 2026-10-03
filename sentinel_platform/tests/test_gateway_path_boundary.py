import unittest
from unittest.mock import patch,Mock
from flask import Flask
from sentinel_platform.router import gateway

class GatewayPathBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.app=Flask(__name__)
        self.app.add_url_rule('/api-keys',endpoint='spa',view_func=lambda:'owned-spa-shell')
        self.app.add_url_rule('/api/private',endpoint='private',view_func=lambda:'must-require-auth')
        self.app.add_url_rule('/api',endpoint='api-root',view_func=lambda:'must-require-auth')
        gateway.install_gateway(self.app)
        self.patches=[patch.object(gateway,'auth_enabled',return_value=True),patch.object(gateway,'activation_enforced',return_value=False),patch.object(gateway,'verify_token',return_value=None),patch.object(gateway,'get_registry',return_value=Mock(get=Mock(return_value=None))),patch('sentinel_platform.modules.honeypot_defense.attack_alert.is_banned',return_value=False)]
        for item in self.patches:item.start()
    def tearDown(self):
        for item in reversed(self.patches):item.stop()
    def test_spa_name_that_begins_with_api_is_not_an_api_request(self):
        response=self.app.test_client().get('/api-keys')
        self.assertEqual(response.status_code,200);self.assertEqual(response.data,b'owned-spa-shell')
    def test_actual_api_stays_authenticated_including_encoded_slash(self):
        for path in ['/api','/api/private','/api%2fprivate']:
            self.assertEqual(self.app.test_client().get(path).status_code,401,path)

if __name__=='__main__':unittest.main()
