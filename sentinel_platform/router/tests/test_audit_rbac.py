"""Audit regression: actual gateway/route authorization, no bootstrap or network."""
import unittest
from unittest.mock import Mock, patch
from flask import Flask
from flask_restx import Api
from sentinel_platform.router import gateway
from sentinel_platform.router.endpoints import task_list, ai_pentest, api_keys
from sentinel_platform.modules.system import rbac


class AuditRbacTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        api = Api(self.app, prefix="/api")
        for ns in (task_list.ns, ai_pentest.ns, api_keys.ns):
            api.add_namespace(ns)
        gateway.install_gateway(self.app)
        self.user = {"username": "bob", "role": "viewer"}
        self.svc = Mock()
        self.svc.stop_task.return_value = {"ok": True}
        self.svc.resume_task.return_value = {"ok": True}
        self.svc.list_tasks.return_value = {"items": [], "total": 0, "page": 1, "size": 10}
        patches = [patch.object(gateway, "auth_enabled", return_value=True),
                   patch.object(gateway, "activation_enforced", return_value=False),
                   patch.object(gateway, "verify_token", side_effect=lambda _: self.user),
                   patch.object(gateway, "check_rbac", side_effect=rbac.check_permission),
                   patch("sentinel_platform.modules.honeypot_defense.attack_alert.is_banned", return_value=False)]
        patches += [patch.object(m, "_svc", return_value=self.svc) for m in (task_list, ai_pentest, api_keys)]
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        self.client = self.app.test_client()

    def test_viewer_cannot_mutate_with_get_or_post(self):
        for method in ("get", "post", "head"):
            for action in ("stop", "resume"):
                r = getattr(self.client, method)("/api/task/%s/audit" % action)
                self.assertEqual(r.status_code, 403)
        self.svc.stop_task.assert_not_called()
        self.svc.resume_task.assert_not_called()

    def test_authorized_operator_and_admin_keep_legacy_and_post(self):
        for role in ("operator", "admin"):
            self.user["role"] = role
            for method in ("get", "post"):
                self.assertEqual(getattr(self.client, method)("/api/task/stop/audit").status_code, 200)

    def test_empty_role_cannot_read_or_match_similar_prefix(self):
        self.user["role"] = "empty"
        for path in ("/api/task/", "/api/ai_config/config", "/api/api_keys/"):
            self.assertEqual(self.client.get(path).status_code, 403)
        self.assertFalse(rbac.check_permission({"role": "operator"}, "/api/task_unmapped", "GET")[0])

    def test_picker_omits_credentials_and_private_configuration(self):
        self.user["role"] = "operator"
        self.svc.list_providers.return_value = [{"_id": "p", "name": "test", "api_key": "SECRET", "base_url": "PRIVATE"}]
        self.svc.get_config_view.return_value = {"active_provider_id": "p", "max_context_tokens": 100, "source_code_dir": "PRIVATE"}
        self.svc.list_prompts.return_value = []
        r = self.client.get("/api/ai_config/options")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("SECRET", r.get_data(as_text=True))
        self.assertNotIn("PRIVATE", r.get_data(as_text=True))
        self.svc.list_prompts.assert_called_with(include_builtin=False)
        self.assertEqual(self.client.get("/api/ai_config/provider").status_code, 403)
