"""信封 + 网关纯逻辑单测（不需 flask app）。

覆盖：①envelope/ok/err/page 形态对齐前端契约 ②is_public 豁免 ③verify_token master key
④check_rbac admin 放行 + 依赖未就绪降级放行。
"""
import unittest
from unittest import mock

from sentinel_platform.router import envelope as env
from sentinel_platform.router import gateway as gw


class TestEnvelope(unittest.TestCase):
    def test_ok_shape(self):
        r = env.ok({"x": 1})
        self.assertEqual(r["code"], 200)
        self.assertEqual(r["message"], "ok")
        self.assertEqual(r["data"], {"x": 1})

    def test_none_data_becomes_empty(self):
        self.assertEqual(env.ok()["data"], {})

    def test_err_returns_status_tuple(self):
        body, status = env.err(403)
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], 403)
        self.assertIn("权限", body["message"])

    def test_page_shape(self):
        r = env.page([1, 2], total=5, page_no=1, size=10)
        self.assertEqual(r["code"], 200)
        self.assertEqual(r["data"]["total"], 5)
        self.assertEqual(r["data"]["items"], [1, 2])
        self.assertEqual(set(r["data"]), {"page", "size", "total", "items"})


class TestGatewayLogic(unittest.TestCase):
    def test_is_public(self):
        self.assertTrue(gw.is_public("/api/user/login"))
        self.assertTrue(gw.is_public("/api/meta/health"))
        self.assertTrue(gw.is_public("/api/doc"))
        self.assertFalse(gw.is_public("/api/task/"))

    def test_disclaimer_public_only_for_get(self):
        # 免责声明签署状态 GET 公开（首登弹窗需登录前后都能读）；POST(记录同意)须登录 token。
        self.assertTrue(gw.is_public("/api/meta/disclaimer", "GET"))
        self.assertFalse(gw.is_public("/api/meta/disclaimer", "POST"))
        # 不传 method 时不命中方法级豁免（保守：默认不公开）
        self.assertFalse(gw.is_public("/api/meta/disclaimer"))

    def test_verify_token_master_key(self):
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: "MASTERKEY123" if a[:1] == ("API_KEY",) else k.get("default", "")
        with mock.patch.object(gw, "get_config", return_value=cfg):
            self.assertIsNone(gw.verify_token(""))
            u = gw.verify_token("MASTERKEY123")
        self.assertEqual(u["role"], "admin")
        self.assertEqual(u["via"], "master_key")

    def test_verify_token_wrong(self):
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: "MASTERKEY123" if a[:1] == ("API_KEY",) else k.get("default", "")
        reg = mock.Mock()
        reg.get.return_value = None            # 无用户服务
        with mock.patch.object(gw, "get_config", return_value=cfg), \
             mock.patch.object(gw, "get_registry", return_value=reg):
            self.assertIsNone(gw.verify_token("wrong"))

    def test_rbac_admin_pass(self):
        allow, reason = gw.check_rbac({"role": "admin"}, "/api/task/", "POST")
        self.assertTrue(allow)

    def test_rbac_degrades_when_service_absent(self):
        reg = mock.Mock()
        reg.get.return_value = None            # rbac 服务未注册
        with mock.patch.object(gw, "get_registry", return_value=reg):
            allow, reason = gw.check_rbac({"role": "operator"}, "/api/task/", "POST")
        self.assertTrue(allow)                 # 降级放行不阻断
        self.assertEqual(reason, "rbac_not_ready")


class TestDualAuthBoundary(unittest.TestCase):
    """双鉴权体系边界核验（核心链路 §11.3.1）：用户会话 Token 与分发系统激活 JWT key
    两套凭证绝不串用。静态扫源码，防回归把两套混起来。"""

    def _read(self, *rel):
        import os
        # 本文件在 sentinel_platform/router/tests/ → 上溯 3 层到项目根
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
        p = os.path.join(root, *rel)
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

    def test_platform_calls_distribution_with_update_key_not_user_token(self):
        """主平台对分发系统的出站调用统一用 X-Update-Key（激活凭证），不掺用户 Token。"""
        about = self._read("sentinel_platform", "router", "endpoints", "about.py")
        # 所有对 _source_url() 的出站请求都应带 X-Update-Key，且取自 _read_update_key()
        self.assertIn("X-Update-Key", about)
        self.assertIn("_read_update_key", about)
        # about.py 里对分发系统的请求不得注入用户会话 Token 头
        self.assertNotIn('"Token"', about)
        self.assertNotIn("verify_token", about)

    def test_distribution_does_not_accept_platform_user_token(self):
        """分发系统不认主平台用户会话 token：不出现 Token 头消费 / verify_token。"""
        try:
            src = self._read("云端", "distribution", "update_source.py")
        except OSError:
            self.skipTest("分发系统源码不在此检出（独立系统），跳过")
        # 分发系统认自己的 X-Update-Key / X-Admin-Token / X-User-Token，但不认主平台的 "Token"
        self.assertIn("X-Update-Key", src)
        self.assertNotIn("verify_token", src)
        # 客户端拉取端点统一过 validate_key 闸（激活 JWT 校验）
        self.assertIn("validate_key", src)

    def test_activation_key_read_is_disk_fresh(self):
        """激活 key 走 activation.read_key（fresh 读盘，多 worker 一致），不经用户体系。"""
        act = self._read("sentinel_platform", "modules", "system", "activation.py")
        self.assertIn("def read_key", act)
        # 激活模块不应依赖用户会话 token 校验
        self.assertNotIn("verify_token", act)


if __name__ == "__main__":
    unittest.main()
