"""端到端：登录→token→网关鉴权→RBAC。证明 user_manage 经 router 真正接驳+权限校验生效。

用真 Flask app + 内存 repo：种 admin/viewer，验证登录发 token、带 token 过网关、
无 token 被 401、viewer 访问 user:manage 被 403（RBAC 真拦，非降级）。
"""
import unittest
from unittest import mock

from sentinel_platform.core import set_repo


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def find(self, q=None):
        return list(self.docs)
    def insert_one(self, doc):
        self.docs.append(dict(doc))
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
        elif upsert:
            nd = dict(q); nd.update(upd.get("$set", {})); self.docs.append(nd)
    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)
    def count_documents(self, q):
        return sum(1 for d in self.docs
                   if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)))


class _FakeRepo:
    def __init__(self):
        self._c = {}
    def collection(self, name):
        return self._c.setdefault(name, _FakeColl())


class TestUserAuthE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(_FakeRepo())
        from sentinel_platform.modules.system.user_manage import get_service
        svc = get_service()
        svc.create_user("admin", "admin123", "admin")
        svc.create_user("bob", "bob12345", "viewer")
        # AUTH 开启（否则网关全放行）：patch config.section
        from sentinel_platform.router import create_app
        cls.app = create_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        set_repo(None)

    def _login(self, u, p):
        r = self.client.post("/api/user/login", json={"username": u, "password": p})
        return r.get_json()

    def test_login_returns_token(self):
        body = self._login("admin", "admin123")
        self.assertEqual(body["code"], 200)
        self.assertTrue(body["data"]["token"])
        self.assertEqual(body["data"]["role"], "admin")

    def test_login_wrong_401(self):
        body = self._login("admin", "wrong")
        self.assertEqual(body["code"], 401)

    def test_authed_request_with_token(self):
        """AUTH 开启下，带 admin token 访问 user_manage 应通过网关+RBAC。"""
        token = self._login("admin", "admin123")["data"]["token"]
        with mock.patch("sentinel_platform.router.gateway.auth_enabled", return_value=True):
            r = self.client.get("/api/user_manage/manage/users", headers={"Token": token})
        body = r.get_json()
        self.assertEqual(body["code"], 200)
        self.assertTrue(any(u["username"] == "admin" for u in body["data"]["items"]))

    def test_no_token_401_when_auth_on(self):
        with mock.patch("sentinel_platform.router.gateway.auth_enabled", return_value=True):
            r = self.client.get("/api/user_manage/manage/users")
        self.assertEqual(r.status_code, 401)

    def test_viewer_forbidden_user_manage(self):
        """RBAC 真拦：viewer 无 user:manage → 403（证明权限校验非降级放行）。"""
        token = self._login("bob", "bob12345")["data"]["token"]
        with mock.patch("sentinel_platform.router.gateway.auth_enabled", return_value=True):
            r = self.client.get("/api/user_manage/manage/users", headers={"Token": token})
        self.assertEqual(r.status_code, 403)

    def test_login_public_no_token_needed(self):
        """登录端点公开：AUTH 开启也不拦。"""
        with mock.patch("sentinel_platform.router.gateway.auth_enabled", return_value=True):
            body = self._login("admin", "admin123")
        self.assertEqual(body["code"], 200)


if __name__ == "__main__":
    unittest.main()
