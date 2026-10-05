"""user_manage + rbac 单测 —— 纯逻辑 + 服务(注入内存 repo)，不需真 Mongo。

覆盖：①rbac 权限解析/校验(admin/operator/viewer/自定义/fail-closed) ②登录口令哈希+token
③用户CRUD+防删最后管理员 ④角色CRUD+内置不可改 ⑤verify_token。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.system import rbac
from sentinel_platform.modules.system.user_manage import (
    UserManageService, hash_password)


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
            return type("R", (), {"matched_count": 1, "modified_count": 1})()
        elif upsert:
            nd = dict(q)
            nd.update(upd.get("$set", {}))
            self.docs.append(nd)
            return type("R", (), {"matched_count": 0, "modified_count": 0})()
        return type("R", (), {"matched_count": 0, "modified_count": 0})()

    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)

    def count_documents(self, q):
        return sum(1 for d in self.docs
                   if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)))


class _FakeRepo:
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


class TestRbac(unittest.TestCase):
    def test_admin_all_perms(self):
        self.assertEqual(set(rbac.resolve_perms({"role": "admin"})), set(rbac.ALL_PERMS))

    def test_viewer_readonly(self):
        perms = rbac.resolve_perms({"role": "viewer"})
        self.assertIn("task:read", perms)
        self.assertNotIn("task:write", perms)

    def test_check_admin_pass(self):
        allow, _ = rbac.check_permission({"role": "admin"}, "/api/task/", "DELETE")
        self.assertTrue(allow)

    def test_check_viewer_write_denied(self):
        allow, _ = rbac.check_permission({"role": "viewer"}, "/api/task/create", "POST")
        self.assertFalse(allow)

    def test_check_unmapped_get_denied(self):
        allow, _ = rbac.check_permission({"role": "viewer"}, "/api/unmapped", "GET")
        self.assertFalse(allow)

    def test_write_failclosed(self):
        # operator 对未映射写操作 → 需 user:manage → 拒
        allow, reason = rbac.check_permission({"role": "operator"}, "/api/unmapped", "POST")
        self.assertFalse(allow)

    def test_user_manage_needs_perm(self):
        allow, _ = rbac.check_permission({"role": "operator"}, "/api/user_manage/manage/users", "GET")
        self.assertFalse(allow)                # operator 无 user:manage

    def test_self_service_change_pass_allowed(self):
        # 自助改密：viewer/operator 改自己密码(/api/user/change_pass POST)必须放行(非 user_manage)
        for role in ("viewer", "operator"):
            allow, reason = rbac.check_permission({"role": role}, "/api/user/change_pass", "POST")
            self.assertTrue(allow, "%s 应能自助改密" % role)
            self.assertEqual(reason, "self_service")

    def test_user_manage_still_gated(self):
        # 自助放行不能误开管理面：/api/user_manage/manage 写仍需 user:manage
        allow, _ = rbac.check_permission({"role": "viewer"}, "/api/user_manage/manage/user/update", "POST")
        self.assertFalse(allow)


class TestUserManageService(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())
        self.svc = UserManageService()
        # 种一个 admin
        self.svc.create_user("admin", "admin123", "admin")

    def tearDown(self):
        set_repo(None)

    def test_login_ok_and_token(self):
        r = self.svc.login("admin", "admin123")
        self.assertIn("token", r)
        self.assertEqual(r["role"], "admin")
        self.assertTrue(r["token"])

    def test_login_wrong_pw(self):
        self.assertIn("error", self.svc.login("admin", "wrong"))

    def test_verify_token_roundtrip(self):
        token = self.svc.login("admin", "admin123")["token"]
        u = self.svc.verify_token(token)
        self.assertEqual(u["username"], "admin")
        self.assertIn("user:manage", u["permissions"])

    def test_verify_bad_token(self):
        self.assertIsNone(self.svc.verify_token("garbage"))

    def test_logout_revokes_token(self):
        """AUD-09：登出（revoke_token）按 token 精确清除服务端 token，旧 token 立即失效。"""
        token = self.svc.login("admin", "admin123")["token"]
        self.assertIsNotNone(self.svc.verify_token(token))   # 登出前有效
        r = self.svc.revoke_token(token)
        self.assertTrue(r["ok"])
        self.assertTrue(r["revoked"])
        self.assertIsNone(self.svc.verify_token(token))      # 登出后立即失效
        # 幂等：重复 revoke 无副作用
        self.assertTrue(self.svc.revoke_token(token)["ok"])
        self.assertTrue(self.svc.revoke_token("")["ok"])

    def test_salt_reads_sentinel_section(self):
        """AUD-14：_salt 优先读 SENTINEL.SALT（配置样例要求配的位置）。"""
        from unittest import mock
        from sentinel_platform.modules.system import user_manage as um

        class _Cfg:
            def __init__(self, d):
                self.d = d
            def section(self, *keys, default=None):
                cur = self.d
                for k in keys:
                    if not isinstance(cur, dict) or k not in cur:
                        return default
                    cur = cur[k]
                return cur if cur is not None else default

        with mock.patch.object(um, "get_config", return_value=_Cfg({"SENTINEL": {"SALT": "CUSTOM_SALT"}})):
            self.assertEqual(um._salt(), "CUSTOM_SALT")

    def test_login_migrates_legacy_salt(self):
        """AUD-14 平滑迁移：存量密码用历史盐哈希 → 新盐验不过，历史盐命中仍可登录，且回写新盐。"""
        from unittest import mock
        import hashlib
        from sentinel_platform.modules.system.user_manage import _users
        from sentinel_platform.modules.system import user_manage as um
        # 直接种一个用历史固定盐 sentinel$alt 哈希的密码（模拟改盐前的存量账户）
        legacy = hashlib.md5(("pw12345" + "sentinel$alt").encode()).hexdigest()
        _users().update_one({"username": "admin"}, {"$set": {"password": legacy}})

        class _Cfg:
            def section(self, *keys, default=None):
                # 当前有效盐 = SENTINEL.SALT=NEWSALT（与历史 sentinel$alt 不同）
                if keys == ("SENTINEL", "SALT"):
                    return "NEWSALT"
                return default
        with mock.patch.object(um, "get_config", return_value=_Cfg()):
            r = self.svc.login("admin", "pw12345")
            self.assertIn("token", r)                        # 历史盐命中，登录成功
            # 回写：密码已用新盐重哈希
            doc = _users().find_one({"username": "admin"})
            self.assertEqual(doc["password"], hashlib.md5(("pw12345" + "NEWSALT").encode()).hexdigest())

    def test_password_hashed_not_plain(self):
        from sentinel_platform.modules.system.user_manage import _users
        d = _users().find_one({"username": "admin"})
        self.assertNotEqual(d["password"], "admin123")
        self.assertEqual(d["password"], hash_password("admin123"))

    def test_create_user_dup(self):
        self.assertIn("error", self.svc.create_user("admin", "x", "viewer"))

    def test_create_user_bad_role(self):
        self.assertIn("error", self.svc.create_user("u1", "pw", "nosuchrole"))

    def test_cannot_delete_last_admin(self):
        r = self.svc.delete_user("admin")
        self.assertIn("error", r)

    def test_delete_non_last_admin_ok(self):
        self.svc.create_user("admin2", "pw123", "admin")
        self.assertNotIn("error", self.svc.delete_user("admin2"))

    def test_cannot_demote_last_admin(self):
        r = self.svc.update_user("admin", role="viewer")
        self.assertIn("error", r)

    def test_change_password(self):
        r = self.svc.change_password("admin", "admin123", "newpass1")
        self.assertTrue(r.get("ok"))
        self.assertIn("error", self.svc.login("admin", "admin123"))   # 旧密码失效
        self.assertIn("token", self.svc.login("admin", "newpass1"))

    def test_role_crud(self):
        r = self.svc.upsert_role("auditor", ["vuln:read", "task:read"], title="审计员")
        self.assertEqual(r["name"], "auditor")
        names = [x["name"] for x in self.svc.list_roles()]
        self.assertIn("auditor", names)
        self.assertIn("admin", names)          # builtin 也在
        self.assertIn("error", self.svc.upsert_role("admin", ["*"]))   # 内置不可改

    def test_role_bad_perm_rejected(self):
        self.assertIn("error", self.svc.upsert_role("bad", ["nonexistent:perm"]))

    def test_custom_role_perms_resolve(self):
        self.svc.upsert_role("auditor", ["vuln:read"], title="审计")
        self.svc.create_user("aud", "pw123", "auditor")
        perms = self.svc.resolve_perms({"role": "auditor"})
        self.assertEqual(perms, ["vuln:read"])


if __name__ == "__main__":
    unittest.main()
