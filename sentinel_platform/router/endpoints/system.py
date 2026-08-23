"""system 类别端点 —— 登录鉴权 + 用户/角色管理（对接 ROLE.USER / ROLE.RBAC）。

路由前缀对齐前端 user.ts：/api/user/*（登录/登出/改密，公开或自身）+ /api/user_manage/*
（profile/用户·角色·权限管理，需 user:manage，由 router 网关按 rbac.PERM_RULES 拦）。

所有响应走统一信封（router.envelope）。经 registry 取 USER/RBAC 服务，未注册则 503 降级。
"""
from __future__ import annotations

from flask import request, g
from flask_restx import Namespace, Resource

from sentinel_platform.contracts import get_registry, ROLE
from ..envelope import ok, err, CODE_ERROR, CODE_BAD_REQUEST, CODE_UNAUTHORIZED

ns = Namespace("user", description="登录鉴权 / 用户与角色管理")


def _user_svc():
    return get_registry().get(ROLE.USER)


def _rbac_svc():
    return get_registry().get(ROLE.RBAC)


def _current_username() -> str:
    return (getattr(g, "current_user", None) or {}).get("username", "")


@ns.route("/login")
class Login(Resource):
    @ns.doc(security=None)
    def post(self):
        """用户登录（公开），成功返回 token"""
        svc = _user_svc()
        if not svc:
            return err(CODE_ERROR, "用户服务未就绪")
        body = request.get_json(silent=True) or {}
        result = svc.login(body.get("username", ""), body.get("password", ""))
        if result.get("error"):
            return err(CODE_UNAUTHORIZED, result["error"])
        return ok(result)


@ns.route("/logout")
class Logout(Resource):
    @ns.doc(security="token")
    def get(self):
        """登出（清除会话 token）"""
        svc = _user_svc()
        u = _current_username()
        if svc and u and hasattr(svc, "update_user"):
            try:
                svc.update_user(u, token=None)
            except Exception:
                pass
        return ok({})


@ns.route("/change_pass")
class ChangePass(Resource):
    @ns.doc(security="token")
    def post(self):
        """修改自己的密码"""
        svc = _user_svc()
        if not svc:
            return err(CODE_ERROR, "用户服务未就绪")
        u = _current_username()
        if not u:
            return err(CODE_UNAUTHORIZED, "未登录")
        body = request.get_json(silent=True) or {}
        if body.get("new_password") != body.get("check_password"):
            return err(CODE_BAD_REQUEST, "两次新密码不一致")
        result = svc.change_password(u, body.get("old_password", ""), body.get("new_password", ""))
        if result.get("error"):
            return err(CODE_BAD_REQUEST, result["error"])
        return ok(result)


# —— 用户管理（前缀 /api/user_manage，网关按 rbac 规则要 user:manage）——
ns_manage = Namespace("user_manage", description="用户/角色/权限管理（需 user:manage）")


@ns_manage.route("/profile")
class Profile(Resource):
    @ns_manage.doc(security="token")
    def get(self):
        """当前登录用户的角色与权限（前端菜单过滤用）"""
        rbac = _rbac_svc()
        u = getattr(g, "current_user", None) or {}
        perms = rbac.resolve_perms(u) if rbac else u.get("permissions", [])
        return ok({"username": u.get("username", ""), "role": u.get("role", ""),
                   "permissions": perms, "type": "session"})


@ns_manage.route("/manage/users")
class Users(Resource):
    @ns_manage.doc(security="token")
    def get(self):
        """用户列表"""
        svc = _user_svc()
        return ok({"items": svc.list_users() if svc else []})

    @ns_manage.doc(security="token")
    def post(self):
        """新建用户"""
        svc = _user_svc()
        if not svc:
            return err(CODE_ERROR, "用户服务未就绪")
        b = request.get_json(silent=True) or {}
        r = svc.create_user(b.get("username", ""), b.get("password", ""), b.get("role", ""),
                            operator=_current_username())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_manage.route("/manage/user/update")
class UserUpdate(Resource):
    @ns_manage.doc(security="token")
    def post(self):
        """更新用户（角色/密码/禁用）"""
        svc = _user_svc()
        if not svc:
            return err(CODE_ERROR, "用户服务未就绪")
        b = request.get_json(silent=True) or {}
        username = b.pop("username", "")
        r = svc.update_user(username, **b)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_manage.route("/manage/user/delete")
class UserDelete(Resource):
    @ns_manage.doc(security="token")
    def post(self):
        """删除用户"""
        svc = _user_svc()
        if not svc:
            return err(CODE_ERROR, "用户服务未就绪")
        b = request.get_json(silent=True) or {}
        r = svc.delete_user(b.get("username", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_manage.route("/manage/roles")
class Roles(Resource):
    @ns_manage.doc(security="token")
    def get(self):
        """角色列表"""
        rbac = _rbac_svc()
        return ok({"items": rbac.list_roles() if rbac else []})

    @ns_manage.doc(security="token")
    def post(self):
        """新建/更新自定义角色"""
        rbac = _rbac_svc()
        if not rbac:
            return err(CODE_ERROR, "RBAC 服务未就绪")
        b = request.get_json(silent=True) or {}
        r = rbac.upsert_role(b.get("name", ""), b.get("permissions", []),
                             title=b.get("title", ""), desc=b.get("desc", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_manage.route("/manage/role/delete")
class RoleDelete(Resource):
    @ns_manage.doc(security="token")
    def post(self):
        """删除自定义角色"""
        rbac = _rbac_svc()
        if not rbac:
            return err(CODE_ERROR, "RBAC 服务未就绪")
        b = request.get_json(silent=True) or {}
        r = rbac.delete_role(b.get("name", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_manage.route("/manage/permissions")
class Permissions(Resource):
    @ns_manage.doc(security="token")
    def get(self):
        """权限点清单（建角色勾选用）"""
        rbac = _rbac_svc()
        return ok({"items": rbac.list_permissions() if rbac else []})
