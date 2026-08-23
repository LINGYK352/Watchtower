"""用户管理 user_manage —— 登录鉴权 / token / 用户·角色 CRUD（实现 USER + RBAC）。

router 网关（router/gateway.py）经 ROLE.USER 校验 token、经 ROLE.RBAC 判权限——本叶子是
平台鉴权的后端支柱（做完网关权限校验从降级态转真）。

净室重写 app/utils/user.py + routes/user_manage.py：口令哈希/token 生成算法、CRUD、角色
管理从零写。集合 user / role。只用 stdlib（hashlib/time），无第三方库（无需 vendor）。
密码哈希加 config 盐，token 不可逆；日志不回显口令/token 明文（守安全边界）。
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_config, get_logger, get_repo
from . import rbac

logger = get_logger()

USER_COLL = "user"
ROLE_COLL = "role"


def _salt() -> str:
    """口令哈希盐：优先 config，回退固定值（部署应配 SALT）。"""
    return str(get_config().section("SALT", default="") or
               get_config().section("ARL", "SALT", default="") or "sentinel$alt")


def hash_password(password: str) -> str:
    """口令哈希：md5(password + salt)，不可逆存储。"""
    return hashlib.md5((str(password) + _salt()).encode("utf-8")).hexdigest()


def gen_token(username: str) -> str:
    """生成会话 token：hash(username + 时间戳 + salt)，唯一不可逆。"""
    raw = "{}|{}|{}".format(username, time.time(), _salt())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _users():
    return get_repo().collection(USER_COLL)


def _roles():
    return get_repo().collection(ROLE_COLL)


def _role_lookup(name: str) -> Optional[Dict[str, Any]]:
    """自定义角色查库（供 rbac.resolve_perms 注入）。builtin 角色不走库。"""
    try:
        return _roles().find_one({"name": name})
    except Exception:
        return None


def _public_user(doc: Dict[str, Any]) -> Dict[str, Any]:
    """脱敏用户视图：不含 password/token。"""
    return {"username": doc.get("username", ""), "role": doc.get("role", ""),
            "disabled": bool(doc.get("disabled", False)),
            "is_manager": doc.get("role") == rbac.ADMIN_ROLE,
            "created_by": doc.get("created_by", ""), "create_date": doc.get("create_date", "")}


class UserManageService:
    """同时满足 UserService + RbacService（两 ROLE 一实现，共享 user/role 集合）。"""

    # ===== UserService =====
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """校验口令→签发 token。成功返回 {token,username,role,permissions}；失败 {error}。"""
        if not username or not password:
            return {"error": "用户名或密码为空"}
        doc = _users().find_one({"username": username})
        if not doc or doc.get("password") != hash_password(password):
            return {"error": "用户名或密码错误"}
        if doc.get("disabled"):
            return {"error": "账号已禁用"}
        token = gen_token(username)
        try:
            _users().update_one({"username": username},
                                {"$set": {"token": token, "login_date": _now()}})
        except Exception as e:
            logger.warning("login token persist error for %s: %s", username, e)
        return {"token": token, "username": username, "role": doc.get("role", ""),
                "permissions": rbac.resolve_perms(doc, _role_lookup)}

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """按 token 查用户（router 网关每请求调）。无效/禁用返回 None。"""
        if not token:
            return None
        doc = _users().find_one({"token": token})
        if not doc or doc.get("disabled"):
            return None
        return {"username": doc.get("username", ""), "role": doc.get("role", ""),
                "permissions": rbac.resolve_perms(doc, _role_lookup), "via": "session"}

    def change_password(self, username: str, old_pw: str, new_pw: str) -> Dict[str, Any]:
        doc = _users().find_one({"username": username})
        if not doc or doc.get("password") != hash_password(old_pw):
            return {"error": "原密码错误"}
        if not new_pw or len(new_pw) < 6:
            return {"error": "新密码至少 6 位"}
        _users().update_one({"username": username},
                            {"$set": {"password": hash_password(new_pw), "token": ""}})
        return {"ok": True, "username": username}

    def list_users(self) -> List[Dict[str, Any]]:
        try:
            return [_public_user(d) for d in _users().find({})]
        except Exception:
            return []

    def create_user(self, username: str, password: str, role: str, **kwargs: Any) -> Dict[str, Any]:
        if not username or not password:
            return {"error": "用户名/密码必填"}
        if role != rbac.ADMIN_ROLE and role not in rbac.BUILTIN_ROLES and not _role_lookup(role):
            return {"error": "角色不存在: {}".format(role)}
        if _users().find_one({"username": username}):
            return {"error": "用户已存在"}
        _users().insert_one({"username": username, "password": hash_password(password),
                             "role": role, "disabled": False, "token": "",
                             "created_by": kwargs.get("operator", ""), "create_date": _now()})
        return {"username": username}

    def update_user(self, username: str, **kwargs: Any) -> Dict[str, Any]:
        doc = _users().find_one({"username": username})
        if not doc:
            return {"error": "用户不存在"}
        upd: Dict[str, Any] = {}
        if kwargs.get("role"):
            upd["role"] = kwargs["role"]
        if kwargs.get("password"):
            upd["password"] = hash_password(kwargs["password"])
            upd["token"] = ""                       # 改密即踢下线
        if "disabled" in kwargs:
            upd["disabled"] = bool(kwargs["disabled"])
        # 禁改最后一个 admin 的角色 / 禁用（防锁死）
        if (upd.get("role") and upd["role"] != rbac.ADMIN_ROLE or upd.get("disabled")) \
                and doc.get("role") == rbac.ADMIN_ROLE and _admin_count() <= 1:
            return {"error": "不能降级/禁用最后一个管理员"}
        if not upd:
            return {"error": "无更新字段"}
        _users().update_one({"username": username}, {"$set": upd})
        return {"username": username}

    def delete_user(self, username: str, **kwargs: Any) -> Dict[str, Any]:
        doc = _users().find_one({"username": username})
        if not doc:
            return {"error": "用户不存在"}
        if doc.get("role") == rbac.ADMIN_ROLE and _admin_count() <= 1:
            return {"error": "不能删除最后一个管理员"}
        _users().delete_one({"username": username})
        return {"username": username}

    # ===== RbacService =====
    def check_permission(self, user: Dict[str, Any], path: str, method: str) -> Any:
        return rbac.check_permission(user, path, method, _role_lookup)

    def resolve_perms(self, user: Dict[str, Any]) -> List[str]:
        return rbac.resolve_perms(user, _role_lookup)

    def list_roles(self) -> List[Dict[str, Any]]:
        out = [{"name": n, "title": r["title"], "permissions": r["permissions"],
                "builtin": True, "desc": r.get("desc", "")} for n, r in rbac.BUILTIN_ROLES.items()]
        try:
            for d in _roles().find({}):
                out.append({"name": d.get("name"), "title": d.get("title", d.get("name")),
                            "permissions": d.get("permissions", []), "builtin": False,
                            "desc": d.get("desc", "")})
        except Exception:
            pass
        return out

    def upsert_role(self, name: str, permissions: List[str], **kwargs: Any) -> Dict[str, Any]:
        if not name:
            return {"error": "角色名必填"}
        if name in rbac.BUILTIN_ROLES:
            return {"error": "内置角色不可改: {}".format(name)}
        bad = [p for p in (permissions or []) if p not in rbac.PERMISSIONS]
        if bad:
            return {"error": "无效权限点: {}".format(bad)}
        _roles().update_one({"name": name}, {"$set": {
            "name": name, "title": kwargs.get("title", name),
            "permissions": list(permissions or []), "desc": kwargs.get("desc", "")}}, upsert=True)
        return {"name": name}

    def delete_role(self, name: str) -> Dict[str, Any]:
        if name in rbac.BUILTIN_ROLES:
            return {"error": "内置角色不可删"}
        if _users().find_one({"role": name}):
            return {"error": "仍有用户属于该角色，不能删"}
        _roles().delete_one({"name": name})
        return {"name": name}

    def list_permissions(self) -> List[Dict[str, Any]]:
        return rbac.list_permissions()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _admin_count() -> int:
    try:
        return _users().count_documents({"role": rbac.ADMIN_ROLE, "disabled": {"$ne": True}})
    except Exception:
        return 99            # 查不到时保守（不误判"最后一个"而阻止操作）


def seed_default_admin() -> dict:
    """开箱即用：首次启动（user 集合为空）时播种一个默认管理员，让 docker 拉取后直接能登录。
    幂等——已有任何用户则跳过（绝不覆盖/重置已存在账号）。默认账号密码可经 config 覆盖：
      SENTINEL.DEFAULT_ADMIN_USER / DEFAULT_ADMIN_PASS（缺省 admin / sentinel@2026）。
    安全：默认口令仅供首次登录，前端/文档提示立即改密（同旧 ARL 的 admin/arlpass 模式）。"""
    try:
        if _users().count_documents({}) > 0:
            return {"seeded": False, "reason": "已有用户，跳过"}
        cfg = get_config()
        user = str(cfg.section("SENTINEL", "DEFAULT_ADMIN_USER", default="") or "admin")
        pw = str(cfg.section("SENTINEL", "DEFAULT_ADMIN_PASS", default="") or "sentinel@2026")
        _users().insert_one({"username": user, "password": hash_password(pw),
                             "role": rbac.ADMIN_ROLE, "disabled": False, "token": "",
                             "created_by": "system-seed", "create_date": _now(),
                             "must_change_password": True})   # 标记：提示首登改密
        logger.info("seed_default_admin: 已创建默认管理员 %s（请首次登录后立即改密）", user)
        return {"seeded": True, "username": user}
    except Exception as e:
        logger.warning("seed_default_admin degraded: %s", e)
        return {"seeded": False, "error": str(e)}


_SINGLETON: Optional[UserManageService] = None


def get_service() -> UserManageService:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = UserManageService()
    return _SINGLETON
