"""RBAC 权限模型 —— 权限点 / 预设角色 / 路径→权限映射 / 校验逻辑。

净室重写 app/utils/rbac.py：权限点表、三预设角色、路径规则表是「配置数据」，
逻辑（resolve_perms / required_permission / check_permission）从零编写。纯函数无副作用，
可脱离 flask/Mongo 单测（自定义角色经 role_lookup 注入，不在此直连库）。
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

# —— 权限点（key: 说明）——
PERMISSIONS: Dict[str, str] = {
    "task:read": "查看任务/资产扫描结果",
    "task:write": "发起/删除/停止任务、批量导入、计划任务",
    "policy:read": "查看扫描策略",
    "policy:write": "新建/编辑/删除扫描策略",
    "asset:read": "查看资产(域名/IP/站点/指纹/GitHub)",
    "asset:write": "资产分组/监控/删除、指纹管理、GitHub 任务",
    "vuln:read": "查看漏洞中心/PoC/漏洞情报",
    "vuln:write": "标记漏洞处理状态、删除漏洞、PoC 管理",
    "pentest:read": "查看 AI 渗透会话/报告/攻击链",
    "pentest:write": "发起/恢复/停止/删除 AI 渗透会话",
    "pentest:view_all": "查看全部渗透会话（否则仅自己创建的；admin 恒含）",
    "intel:read": "查看资产情报/单位视图/对外情报",
    "proxy:write": "代理中心配置/启停/切换节点",
    "ai_config:write": "AI 配置中心(provider/提示词/闸刀)",
    "ai_extension:read": "查看系统扩展（AI 扩展/功能扩展）、扩展商店和运行日志",
    "ai_extension:manage": "上传、安装、启停、删除系统扩展",
    "apikey:write": "API 密钥中心/SRC 来源管理",
    "system:read": "查看日志监测/访问日志/拦截日志/控制台",
    "system:update": "系统更新:一键更新/回退到历史版本(高危,影响全站运行代码)",
    "user:manage": "用户管理:增删用户、分配角色、管理角色权限(最高危)",
}
ALL_PERMS = sorted(PERMISSIONS.keys())

ADMIN_ROLE = "admin"
BUILTIN_ROLES: Dict[str, Dict[str, Any]] = {
    "admin": {"title": "管理员", "permissions": ["*"], "builtin": True,
              "desc": "全部权限 + 用户管理,内置不可删改"},
    "operator": {"title": "操作员", "permissions": [
        "task:read", "task:write", "policy:read", "policy:write",
        "asset:read", "asset:write", "vuln:read", "vuln:write",
        "pentest:read", "pentest:write", "intel:read", "system:read", "system:update", "ai_extension:read"],
        "builtin": True, "desc": "任务/资产/漏洞/AI渗透读写,无用户管理/密钥/代理/AI配置写"},
    "viewer": {"title": "只读", "permissions": [
        "task:read", "policy:read", "asset:read", "vuln:read",
        "pentest:read", "intel:read", "system:read", "ai_extension:read"],
        "builtin": True, "desc": "所有查看权限,无任何写操作"},
}

# 路径前缀 → 所需权限（按序匹配，命中即用）。写操作未命中 → fail-closed 需 user:manage。
PERM_RULES: List[Tuple[str, Tuple[str, ...], str]] = [
    ("/api/user_manage/manage", ("GET", "POST", "PUT", "DELETE"), "user:manage"),
    # 系统更新：一键更新(/apply)/回退(/rollback) 高危写操作，需 system:update。
    # /report_error 是报错上报（运营性质，任何已认证用户可上报）→ 归 system:read。
    ("/api/about/apply", ("POST",), "system:update"),
    ("/api/about/rollback", ("POST",), "system:update"),
    ("/api/about/report_error", ("POST",), "system:read"),
    ("/api/policy", ("POST", "PUT", "DELETE"), "policy:write"),
    ("/api/proxy", ("POST", "PUT", "DELETE"), "proxy:write"),
    ("/api/ai_config", ("POST", "PUT", "DELETE"), "ai_config:write"),
    ("/api/ai-config", ("POST", "PUT", "DELETE"), "ai_config:write"),
    ("/api/api_keys", ("POST", "PUT", "DELETE"), "apikey:write"),
    ("/api/api-keys", ("POST", "PUT", "DELETE"), "apikey:write"),
    ("/api/pentest/extensions", ("POST", "PUT", "DELETE"), "ai_extension:manage"),
    ("/api/pentest/extensions", ("GET",), "ai_extension:read"),
    ("/api/pentest", ("POST", "PUT", "DELETE"), "pentest:write"),
    ("/api/intel/chain", ("POST", "PUT", "DELETE"), "pentest:write"),  # 攻击链属AI渗透产出(Claude-Opus[chain])
    ("/api/intel/chain", ("GET",), "pentest:read"),                    # PERMISSIONS 表 pentest:read 明含「攻击链」
    ("/api/intel/delete", ("POST",), "pentest:write"),                 # 删情报记录(资产/报告等,属渗透产出,同 chain 口径)
    ("/api/policy", ("GET",), "policy:read"),
    ("/api/vuln", ("POST", "PUT", "DELETE"), "vuln:write"),
    ("/api/poc", ("POST", "PUT", "DELETE"), "vuln:write"),
    ("/api/task", ("POST", "PUT", "DELETE"), "task:write"),
    ("/api/task_fofa", ("POST", "PUT", "DELETE"), "task:write"),  # FOFA/单位名建任务(Claude-Opus[taskcreate])
    ("/api/asset", ("POST", "PUT", "DELETE"), "asset:write"),
    ("/api/fingerprint", ("POST", "PUT", "DELETE"), "asset:write"),
    ("/api/github", ("POST", "PUT", "DELETE"), "asset:write"),
]


def resolve_perms(user: Dict[str, Any],
                  role_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None) -> List[str]:
    """求用户的权限集。admin/含 '*' → 全量。自定义角色经 role_lookup(name)->role_doc 取权限。"""
    role = (user or {}).get("role", "")
    if role == ADMIN_ROLE:
        return list(ALL_PERMS)
    role_doc = BUILTIN_ROLES.get(role)
    if role_doc is None and role_lookup:
        try:
            role_doc = role_lookup(role)
        except Exception:
            role_doc = None
    if not role_doc:
        return []
    perms = role_doc.get("permissions", []) or []
    if "*" in perms:
        return list(ALL_PERMS)
    return [p for p in perms if p in PERMISSIONS]


def required_permission(path: str, method: str) -> Optional[str]:
    """按 PERM_RULES 求 path+method 所需权限；未命中返回 None（交 check_permission 决策）。"""
    method = (method or "GET").upper()
    for prefix, methods, perm in PERM_RULES:
        if path.startswith(prefix) and method in methods:
            return perm
    return None


def check_permission(user: Dict[str, Any], path: str, method: str,
                     role_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None
                     ) -> Tuple[bool, str]:
    """核心校验。返回 (allow, reason)。
    admin 直放；命中规则需对应权限；GET 未命中默认放行；写操作未命中 fail-closed 需 user:manage。"""
    if (user or {}).get("role") == ADMIN_ROLE:
        return True, "admin"
    method = (method or "GET").upper()
    # 自助端点：/api/user/*（改自己密码 change_pass、登出 logout）任何已认证用户放行。
    # 这些是"操作自身账号"（change_pass 内部按当前 token 用户 + 校验旧密码，天然自限范围），
    # 不该被写操作 fail-closed 默认要求 user:manage 拦（否则 viewer/operator 改不了自己密码）。
    # 注意排除 /api/user_manage（那才是管理他人的高危面，仍需 user:manage）。
    if path.startswith("/api/user/") and not path.startswith("/api/user_manage"):
        return True, "self_service"
    perms = set(resolve_perms(user, role_lookup))
    need = required_permission(path, method)
    if need:
        return (need in perms), ("need " + need)
    if method == "GET":
        return True, "read_default_allow"     # 读操作未映射 → 放行
    return ("user:manage" in perms), "write_failclosed_need_user:manage"


def list_permissions() -> List[Dict[str, str]]:
    """权限点清单（建角色勾选用）。"""
    return [{"key": k, "desc": v} for k, v in PERMISSIONS.items()]
