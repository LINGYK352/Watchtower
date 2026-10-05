"""access_log 端点 —— 访问/操作审计的对外 REST（挂 /api/access_log/）。

**独立成文件**：system 类别的 endpoints/system.py 被 user_manage(recon) 占用，为零撞车 access_log 单独成文件、单独挂载。

对齐前端 frontend/src/api/accessLog.ts + pages/logs/AccessLog.vue：
  GET /api/access_log/stat/   统计（总量/写操作/今日/错误）
  GET /api/access_log/        列表（分页 + is_write/username/path/status 过滤）
  （retention 端点属 log_retention，归 system/log_monitor 叶子，本文件不做，见遗留）

范式（照 endpoints/risk_intel.py）：Namespace + docstring 首行=summary + @ns.doc(security) +
经 get_registry().get("audit_service") 调门面（**不 import 叶子内部**，缺失降级 500）+ env 信封。
**禁硬限制参数**：size 透传给叶子，端点不设上限（size<=0 → 叶子返全量）。
权限（RBAC 网关据 rbac_service 校验；权限点写 docstring）：读 = `system:read`（审计属系统管理）。
"""
from __future__ import annotations

from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_ERROR

logger = get_logger()

ns = Namespace("access_log", path="/access_log", description="系统访问/操作审计日志")
try:
    from ..openapi import register_envelope_models
    _models = register_envelope_models(ns)
except Exception:  # openapi 模型注册失败不阻断端点
    pass


def _svc():
    """取审计服务（字符串键 "audit_service"，非 ROLE）；未注册返回 None（端点降级 500，不崩）。"""
    return get_registry().get("audit_service")


_list_parser = ns.parser()
_list_parser.add_argument("is_write", type=str, location="args", help="仅操作日志(增删改): 1/true")
_list_parser.add_argument("username", type=str, location="args", help="用户名精确过滤")
_list_parser.add_argument("path", type=str, location="args", help="路径模糊过滤")
_list_parser.add_argument("status", type=str, location="args", help="HTTP 状态码过滤")
_list_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_list_parser.add_argument("size", type=int, location="args", help="每页条数, 默认20; <=0 返全量(不硬限)")


def _bool_arg(v):
    if v in (None, ""):
        return None
    return v in ("1", "true", "True", True)


@ns.route("/stat/")
class AccessLogStat(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    def get(self):
        """访问日志统计（总量/写操作/今日/错误）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "审计服务未就绪")
        return ok(svc.stat_access())


@ns.route("/")
class AccessLogList(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    @ns.expect(_list_parser)
    def get(self):
        """访问/操作日志列表（分页 + 过滤；is_write=1 即操作日志）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "审计服务未就绪")
        a = _list_parser.parse_args()
        data = svc.list_access(
            is_write=_bool_arg(a.get("is_write")),
            username=a.get("username") or "",
            path=a.get("path") or "",
            status=a.get("status") or "",
            page=a.get("page") or 1,
            size=a.get("size") if a.get("size") is not None else 20,
        )
        return ok(data)
