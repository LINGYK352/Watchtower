"""guard_log 端点 —— 闸刀拦截日志对外 REST（挂 /api/log_monitor/guard/...）。

**独立成文件的原因**：`endpoints/log_monitor.py` 已被 logmon 作者占用（程序日志/保留策略），
其文件头明确「/api/log_monitor/guard/* 属 system/guard_log 叶子，本文件不做」。为零撞车，
guard 端点单独成文件、单独挂载（router 按 (module, ns_attr) 挂 Namespace，文件粒度不影响；
Namespace path=/log_monitor/guard 使 URL 落在 log_monitor 下的 guard 子路径，与前端锁定一致）。

对齐前端 `frontend/src/api/logMonitor.ts` guardLogApi + `pages/logs/GuardLog.vue`：
  GET  /api/log_monitor/guard/       列表（allow/mode/level 过滤 + 分页）
  GET  /api/log_monitor/guard/stat/  统计（总数/拦截/放行 + 容量）
  POST /api/log_monitor/guard/size/  设置 capped 容量(MB)
路径/形状锁定（前端已用），勿改。

范式（照 endpoints/log_monitor.py 无 ROLE 叶子写法）：Namespace + docstring summary +
@ns.doc(security) + 经 get_registry().get("guard_log_service") 调门面（**不 import 叶子内部**，
缺失降级 500）+ env 信封。
权限（RBAC，网关据 rbac_service 校验；未建降级放行）：读(list/stat)=`system:read`；写(size)=`system:write`。
数据 API 规范（INTERFACES §5）：list 走信封分页；**禁止硬限制参数**——size 客户端定不砍，
容量 size_mb 只保物理下限（叶子层已守）。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("guard_log", path="/log_monitor/guard", description="智能闸刀拦截日志（capped 环形）")
_models = register_envelope_models(ns)


def _svc():
    """取 guard_log 服务（字符串键 "guard_log_service"，无 ROLE）。未注册降级 500。"""
    return get_registry().get("guard_log_service")


def _tri_bool(v):
    """三态布尔：'1'/'true'→True，'0'/'false'→False，其余→None（不过滤）。"""
    if v in ("1", "true", "True"):
        return True
    if v in ("0", "false", "False"):
        return False
    return None


_list_parser = ns.parser()
_list_parser.add_argument("allow", type=str, location="args", help="放行过滤 1/true=放行 0/false=拦截")
_list_parser.add_argument("mode", type=str, location="args", help="模式 src/redteam/conservative")
_list_parser.add_argument("level", type=str, location="args", help="判定档 safe/danger/ambiguous/ai_safe/ai_danger")
_list_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_list_parser.add_argument("size", type=int, location="args", help="每页条数, 默认30（无硬上限，传多大返多少）")

_size_req = ns.model("GuardSizeReq", {})    # body {size_mb:int}；下限 1MB 无上限


@ns.route("/")
class GuardLogList(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    @ns.expect(_list_parser)
    def get(self):
        """拦截日志列表（capped 最新在前 + allow/mode/level 过滤 + 分页，size 无硬上限）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "拦截日志服务未就绪")
        a = _list_parser.parse_args()
        try:
            page = int(a.get("page") or 1)
            size = int(a.get("size") or 30)
        except (TypeError, ValueError):
            page, size = 1, 30
        return ok(svc.list_logs(allow=_tri_bool(a.get("allow")), mode=a.get("mode") or "",
                                level=a.get("level") or "", page=page, size=size))


@ns.route("/stat/")
class GuardLogStat(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    def get(self):
        """拦截日志统计（总数/拦截/放行 + 当前容量配置）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "拦截日志服务未就绪")
        return ok(svc.stat())


@ns.route("/size/")
class GuardLogSize(Resource):
    @ns.doc(security="token", description="需权限 system:write")
    @ns.expect(_size_req)
    def post(self):
        """设置拦截日志容量(MB，下限 1 无上限；改容量可能清空历史)"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "拦截日志服务未就绪")
        body = request.get_json(silent=True) or {}
        if "size_mb" not in body:
            return err(CODE_BAD_REQUEST, "size_mb 必填")
        return ok({"size_mb": svc.set_size_mb(body.get("size_mb"))})
