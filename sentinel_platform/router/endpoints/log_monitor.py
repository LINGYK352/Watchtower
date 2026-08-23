"""log_monitor 端点 —— 日志监测的对外 REST（挂 /api/log_monitor/）。

对齐前端 frontend/src/api/logMonitor.ts + pages/logs/LogMonitor.vue：
  GET  /api/log_monitor/            程序日志列表（分页 + level/message/module 过滤）
  POST /api/log_monitor/delete/     按 _id 删除
  GET  /api/log_monitor/clear/      清空
  GET  /api/log_monitor/stat/       级别统计
  GET  /api/log_monitor/retention/  查保留天数
  POST /api/log_monitor/retention/  设保留天数（闭合 access_log retention 遗留）
  （/api/log_monitor/guard/* 拦截日志属 system/guard_log 叶子，本文件不做，见遗留）

范式（照 endpoints/access_log.py）：Namespace + docstring summary + @ns.doc(security) +
经 get_registry().get("log_service") 调门面（不 import 叶子内部，缺失降级 500）+ env 信封。
**禁硬限制参数**：size 透传（size<=0 全量）；retention 无天数上限。权限：读 system:read / 写 system:write。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

logger = get_logger()

ns = Namespace("log_monitor", path="/log_monitor", description="日志监测 / 保留策略")
try:
    from ..openapi import register_envelope_models
    _models = register_envelope_models(ns)
except Exception:
    pass


def _svc():
    """取日志服务（字符串键 "log_service"，非 ROLE）；未注册 None（降级 500）。"""
    return get_registry().get("log_service")


_list_parser = ns.parser()
_list_parser.add_argument("level", type=str, location="args", help="级别 ERROR/WARNING/CRITICAL")
_list_parser.add_argument("message", type=str, location="args", help="内容模糊过滤")
_list_parser.add_argument("module", type=str, location="args", help="来源文件")
_list_parser.add_argument("process_type", type=str, location="args", help="进程类型 web/scheduler/worker")
_list_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_list_parser.add_argument("size", type=int, location="args", help="每页条数, 默认20; <=0 返全量(不硬限)")

_del_req = ns.model("LogDeleteReq", {})
_ret_req = ns.model("LogRetentionReq", {})


@ns.route("/")
class LogList(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    @ns.expect(_list_parser)
    def get(self):
        """程序日志列表（分页 + 过滤）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "日志服务未就绪")
        a = _list_parser.parse_args()
        return ok(svc.list_logs(
            level=a.get("level") or "", message=a.get("message") or "",
            module=a.get("module") or "", process_type=a.get("process_type") or "",
            page=a.get("page") or 1,
            size=a.get("size") if a.get("size") is not None else 20))


@ns.route("/stat/")
class LogStat(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    def get(self):
        """日志级别统计"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "日志服务未就绪")
        return ok(svc.stat_logs())


@ns.route("/delete/")
class LogDelete(Resource):
    @ns.doc(security="token", description="需权限 system:write")
    @ns.expect(_del_req)
    def post(self):
        """按 _id 列表删除日志"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "日志服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("_id") or body.get("ids") or []
        if isinstance(ids, str):
            ids = [ids]
        return ok(svc.delete_logs(ids))


@ns.route("/clear/")
class LogClear(Resource):
    @ns.doc(security="token", description="需权限 system:write")
    def get(self):
        """清空全部程序日志"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "日志服务未就绪")
        return ok(svc.clear_logs())


@ns.route("/retention/")
class LogRetention(Resource):
    @ns.doc(security="token", description="需权限 system:read")
    def get(self):
        """查各类运营日志保留天数"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "日志服务未就绪")
        return ok(svc.get_retention())

    @ns.doc(security="token", description="需权限 system:write")
    @ns.expect(_ret_req)
    def post(self):
        """设运营日志保留天数（collMod 即时生效；无天数上限，仅 days>=1）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "日志服务未就绪")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return err(CODE_BAD_REQUEST, "请求体必须为 JSON 对象")
        updates = {k: v for k, v in body.items() if v is not None}
        return ok(svc.set_retention(updates))
