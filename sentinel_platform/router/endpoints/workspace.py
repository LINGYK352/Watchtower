"""workspace 类别端点 —— 工作台/态势总览对外 REST（挂 /api/console/...）。

对齐前端 `frontend/src/api/console.ts` + `pages/dashboard/Dashboard.vue`：
  GET /api/console/info              设备信息（CPU/内存/磁盘/uptime 实时快照）
  GET /api/console/resource_history  资源趋势（days 参数，降采样点列）
路径/形状锁定（前端已在用），勿改。

范式（照 endpoints/api_keys.py 无 ROLE 叶子写法）：Namespace + docstring 首行=summary +
@ns.doc(security) + 经 get_registry().get("dashboard_service") 调叶子门面（**不 import 叶子内部**，
守解耦，服务缺失降级 500）+ env 信封。
权限（RBAC，网关据 rbac_service 校验；未建降级放行）：设备信息只读=登录即可（落地页，
无独立权限点；网关已保证 /api 需认证）。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_ERROR
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("console", path="/console", description="工作台态势总览：设备信息 / 资源趋势")
_models = register_envelope_models(ns)


def _svc():
    """取 dashboard 服务（字符串键 "dashboard_service"，无 ROLE 纯查询叶子）。
    未注册返回 None（端点降级 500，不崩）。"""
    return get_registry().get("dashboard_service")


_history_parser = ns.parser()
_history_parser.add_argument("days", type=int, location="args", help="回溯天数 1-360，默认1")


@ns.route("/info")
class ConsoleInfo(Resource):
    @ns.doc(security="token", description="登录即可（落地页设备监控）")
    def get(self):
        """控制台设备信息（CPU/内存/磁盘/uptime 实时快照）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "态势总览服务未就绪")
        return ok({"device_info": svc.device_info()})


@ns.route("/resource_history")
class ConsoleResourceHistory(Resource):
    @ns.doc(security="token", description="登录即可（资源趋势图）")
    @ns.expect(_history_parser)
    def get(self):
        """资源趋势历史（CPU/内存/磁盘采样，按天数降采样）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "态势总览服务未就绪")
        try:
            days = int(request.args.get("days", 1))
        except (TypeError, ValueError):
            days = 1
        return ok(svc.resource_history(days))


@ns.route("/resource_alert")
class ConsoleResourceAlert(Resource):
    @ns.doc(security="token", description="登录即可（资源水位告警弹窗轮询）")
    def get(self):
        """当前资源水位明细（内存/CPU/磁盘 + 综合水位 + 超标维度，供前端弹窗判定）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "态势总览服务未就绪")
        return ok(svc.resource_alert())
