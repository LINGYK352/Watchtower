"""asset 监控端点 —— 资产监控周期任务对外 REST（挂 /api/scheduler/*）。

对齐前端 `api/scheduler.ts` + `pages/assets/AssetMonitor.vue`：列表/新增（域名/站点/WIH）/
删除/停止/恢复。经 `get_registry().get("monitor_service")` 调叶子门面（**不 import 叶子内部**，
守解耦，服务缺失降级 500）+ env 信封。

停止/恢复兼容单条（stop/recover 传 job_id:<str>）与批量（stop/batch、recover/batch 传 job_id:[...]），
端点统一归一为 list 交叶子处理。列表走统一分页信封 {page,size,total,items}；size 透传按需取，
**禁止硬限制参数**：端点不设上限。

权限（RBAC 网关据 rbac_service 校验）：读(list)=`asset:read`；写(新增/删除/停止/恢复)=`asset:write`。
全局 Token 鉴权（Api security='token'）。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("scheduler", path="/scheduler", description="资产监控周期任务")
_models = register_envelope_models(ns)

_parser = ns.parser()
_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_parser.add_argument("size", type=int, location="args", help="每页条数, 默认10（无上限）")
_parser.add_argument("order", type=str, location="args", help="排序字段, 默认 -_id(倒序)")


def _svc():
    """取资产监控服务门面（字符串键 "monitor_service"，非 ROLE）；未注册返回 None（端点降级 500）。"""
    return get_registry().get("monitor_service")


def _body():
    return request.get_json(silent=True) or {}


def _ids(jid):
    """job_id 归一为 list（兼容单条 str 与批量 list）。"""
    return jid if isinstance(jid, list) else [jid]


@ns.route("/")
class _List(Resource):
    @ns.doc(security="token", description="需权限 asset:read")
    @ns.expect(_parser)
    def get(self):
        """监控任务列表（分页 + 任意字段过滤 + 排序）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        return ok(svc.list_jobs(dict(request.args)))


@ns.route("/add/")
class _AddDomain(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """新增域名监控任务（domain 支持逗号分隔多域名）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        b = _body()
        res = svc.add_domain_job(
            str(b.get("scope_id") or ""), str(b.get("domain") or ""),
            b.get("interval"), b.get("name") or "", b.get("policy_id") or "")
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/add/site_monitor/")
class _AddSiteMonitor(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """新增站点更新监控任务"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        b = _body()
        res = svc.add_site_monitor(str(b.get("scope_id") or ""), b.get("interval"), b.get("name") or "")
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/add/wih_monitor/")
class _AddWihMonitor(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """新增 WIH 更新监控任务"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        b = _body()
        res = svc.add_wih_monitor(str(b.get("scope_id") or ""), b.get("interval"), b.get("name") or "")
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/delete/")
class _Delete(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """按 job_id 批量删除监控任务"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        res = svc.delete_jobs(_body().get("job_id", []))
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/stop/")
class _Stop(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """停止单个监控任务（job_id:<str>）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        res = svc.stop_jobs(_ids(_body().get("job_id")))
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/stop/batch")
class _StopBatch(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """批量停止监控任务（job_id:[...]）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        res = svc.stop_jobs(_ids(_body().get("job_id")))
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/recover/")
class _Recover(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """恢复单个监控任务（job_id:<str>）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        res = svc.recover_jobs(_ids(_body().get("job_id")))
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)


@ns.route("/recover/batch")
class _RecoverBatch(Resource):
    @ns.doc(security="token", description="需权限 asset:write")
    def post(self):
        """批量恢复监控任务（job_id:[...]）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产监控服务未就绪")
        res = svc.recover_jobs(_ids(_body().get("job_id")))
        return err(CODE_BAD_REQUEST, res["error"]) if res.get("error") else ok(res)
