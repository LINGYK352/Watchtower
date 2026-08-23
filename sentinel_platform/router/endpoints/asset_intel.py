"""asset_intel 端点 —— 资产情报中心的对外 REST（挂 /api/intel/）。

**独立成文件**：risk_intel 类别的 endpoints/risk_intel.py 已被 vuln_intel(ns intel/vuln_feed)+vuln_center(ns_finding)
占用；asset_intel 单独成文件、单独挂载（一类别多 AI 并行按叶子拆文件避撞车）。
注意：Namespace `intel` 的 `/vuln_feed/*` 归 vuln_intel（risk_intel.py 的 ns），本文件用**另一 Namespace（tag intel_asset, path /intel）**
只挂资产情报路由（stat/asset/system/code/report/collect/match/context/resolve_icp）；chain/*、units/* 归 attack_chain、unit_view 叶子。

对齐前端 api/intel.ts（路径/形状锁定）：
  GET  /api/intel/stat/         总览统计       GET /api/intel/asset|system|code|report/  各集合分页
  POST /api/intel/collect/      手动归集(task_id)
  GET  /api/intel/match/        渗透前去重(?site)     GET /api/intel/context/ 渗透档案(?asset_key)
  POST /api/intel/resolve_icp/  域名→备案单位

范式：经 get_registry().get(ROLE.INTEL) 调门面（**不 import 叶子内部**，缺失降级 500）+ env 信封。
权限：读 intel:read（stat/list/match/context）/ 写 intel:write（collect/resolve_icp）。**禁硬限制参数**：list size 透传不砍。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry, ROLE
from ..envelope import ok, err, page as env_page, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND

logger = get_logger()

ns = Namespace("intel_asset", path="/intel", description="资产情报中心：归集/资产/系统/报告")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns)
except Exception:
    pass

_collect_req = ns.model("IntelCollectReq", {})
_icp_req = ns.model("IntelResolveIcpReq", {})


def _svc():
    """取 INTEL 服务（ROLE.INTEL，asset_intel 实现）；未注册 None（降级 500）。"""
    return get_registry().get(ROLE.INTEL)


def _int(v, d):
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


@ns.route("/stat/")
class IntelStat(Resource):
    @ns.doc(security="token", description="需权限 intel:read")
    def get(self):
        """情报中心总览统计"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        return ok(svc.stat())


def _make_list_resource(coll_name: str):
    @ns.route("/{}/".format(coll_name.split("_", 1)[1] if coll_name.startswith("intel_") else coll_name))
    class _IntelList(Resource):
        @ns.doc(security="token", description="需权限 intel:read")
        def get(self):
            """{} 分页列表""".format(coll_name)
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "情报服务未就绪")
            a = request.args
            r = svc.list_collection(coll_name, page=_int(a.get("page"), 1), size=_int(a.get("size"), 10),
                                    unit=a.get("unit") or "", system_id=a.get("system_id") or "",
                                    pentest_status=a.get("pentest_status") or "", keyword=a.get("keyword") or "")
            return env_page(r["items"], r["total"], r["page"], r["size"])
    return _IntelList


# /api/intel/{asset,system,code,report}/
IntelAssetList = _make_list_resource("intel_asset")
IntelSystemList = _make_list_resource("intel_system")
IntelCodeList = _make_list_resource("intel_code")
IntelReportList = _make_list_resource("intel_report")


@ns.route("/report_tree/")
class IntelReportTree(Resource):
    @ns.doc(security="token", description="需权限 intel:read：渗透报告三级目录树（任务>单位>资产）")
    def get(self):
        """渗透报告三级目录（BUG-014：前端「三级目录」默认视图数据源）"""
        svc = _svc()
        if not (svc and hasattr(svc, "report_tree")):
            return err(CODE_ERROR, "情报服务未就绪")
        return ok(svc.report_tree())


@ns.route("/report/<string:report_id>")
class IntelReportDetail(Resource):
    @ns.doc(security="token", description="需权限 intel:read：渗透报告详情")
    def get(self, report_id):
        """渗透报告详情（#4：前端点报告查看，原缺此端点→404）"""
        svc = _svc()
        if not (svc and hasattr(svc, "get_report")):
            return err(CODE_ERROR, "情报服务未就绪")
        d = svc.get_report(report_id)
        if d is None:
            return err(CODE_NOT_FOUND, "报告不存在")
        return ok(d)


@ns.route("/delete/")
class IntelDelete(Resource):
    @ns.doc(security="token", description="需权限 intel:write：删除情报记录（asset/system/code/report）")
    def post(self):
        """批量删除情报记录（#5：前端点选删除，原缺此端点→404）。body:{collection,_id:[...]}"""
        svc = _svc()
        if not (svc and hasattr(svc, "delete_records")):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        collection = (body.get("collection") or "").strip()
        ids = body.get("_id") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "_id(非空数组) 必填")
        r = svc.delete_records(collection, ids)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok({"deleted": r.get("deleted", 0)})


@ns.route("/collect/")
class IntelCollect(Resource):
    @ns.doc(security="token", description="需权限 intel:write：手动归集某任务的 site 结果")
    @ns.expect(_collect_req)
    def post(self):
        """手动归集任务资产"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        task_id = (body.get("task_id") or "").strip()
        if not task_id:
            return err(CODE_BAD_REQUEST, "task_id 必填")
        r = svc.collect_from_task(task_id)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/match/")
class IntelMatch(Resource):
    @ns.doc(security="token", description="需权限 intel:read：渗透前查资产是否已存在/已渗透")
    def get(self):
        """按 site 匹配资产实例"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        asset = svc.match_asset(request.args.get("site", ""))
        return ok({"matched": bool(asset), "asset": asset})


@ns.route("/context/")
class IntelContext(Resource):
    @ns.doc(security="token", description="需权限 intel:read：AI 渗透前情报档案")
    def get(self):
        """按 asset_key 装配渗透情报档案"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        return ok(svc.build_pentest_context(request.args.get("asset_key", "")))


@ns.route("/resolve_icp/")
class IntelResolveIcp(Resource):
    @ns.doc(security="token", description="需权限 intel:write：域名→备案单位（经 ext_source，未建降级空）")
    @ns.expect(_icp_req)
    def post(self):
        """域名反查备案单位"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        return ok(svc.resolve_icp((body.get("domain") or "").strip()))
