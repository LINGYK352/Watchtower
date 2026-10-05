"""asset_groups 端点 —— 资产分组的对外 REST。

**独立成文件**：asset 类别的 endpoints/asset.py 已被 search/fingerprint 占用（8 侦察集合 + fingerprint），
为零撞车，资产分组单独成文件、单独挂载（一类别多 AI 并行按叶子拆文件更安全）。

对齐前端 api/scope.ts + api/assets.ts + pages/assets/AssetGroupList.vue、AssetGroupDetail.vue（路径/形状锁定）：
  /api/asset_scope/            GET 组列表 / POST 建组
  /api/asset_scope/delete/     POST 删组(级联) / GET(?scope&scope_id) 删单条范围
  /api/asset_scope/add/        POST 追加范围
  /api/asset_{domain,ip,site,wih}/         GET 列表 / POST 建(domain,site)
  /api/asset_{...}/delete/     POST 删
  /api/asset_{...}/export/     GET 导出全量
  /api/asset_site/{add_tag,delete_tag}/    POST 站点标签

范式（照 endpoints/asset.py 工厂）：经 get_registry().get("asset_group_service") 调门面（不 import 叶子内部，缺失降级 500）+ env 信封。
权限：读 asset:read（list/export）/ 写 asset:write（add/delete/tag）。**禁硬限制参数**：size 透传、export 不 limit。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, page as env_page, CODE_BAD_REQUEST, CODE_ERROR

logger = get_logger()


def _svc():
    """取资产分组服务（字符串键 "asset_group_service"，非 ROLE）；未注册 None（降级 500）。"""
    return get_registry().get("asset_group_service")


def _int(v, d):
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


# ========== 资产组 asset_scope ==========
ns_scope = Namespace("asset_scope", path="/asset_scope", description="资产组范围管理")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns_scope)
except Exception:
    pass

_scope_add = ns_scope.model("AssetScopeAddReq", {})
_scope_del = ns_scope.model("AssetScopeDelReq", {})


@ns_scope.route("/")
class ScopeList(Resource):
    @ns_scope.doc(security="token", description="需权限 asset:read")
    def get(self):
        """资产组列表"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产分组服务未就绪")
        a = request.args
        r = svc.list_scopes(page=_int(a.get("page"), 1), size=_int(a.get("size"), 10), name=a.get("name") or "")
        return env_page(r["items"], r["total"], r["page"], r["size"])

    @ns_scope.doc(security="token", description="需权限 asset:write")
    @ns_scope.expect(_scope_add)
    def post(self):
        """新建资产组"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产分组服务未就绪")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return err(CODE_BAD_REQUEST, "请求体必须为 JSON 对象")
        r = svc.add_scope_group(data)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_scope.route("/delete/")
class ScopeDelete(Resource):
    @ns_scope.doc(security="token", description="需权限 asset:write：删除单条范围段(?scope&scope_id)")
    def get(self):
        """从资产组删除单条范围段"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产分组服务未就绪")
        r = svc.delete_scope_range(request.args.get("scope_id", ""), request.args.get("scope", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)

    @ns_scope.doc(security="token", description="需权限 asset:write：删组+级联清资产")
    @ns_scope.expect(_scope_del)
    def post(self):
        """删除资产组及组内资产（级联）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产分组服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("scope_id") or []
        if isinstance(ids, str):
            ids = [ids]
        return ok(svc.delete_scope_groups(ids))


@ns_scope.route("/add/")
class ScopeAdd(Resource):
    @ns_scope.doc(security="token", description="需权限 asset:write")
    @ns_scope.expect(_scope_add)
    def post(self):
        """向资产组追加范围段"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "资产分组服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.add_scope_range(body.get("scope_id", ""), body.get("scope", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


# ========== 组内资产 asset_domain/ip/site/wih（工厂）==========

def _build_asset_ns(coll: str):
    """为一个组内资产集合建 Namespace（list/delete/export；domain/site 额外 add；site 额外 tag）。"""
    ns = Namespace(coll, path="/{}".format(coll), description="资产组内 {} 管理".format(coll))
    try:
        register_envelope_models(ns)
    except Exception:
        pass
    _req = ns.model(coll + "Req", {})

    @ns.route("/")
    class _AssetList(Resource):
        @ns.doc(security="token", description="需权限 asset:read")
        def get(self):
            """列表（分页 + scope_id 过滤）"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产分组服务未就绪")
            a = request.args
            r = svc.list_assets(coll, page=_int(a.get("page"), 1), size=_int(a.get("size"), 10),
                                scope_id=a.get("scope_id") or "", domain=a.get("domain") or "",
                                ip=a.get("ip") or "", site=a.get("site") or "")
            return env_page(r["items"], r["total"], r["page"], r["size"])

        @ns.doc(security="token", description="需权限 asset:write（asset_domain/asset_site 支持手动新增）")
        @ns.expect(_req)
        def post(self):
            """手动新增一条组内资产（仅 asset_domain/asset_site）"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产分组服务未就绪")
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return err(CODE_BAD_REQUEST, "请求体必须为 JSON 对象")
            r = svc.add_asset(coll, data)
            return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)

    @ns.route("/delete/")
    class _AssetDelete(Resource):
        @ns.doc(security="token", description="需权限 asset:write")
        def post(self):
            """按 _id 删除"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产分组服务未就绪")
            body = request.get_json(silent=True) or {}
            ids = body.get("_id") or body.get("ids") or []
            if isinstance(ids, str):
                ids = [ids]
            return ok(svc.delete_assets(coll, ids))

    @ns.route("/export/")
    class _AssetExport(Resource):
        @ns.doc(security="token", description="需权限 asset:read：导出全量(不限条数)")
        def get(self):
            """导出全量（禁硬限制参数，不 limit）"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产分组服务未就绪")
            a = request.args
            items = svc.export_assets(coll, scope_id=a.get("scope_id") or "")
            return ok({"items": items, "total": len(items)})

    if coll == "asset_site":
        @ns.route("/add_tag/")
        class _SiteAddTag(Resource):
            @ns.doc(security="token", description="需权限 asset:write")
            def post(self):
                """站点加标签"""
                svc = _svc()
                if not svc:
                    return err(CODE_ERROR, "资产分组服务未就绪")
                b = request.get_json(silent=True) or {}
                r = svc.add_site_tag(coll, b.get("_id", ""), b.get("tag", ""))
                return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)

        @ns.route("/delete_tag/")
        class _SiteDelTag(Resource):
            @ns.doc(security="token", description="需权限 asset:write")
            def post(self):
                """站点删标签"""
                svc = _svc()
                if not svc:
                    return err(CODE_ERROR, "资产分组服务未就绪")
                b = request.get_json(silent=True) or {}
                r = svc.delete_site_tag(coll, b.get("_id", ""), b.get("tag", ""))
                return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)

    return ns


ns_asset_domain = _build_asset_ns("asset_domain")
ns_asset_ip = _build_asset_ns("asset_ip")
ns_asset_site = _build_asset_ns("asset_site")
ns_asset_wih = _build_asset_ns("asset_wih")

