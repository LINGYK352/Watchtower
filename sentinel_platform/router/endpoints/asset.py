"""asset 类别端点 —— 资产检索对外 REST（挂 /api/{集合}/*）。

8 侦察集合 domain/ip/site/url/cert/service/fileleak/wih 各一个顶级 Namespace（前端
`api/assets.ts` 的 collectionApi 按 namespace 打 `/api/{ns}/`），工厂 `_build_ns` 批量生成，
避免 8 份重复。站点类（site）额外挂 dedup/add_tag/delete_tag。

经 `get_registry().get("asset_search_service")` 调叶子门面（**不 import 叶子内部**，守解耦，
服务缺失降级 500）。列表走统一分页信封 {page,size,total,items}；导出走 CSV/文本流（非信封，
浏览器直接下载）。**禁止硬限制参数**：size 透传给叶子按需取，端点不设上限。

权限（RBAC 网关据 rbac_service 校验）：读(list/dedup/export)=`asset:read`；
写(delete/add_tag/delete_tag)=`asset:write`。全局 Token 鉴权（Api security='token'）。

导出 mount：本文件导出多个 Namespace（ns_domain/ns_ip/.../ns_site），在 router/__init__
的 _mount_namespaces 各加一行。
"""
from __future__ import annotations

from flask import request, Response
from flask_restx import Namespace, Resource, fields

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

logger = get_logger()

# 8 侦察集合；site 支持 dedup + 标签
_COLLECTIONS = ["domain", "ip", "site", "url", "cert", "service", "fileleak", "wih"]
_SITE_LIKE = {"site"}


def _svc():
    """取资产检索服务门面；未注册返回 None（端点降级 500）。"""
    return get_registry().get("asset_search_service")


def _fp_svc():
    """取指纹管理服务门面（字符串键 "fingerprint_service"，无 ROLE）；未注册降级。"""
    return get_registry().get("fingerprint_service")


def _args_dict():
    """请求 query 参数转 dict（含过滤字段 + page/size/order），全透传给叶子。"""
    return {k: v for k, v in request.args.items()}


def _ids_from_body():
    body = request.get_json(silent=True) or {}
    ids = body.get("_id")
    if isinstance(ids, str):
        ids = [ids]
    return ids or []


def _build_ns(coll: str) -> Namespace:
    """为一个集合生成 Namespace（list/delete/export；site 加 dedup/tag）。"""
    ns = Namespace(coll, path="/{}".format(coll), description="资产集合 {} 检索".format(coll))

    parser = ns.parser()
    parser.add_argument("page", type=int, location="args", help="页码, 默认1")
    parser.add_argument("size", type=int, location="args", help="每页条数, 默认10（无上限）")
    parser.add_argument("order", type=str, location="args", help="排序字段, 默认 -_id(倒序)")

    @ns.route("/")
    class _List(Resource):
        @ns.doc(security="token", description="需权限 asset:read")
        @ns.expect(parser)
        def get(self):
            """资产集合查询（分页 + 任意字段过滤 + 排序）"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产检索服务未就绪")
            return ok(svc.list_records(coll, _args_dict()))

    @ns.route("/delete/")
    class _Delete(Resource):
        @ns.doc(security="token", description="需权限 asset:write")
        def post(self):
            """按 _id 批量删除资产记录"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产检索服务未就绪")
            ids = _ids_from_body()
            if not ids:
                return err(CODE_BAD_REQUEST, "_id 必填(非空数组)")
            res = svc.delete_by_ids(coll, ids)
            if res.get("error"):
                return err(CODE_BAD_REQUEST, res["error"])
            return ok(res)

    @ns.route("/export/")
    class _Export(Resource):
        @ns.doc(security="token", description="需权限 asset:read；返回文本文件下载(非信封)")
        @ns.expect(parser)
        def get(self):
            """导出集合代表字段（一值一行，去重，全量不设上限）"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "资产检索服务未就绪")
            text, filename = svc.export_values(coll, _args_dict())
            resp = Response(text, mimetype="application/octet-stream")
            resp.headers["Content-Disposition"] = "attachment; filename={}".format(filename)
            resp.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
            return resp

    if coll in _SITE_LIKE:
        @ns.route("/dedup/")
        class _Dedup(Resource):
            @ns.doc(security="token", description="需权限 asset:read")
            @ns.expect(parser)
            def get(self):
                """站点按 域名+端口 去重查询（代表行带 _group_ids 供整组删除）"""
                svc = _svc()
                if not svc:
                    return err(CODE_ERROR, "资产检索服务未就绪")
                return ok(svc.list_dedup(coll, _args_dict()))

        @ns.route("/add_tag/")
        class _AddTag(Resource):
            @ns.doc(security="token", description="需权限 asset:write")
            def post(self):
                """给站点添加标签"""
                svc = _svc()
                if not svc:
                    return err(CODE_ERROR, "资产检索服务未就绪")
                body = request.get_json(silent=True) or {}
                res = svc.add_tag(coll, str(body.get("_id") or ""), body.get("tag") or "")
                if res.get("error"):
                    return err(CODE_BAD_REQUEST, res["error"])
                return ok(res)

        @ns.route("/delete_tag/")
        class _DeleteTag(Resource):
            @ns.doc(security="token", description="需权限 asset:write")
            def post(self):
                """删除站点标签"""
                svc = _svc()
                if not svc:
                    return err(CODE_ERROR, "资产检索服务未就绪")
                body = request.get_json(silent=True) or {}
                res = svc.delete_tag(coll, str(body.get("_id") or ""), body.get("tag") or "")
                if res.get("error"):
                    return err(CODE_BAD_REQUEST, res["error"])
                return ok(res)

    return ns


# 为每个集合生成并导出 Namespace（router/__init__ 各挂一行）。
ns_domain = _build_ns("domain")
ns_ip = _build_ns("ip")
ns_site = _build_ns("site")
ns_url = _build_ns("url")
ns_cert = _build_ns("cert")
ns_service = _build_ns("service")
ns_fileleak = _build_ns("fileleak")
ns_wih = _build_ns("wih")

# 供 router 遍历挂载的清单（属性名, ns 对象）。
ALL_NAMESPACES = [
    ("ns_domain", ns_domain), ("ns_ip", ns_ip), ("ns_site", ns_site),
    ("ns_url", ns_url), ("ns_cert", ns_cert), ("ns_service", ns_service),
    ("ns_fileleak", ns_fileleak), ("ns_wih", ns_wih),
]


# ============ 指纹管理（/api/fingerprint/*，Claude-Opus[recon] 2026-07-05）============
# fingerprint 是无 ROLE 的"核心路由暴露"叶子，endpoint 直调叶子函数（router→leaf 暴露路径）。
# 数据 API 规范：list 走 env.page 分页信封；size 无硬上限（禁硬限制参数）。
# 权限：GET list=asset:read（默认放行）；POST add/delete=asset:write（网关 rbac 按方法拦）。
ns_fingerprint = Namespace("fingerprint", path="/fingerprint", description="指纹规则管理：查询/新增/删除")
_fp_parser = ns_fingerprint.parser()
_fp_parser.add_argument("name", type=str, location="args", help="名称(模糊)")
_fp_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_fp_parser.add_argument("size", type=int, location="args", help="每页条数,默认10（无上限）")
_fp_add = ns_fingerprint.model("FingerprintAdd", {
    "name": fields.String(required=True, description="指纹名称"),
    "human_rule": fields.String(required=True, description='规则,如 body="X" && title="登录"'),
})


@ns_fingerprint.route("/")
class _FingerprintList(Resource):
    @ns_fingerprint.doc(security="token", description="需权限 asset:read")
    @ns_fingerprint.expect(_fp_parser)
    def get(self):
        """指纹信息查询（分页）"""
        fp = _fp_svc()
        if not fp:
            return err(CODE_ERROR, "指纹管理服务未就绪")
        from ..envelope import page as _page
        args = _fp_parser.parse_args()
        data = fp.list_fingerprint(args)
        return _page(data["items"], data["total"], data["page"], data["size"])

    @ns_fingerprint.doc(security="token", description="需权限 asset:write")
    @ns_fingerprint.expect(_fp_add, validate=True)
    def post(self):
        """新增指纹（规则语法校验 + 去重）"""
        fp = _fp_svc()
        if not fp:
            return err(CODE_ERROR, "指纹管理服务未就绪")
        b = request.get_json(silent=True) or {}
        r = fp.add_fingerprint(b.get("name", ""), b.get("human_rule", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_fingerprint.route("/delete/")
class _FingerprintDelete(Resource):
    @ns_fingerprint.doc(security="token", description="需权限 asset:write")
    def post(self):
        """删除指纹（按 _id 列表）"""
        fp = _fp_svc()
        if not fp:
            return err(CODE_ERROR, "指纹管理服务未就绪")
        b = request.get_json(silent=True) or {}
        r = fp.delete_fingerprint(b.get("_id", []))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_fingerprint.route("/export/")
class _FingerprintExport(Resource):
    @ns_fingerprint.doc(security="token", description="需权限 asset:read；返回 YAML 文件下载(非信封)")
    def get(self):
        """指纹导出（全部指纹 → YAML 文件，一条一 {name,rule}，禁硬限制不 limit）"""
        import time as _t
        fp = _fp_svc()
        if not fp:
            return err(CODE_ERROR, "指纹管理服务未就绪")
        text = fp.export_yaml()
        resp = Response(text, mimetype="application/octet-stream")
        resp.headers["Content-Disposition"] = "attachment; filename=fingerprint_{}.yml".format(int(_t.time()))
        resp.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return resp


@ns_fingerprint.route("/upload/")
class _FingerprintUpload(Resource):
    @ns_fingerprint.doc(security="token", description="需权限 asset:write；multipart 上传 YAML 指纹文件")
    def post(self):
        """指纹上传（multipart file，YAML 逐条校验+去重导入）"""
        fp = _fp_svc()
        if not fp:
            return err(CODE_ERROR, "指纹管理服务未就绪")
        f = request.files.get("file")
        if f is None:
            return err(CODE_BAD_REQUEST, "file 必填(multipart)")
        try:
            text = f.read().decode("utf-8", "ignore")
        except Exception as exc:
            return err(CODE_BAD_REQUEST, "文件读取失败: {}".format(exc))
        r = fp.import_yaml(text)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)
