"""scan_result 端点 —— 扫描结果集合对外 REST（挂 /api/{vuln,nuclei_result,npoc_service}/*）。

对齐前端 `api/poc.ts` 的 vulnApi/nucleiResultApi/npocServiceApi + `pages/risk/VulnCenter.vue`
（三来源混排里 poc/nuclei 单源删除）。经 `get_registry().get("scan_result_service")` 调
risk_intel/scan_result 叶子门面（**不 import 叶子内部**，守解耦，服务缺失降级 500）+ env 信封。

vuln/nuclei_result 支持 list + delete；npoc_service 仅 list（前端无删除入口）。
列表走统一分页信封 {page,size,total,items}；**禁止硬限制参数**：size 透传按需取，不设上限。
权限：读(list)=`vuln:read`；写(delete)=`vuln:write`。全局 Token 鉴权。

导出 3 个 Namespace（ns_vuln/ns_nuclei/ns_npoc），router/__init__ 各挂一行。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

logger = get_logger()


def _svc():
    """取扫描结果服务门面（字符串键 "scan_result_service"，非 ROLE）；未注册返回 None（端点降级 500）。"""
    return get_registry().get("scan_result_service")


def _ids_from_body():
    body = request.get_json(silent=True) or {}
    ids = body.get("_id")
    if isinstance(ids, str):
        ids = [ids]
    return ids or []


def _list_parser(ns: Namespace):
    p = ns.parser()
    p.add_argument("page", type=int, location="args", help="页码, 默认1")
    p.add_argument("size", type=int, location="args", help="每页条数, 默认10（无上限）")
    p.add_argument("order", type=str, location="args", help="排序字段, 默认 -_id(倒序)")
    return p


def _build_ns(coll: str, with_delete: bool) -> Namespace:
    """为一个扫描结果集合生成 Namespace（list；with_delete 时加 delete/）。"""
    ns = Namespace(coll, path="/{}".format(coll), description="扫描结果集合 {} 查询".format(coll))
    parser = _list_parser(ns)

    @ns.route("/")
    class _List(Resource):
        @ns.doc(security="token", description="需权限 vuln:read")
        @ns.expect(parser)
        def get(self):
            """扫描结果查询（分页 + 任意字段过滤 + 排序）"""
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "扫描结果服务未就绪")
            return ok(svc.list_records(coll, {k: v for k, v in request.args.items()}))

    if with_delete:
        @ns.route("/delete/")
        class _Delete(Resource):
            @ns.doc(security="token", description="需权限 vuln:write")
            def post(self):
                """按 _id 批量删除扫描结果"""
                svc = _svc()
                if not svc:
                    return err(CODE_ERROR, "扫描结果服务未就绪")
                ids = _ids_from_body()
                if not ids:
                    return err(CODE_BAD_REQUEST, "_id 必填(非空数组)")
                res = svc.delete_by_ids(coll, ids)
                if res.get("error"):
                    return err(CODE_BAD_REQUEST, res["error"])
                return ok(res)

    return ns


# vuln / nuclei_result 可删；npoc_service 仅列表。
ns_vuln = _build_ns("vuln", with_delete=True)
ns_nuclei = _build_ns("nuclei_result", with_delete=True)
ns_npoc = _build_ns("npoc_service", with_delete=False)
