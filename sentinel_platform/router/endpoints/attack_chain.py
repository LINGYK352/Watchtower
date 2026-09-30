"""attack_chain 端点 —— 攻击链情报对外 REST（挂 /api/intel/chain/...）。

**独立成文件的原因**：`endpoints/risk_intel.py` 的 `intel` Namespace(path `/intel`) 已被 vuln_intel
作者占用（`/intel/vuln_feed/*`，明确「勿改」）。为零撞车，攻击链端点单独成文件、独立 Namespace
（名 `attack_chain`，path `/intel`，路由 `/chain/*`）——flask_restx 多 Namespace 同 path 前缀不冲突
（路由各异），swagger 按 tag 分组。同 guard_log 独立文件先例。

对齐前端 `frontend/src/api/intel.ts` intelApi.chains/chainDetail/chainStat/chainDelete + `pages/intel/AttackChain.vue`：
  GET  /api/intel/chain/         列表（unit/status 过滤 + 分页）
  GET  /api/intel/chain/<id>     详情
  GET  /api/intel/chain/stat/    概览（总数/跨会话/各危害）
  POST /api/intel/chain/delete/  批量删除 {_id:[...]}
路径/形状锁定（前端已用），勿改。

范式（照 endpoints/guard_log.py 无 ROLE 叶子写法）：经 get_registry().get("attack_chain_service")
调门面（**不 import 叶子内部**，缺失降级 500）+ env 信封。
权限（RBAC，网关据 rbac_service 校验；PERMISSIONS 表 pentest:read 明含「攻击链」）：
  读(list/detail/stat)=`pentest:read`；写(delete)=`pentest:write`（rbac.PERM_RULES 已加 /api/intel/chain 规则）。
数据 API 规范（INTERFACES §5）：list 走信封分页；**禁止硬限制参数**——size 客户端定不砍（叶子层已守）。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("attack_chain", path="/intel", description="攻击链情报（跨会话利用链）")
_models = register_envelope_models(ns)


def _svc():
    """取 attack_chain 服务（字符串键 "attack_chain_service"，无 ROLE）。未注册降级 500。"""
    return get_registry().get("attack_chain_service")


_list_parser = ns.parser()
_list_parser.add_argument("unit", type=str, location="args", help="单位过滤")
_list_parser.add_argument("status", type=str, location="args", help="状态过滤 building/done")
_list_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_list_parser.add_argument("size", type=int, location="args", help="每页条数, 默认20（无硬上限，传多大返多少）")
_list_parser.add_argument("min_severity", type=str, location="args",
                          help="危害门槛, 默认 high（只列高危及以上利用链）；传 info/空显示全部含低危链")

_stat_parser = ns.parser()
_stat_parser.add_argument("unit", type=str, location="args", help="单位过滤（可选）")
_stat_parser.add_argument("min_severity", type=str, location="args",
                          help="危害门槛, 默认 high；传 info/空统计全部")


def _floor_arg(v) -> str:
    """危害门槛入参归一：None（未传）→ 默认 'high'；显式传空串 → '' 表示不过滤（显示全部）。"""
    return "high" if v is None else str(v)

_del_req = ns.model("ChainDeleteReq", {})    # body {_id:[...]}


@ns.route("/chain/")
class ChainList(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    @ns.expect(_list_parser)
    def get(self):
        """攻击链列表（unit/status 过滤 + 分页，size 无硬上限）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "攻击链服务未就绪")
        a = _list_parser.parse_args()
        try:
            page = int(a.get("page") or 1)
            size = int(a.get("size") or 20)
        except (TypeError, ValueError):
            page, size = 1, 20
        return ok(svc.list_chains(unit=a.get("unit") or "", status=a.get("status") or "",
                                  page=page, size=size, min_severity=_floor_arg(a.get("min_severity"))))


@ns.route("/chain/stat/")
class ChainStat(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    @ns.expect(_stat_parser)
    def get(self):
        """攻击链概览（链总数/跨会话链数/各危害等级链数）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "攻击链服务未就绪")
        return ok(svc.stat(request.args.get("unit") or "",
                            min_severity=_floor_arg(request.args.get("min_severity"))))


@ns.route("/chain/delete/")
class ChainDelete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    @ns.expect(_del_req)
    def post(self):
        """批量删除攻击链"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "攻击链服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("_id") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "_id(非空数组) 必填")
        r = svc.delete_chains(ids)
        return ok({"deleted": r.get("deleted", 0)})


@ns.route("/chain/<string:chain_id>")
class ChainDetail(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, chain_id):
        """攻击链详情（完整环节列表）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "攻击链服务未就绪")
        d = svc.get_chain(chain_id)
        if d is None:
            return err(CODE_NOT_FOUND, "攻击链不存在")
        return ok(d)
