"""task_plan 类别端点 —— 任务与计划的对外 REST（当前挂 /api/policy/...）。

已挂：policy 策略配置 → /api/policy/{,add,edit,delete}
  对齐前端 `frontend/src/api/policy.ts` + `pages/settings/Policy.vue`（路径/形状锁定，勿改）。

范式（照 endpoints/api_keys.py 无 ROLE 叶子写法）：Namespace + docstring 首行=summary +
@ns.doc(security) + RequestParser/model 声明入参（进 swagger）+ 经 get_registry().get("policy_service")
调叶子门面（**不 import 叶子内部**，守解耦，服务缺失降级 500）+ env 信封。

权限（RBAC，网关据 rbac_service 校验；未建降级放行，权限点写 docstring）：
  读（list）= `policy:read`；写（add/edit/delete）= `policy:write`（均在 rbac 16 权限点内）。

数据 API 规范（INTERFACES §5）：list 走信封分页；**禁止硬限制参数**——size 透传不砍上限，
策略内 port_parallelism/port_min_rate/host_timeout 等是缺省值非硬限制（叶子层已守，端点不再夹）。

后续 task_plan 叶子（task_list/task_create/task_schedule）在本文件追加独立 Namespace + 挂载行。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("policy", path="/policy", description="扫描/AI渗透策略配置")
_models = register_envelope_models(ns)


def _svc():
    """取 policy 服务（字符串键 "policy_service"，无 ROLE 纯配置叶子）。未注册降级 500。"""
    return get_registry().get("policy_service")


def _ts_svc():
    """取 task_schedule 服务门面（字符串键 "task_schedule_service"，无 ROLE）；未注册降级。"""
    return get_registry().get("task_schedule_service")


_list_parser = ns.parser()
_list_parser.add_argument("name", type=str, location="args", help="策略名(模糊)")
_list_parser.add_argument("_id", type=str, location="args", help="策略 _id(精确，编辑页加载用)")
_list_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_list_parser.add_argument("size", type=int, location="args", help="每页条数, 默认10（无硬上限，传多大返多少）")

_add_req = ns.model("PolicyAddReq", {})    # body {name, desc?, policy{...}}；宽松，叶子层校验+归一
_edit_req = ns.model("PolicyEditReq", {})   # body {policy_id, policy_data{...}}
_del_req = ns.model("PolicyDeleteReq", {})  # body {policy_id:[...]}


@ns.route("/")
class PolicyList(Resource):
    @ns.doc(security="token", description="需权限 policy:read")
    @ns.expect(_list_parser)
    def get(self):
        """策略列表（名称模糊 + 分页，size 无硬上限）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "策略服务未就绪")
        a = _list_parser.parse_args()
        try:
            page = int(a.get("page") or 1)
            size = int(a.get("size") or 10)
        except (TypeError, ValueError):
            page, size = 1, 10
        return ok(svc.list_policies(name=a.get("name") or None, page=page, size=size,
                                    _id=a.get("_id") or None))


@ns.route("/add/")
class PolicyAdd(Resource):
    @ns.doc(security="token", description="需权限 policy:write")
    @ns.expect(_add_req)
    def post(self):
        """新建策略（校验插件/端口语法，归一模式与三轨代理）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "策略服务未就绪")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return err(CODE_BAD_REQUEST, "请求体必须为 JSON 对象")
        r = svc.add_policy(body.get("name", ""), body.get("policy") or {}, body.get("desc", ""))
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "新建失败"))
        return ok({"policy_id": r["policy_id"]})


@ns.route("/edit/")
class PolicyEdit(Resource):
    @ns.doc(security="token", description="需权限 policy:write")
    @ns.expect(_edit_req)
    def post(self):
        """编辑策略（深合并允许字段 + 重校验插件）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "策略服务未就绪")
        body = request.get_json(silent=True) or {}
        policy_id = (body.get("policy_id") or "").strip()
        if not policy_id:
            return err(CODE_BAD_REQUEST, "policy_id 必填")
        r = svc.edit_policy(policy_id, body.get("policy_data") or {})
        if not r.get("ok"):
            msg = r.get("error", "编辑失败")
            code = CODE_NOT_FOUND if msg == "策略不存在" else CODE_BAD_REQUEST
            return err(code, msg)
        return ok({"data": r["data"]})


@ns.route("/delete/")
class PolicyDelete(Resource):
    @ns.doc(security="token", description="需权限 policy:write")
    @ns.expect(_del_req)
    def post(self):
        """批量删除策略"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "策略服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("policy_id") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "policy_id(非空数组) 必填")
        r = svc.delete_policy(ids)
        return ok({"deleted": r.get("deleted", 0)})


# ============ 计划任务（/api/task_schedule/*，Claude-Opus[recon] 2026-07-05）============
# task_schedule 无 ROLE，核心路由暴露：endpoint 直调叶子函数（router→leaf 暴露路径）。
# 数据 API 规范：list 走 env.page 分页信封；size 无硬上限（禁硬限制参数）。
# 权限：GET list=task:read（默认放行）；POST add/delete/stop/recover=task:write（网关 rbac 拦）。
from flask_restx import fields as _fields  # noqa: E402（本段局部用，不影响上方 policy 段）

ns_schedule = Namespace("task_schedule", path="/task_schedule", description="计划任务：定时/周期扫描定义 CRUD + 启停")
_sched_parser = ns_schedule.parser()
_sched_parser.add_argument("name", type=str, location="args", help="名称(模糊)")
_sched_parser.add_argument("schedule_type", type=str, location="args", help="future_scan/recurrent_scan")
_sched_parser.add_argument("status", type=str, location="args", help="scheduled/stopped")
_sched_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_sched_parser.add_argument("size", type=int, location="args", help="每页条数,默认10（无上限）")
_sched_add = ns_schedule.model("ScheduleAdd", {
    "name": _fields.String(required=True, description="名称"),
    "target": _fields.String(required=True, description="目标"),
    "schedule_type": _fields.String(required=True, description="future_scan|recurrent_scan"),
    "policy_id": _fields.String(required=True, description="策略 ID"),
    "task_tag": _fields.String(required=True, description="task|risk_cruising"),
    "cron": _fields.String(description="cron(周期任务)"),
    "start_date": _fields.String(description="开始时间(定时任务)"),
})
_sched_ids = ns_schedule.model("ScheduleIds", {"_id": _fields.List(_fields.String, description="计划任务ID列表")})


@ns_schedule.route("/")
class _ScheduleList(Resource):
    @ns_schedule.doc(security="token", description="需权限 task:read")
    @ns_schedule.expect(_sched_parser)
    def get(self):
        """计划任务查询（分页）"""
        ts = _ts_svc()
        if not ts:
            return err(CODE_ERROR, "计划任务服务未就绪")
        from ..envelope import page as _page
        d = ts.list_schedules(_sched_parser.parse_args())
        return _page(d["items"], d["total"], d["page"], d["size"])

    @ns_schedule.doc(security="token", description="需权限 task:write")
    @ns_schedule.expect(_sched_add)
    def post(self):
        """新建计划任务（校验 cron/类型 + 反查策略名）"""
        ts = _ts_svc()
        if not ts:
            return err(CODE_ERROR, "计划任务服务未就绪")
        r = ts.add_schedule(request.get_json(silent=True) or {})
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


def _ids_body():
    b = request.get_json(silent=True) or {}
    ids = b.get("_id") or []
    return ids if isinstance(ids, list) else []


@ns_schedule.route("/delete/")
class _ScheduleDelete(Resource):
    @ns_schedule.doc(security="token", description="需权限 task:write")
    @ns_schedule.expect(_sched_ids)
    def post(self):
        """删除计划任务"""
        ts = _ts_svc()
        if not ts:
            return err(CODE_ERROR, "计划任务服务未就绪")
        r = ts.delete_schedules(_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_schedule.route("/stop/")
class _ScheduleStop(Resource):
    @ns_schedule.doc(security="token", description="需权限 task:write")
    @ns_schedule.expect(_sched_ids)
    def post(self):
        """停止（暂停）计划任务"""
        ts = _ts_svc()
        if not ts:
            return err(CODE_ERROR, "计划任务服务未就绪")
        r = ts.stop_schedules(_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_schedule.route("/recover/")
class _ScheduleRecover(Resource):
    @ns_schedule.doc(security="token", description="需权限 task:write")
    @ns_schedule.expect(_sched_ids)
    def post(self):
        """恢复计划任务"""
        ts = _ts_svc()
        if not ts:
            return err(CODE_ERROR, "计划任务服务未就绪")
        r = ts.recover_schedules(_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)
