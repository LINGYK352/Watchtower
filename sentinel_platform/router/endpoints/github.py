"""GitHub 端点 —— GitHub 敏感信息搜索任务/结果（/api/github_task/*, /api/github_result/*）。

对接 asset/github_task 叶子（无 ROLE，核心路由暴露，endpoint 直调叶子函数）。
数据 API 规范：list 走 env.page 分页信封；size 无硬上限（禁硬限制参数）。
权限：GET list=asset:read（默认放行）；POST add/delete/stop=asset:write（网关 rbac 拦）。

github_scheduler / github_monitor_result 属 github_monitor 叶子（另建），本文件不含。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource, fields

from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, page as _page, CODE_BAD_REQUEST, CODE_ERROR


def _gt_svc():
    """取 github_task 服务门面（字符串键 "github_task_service"，无 ROLE）；未注册降级。"""
    return get_registry().get("github_task_service")


def _gm_svc():
    """取 github_monitor 服务门面（字符串键 "github_monitor_service"，无 ROLE）；未注册降级。"""
    return get_registry().get("github_monitor_service")


# —— GitHub 任务（一次性关键字搜索）——
ns_task = Namespace("github_task", path="/github_task", description="GitHub 敏感信息搜索任务")
_task_parser = ns_task.parser()
_task_parser.add_argument("name", type=str, location="args", help="任务名(模糊)")
_task_parser.add_argument("keyword", type=str, location="args", help="关键字(模糊)")
_task_parser.add_argument("status", type=str, location="args", help="状态")
_task_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_task_parser.add_argument("size", type=int, location="args", help="每页条数,默认10（无上限）")
_task_add = ns_task.model("GithubTaskAdd", {
    "name": fields.String(description="任务名(空则取关键字)"),
    "keyword": fields.String(required=True, description="搜索关键字"),
})
_task_ids = ns_task.model("GithubTaskIds", {"_id": fields.List(fields.String, description="任务ID列表")})


def _ids_body():
    b = request.get_json(silent=True) or {}
    ids = b.get("_id") or []
    return ids if isinstance(ids, list) else []


@ns_task.route("/")
class _TaskList(Resource):
    @ns_task.doc(security="token", description="需权限 asset:read")
    @ns_task.expect(_task_parser)
    def get(self):
        """GitHub 任务查询（分页）"""
        gt = _gt_svc()
        if not gt:
            return err(CODE_ERROR, "GitHub 任务服务未就绪")
        d = gt.list_tasks(_task_parser.parse_args())
        return _page(d["items"], d["total"], d["page"], d["size"])

    @ns_task.doc(security="token", description="需权限 asset:write")
    @ns_task.expect(_task_add)
    def post(self):
        """新建 GitHub 搜索任务（status=waiting，待编排执行）"""
        gt = _gt_svc()
        if not gt:
            return err(CODE_ERROR, "GitHub 任务服务未就绪")
        b = request.get_json(silent=True) or {}
        r = gt.add_task(b.get("name", ""), b.get("keyword", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_task.route("/delete/")
class _TaskDelete(Resource):
    @ns_task.doc(security="token", description="需权限 asset:write")
    @ns_task.expect(_task_ids)
    def post(self):
        """删除 GitHub 任务（运行中不可删，级联删结果）"""
        gt = _gt_svc()
        if not gt:
            return err(CODE_ERROR, "GitHub 任务服务未就绪")
        r = gt.delete_tasks(_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_task.route("/stop/")
class _TaskStop(Resource):
    @ns_task.doc(security="token", description="需权限 asset:write")
    @ns_task.expect(_task_ids)
    def post(self):
        """停止 GitHub 任务"""
        gt = _gt_svc()
        if not gt:
            return err(CODE_ERROR, "GitHub 任务服务未就绪")
        r = gt.stop_tasks(_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


# —— GitHub 搜索结果 ——
ns_result = Namespace("github_result", path="/github_result", description="GitHub 搜索命中结果")
_result_parser = ns_result.parser()
_result_parser.add_argument("github_task_id", type=str, location="args", help="按任务ID过滤")
_result_parser.add_argument("keyword", type=str, location="args", help="关键字(模糊)")
_result_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_result_parser.add_argument("size", type=int, location="args", help="每页条数,默认10（无上限）")


@ns_result.route("/")
class _ResultList(Resource):
    @ns_result.doc(security="token", description="需权限 asset:read")
    @ns_result.expect(_result_parser)
    def get(self):
        """GitHub 搜索结果查询（分页，可按 github_task_id 过滤）"""
        gt = _gt_svc()
        if not gt:
            return err(CODE_ERROR, "GitHub 任务服务未就绪")
        d = gt.list_results(_result_parser.parse_args())
        return _page(d["items"], d["total"], d["page"], d["size"])


# —— GitHub 周期监控（github_monitor 叶子，Claude-Opus[recon] 2026-07-05）——
ns_scheduler = Namespace("github_scheduler", path="/github_scheduler", description="GitHub 周期监控任务")
_sch_parser = ns_scheduler.parser()
_sch_parser.add_argument("name", type=str, location="args", help="任务名(模糊)")
_sch_parser.add_argument("keyword", type=str, location="args", help="关键字(模糊)")
_sch_parser.add_argument("status", type=str, location="args", help="running/stopped")
_sch_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_sch_parser.add_argument("size", type=int, location="args", help="每页条数,默认10（无上限）")
_sch_add = ns_scheduler.model("GithubMonitorAdd", {
    "name": fields.String(description="任务名(空则取关键字)"),
    "keyword": fields.String(required=True, description="监控关键字"),
    "cron": fields.String(required=True, description="cron 表达式"),
})
_sch_upd = ns_scheduler.model("GithubMonitorUpdate", {
    "_id": fields.String(required=True, description="监控任务ID"),
    "name": fields.String(description="任务名"),
    "keyword": fields.String(description="关键字"),
    "cron": fields.String(description="cron"),
})
_sch_ids = ns_scheduler.model("GithubMonitorIds", {"_id": fields.List(fields.String, description="监控任务ID列表")})


def _sch_ids_body():
    b = request.get_json(silent=True) or {}
    ids = b.get("_id") or []
    return ids if isinstance(ids, list) else []


@ns_scheduler.route("/")
class _MonitorList(Resource):
    @ns_scheduler.doc(security="token", description="需权限 asset:read")
    @ns_scheduler.expect(_sch_parser)
    def get(self):
        """GitHub 监控任务查询（分页）"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        d = gm.list_monitors(_sch_parser.parse_args())
        return _page(d["items"], d["total"], d["page"], d["size"])

    @ns_scheduler.doc(security="token", description="需权限 asset:write")
    @ns_scheduler.expect(_sch_add)
    def post(self):
        """新建 GitHub 周期监控任务（校验 cron）"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        b = request.get_json(silent=True) or {}
        r = gm.add_monitor(b.get("name", ""), b.get("keyword", ""), b.get("cron", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_scheduler.route("/update/")
class _MonitorUpdate(Resource):
    @ns_scheduler.doc(security="token", description="需权限 asset:write")
    @ns_scheduler.expect(_sch_upd)
    def post(self):
        """更新 GitHub 监控任务"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        b = request.get_json(silent=True) or {}
        mid = b.pop("_id", "")
        r = gm.update_monitor(mid, **b)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_scheduler.route("/delete/")
class _MonitorDelete(Resource):
    @ns_scheduler.doc(security="token", description="需权限 asset:write")
    @ns_scheduler.expect(_sch_ids)
    def post(self):
        """删除 GitHub 监控任务（级联删结果）"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        r = gm.delete_monitors(_sch_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_scheduler.route("/stop/")
class _MonitorStop(Resource):
    @ns_scheduler.doc(security="token", description="需权限 asset:write")
    @ns_scheduler.expect(_sch_ids)
    def post(self):
        """停止 GitHub 监控任务"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        r = gm.stop_monitors(_sch_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns_scheduler.route("/recover/")
class _MonitorRecover(Resource):
    @ns_scheduler.doc(security="token", description="需权限 asset:write")
    @ns_scheduler.expect(_sch_ids)
    def post(self):
        """恢复 GitHub 监控任务"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        r = gm.recover_monitors(_sch_ids_body())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


# —— GitHub 监控结果 ——
ns_monitor_result = Namespace("github_monitor_result", path="/github_monitor_result",
                              description="GitHub 周期监控命中结果")
_mr_parser = ns_monitor_result.parser()
_mr_parser.add_argument("github_scheduler_id", type=str, location="args", help="按监控任务ID过滤")
_mr_parser.add_argument("keyword", type=str, location="args", help="关键字(模糊)")
_mr_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_mr_parser.add_argument("size", type=int, location="args", help="每页条数,默认10（无上限）")


@ns_monitor_result.route("/")
class _MonitorResultList(Resource):
    @ns_monitor_result.doc(security="token", description="需权限 asset:read")
    @ns_monitor_result.expect(_mr_parser)
    def get(self):
        """GitHub 监控结果查询（分页，可按 github_scheduler_id 过滤）"""
        gm = _gm_svc()
        if not gm:
            return err(CODE_ERROR, "GitHub 监控服务未就绪")
        d = gm.list_results(_mr_parser.parse_args())
        return _page(d["items"], d["total"], d["page"], d["size"])
