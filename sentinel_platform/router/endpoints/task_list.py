"""task_list 端点 —— 任务列表与生命周期的对外 REST（挂 /api/task/）。

**独立成文件**：task_plan 类别的 endpoints/task_plan.py 被 policy 占用（Namespace `policy`），
task_schedule 由 recon 另建；task_list 单独成文件、单独挂载（一类别多 AI 并行按叶子拆文件避撞车）。
注意：Namespace `task` 只挂 task_list 的路由（list/stop/resume/restart/delete/sync）；
**任务创建 POST /api/task/ 归 task_create 叶子**（另一 AI，用另一文件的同名 path 追加 POST，勿在此实现 create）。

对齐前端 api/task.ts（路径/形状锁定）：
  GET  /api/task/                任务列表（分页 + 过滤）
  GET  /api/task/stop/<id>       停止      GET /api/task/resume/<id> 续跑
  POST /api/task/restart/        重启(body task_id[])
  POST /api/task/delete/         删除(body task_id[], del_task_data)
  POST /api/task/batch_stop/     批量停
  POST /api/task/sync/           同步结果到资产组(task_id, scope_id)
  GET  /api/task/sync_scope/<target>  按目标反查可同步资产组

范式（照 endpoints/asset_groups.py）：经 get_registry().get("task_list_service") 调门面（不 import 叶子内部，缺失降级 500）+ env 信封。
权限：读 task:read（list/sync_scope）/ 写 task:write（stop/resume/restart/delete/sync）。**禁硬限制参数**：list size 透传不砍。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, page as env_page, CODE_BAD_REQUEST, CODE_ERROR

logger = get_logger()

ns = Namespace("task", path="/task", description="资产发现任务：列表与生命周期")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns)
except Exception:
    pass

_restart_req = ns.model("TaskRestartReq", {})
_delete_req = ns.model("TaskDeleteReq", {})
_sync_req = ns.model("TaskSyncReq", {})


def _svc():
    """取任务列表服务（字符串键 "task_list_service"，非 ROLE）；未注册 None（降级 500）。"""
    return get_registry().get("task_list_service")


def _int(v, d):
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


@ns.route("/")
class TaskList(Resource):
    @ns.doc(security="token", description="需权限 task:read")
    def get(self):
        """任务列表（分页 + name/target/status/task_tag 过滤）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        a = request.args
        r = svc.list_tasks(page=_int(a.get("page"), 1), size=_int(a.get("size"), 10),
                           name=a.get("name") or "", target=a.get("target") or "",
                           status=a.get("status") or "", task_tag=a.get("task_tag") or "")
        return env_page(r["items"], r["total"], r["page"], r["size"])


@ns.route("/stop/<string:task_id>")
class TaskStop(Resource):
    @ns.doc(security="token", description="需权限 task:write（协作式停止：置 status=stop）")
    def get(self, task_id):
        """停止任务"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        r = svc.stop_task(task_id)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/resume/<string:task_id>")
class TaskResume(Resource):
    @ns.doc(security="token", description="需权限 task:write")
    def get(self, task_id):
        """续跑任务（置 waiting，待编排层重新投递）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        r = svc.resume_task(task_id)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/restart/")
class TaskRestart(Resource):
    @ns.doc(security="token", description="需权限 task:write（重启：清 checkpoint 从头跑）")
    @ns.expect(_restart_req)
    def post(self):
        """重启任务（清 checkpoint）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("task_id") or body.get("ids") or []
        if isinstance(ids, str):
            ids = [ids]
        results = [svc.restart_task(t) for t in ids]
        return ok({"results": results, "count": len(results)})


@ns.route("/batch_stop/")
class TaskBatchStop(Resource):
    @ns.doc(security="token", description="需权限 task:write")
    @ns.expect(_restart_req)
    def post(self):
        """批量停止任务"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("task_id") or []
        if isinstance(ids, str):
            ids = [ids]
        return ok(svc.batch_stop(ids))


@ns.route("/delete/")
class TaskDelete(Resource):
    @ns.doc(security="token", description="需权限 task:write（del_task_data=true 级联清结果）")
    @ns.expect(_delete_req)
    def post(self):
        """删除任务（可选级联清结果集合）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        body = request.get_json(silent=True) or {}
        ids = body.get("task_id") or []
        if isinstance(ids, str):
            ids = [ids]
        return ok(svc.delete_tasks(ids, bool(body.get("del_task_data", False))))


@ns.route("/orphan_assets")
class TaskOrphanScan(Resource):
    @ns.doc(security="token", description="需权限 task:read")
    def get(self):
        """扫描孤儿资产（task_id 指向已删除任务的结果记录，只统计不删，供清理前预览）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        return ok(svc.scan_orphan_assets())


@ns.route("/orphan_assets/purge")
class TaskOrphanPurge(Resource):
    @ns.doc(security="token", description="需权限 task:write")
    def post(self):
        """清理孤儿资产（删 task_id 指向已删除任务的结果记录；无现存任务时跳过防误删）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        return ok(svc.purge_orphan_assets())


@ns.route("/sync/")
class TaskSync(Resource):
    @ns.doc(security="token", description="需权限 task:write（结果同步资产组，经 asset_group_service）")
    @ns.expect(_sync_req)
    def post(self):
        """把任务结果同步到资产组"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.sync_to_scope(body.get("task_id", ""), body.get("scope_id", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/sync_scope/<path:target>")
class TaskSyncScope(Resource):
    @ns.doc(security="token", description="需权限 task:read")
    def get(self, target):
        """按目标反查可同步的资产组"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务服务未就绪")
        r = svc.sync_scope_candidates(target)
        return env_page(r["items"], r["total"], 1, r["total"] or 1)


if __name__ == "__main__":
    pass
