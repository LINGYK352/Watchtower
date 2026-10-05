"""探针管理端点 —— /api/probe/*"""
from __future__ import annotations

import os

from flask import request, send_file
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND

logger = get_logger()

ns = Namespace("probe", path="/probe", description="探针管理：红队/蓝队探针配置与打包")


def _svc():
    return get_registry().get("probe_service")


def _body():
    return request.get_json(silent=True) or {}


@ns.route("/list")
class ProbeList(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        probe_type = request.args.get("type", "red")
        return ok(svc.list_probes(probe_type))


@ns.route("/create")
class ProbeCreate(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def post(self):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        body = _body()
        vps_ip = body.get("vps_ip", "").strip()
        if not vps_ip:
            return err(CODE_BAD_REQUEST, "vps_ip 必填")
        doc = svc.create_probe(
            name=body.get("name", ""),
            vps_ip=vps_ip,
            port=int(body.get("port", 8443)),
            tunnel_port=int(body.get("tunnel_port", 8444)),
            auth_key=body.get("auth_key", ""),
            protocol=body.get("protocol", "https"),
            probe_type=body.get("type", "red"),
        )
        return ok(doc)


@ns.route("/build/<string:probe_id>")
class ProbeBuild(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def post(self, probe_id):
        """触发探针打包（耗时操作）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        # 打包是耗时且可能失败的操作（PyInstaller 缺失/OOM/环境异常）：服务层已 honest degrade 返回 None，
        # 这里再兜一层防任何意外异常逃逸成 500，并把失败真因（build_error）回给用户而非笼统提示。
        try:
            path = svc.generate_probe_binary(probe_id)
        except Exception as e:
            # 真正意外异常（服务层已兜住绝大多数）：保留 500，值得上报开发者
            return err(CODE_ERROR, "打包异常：{}".format(str(e)[:200]))
        if not path:
            # 预期内的打包失败（PyInstaller 缺失/OOM/环境异常）：返回 400 而非 500——
            # 这是可读的操作性失败，前端只 toast 显示真因，不触发「上报开发者」崩溃弹窗。
            reason = svc.last_build_error(probe_id) if hasattr(svc, "last_build_error") else ""
            return err(CODE_BAD_REQUEST, "打包失败：{}".format(reason) if reason
                       else "打包失败，请检查 PyInstaller 是否安装及打包环境（内存/编译链）")
        return ok({"build_path": os.path.basename(path)})


@ns.route("/download/<string:probe_id>")
class ProbeDownload(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, probe_id):
        """下载已打包探针文件"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        path = svc.get_build_path(probe_id)
        if not path or not os.path.exists(path):
            return err(CODE_NOT_FOUND, "探针尚未打包或文件不存在")
        resp = send_file(path, as_attachment=True, download_name=os.path.basename(path))
        resp.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return resp


@ns.route("/delete/<string:probe_id>")
class ProbeDelete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def delete(self, probe_id):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        if svc.delete_probe(probe_id):
            return ok({"deleted": True})
        return err(CODE_NOT_FOUND, "探针不存在")


@ns.route("/status/<string:probe_id>")
class ProbeStatus(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, probe_id):
        """实时探测探针在线状态"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        status = svc.get_probe_status(probe_id)
        if status is None:
            return err(CODE_NOT_FOUND, "探针不存在")
        return ok(status)


# ═══ Agent Endpoints ═══

@ns.route("/agent/list")
class AgentList(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        probe_id = request.args.get("probe_id", "")
        return ok(svc.list_agents(probe_id or None))


@ns.route("/agent/create")
class AgentCreate(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def post(self):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        body = _body()
        probe_id = body.get("probe_id", "").strip()
        probe_ids = body.get("probe_ids") or []
        if not probe_id and not probe_ids:
            return err(CODE_BAD_REQUEST, "probe_id 或 probe_ids 必填（需先创建探针）")
        doc = svc.create_agent(
            name=body.get("name", ""),
            probe_id=body.get("probe_id", "").strip(),
            platform=body.get("platform", "linux_x64"),
            mode=body.get("mode", "reverse"),
            listen_port=int(body.get("listen_port", 9443)),
            reuse_port=int(body.get("reuse_port", 0)),
            beacon_interval=int(body.get("beacon_interval", 5)),
            beacon_jitter=int(body.get("beacon_jitter", 30)),
            probe_ids=body.get("probe_ids"),
        )
        return ok(doc)


@ns.route("/agent/build/<string:agent_id>")
class AgentBuild(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def post(self, agent_id):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        try:
            path = svc.generate_agent_binary(agent_id)
        except Exception as e:
            return err(CODE_ERROR, "打包异常：{}".format(str(e)[:200]))
        if not path:
            reason = svc.last_agent_build_error(agent_id) if hasattr(svc, "last_agent_build_error") else ""
            return err(CODE_BAD_REQUEST, "打包失败：{}".format(reason) if reason
                       else "打包失败，请检查 PyInstaller 是否安装及打包环境（内存/编译链）")
        return ok({"build_path": os.path.basename(path)})


@ns.route("/agent/download/<string:agent_id>")
class AgentDownload(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, agent_id):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        path = svc.get_agent_build_path(agent_id)
        if not path or not os.path.exists(path):
            return err(CODE_NOT_FOUND, "Agent 尚未打包或文件不存在")
        resp = send_file(path, as_attachment=True, download_name=os.path.basename(path))
        resp.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return resp


@ns.route("/agent/<string:agent_id>")
class AgentDelete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def delete(self, agent_id):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        if svc.delete_agent(agent_id):
            return ok({"deleted": True})
        return err(CODE_NOT_FOUND, "Agent 不存在")


@ns.route("/agent/status/<string:agent_id>")
class AgentStatus(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, agent_id):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "探针服务未就绪")
        status = svc.get_agent_status(agent_id)
        if status is None:
            return err(CODE_NOT_FOUND, "Agent 不存在")
        return ok(status)

