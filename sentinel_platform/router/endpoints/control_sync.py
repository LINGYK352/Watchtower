"""Logged-in administrator management; MCP/peer transports authenticate independently."""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from flask_restx import Namespace, Resource

from sentinel_platform.contracts import get_registry
from sentinel_platform.router.envelope import envelope
from sentinel_platform.router.gateway import verify_token
from sentinel_platform.modules.workspace.control_sync.security import ControlSyncError

ns = Namespace("control_sync", path="/control_sync", description="控制凭据与跨平台同步 / Control credentials and cross-platform sync")
transport_routes = Blueprint("control_sync_transport", __name__)


def _service():
    service = get_registry().get("control_sync_service")
    if not service:
        raise ControlSyncError("控制同步服务未就绪 / Control sync service unavailable", 503)
    return service


def _admin():
    # Authentication remains mandatory here even if a legacy AUTH switch is disabled.
    user = getattr(g, "current_user", None) or verify_token(request.headers.get("Token", ""))
    if not user:
        raise ControlSyncError("需要登录 / Login required", 401)
    if user.get("role") != "admin" or user.get("via") == "control_key":
        raise ControlSyncError("仅管理员可管理控制和同步 / Administrator required", 403)
    return user


def _body():
    if request.content_length and request.content_length > 16 * 1024:
        raise ControlSyncError("请求过大 / Request too large", 413)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ControlSyncError("JSON对象必填 / JSON object required")
    return body


def _call(fn):
    try:
        user = _admin()
        return envelope(data=fn(_service(), user)), 200
    except ControlSyncError as exc:
        return envelope(code=exc.status, message=str(exc)), exc.status
    except Exception:
        from sentinel_platform.core import get_logger
        get_logger().exception("control sync management failed")
        return envelope(code=503, message="控制同步服务暂不可用 / Control sync temporarily unavailable"), 503


@ns.route("/state")
class State(Resource):
    def get(self):
        from sentinel_platform.modules.workspace.control_sync.control import SCOPES
        from sentinel_platform.modules.workspace.control_sync.pairing import CATEGORIES
        def state(s, u):
            from sentinel_platform.modules.workspace import preferences
            s.snapshots.recover()
            return {"identity": s.pairing.identity(), "keys": s.control.list(), "links": s.pairing.list(),
                    "history": s.pairing.history_list(), "runs": s.transfers.list(), "listener": s.listener.public(), "scopes": SCOPES, "categories": list(CATEGORIES),"preferences":preferences.get(s.repo,u)}
        return _call(state)


@ns.route("/keys")
class Keys(Resource):
    def post(self):
        return _call(lambda s, u: s.control.create(u, _body()))


@ns.route("/listener")
class Listener(Resource):
    def post(self):
        return _call(lambda s, u: s.listener.configure(_body()))


@ns.route("/keys/<string:key_id>/revoke")
class KeyRevoke(Resource):
    def post(self, key_id):
        return _call(lambda s, u: s.control.revoke(key_id))


@ns.route("/keys/<string:key_id>")
class KeyDelete(Resource):
    def delete(self, key_id):
        return _call(lambda s, u: s.control.delete(key_id))


@ns.route("/pair-key")
class PairKey(Resource):
    def post(self):
        return _call(lambda s, u: s.pairing.create(u, _body()))


@ns.route("/connect")
class Connect(Resource):
    def post(self):
        return _call(lambda s, u: s.pairing.connect(u, _body()))


@ns.route("/links/<string:link_id>/confirm")
class Confirm(Resource):
    def post(self, link_id):
        return _call(lambda s, u: s.pairing.confirm(link_id, u))


@ns.route("/links/<string:link_id>/refresh")
class Refresh(Resource):
    def post(self, link_id):
        return _call(lambda s, u: s.pairing.refresh(link_id,background=_body().get('background') is True))


@ns.route("/links/<string:link_id>/revoke")
class LinkRevoke(Resource):
    def post(self, link_id):
        return _call(lambda s, u: s.pairing.revoke(link_id))

@ns.route('/links/<string:link_id>/delete')
class LinkDelete(Resource):
    def post(self,link_id):
        def remove(s,u):
            if _body().get('confirmed') is not True:raise ControlSyncError('请确认删除 / Confirm deletion')
            return s.pairing.delete(link_id,u)
        return _call(remove)


@ns.route("/runs")
class Runs(Resource):
    def post(self):
        return _call(lambda s, u: s.transfers.start(u, _body()))


@ns.route('/runs/<string:run_id>')
class RunHistory(Resource):
    def get(self,run_id):return _call(lambda s,u:s.transfers.history_detail(run_id))
    def delete(self,run_id):
        def remove(s,u):
            if _body().get('confirmed') is not True:raise ControlSyncError('请确认删除记录 / Confirm record deletion')
            return s.transfers.delete_history(run_id,u)
        return _call(remove)


@ns.route("/runs/<string:run_id>/decide")
class RunDecision(Resource):
    def post(self, run_id):
        return _call(lambda s, u: s.transfers.decide(run_id, u, _body().get("accepted") is True))


@ns.route("/runs/<string:run_id>/progress")
class RunProgress(Resource):
    def post(self, run_id):
        return _call(lambda s, u: s.transfers.status(run_id))


@ns.route("/runs/<string:run_id>/advance")
class RunAdvance(Resource):
    def post(self, run_id):
        return _call(lambda s, u: s.transfers.advance(run_id))


@transport_routes.route("/api/control_sync/mcp", methods=["POST", "GET", "DELETE"])
def mcp():
    from sentinel_platform.router.control_mcp import handle_mcp
    try:
        return handle_mcp(_service().control)
    except ControlSyncError as exc:
        return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}), exc.status


@transport_routes.route("/api/control_sync/watchtower_operations", methods=["GET"])
def operations():
    from sentinel_platform.router.control_mcp import handle_http_control
    try:
        return handle_http_control(_service().control, operations=True)
    except ControlSyncError as exc:
        return jsonify(error=str(exc)), exc.status


@transport_routes.route("/api/control_sync/watchtower_request", methods=["POST"])
def control_request():
    from sentinel_platform.router.control_mcp import handle_http_control
    try:
        return handle_http_control(_service().control)
    except ControlSyncError as exc:
        return jsonify(error=str(exc)), exc.status


@transport_routes.route("/api/control_sync/peer/<string:action>", methods=["POST"])
def peer(action):
    try:
        if request.headers.get("Origin"):
            raise ControlSyncError("Peer transport does not accept browser requests", 403)
        from sentinel_platform.modules.workspace.control_sync.pairing import MAX_PACKET
        if request.content_length is None or request.content_length > MAX_PACKET:
            raise ControlSyncError("Invalid peer request size", 413)
        packet = request.get_json(silent=True)
        if not isinstance(packet, dict):
            raise ControlSyncError("Invalid peer request")
        return jsonify(_service().pairing.handle_peer(action, packet))
    except ControlSyncError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except Exception:
        from sentinel_platform.core import get_logger
        get_logger().exception("control sync peer request failed")
        return jsonify({"error": "Peer service unavailable"}), 503
