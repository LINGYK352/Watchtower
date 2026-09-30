"""光纤桥接 REST API（/api/appbridge/*）—— 光纤 Agent 拨回专用。

**鉴权特殊**：光纤不是浏览器用户，不带用户 Token，而是带 **平台编号 platform_key**（Header
`X-Platform-Key`）鉴权（见 云端/docs/App渗透子系统设计.md §6.9）。故这些端点在 gateway 网关
**放行用户 Token 校验**（public），改由本层用 `_app_bridge.verify_key` 逐请求校验 platform_key。

四个端点（全 Agent→平台 单向出站，见 §6.1）：
  - POST /handshake  三次会话模拟校验（§6.9），上线前握手
  - GET  /poll       长轮询取命令（兼心跳）
  - POST /result     回传命令结果
  - POST /traffic    批量推抓包 flow（P2 抓包层，P0 先占位接收不落库）
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_UNAUTHORIZED

ns = Namespace("appbridge", path="/appbridge", description="光纤桥接：握手/取命令/回结果/推流量（platform_key 鉴权）")


def _bridge():
    from sentinel_platform.modules.ai_pentest import _app_bridge
    return _app_bridge


def _req_key() -> str:
    return request.headers.get("X-Platform-Key", "") or ""


def _check_key():
    """校验 platform_key。通过返 None；不通过返错误响应（每请求鉴权，握手内单独校验时序）。"""
    if not _bridge().verify_key(_req_key()):
        return err(CODE_UNAUTHORIZED, "platform_key 无效（非本平台光纤）")
    return None


@ns.route("/handshake")
class Handshake(Resource):
    @ns.doc(description="三次会话模拟校验上线（step=1/2/3）。key 校验在各步内按时序处理")
    def post(self):
        b = request.get_json(silent=True) or {}
        try:
            step = int(b.get("step", 0))
        except (TypeError, ValueError):
            return err(CODE_BAD_REQUEST, "step 非法")
        if step not in (1, 2, 3):
            return err(CODE_BAD_REQUEST, "step 必须为 1/2/3")
        r = _bridge().handshake(step, b)
        return ok(r) if r.get("ok") else err(CODE_UNAUTHORIZED, r.get("error", "握手失败"), data=r)


@ns.route("/poll")
class Poll(Resource):
    @ns.doc(description="光纤长轮询取命令（兼心跳）。带 X-Platform-Key + device 参数")
    def get(self):
        bad = _check_key()
        if bad:
            return bad
        device_id = (request.args.get("device") or "").strip()
        if not device_id:
            return err(CODE_BAD_REQUEST, "device 参数必填")
        wait = request.args.get("wait", "1") != "0"
        caps = {"acc": request.args.get("acc") == "1", "cap": request.args.get("cap") == "1"}
        return ok(_bridge().poll(device_id, wait=wait, caps=caps))


@ns.route("/result")
class Result(Resource):
    @ns.doc(description="光纤回传命令结果。带 X-Platform-Key")
    def post(self):
        bad = _check_key()
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        device_id = (b.get("device_id") or "").strip()
        cmd_id = (b.get("cmd_id") or "").strip()
        if not device_id or not cmd_id:
            return err(CODE_BAD_REQUEST, "device_id 和 cmd_id 必填")
        r = _bridge().submit_result(device_id, cmd_id, b.get("result"))
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "回传失败"))


@ns.route("/traffic")
class Traffic(Resource):
    @ns.doc(description="光纤批量推抓包 flow（P2 抓包层）。P0 占位接收，暂不落库")
    def post(self):
        bad = _check_key()
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        flows = b.get("flows") or []
        # P0：占位接收，返回收到数量；P2 落 app_traffic（capped/TTL）
        return ok({"received": len(flows) if isinstance(flows, list) else 0, "stored": 0})


@ns.route("/fiber_version")
class FiberVersion(Resource):
    @ns.doc(description="光纤查平台最新版本（自更新用）。带 X-Platform-Key")
    def get(self):
        bad = _check_key()
        if bad:
            return bad
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("app_pentest_service")
        v = svc.fiber_version() if (svc and hasattr(svc, "fiber_version")) else {}
        return ok(v)


@ns.route("/fiber_download")
class FiberDownload(Resource):
    @ns.doc(description="光纤下载新版 APK（自更新用，注入本机地址+平台编号）。带 X-Platform-Key")
    def get(self):
        bad = _check_key()
        if bad:
            return bad
        from sentinel_platform.contracts import get_registry
        from flask import make_response
        svc = get_registry().get("app_pentest_service")
        if not (svc and hasattr(svc, "gen_fiber_apk")):
            return err(CODE_BAD_REQUEST, "服务未就绪")
        scheme = request.headers.get("X-Forwarded-Proto", "") or request.scheme or "http"
        host = request.host or ""
        r = svc.gen_fiber_apk(scheme, host)
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "生成失败"))
        resp = make_response(r.get("apk_bytes") or b"")
        resp.headers["Content-Type"] = "application/vnd.android.package-archive"
        resp.headers["Content-Disposition"] = 'attachment; filename="watchtower-fiber.apk"'
        return resp
