"""broker_health 端点 —— celery 调度降级状态查询 + 手动切回（/api/system/broker/*）。

配合 kernel/_broker_health：rabbitmq 投递 60s 内 3 次失败自动降级线程模式；本端点供前端顶栏
红标签轮询降级状态、并让用户手动切回 rabbitmq 模式（切回前真 ping broker，通了才切）。

- GET  /api/system/broker/status  查当前模式（celery/thread）—— 需登录（pentest:read 级别，任意登录用户可见）
- POST /api/system/broker/switch_back  手动切回 celery —— 需 system:update（admin/operator）
默认走网关登录鉴权。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from ..envelope import ok, err, CODE_ERROR

ns = Namespace("broker", path="/system/broker", description="调度 broker 降级状态")


@ns.route("/status")
class _Status(Resource):
    @ns.doc(security="token")
    def get(self):
        """当前调度模式：{mode, degraded, reason, degraded_at, recovered_at}。"""
        try:
            from sentinel_platform.modules.kernel import _broker_health
            return ok(_broker_health.status())
        except Exception as exc:
            return err(CODE_ERROR, "读取调度状态失败：{}".format(str(exc)[:120]))


@ns.route("/switch_back")
class _SwitchBack(Resource):
    @ns.doc(security="token", description="需权限 system:update（手动切回 rabbitmq/celery 模式，切回前 ping broker）")
    def post(self):
        """手动切回 celery：先 ping broker，通了才切；不通则拒绝并提示。body 可选 {force:true} 强制切。"""
        try:
            from sentinel_platform.modules.kernel import _broker_health
        except Exception as exc:
            return err(CODE_ERROR, "调度模块未就绪：{}".format(str(exc)[:120]))
        force = bool((request.get_json(silent=True) or {}).get("force"))
        r = _broker_health.switch_back(force=force)
        if not r.get("ok"):
            return err(CODE_ERROR, r.get("message") or "切回失败", data=r)
        return ok(r, message=r.get("message", ""))
