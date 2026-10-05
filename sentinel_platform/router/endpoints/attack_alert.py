"""attack_alert 端点 —— 攻击告警（防御型蜜罐 + 入侵检测）。

路径: /api/attack_alert/*
权限: system:read（查看）/ system:update（手动检测测试）
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

ns = Namespace("attack_alert", description="攻击告警")


@ns.route("/stats")
class AttackStats(Resource):
    @ns.doc(security="token", description="system:read")
    def get(self):
        """获取攻击统计信息"""
        try:
            from sentinel_platform.modules.honeypot_defense.attack_alert import get_attack_stats
            stats = get_attack_stats()
            return ok(stats)
        except Exception as exc:
            return err(CODE_ERROR, f"获取统计失败: {exc}")


@ns.route("/list")
class AttackList(Resource):
    @ns.doc(security="token", description="system:read")
    def get(self):
        """列出攻击记录"""
        try:
            from sentinel_platform.modules.honeypot_defense.attack_alert import list_attacks

            page = int(request.args.get("page", 1))
            size = int(request.args.get("size", 20))

            # 筛选条件
            filters = {}
            if request.args.get("attack_type"):
                filters["attack_type"] = request.args.get("attack_type")
            if request.args.get("severity"):
                filters["severity"] = request.args.get("severity")
            if request.args.get("source_ip"):
                filters["source_ip"] = request.args.get("source_ip")
            if request.args.get("start_time"):
                filters["start_time"] = float(request.args.get("start_time"))
            if request.args.get("end_time"):
                filters["end_time"] = float(request.args.get("end_time"))

            sort_order = request.args.get("sort_order", "desc")   # 最近时间排序方向（前端点击列切换）
            result = list_attacks(page=page, size=size, filters=filters if filters else None,
                                  sort_order=sort_order)
            return ok(result)
        except Exception as exc:
            return err(CODE_ERROR, f"获取攻击列表失败: {exc}")


@ns.route("/trace/<string:ip>")
class AttackerTrace(Resource):
    @ns.doc(security="token", description="system:read")
    def get(self, ip: str):
        """溯源攻击者"""
        try:
            from sentinel_platform.modules.honeypot_defense.attack_alert import trace_attacker
            result = trace_attacker(ip)
            return ok(result)
        except Exception as exc:
            return err(CODE_ERROR, f"溯源失败: {exc}")


@ns.route("/detect")
class AttackDetect(Resource):
    @ns.doc(security="token", description="system:update")
    def post(self):
        """手动检测攻击（测试用）"""
        try:
            from sentinel_platform.modules.honeypot_defense.attack_alert import AttackDetector, record_attack

            body = request.get_json(silent=True) or {}
            request_data = {
                "method": body.get("method", "GET"),
                "path": body.get("path", ""),
                "query": body.get("query", ""),
                "headers": body.get("headers", {}),
                "body": body.get("body", ""),
                "source_ip": body.get("source_ip", request.remote_addr),
                "timestamp": body.get("timestamp", None)
            }

            detector = AttackDetector()
            attack_info = detector.detect(request_data)

            if attack_info:
                # 记录攻击
                import time
                if not request_data["timestamp"]:
                    request_data["timestamp"] = time.time()
                attack_id = record_attack(request_data, attack_info)
                return ok({"detected": True, "attack_id": attack_id, "attack_info": attack_info})
            else:
                return ok({"detected": False})

        except Exception as exc:
            return err(CODE_ERROR, f"检测失败: {exc}")


def _operator():
    """当前操作人用户名（封禁/加白记 operator 用；取不到用 manual）。"""
    try:
        from flask import g
        return (getattr(g, "current_user", None) or {}).get("username", "") or "manual"
    except Exception:
        return "manual"


# ── 封禁管理 ──
@ns.route("/ban")
class Ban(Resource):
    @ns.doc(security="token", description="system:update")
    def post(self):
        """手动封禁 IP。body: {ip, reason?, permanent?(默认true)}"""
        from sentinel_platform.modules.honeypot_defense.attack_alert import ban_ip
        b = request.get_json(silent=True) or {}
        r = ban_ip(str(b.get("ip", "")).strip(), operator=_operator(),
                   reason=b.get("reason", ""), permanent=bool(b.get("permanent", True)))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/unban")
class Unban(Resource):
    @ns.doc(security="token", description="system:update")
    def post(self):
        """手动解封 IP。body: {ip}"""
        from sentinel_platform.modules.honeypot_defense.attack_alert import unban_ip
        b = request.get_json(silent=True) or {}
        r = unban_ip(str(b.get("ip", "")).strip())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/banlist")
class BanList(Resource):
    @ns.doc(security="token", description="system:read")
    def get(self):
        """封禁名单列表"""
        from sentinel_platform.modules.honeypot_defense.attack_alert import list_bans
        return ok(list_bans(int(request.args.get("page", 1)), int(request.args.get("size", 50))))


# ── 白名单管理 ──
@ns.route("/whitelist")
class Whitelist(Resource):
    @ns.doc(security="token", description="system:read")
    def get(self):
        """白名单列表"""
        from sentinel_platform.modules.honeypot_defense.attack_alert import list_whitelist
        return ok(list_whitelist(int(request.args.get("page", 1)), int(request.args.get("size", 100))))

    @ns.doc(security="token", description="system:update")
    def post(self):
        """加白名单。body: {ip, note?}"""
        from sentinel_platform.modules.honeypot_defense.attack_alert import add_whitelist
        b = request.get_json(silent=True) or {}
        r = add_whitelist(str(b.get("ip", "")).strip(), operator=_operator(), note=b.get("note", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)

    @ns.doc(security="token", description="system:update")
    def delete(self):
        """移出白名单。body: {ip}"""
        from sentinel_platform.modules.honeypot_defense.attack_alert import del_whitelist
        b = request.get_json(silent=True) or {}
        r = del_whitelist(str(b.get("ip", "")).strip())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)
