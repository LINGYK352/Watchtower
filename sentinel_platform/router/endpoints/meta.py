"""meta 端点 —— 健康检查 / 版本 / 模块就绪度 / 激活状态（端到端范式 + 前端可调证明）。

公开端点（网关豁免），前端/运维无需鉴权即可探活。同时作为「一类别一 endpoints 文件」
的**参考范式**：Namespace + docstring summary + @ns.doc + marshal 信封 + 经 registry 探能力。
其余类别端点照此写。
"""
from __future__ import annotations

from flask import request as flask_request
from flask_restx import Namespace, Resource

from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.core import get_config
from sentinel_platform.core.config import _first_existing, _config_candidates
from ..envelope import ok, err, CODE_ERROR
from ..openapi import register_envelope_models

ns = Namespace("meta", description="平台元信息：健康/版本/模块就绪度")
_models = register_envelope_models(ns)
from pathlib import Path
_UPDATE_ROOT=Path(__file__).resolve().parents[3]
_BOOT_UPDATE_VERSION=(_UPDATE_ROOT/'version.txt').read_text(encoding='utf-8').strip()

@ns.route('/health/update-ready')
class UpdateReady(Resource):
    @ns.doc(security=None)
    def get(self):
        from sentinel_platform.modules.about._update_chain import ready_status
        try:return ok(ready_status(_UPDATE_ROOT,_BOOT_UPDATE_VERSION))
        except Exception:return ok({'ready':False,'version':_BOOT_UPDATE_VERSION})

# 探测的核心 ROLE（就绪度报告用）
_PROBE_ROLES = [
    ("recon", ROLE.RECON), ("notify", ROLE.NOTIFY), ("exploit_clue", ROLE.EXPLOIT_CLUE),
    ("system_tags", ROLE.SYSTEM_TAGS), ("intel", ROLE.INTEL), ("finding", ROLE.FINDING),
    ("vuln_intel", ROLE.VULN_INTEL), ("pentest_dispatch", ROLE.PENTEST_DISPATCH),
    ("proxy", ROLE.PROXY),
]


@ns.route("/health")
class Health(Resource):
    @ns.doc(security=None)
    def get(self):
        """健康检查（公开，探活用）"""
        return ok({"status": "up"})


# IANA 时区名 → 人类可读中文地理名（常见区，覆盖不到则按 UTC 偏移兜底）。
_TZ_CN = {
    "Etc/UTC": "协调世界时", "UTC": "协调世界时", "GMT": "格林尼治时间",
    "America/New_York": "美国东部时间", "America/Detroit": "美国东部时间",
    "America/Chicago": "美国中部时间", "America/Denver": "美国山地时间",
    "America/Phoenix": "美国山地时间", "America/Los_Angeles": "美国西部时间",
    "America/Anchorage": "美国阿拉斯加时间", "Pacific/Honolulu": "美国夏威夷时间",
    "America/Sao_Paulo": "巴西时间", "Europe/London": "英国时间",
    "Europe/Paris": "中欧时间", "Europe/Berlin": "中欧时间", "Europe/Moscow": "莫斯科时间",
    "Asia/Shanghai": "北京时间", "Asia/Hong_Kong": "香港时间", "Asia/Taipei": "台北时间",
    "Asia/Tokyo": "日本时间", "Asia/Seoul": "韩国时间", "Asia/Singapore": "新加坡时间",
    "Asia/Kolkata": "印度时间", "Asia/Dubai": "海湾时间", "Australia/Sydney": "澳东时间",
}


def _tz_label(iana: str, off_min: int) -> str:
    """时区中文地理名。优先按 IANA 名精确映射；命中不了按 UTC 偏移给通用中文名（如"东八区"级别）。"""
    if iana in _TZ_CN:
        return _TZ_CN[iana]
    # 偏移兜底：常见整点区给地理名，其余用"UTC±N"
    _OFF_CN = {0: "协调世界时", -300: "美国东部时间", -360: "美国中部时间",
               -420: "美国山地时间", -480: "美国西部时间", 480: "北京时间",
               540: "日本时间", 60: "中欧时间", 0.0: "协调世界时"}
    if off_min in _OFF_CN:
        return _OFF_CN[off_min]
    return ""   # 交前端用 UTC±偏移展示


def _os_timezone() -> dict:
    """操作系统时区（态势总览/全局顶栏展示，说明平台所有时间戳都是该 OS 时区的本地时间，无时区标注）。
    平台不改时间存储；要改时间显示只能改 OS/容器时区。返回 {tz_name, tz_abbr, tz_label, utc_offset_min}。"""
    try:
        import time as _t, os as _os
        is_dst = _t.daylight and _t.localtime().tm_isdst > 0
        off_sec = -(_t.altzone if is_dst else _t.timezone)   # 东区为正
        abbr = _t.tzname[1] if is_dst else _t.tzname[0]
        name = _os.environ.get("TZ", "") or ""
        if not name and _os.path.exists("/etc/timezone"):
            try:
                with open("/etc/timezone") as f:
                    name = f.read().strip()
            except Exception:
                pass
        off_min = int(off_sec // 60)
        return {"tz_name": name or abbr, "tz_abbr": abbr, "utc_offset_min": off_min,
                "tz_label": _tz_label(name or abbr, off_min)}
    except Exception:
        return {"tz_name": "", "tz_abbr": "", "utc_offset_min": 0, "tz_label": ""}


@ns.route("/version")
class Version(Resource):
    @ns.doc(security=None)
    def get(self):
        """平台版本 + 服务器操作系统时区（前端展示时间戳所属时区）"""
        return ok({"name": "瞭望塔 Watchtower", "api": "1.0", **_os_timezone()})


@ns.route("/modules")
class Modules(Resource):
    @ns.doc(security=None)
    def get(self):
        """各模块能力就绪度（经 registry 探，未注册=未就绪）"""
        reg = get_registry()
        status = {}
        for name, role in _PROBE_ROLES:
            try:
                status[name] = reg.get(role) is not None
            except Exception:
                status[name] = False
        return ok({"modules": status, "ready": sum(status.values()), "total": len(status)})


# ---------- 激活状态（需登录） ----------

_DEFAULT_SOURCE_URL = "https://watchtowers.info"


def _decode_jwt_payload(token: str) -> dict:
    """解码 JWT payload（不验签，离线读 exp/claims）。纯 stdlib，内联实现避免跨包 import。"""
    import base64 as _b64, json as _json
    parts = (token or "").split(".")
    if len(parts) != 3:
        return {}
    try:
        s = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return _json.loads(_b64.urlsafe_b64decode(s))
    except Exception:
        return {}


def _is_jwt(token: str) -> bool:
    return bool(token) and token.startswith("eyJ") and token.count(".") == 2


def _read_activation_key_fresh() -> str:
    """激活 key —— 统一走 system/activation.read_key()（始终 fresh 读盘，多 worker 一致）。薄封装保留旧调用点。"""
    from sentinel_platform.modules.system import activation
    return activation.read_key()


@ns.route("/activation-info")
class ActivationInfo(Resource):
    @ns.doc(security="token")
    def get(self):
        """激活信息（key 脱敏，不返回明文）"""
        import time as _time
        import math
        key = _read_activation_key_fresh()

        if not _is_jwt(key):
            return ok({"activated": False, "expired": False, "revoked": False, "key_masked": "",
                       "activated_at": "", "expires_at": "", "remaining_days": 0, "auth_days": 0, "username": ""})

        payload = _decode_jwt_payload(key)
        exp = payload.get("exp", 0)
        activated_at = payload.get("activated_at", 0)

        # Mask key: show first 20 chars + ... + last 10 chars
        key_masked = key[:20] + "..." + key[-10:] if len(key) > 40 else "***"

        expires_at_str = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(exp)) if exp else ""
        activated_at_str = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(activated_at)) if activated_at else ""

        # 与 local_status 一致：remaining_days 用 ceil（剩<1天显示1天）
        remaining_days = max(1, math.ceil((exp - _time.time()) / 86400)) if (exp and exp > _time.time()) else 0

        # 叠加吊销标记（与 local_status 口径一致）
        from sentinel_platform.modules.system import activation
        revoked = activation.is_revoked()
        activated = (exp > _time.time()) if exp else False
        expired = (exp <= _time.time()) if exp else False
        if revoked:
            activated = False
            expired = True
            remaining_days = 0

        return ok({
            "activated": activated,
            "expired": expired,
            "revoked": revoked,
            "key_masked": key_masked,
            "activated_at": activated_at_str,
            "expires_at": expires_at_str,
            "remaining_days": remaining_days,
            "auth_days": payload.get("auth_days", 0),
            "username": payload.get("name", ""),
        })


@ns.route("/activation")
class Activation(Resource):
    @ns.doc(security="token")
    def get(self):
        """查询系统激活状态 —— 统一走 system/activation.local_status()（本地校 JWT 时效，全 worker 一致）。"""
        from sentinel_platform.modules.system import activation
        st = activation.local_status()
        # 附服务器时区：剩余天数/到期时间按服务器 OS 时区计算，前端徽标标注时区避免误解（见 §7.8）。
        return ok({"activated": st["activated"], "expired": st["expired"], "revoked": st["revoked"],
                   "expires_at": st["expires_at"], "activated_at": st["activated_at"],
                   "source_url": activation.source_url(),
                   "remaining_days": st["remaining_days"], **_os_timezone()})

    @ns.doc(security="token")
    def post(self):
        """激活系统：将注册凭证发到分发服务器校验，获得激活凭证"""
        body = flask_request.get_json(silent=True) or {}
        reg_token = (body.get("key") or "").strip()
        if not reg_token or not _is_jwt(reg_token):
            return err(CODE_ERROR, "请输入有效的授权凭证（从分发系统注册页获取）")

        # Call distribution server to activate
        cfg = get_config()
        source_url = (cfg.section("UPDATE", "SOURCE_URL", default="") or _DEFAULT_SOURCE_URL).rstrip("/")
        import requests
        try:
            resp = requests.post(f"{source_url}/activate", json={"token": reg_token}, timeout=15)
            result = resp.json()
        except Exception as e:
            return err(CODE_ERROR, f"无法连接分发服务器: {e}")

        if not result.get("ok"):
            return err(CODE_ERROR, result.get("error", "激活失败"))

        # Save the activated token locally
        activated_token = result["activated_token"]
        import os
        cfg_path = _first_existing(_config_candidates())
        written = False
        if cfg_path:
            try:
                import yaml
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh) or {}
                if not isinstance(raw, dict):
                    raw = {}
                if "UPDATE" not in raw or not isinstance(raw.get("UPDATE"), dict):
                    raw["UPDATE"] = {}
                raw["UPDATE"]["KEY"] = activated_token
                with open(cfg_path, "w", encoding="utf-8") as fh:
                    yaml.dump(raw, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
                written = True
            except OSError:
                pass
        if not written:
            fallback_paths = [
                os.path.join(os.path.dirname(cfg_path), ".activation_key") if cfg_path else None,
                os.path.join(os.getcwd(), ".activation_key"),
                "/tmp/.sentinel_activation_key",
            ]
            for fp in fallback_paths:
                if not fp:
                    continue
                try:
                    os.makedirs(os.path.dirname(fp), exist_ok=True)
                    with open(fp, "w", encoding="utf-8") as fh:
                        fh.write(activated_token)
                    written = True
                    break
                except OSError:
                    continue
        if not written:
            return err(CODE_ERROR, "激活成功但写入本地失败（文件系统只读）")
        try:
            from sentinel_platform.core.config import reset_config_cache
            reset_config_cache()
        except Exception:
            pass
        # 激活成功 → 清除吊销标记（云端重新认可 / 用户重新激活后恢复已激活态）
        try:
            from sentinel_platform.modules.system import activation
            activation.clear_revoked()
        except Exception:
            pass
        return ok({"activated_at": result.get("activated_at"),
                   "expires_at": result.get("expires_at"),
                   "auth_days": result.get("auth_days")})


@ns.route("/setup-status")
class SetupStatus(Resource):
    @ns.doc(security="token")
    def get(self):
        """首次配置向导状态：激活 + AI provider + API Keys 是否已配置"""
        import time as _time
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections

        # 1) 激活状态（复用同一逻辑）
        cfg = get_config()
        key = cfg.section("UPDATE", "KEY", default="") or ""
        activated = False
        expired = False
        if _is_jwt(key):
            payload = _decode_jwt_payload(key)
            exp = payload.get("exp", 0)
            activated = exp > _time.time()
            if not activated and exp > 0:
                expired = True

        # 2) AI provider 是否配置（至少 1 条 enabled + 有非空 api_key）
        ai_configured = False
        try:
            repo = get_repo()
            ai_coll = repo.collection(Collections.AI_PROVIDER)
            ai_configured = ai_coll.count_documents(
                {"api_key": {"$exists": True, "$ne": ""}, "enabled": True}, limit=1
            ) > 0
        except Exception:
            pass

        # 3) API Keys 是否配置（api_keys.default 文档中至少 1 个子项 enabled + 有值）
        keys_configured = False
        try:
            repo = get_repo()
            doc = repo.collection(Collections.API_KEYS).find_one({"name": "default"})
            if doc:
                from sentinel_platform.modules.system.api_keys import KEY_DEFS, SECRET_FIELDS
                for d in KEY_DEFS:
                    sub = doc.get(d["id"])
                    if not isinstance(sub, dict):
                        continue
                    if not sub.get("enabled"):
                        continue
                    # 至少一个密钥字段非空
                    for f in d["fields"]:
                        if f in SECRET_FIELDS and sub.get(f):
                            keys_configured = True
                            break
                    if keys_configured:
                        break
        except Exception:
            pass

        # 4) 逐个资产测绘源是否已配置（enabled + 密钥字段非空）——需求1：广域收集工具多选置灰依据。
        #    单一事实源=KEY_DEFS 中 group「资产测绘/情报」的源（fofa/hunter/quake/zoomeye）。
        sources_configured: Dict[str, bool] = {}
        try:
            from sentinel_platform.modules.system.api_keys import KEY_DEFS, SECRET_FIELDS
            for d in KEY_DEFS:
                if d.get("group") != "资产测绘/情报":
                    continue
                sid = d["id"]
                sources_configured[sid] = False
                sub = doc.get(sid) if doc else None
                if isinstance(sub, dict) and sub.get("enabled"):
                    for f in d["fields"]:
                        if f in SECRET_FIELDS and sub.get(f):
                            sources_configured[sid] = True
                            break
        except Exception:
            pass
        # fofa_configured 保留（向后兼容旧前端），派生自 sources_configured
        fofa_configured = bool(sources_configured.get("fofa"))

        return ok({
            "activated": activated,
            "expired": expired,
            "ai_configured": ai_configured,
            "keys_configured": keys_configured,
            "fofa_configured": fofa_configured,
            "sources_configured": sources_configured,   # {fofa:bool, hunter:bool, quake:bool, zoomeye:bool}
        })


_disc_parser = ns.parser()
_disc_parser.add_argument("version", type=str, location="json", help="条款版本(前端 DISCLAIMER_VERSION)")


@ns.route("/disclaimer")
class DisclaimerState(Resource):
    @ns.doc(security=None)
    def get(self):
        """免责声明签署状态（服务端磁盘持久化，重启/换浏览器保留，仅重装需重签）。

        公开：未激活也能读——首登弹窗需在激活前就能拿到签署状态。
        返回 {accepted, accepted_version, accepted_at}。"""
        from sentinel_platform.modules.system import disclaimer
        return ok(disclaimer.get_status())

    @ns.doc(security="token")
    def post(self):
        """记录同意（登录后调）：写磁盘标记，携带条款版本。"""
        from flask import request as _rq
        from sentinel_platform.modules.system import disclaimer
        body = _rq.get_json(silent=True) or {}
        version = str(body.get("version") or "").strip()
        return ok(disclaimer.accept(version))
