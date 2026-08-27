"""system/api_keys —— 统一 API 密钥中心。

全系统唯一密钥源（集合 `api_keys` 单文档 name=default）：FOFA/鹰图/Quake/ZoomEye/
SecurityTrails/VirusTotal/Chaos/PassiveTotal/GitHub/飞书。一处配置，各消费方通用。

对外（供 router endpoints/system.py 挂 /api/api_keys/* + 其他模块经 registry 取）：
  list_keys() -> dict     列出（密钥字段掩码 + KEY_DEFS 元数据供前端渲染分组）
  save_keys(data) -> dict  保存（掩码值不覆盖原密钥），返回 list_keys()
  get_key(key_id) -> dict  读某密钥明文（仅 enabled 时返值，供消费方用）——注意：只在授权内部调用，不经 HTTP 暴露明文

注册：字符串键 `"api_keys_service"`（照 gateway 的 user_service/rbac_service 先例，不进冻结 ROLE）。
迁移来源：app/services/api_keys.py。**净室调整**：旧 `ensure_applied()` 把密钥推进 ARL `Config`
静态属性——新架构无 Config 静态类，消费方（notify 已如此/proxy/ext_source）**直接读集合或经
get_key()**，故不做 Config 推送。依赖：仅 stdlib（time），**无新增 vendor**。
不放 HTTP 路由；被 registry 以 "api_keys_service" 注册。跨模块对接实证：notify 读 api_keys.default.feishu。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

MASK_TAIL = 4  # 掩码保留末尾位数

# 密钥定义（UI 分组展示 + 字段声明）。fields=该密钥的字段；group=前端分组；select=下拉字段选项。
KEY_DEFS: List[Dict[str, Any]] = [
    {"id": "fofa", "label": "FOFA", "group": "资产测绘/情报", "fields": ["key"], "site": "https://fofa.info"},
    {"id": "hunter", "label": "鹰图 Hunter", "group": "资产测绘/情报", "fields": ["key"], "site": "https://hunter.qianxin.com"},
    {"id": "quake", "label": "Quake 360", "group": "资产测绘/情报", "fields": ["token"], "site": "https://quake.360.cn"},
    {"id": "zoomeye", "label": "ZoomEye", "group": "资产测绘/情报", "fields": ["key"], "site": "https://www.zoomeye.org"},
    {"id": "securitytrails", "label": "SecurityTrails", "group": "资产测绘/情报", "fields": ["key"], "site": "https://securitytrails.com"},
    {"id": "virustotal", "label": "VirusTotal", "group": "资产测绘/情报", "fields": ["key"], "site": "https://www.virustotal.com"},
    {"id": "chaos", "label": "Chaos", "group": "资产测绘/情报", "fields": ["key"], "site": "https://chaos.projectdiscovery.io"},
    {"id": "passivetotal", "label": "PassiveTotal", "group": "资产测绘/情报", "fields": ["email", "key"], "site": "https://community.riskiq.com"},
    {"id": "github", "label": "GitHub Token", "group": "代码情报", "fields": ["token"], "site": "https://github.com/settings/tokens"},
    {"id": "feishu", "label": "飞书 Webhook", "group": "告警推送",
     "fields": ["webhook", "secret", "min_severity", "vuln_feed_notify"],
     "select": {"min_severity": [
         {"value": "critical", "label": "仅严重"},
         {"value": "high", "label": "高危及以上"},
         {"value": "medium", "label": "中危及以上"}]},
     "defaults": {"min_severity": "medium", "vuln_feed_notify": True},
     "site": "https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot"},
    {"id": "dingtalk", "label": "钉钉 Webhook", "group": "告警推送",
     "fields": ["webhook", "secret"],
     "site": "https://open.dingtalk.com/document/robots/custom-robot-access"},
    {"id": "wework", "label": "企业微信 Webhook", "group": "告警推送",
     "fields": ["webhook"],
     "site": "https://developer.work.weixin.qq.com/document/path/91770"},
]
KEY_DEF_MAP = {d["id"]: d for d in KEY_DEFS}
SECRET_FIELDS = {"key", "token", "auth_key", "secret", "webhook"}   # 需掩码的字段

def _default_doc() -> Dict[str, Any]:
    doc: Dict[str, Any] = {"name": "default"}
    for d in KEY_DEFS:
        defs = d.get("defaults", {})
        sub = {f: defs.get(f, "") for f in d["fields"]}
        sub["enabled"] = False
        doc[d["id"]] = sub
    doc["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return doc


def get_doc() -> Dict[str, Any]:
    """读密钥文档（api_keys.default）；不存在则建默认。读库失败降级返回内存默认（不崩）。"""
    try:
        coll = get_repo().collection(Collections.API_KEYS)
        doc = coll.find_one({"name": "default"})
        if not doc:
            doc = _default_doc()
            coll.insert_one(dict(doc))
        return doc
    except Exception as exc:
        logger.debug("api_keys get_doc degraded: %s", exc)
        return _default_doc()


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= MASK_TAIL:
        return "*" * len(value)
    return "*" * (len(value) - MASK_TAIL) + value[-MASK_TAIL:]


def _is_masked(value: str) -> bool:
    """判断是否为掩码回传值（前端把掩码原样提交=未改动，不应覆盖真值）。"""
    if not value:
        return False
    body = value[:-MASK_TAIL] if len(value) > MASK_TAIL else value
    return set(body) <= {"*"}


def list_keys() -> Dict[str, Any]:
    """列出（密钥字段掩码），附 KEY_DEFS 元数据供前端渲染。对齐前端 api/apiKeys.ts 的 ApiKeysResult。"""
    doc = get_doc()
    items = []
    for d in KEY_DEFS:
        sub = doc.get(d["id"], {}) or {}
        out: Dict[str, Any] = {
            "id": d["id"], "label": d["label"], "group": d["group"], "site": d.get("site", ""),
            "fields": d["fields"], "select": d.get("select", {}), "enabled": bool(sub.get("enabled")),
        }
        for f in d["fields"]:
            val = sub.get(f, "") or ""
            out[f] = _mask(val) if f in SECRET_FIELDS else val
            out[f + "_set"] = bool(val)
        for f in (d.get("select") or {}):
            if not out.get(f):
                out[f] = (d.get("defaults", {}) or {}).get(f, "")
        items.append(out)
    return {"items": items, "updated_at": doc.get("updated_at", "")}


def save_keys(data: Dict[str, Any]) -> Dict[str, Any]:
    """保存：掩码值不覆盖原密钥（同 ai_provider 约定）。data 形如 {fofa:{key,enabled}, ...}。
    启用的密钥先校验有效性——无效则拒绝启用并返回错误。返回 list_keys()。"""
    if not isinstance(data, dict):
        return {"error": "data 必须为对象"}
    doc = get_doc()
    update: Dict[str, Any] = {}
    for d in KEY_DEFS:
        kid = d["id"]
        incoming = data.get(kid)
        if not isinstance(incoming, dict):
            continue
        new_sub = dict(doc.get(kid, {}) or {})
        for f in d["fields"]:
            if f not in incoming or incoming[f] is None:
                continue
            # bool 字段直接存 bool（如 vuln_feed_notify）
            if isinstance(incoming[f], bool):
                new_sub[f] = incoming[f]
                continue
            v = str(incoming[f]).strip()
            if f in SECRET_FIELDS and _is_masked(v):
                continue  # 掩码回传=未改，保留原值
            new_sub[f] = v
        if incoming.get("enabled") is not None:
            new_sub["enabled"] = bool(incoming["enabled"])
        # 启用时校验：必须有密钥值 + 有验证器的做有效性验证
        if new_sub.get("enabled"):
            # 检查必填密钥字段非空（排除 bool/select 类型字段）
            secret_fields = [f for f in d["fields"] if f in SECRET_FIELDS]
            has_any_secret = False
            for sf in secret_fields:
                val = new_sub.get(sf, "")
                if val and not _is_masked(str(val)):
                    has_any_secret = True
                    break
                elif val and _is_masked(str(val)):
                    has_any_secret = True  # 掩码=已有旧值
                    break
            if secret_fields and not has_any_secret:
                return {"error": "启用失败：密钥参数不能为空"}
            # 有验证器则做有效性验证
            if kid in _VALIDATORS:
                real_key = new_sub.get("key") or new_sub.get("token") or new_sub.get("webhook") or ""
                if real_key and not _is_masked(str(real_key)):
                    valid, reason = _VALIDATORS[kid](real_key, new_sub)
                    if not valid:
                        return {"error": "{}：密钥校验失败（{}）".format(d["label"], reason)}
        update[kid] = new_sub
    update["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        get_repo().collection(Collections.API_KEYS).update_one(
            {"name": "default"}, {"$set": update}, upsert=True)
    except Exception as exc:
        logger.debug("api_keys save failed: %s", exc)
        return {"error": "保存失败: {}".format(exc)}
    return list_keys()


# ── 密钥校验器 ──

def _validate_fofa(key: str, sub: Dict[str, Any]) -> tuple:
    """FOFA key 校验：调 /api/v1/info/my 看是否 200。"""
    try:
        from sentinel_platform.core.http import http_req
        r = http_req("https://fofa.info/api/v1/info/my", "get",
                     params={"key": key}, timeout=(5, 10))
        if r.status_code == 200:
            data = r.json()
            if data.get("email"):
                return True, ""
            return False, data.get("errmsg", "响应无 email 字段")
        return False, "HTTP {}".format(r.status_code)
    except Exception as e:
        return False, str(e)[:80]


def _validate_hunter(key: str, sub: Dict[str, Any]) -> tuple:
    """鹰图 key 校验：调 /openApi/search 看 code=200。"""
    import base64
    try:
        from sentinel_platform.core.http import http_req
        q = base64.urlsafe_b64encode(b'ip="1.1.1.1"').decode()
        r = http_req("https://hunter.qianxin.com/openApi/search", "get",
                     params={"api-key": key, "search": q, "page": 1, "page_size": 1},
                     timeout=(5, 10))
        if r.status_code == 200:
            data = r.json()
            if data.get("code") == 200:
                return True, ""
            return False, data.get("message", "code!=200")
        return False, "HTTP {}".format(r.status_code)
    except Exception as e:
        return False, str(e)[:80]


def _validate_feishu(key: str, sub: Dict[str, Any]) -> tuple:
    """飞书 webhook 校验：发一条测试消息验证 webhook 有效性。"""
    webhook = sub.get("webhook") or key
    if not webhook or not webhook.startswith("http"):
        return False, "webhook URL 格式无效"
    try:
        from sentinel_platform.core.http import http_req
        import json as _json
        import hashlib, hmac, base64
        body = {"msg_type": "text", "content": {"text": "瞭望塔 Watchtower 连接测试 ✓（本消息确认 webhook 有效）"}}
        # 如果有签名密钥，带签
        secret = (sub.get("secret") or "").strip()
        if secret:
            import time as _t
            ts = str(int(_t.time()))
            sign_str = "{}\n{}".format(ts, secret)
            hmac_code = hmac.new(sign_str.encode("utf-8"), digestmod=hashlib.sha256).digest()
            sign = base64.b64encode(hmac_code).decode("utf-8")
            body["timestamp"] = ts
            body["sign"] = sign
        r = http_req(webhook, "post", json=body, timeout=(5, 10))
        data = r.json()
        if data.get("code") == 0 or data.get("StatusCode") == 0:
            return True, ""
        return False, data.get("msg") or data.get("StatusMessage") or "code={}".format(data.get("code"))
    except Exception as e:
        return False, str(e)[:80]


_VALIDATORS = {
    "fofa": _validate_fofa,
    "hunter": _validate_hunter,
    "feishu": _validate_feishu,
}


def get_key(key_id: str) -> Dict[str, Any]:
    """读某密钥明文（供消费方内部调，如 ext_source 取 fofa/hunter、notify 取 feishu）。
    仅 enabled 时返字段值，否则返空字段。**不经 HTTP 暴露明文**（HTTP 只走 list_keys 掩码）。"""
    d = KEY_DEF_MAP.get(key_id)
    if not d:
        return {}
    sub = get_doc().get(key_id, {}) or {}
    if not sub.get("enabled"):
        return {f: "" for f in d["fields"]}
    return {f: sub.get(f, "") for f in d["fields"]}


class ApiKeysServiceImpl:
    """密钥中心服务。注册字符串键 "api_keys_service"（照 gateway user_service/rbac_service 先例）。"""

    def list_keys(self) -> Dict[str, Any]:
        return list_keys()

    def save_keys(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return save_keys(data)

    def get_key(self, key_id: str) -> Dict[str, Any]:
        return get_key(key_id)


_service = ApiKeysServiceImpl()


def get_service() -> ApiKeysServiceImpl:
    return _service

