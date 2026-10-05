"""kernel/notify —— 集成推送（实现 NOTIFY / NotifyService）。

通用 notify(message, **kwargs) 出口 + 可插渠道注册表。设计 §九 写死三渠道：飞书(HMAC签名)/
钉钉(HMAC加签可选)/企业微信(直接POST)——均已实现（邮件设计未要求，不加）。
配置来源：api_keys 集合（前端「API 密钥 > 告警推送」可配），回退平台配置段。
保留旧 notify.py 语义：漏洞推送阈值（notify_vuln）、严重日志去重节流+噪音过滤（notify_critical_log）。

迁移来源：app/services/notify.py（飞书签名+阈值+去重）、app/services/webhook.py（事件回调）。
不放 HTTP 路由；被 registry 以 ROLE.NOTIFY 注册，供各叶子「缺失降级」调用。
"""
from __future__ import annotations

import time
import hmac
import hashlib
import base64
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_config, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

_SEV_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CACHE_TTL = 60
_DEDUP_TTL = 600

# —— 进程级缓存（配置读取带 TTL；日志去重节流）——
_cfg_cache: Dict[str, Any] = {"data": None, "ts": 0.0}
_notify_dedup: Dict[str, float] = {}


def _api_keys_doc() -> Dict[str, Any]:
    """读 api_keys 集合 default 文档（带 TTL 缓存）；失败返回 {}。"""
    now = time.time()
    if _cfg_cache["data"] is not None and now - _cfg_cache["ts"] < _CACHE_TTL:
        return _cfg_cache["data"]
    doc: Dict[str, Any] = {}
    try:
        doc = get_repo().collection(Collections.API_KEYS).find_one({"name": "default"}) or {}
    except Exception as exc:  # 库不可用等：降级空配置，不崩
        logger.debug("notify: read api_keys failed: %s", exc)
        doc = {}
    _cfg_cache.update(data=doc, ts=now)
    return doc


def _channel_config(channel: str) -> Dict[str, Any]:
    """取某渠道配置（api_keys.<channel>）。飞书回退平台配置段 FEISHU。"""
    conf = _api_keys_doc().get(channel)
    if isinstance(conf, dict) and conf:
        return conf
    if channel == "feishu":
        cfg = get_config()
        url = cfg.section("FEISHU", "WEBHOOK", default="") or ""
        if url:
            return {"enabled": True, "webhook": url,
                    "secret": cfg.section("FEISHU", "SECRET", default="") or ""}
    return {}


def _feishu_send(conf: Dict[str, Any], title: str, content: str) -> None:
    """飞书富文本 post 消息（可选 HMAC-SHA256 签名）。失败抛异常由渠道层捕获。"""
    url = conf.get("webhook") or ""
    if not url:
        raise ValueError("feishu webhook 未配置")
    secret = conf.get("secret") or ""
    payload: Dict[str, Any] = {
        "msg_type": "post",
        "content": {"post": {"zh_cn": {
            "title": title,
            "content": [[{"tag": "text", "text": content}]],
        }}},
    }
    if secret:
        ts = str(int(time.time()))
        string_to_sign = "{}\n{}".format(ts, secret)
        sign = base64.b64encode(
            hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        payload["timestamp"] = ts
        payload["sign"] = sign

    import requests as _req  # 惰性，避免无网络环境 import 即失败
    resp = _req.post(url, json=payload, timeout=10)
    body = {}
    try:
        body = resp.json()
    except Exception:
        pass
    if resp.status_code != 200 or body.get("code", -1) != 0:
        raise RuntimeError("feishu resp {}: {}".format(resp.status_code, str(body)[:120]))


def _dingtalk_send(conf: Dict[str, Any], title: str, content: str) -> None:
    """钉钉自定义机器人 text 消息（可选 HMAC-SHA256 加签）。失败抛异常由渠道层捕获。
    加签协议：timestamp(毫秒) + '\\n' + secret → HMAC-SHA256 → base64 → URL 加 &timestamp=&sign=。"""
    url = conf.get("webhook") or ""
    if not url:
        raise ValueError("dingtalk webhook 未配置")
    secret = conf.get("secret") or ""
    if secret:
        ts = str(round(time.time() * 1000))
        string_to_sign = "{}\n{}".format(ts, secret)
        sign = base64.b64encode(
            hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        # urlencode sign（含 +// 等需转义）
        from urllib.parse import quote_plus
        url = "{}&timestamp={}&sign={}".format(url, ts, quote_plus(sign))
    payload = {"msgtype": "text", "text": {"content": "{}\n{}".format(title, content)}}
    import requests as _req
    resp = _req.post(url, json=payload, timeout=10)
    body = {}
    try:
        body = resp.json()
    except Exception:
        pass
    if resp.status_code != 200 or body.get("errcode", -1) != 0:
        raise RuntimeError("dingtalk resp {}: {}".format(resp.status_code, str(body)[:120]))


def _wework_send(conf: Dict[str, Any], title: str, content: str) -> None:
    """企业微信群机器人 text 消息（webhook 直接 POST，无签名）。失败抛异常由渠道层捕获。"""
    url = conf.get("webhook") or ""
    if not url:
        raise ValueError("wework webhook 未配置")
    payload = {"msgtype": "text", "text": {"content": "{}\n{}".format(title, content)}}
    import requests as _req
    resp = _req.post(url, json=payload, timeout=10)
    body = {}
    try:
        body = resp.json()
    except Exception:
        pass
    if resp.status_code != 200 or body.get("errcode", -1) != 0:
        raise RuntimeError("wework resp {}: {}".format(resp.status_code, str(body)[:120]))


# 渠道注册表：channel 名 → 发送函数(conf, title, content)。设计 §九 写死三渠道（飞书/钉钉/企微）。
# 用惰性间接（lambda 运行时按名解析模块函数）而非直接存函数引用——
# 否则字典在加载时冻结引用，热替换/测试 patch 模块函数不生效。
_CHANNELS = {
    "feishu": lambda conf, title, content: _feishu_send(conf, title, content),
    "dingtalk": lambda conf, title, content: _dingtalk_send(conf, title, content),
    "wework": lambda conf, title, content: _wework_send(conf, title, content),
}


class NotifyServiceImpl:
    """NOTIFY 实现。满足 contracts.NotifyService（结构化子类型，无需继承）。"""

    def notify(self, message: str, **kwargs: Any) -> Dict[str, Any]:
        """推送消息到一个或多个渠道。

        kwargs: channel(str|list, 默认所有已启用渠道) / level(str) / title(str) / extra(dict)。
        返回 {"ok": bool, "sent": [渠道...], "error": str?}。单渠道失败不影响其他，汇总不抛。
        """
        if not message or not str(message).strip():
            return {"ok": False, "sent": [], "error": "message 必填"}

        title = kwargs.get("title") or "瞭望塔 Watchtower 通知"
        req = kwargs.get("channel")
        if isinstance(req, str) and req:
            channels = [req]
        elif isinstance(req, (list, tuple)) and req:
            channels = list(req)
        else:
            channels = [c for c in _CHANNELS if _channel_config(c).get("enabled")]

        sent: List[str] = []
        errors: List[str] = []
        for ch in channels:
            sender = _CHANNELS.get(ch)
            if sender is None:
                errors.append("{}: 未知渠道".format(ch))
                continue
            conf = _channel_config(ch)
            if not conf.get("enabled") and req is None:
                continue  # 自动模式跳过未启用渠道
            try:
                sender(conf, title, str(message))
                sent.append(ch)
            except Exception as exc:
                errors.append("{}: {}".format(ch, exc))
                logger.debug("notify channel %s failed: %s", ch, exc)

        result: Dict[str, Any] = {"ok": bool(sent), "sent": sent}
        if errors:
            result["error"] = "; ".join(errors)
        return result


# —— 保留旧语义的便捷函数（供 finding/日志等调用；内部走 NotifyServiceImpl）——
_service = NotifyServiceImpl()


def _min_severity() -> str:
    v = (_channel_config("feishu") or {}).get("min_severity", "")
    return v if v in _SEV_MAP else "medium"


def notify_vuln(vuln_type: str, target: str, severity: str,
                cvss_score: Any = None, unit: str = "") -> Dict[str, Any]:
    """漏洞发现推送。低于配置阈值（api_keys.feishu.min_severity，默认中危+）不推。"""
    if _SEV_MAP.get(severity, 0) < _SEV_MAP.get(_min_severity(), 2):
        return {"ok": False, "sent": [], "error": "below threshold"}
    title = "漏洞告警 [{}]".format(str(severity).upper())
    lines = ["类型: {}".format(vuln_type), "目标: {}".format(target),
             "等级: {}".format(severity)]
    if cvss_score:
        lines.append("CVSS: {}".format(cvss_score))
    if unit:
        lines.append("单位: {}".format(unit))
    lines.append("时间: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")))
    return _service.notify("\n".join(lines), title=title)


_NOISE_KEYWORDS = (
    "Certificate did not match", "Expecting value: line 1 column 1", "passive_dns",
    "Read timed out", "Max retries exceeded", "session deleted, abort",
    "Connection refused", "connect failed",
)


def notify_critical_log(module: str, message: str) -> Dict[str, Any]:
    """严重日志告警。噪音过滤 + 同模块+消息前 50 字 10 分钟内只推一次。"""
    msg = str(message)
    if any(kw in msg for kw in _NOISE_KEYWORDS):
        return {"ok": False, "sent": [], "error": "noise filtered"}
    now = time.time()
    key = "{}:{}".format(module, msg[:50])
    if key in _notify_dedup and now - _notify_dedup[key] < _DEDUP_TTL:
        return {"ok": False, "sent": [], "error": "throttled"}
    _notify_dedup[key] = now
    if len(_notify_dedup) > 100:  # 防内存泄漏
        for k in [k for k, t in _notify_dedup.items() if now - t > _DEDUP_TTL]:
            _notify_dedup.pop(k, None)
    content = "模块: {}\n信息: {}\n时间: {}".format(
        module, msg[:200], time.strftime("%Y-%m-%d %H:%M:%S"))
    return _service.notify(content, title="系统告警 [ERROR]")


def get_service() -> NotifyServiceImpl:
    return _service
