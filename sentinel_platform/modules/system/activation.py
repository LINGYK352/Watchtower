"""system/activation —— 激活凭证单一权威（全项目激活判定统一入口）。

**背景（治多 worker 缓存不一致的间歇性误报）**：gunicorn -w 3 多 worker，get_config() 是每进程
各自的模块级 _cached 单例；激活写 key 后只重置当前 worker 缓存，其他 worker 仍持旧缓存 →
"一个 worker 激活了其他没激活、过会儿又弹请重新激活；一个失效了其他仍有效"。且历史上读 key 有三套
写法(meta 直读盘 / update_check 与 about 与 _extension_store 读缓存)，部分走缓存故不一致。

**本模块统一规则**：
  • read_key()  —— 激活 key **始终从磁盘 fresh 读**（config.yaml 的 UPDATE.KEY > .activation_key 候选文件），
                   绝不读 get_config() 缓存 → 全 worker 读同一磁盘文件，天然一致，写后立即生效。
  • local_status() —— "系统是否激活"的唯一权威：**本地离线校验 JWT 时效**（exp vs now）。UI 门控/徽标用。
  • validate_remote() —— 需与分发系统交互的操作（更新检测/扩展商店）用：带 fresh key 去分发系统**完整校验**。

语义分层（用户明确要求）：本地只校时效（快、全 worker 一致）；和分发系统交互时才完整校验 key。
纯 stdlib（base64/json/yaml/urllib），不验签（验签由分发系统在 validate_remote 时做），无 ROLE、无副作用。
"""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError

DEFAULT_SOURCE_URL = "http://124.222.145.172:5080"


def _config_path() -> Optional[str]:
    from sentinel_platform.core.config import _first_existing, _config_candidates
    return _first_existing(_config_candidates())


def _key_file_candidates() -> list:
    """.activation_key 兜底文件候选（Docker 只读 config 场景）。与历史各处顺序一致。"""
    cfg_path = _config_path()
    return [
        os.path.join(os.path.dirname(cfg_path), ".activation_key") if cfg_path else "",
        os.path.join(os.getcwd(), ".activation_key"),
        "/tmp/.sentinel_activation_key",
    ]


def is_jwt(token: str) -> bool:
    token = token or ""
    return token.startswith("eyJ") and token.count(".") == 2


def read_key() -> str:
    """激活 key —— **始终从磁盘 fresh 读**，绝不经 get_config() 缓存（多 worker 一致的关键）。
    顺序：config.yaml 的 UPDATE.KEY（直读文件，非缓存）> .activation_key 兜底文件。取到 JWT 即返。"""
    cfg_path = _config_path()
    if cfg_path:
        try:
            import yaml
            with open(cfg_path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            key = str((raw.get("UPDATE") or {}).get("KEY", "") or "").strip()
            if is_jwt(key):
                return key
        except Exception:
            pass
    for fp in _key_file_candidates():
        if fp and os.path.isfile(fp):
            try:
                with open(fp, "r", encoding="utf-8") as fh:
                    k = fh.read().strip()
                if is_jwt(k):
                    return k
            except OSError:
                pass
    return ""


def decode_payload(token: str) -> Dict[str, Any]:
    """离线解 JWT payload（不验签，取 exp/claims）。失败返 {}。"""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return {}
    try:
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
    except Exception:
        return {}


def local_status() -> Dict[str, Any]:
    """系统激活状态（唯一权威）：本地离线校验 JWT 时效。全 worker 读同一磁盘 key 故一致。
    返回 {has_key, activated, expired, expires_at, remaining_days, username}。"""
    key = read_key()
    out = {"has_key": bool(key), "activated": False, "expired": False,
           "expires_at": "", "remaining_days": 0, "username": ""}
    if not is_jwt(key):
        return out
    payload = decode_payload(key)
    exp = int(payload.get("exp", 0) or 0)
    out["username"] = payload.get("name", "") or ""
    if not exp:
        return out
    now = time.time()
    out["expires_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
    out["remaining_days"] = max(0, int((exp - now) / 86400))
    if exp > now:
        out["activated"] = True
    else:
        out["expired"] = True
    return out


def source_url() -> str:
    """分发系统地址：优先 config UPDATE.SOURCE_URL（源地址稳定，读缓存亦可），未配回退官方源。"""
    try:
        from sentinel_platform.core import get_config
        return (get_config().section("UPDATE", "SOURCE_URL", default="") or DEFAULT_SOURCE_URL).strip().rstrip("/")
    except Exception:
        return DEFAULT_SOURCE_URL


def validate_remote(path: str = "/version", timeout: int = 15) -> Dict[str, Any]:
    """**完整校验**：带 fresh key 请求分发系统（需交互的操作用：更新检测/扩展商店）。
    返回 {ok, status, reason}：ok=True 服务器接受；reason=no_key/unauthorized/network/http_<code>。
    不抛异常（调用方按 reason 决定文案）。"""
    key = read_key()
    if not key:
        return {"ok": False, "status": 0, "reason": "no_key"}
    url = source_url() + path
    try:
        with urlopen(Request(url, headers={"X-Update-Key": key}), timeout=timeout) as resp:
            return {"ok": True, "status": getattr(resp, "status", 200), "reason": ""}
    except HTTPError as he:
        if he.code in (401, 403):
            return {"ok": False, "status": he.code, "reason": "unauthorized"}
        return {"ok": False, "status": he.code, "reason": "http_{}".format(he.code)}
    except Exception:
        return {"ok": False, "status": 0, "reason": "network"}
