"""system/activation —— 激活凭证单一权威（全项目激活判定统一入口）+ 独立激活时钟。

**背景（治多 worker 缓存不一致的间歇性误报）**：gunicorn -w 3 多 worker，get_config() 是每进程
各自的模块级 _cached 单例；激活写 key 后只重置当前 worker 缓存，其他 worker 仍持旧缓存 →
"一个 worker 激活了其他没激活、过会儿又弹请重新激活；一个失效了其他仍有效"。且历史上读 key 有三套
写法(meta 直读盘 / update_check 与 about 与 _extension_store 读缓存)，部分走缓存故不一致。

**本模块统一规则（v1.21.157-15 升级为激活时钟 + 云端一票否决）**：
  • read_key()  —— 激活 key **始终从磁盘 fresh 读**（config.yaml 的 UPDATE.KEY > .activation_key 候选文件），
                   绝不读 get_config() 缓存 → 全 worker 读同一磁盘文件，天然一致，写后立即生效。
  • local_status() —— **「激活时钟」单一权威**：本地离线校验 JWT 时间字段（activated_at/exp/auth_days），
                   叠加云端否决标记(.activation_revoked fresh 读盘)。徽标/剩余天数/到期提示全由它驱动，
                   离线、稳定、全 worker 一致，不因日常网络通信抖动。
  • validate_remote() —— 需与分发系统交互的操作（更新检测/扩展商店）用：带 fresh key 去分发系统**完整校验**。
  • note_remote_result(reason) —— **云端一票否决入口**：更新检测/扩展商店收到云端 401/403(reason=unauthorized)
                   时调用 → 落盘否决标记 → 激活时钟立即结束（吊销即时生效）；云端重新认可时自动解除。
  • mark_revoked() / clear_revoked() —— 落盘/清除否决标记（与 key 同目录，fresh 读，多 worker 一致）。

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

DEFAULT_SOURCE_URL = "https://watchtowers.info"


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


def _revoked_file_candidates() -> list:
    """吊销标记文件候选路径（与 key 同目录策略，fresh 读，多 worker 一致）。"""
    cfg_path = _config_path()
    candidates = []
    if cfg_path:
        candidates.append(os.path.join(os.path.dirname(cfg_path), ".activation_revoked"))
    candidates.extend([
        "/opt/sentinel/current/.activation_revoked",
        "/tmp/.sentinel_activation_revoked",
    ])
    return candidates


def is_revoked() -> bool:
    """读吊销标记（云端一票否决）—— fresh 读盘，多 worker 一致。任一候选文件存在即判吊销。"""
    for fp in _revoked_file_candidates():
        if fp and os.path.isfile(fp):
            return True
    return False


def mark_revoked(reason: str = "remote_unauthorized") -> bool:
    """落盘吊销标记（云端一票否决）—— 激活时钟立即结束。返回是否写入成功。"""
    import time as _time
    payload = json.dumps({"reason": reason, "revoked_at": _time.time()}, ensure_ascii=False)
    for fp in _revoked_file_candidates():
        if not fp:
            continue
        try:
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            with open(fp, "w", encoding="utf-8") as fh:
                fh.write(payload)
            return True
        except OSError:
            continue
    return False


def clear_revoked() -> None:
    """清除吊销标记（重新激活成功 / 云端重新认可时调用）—— 恢复已激活态。"""
    for fp in _revoked_file_candidates():
        if fp and os.path.isfile(fp):
            try:
                os.unlink(fp)
            except OSError:
                pass


def note_remote_result(reason: str) -> None:
    """云端一票否决入口 —— 更新检测/扩展商店收到云端结论后调用。
    reason=unauthorized → 落盘否决标记（时钟结束）；reason 成功 → 清除标记（云端重新认可则恢复）；
    network/http_x → 不动（网络问题不终结时钟，避免断网误杀）。"""
    if reason == "unauthorized":
        mark_revoked("remote_unauthorized")
    elif reason == "":  # 成功（validate_remote 的 ok=True 时 reason=""）
        clear_revoked()
    # network / http_x 等其他：不动


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
    """**激活时钟（唯一权威）**：本地离线校验 JWT 时间字段 + 云端否决标记。全 worker 读同一磁盘故一致。
    返回 {has_key, activated, expired, revoked, expires_at, activated_at, remaining_days, username}。
    remaining_days 用 ceil 取整（剩<1天显示1天，与用户直觉一致）；云端吊销时即便 JWT 未到期也判 expired。"""
    import math
    key = read_key()
    revoked = is_revoked()
    out = {"has_key": bool(key), "activated": False, "expired": False, "revoked": revoked,
           "expires_at": "", "activated_at": "", "remaining_days": 0, "username": ""}
    if not is_jwt(key):
        return out
    payload = decode_payload(key)
    exp = int(payload.get("exp", 0) or 0)
    activated_at = int(payload.get("activated_at", 0) or 0)
    out["username"] = payload.get("name", "") or ""
    if not exp:
        return out
    now = time.time()
    out["expires_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
    out["activated_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(activated_at)) if activated_at else ""
    # 云端一票否决：吊销标记存在 → 时钟立即结束（即便 JWT 未到期）
    if revoked:
        out["activated"] = False
        out["expired"] = True
        out["remaining_days"] = 0
        return out
    # 正常路径：只看 JWT 时效
    if exp > now:
        out["activated"] = True
        # remaining_days 向上取整：剩 0.9 天 → 显示 1 天（用户直觉「还剩1天」，不会误显过期）
        out["remaining_days"] = max(1, math.ceil((exp - now) / 86400))
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
