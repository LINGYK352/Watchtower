"""system/disclaimer —— 免责声明签署状态（服务端磁盘持久化，单一权威）。

**为什么服务端存**：免责声明"同意"必须重启服务器/容器后仍保留、换浏览器后仍保留，
只有清目录/重装才需重签。纯前端 localStorage 满足不了（换浏览器/清缓存即丢）。
故照 `system/activation` 的磁盘文件先例：签署标记落盘到 config 目录旁的隐藏文件，
全 worker 读同一文件天然一致，写后立即生效。

签署标记按**条款版本**区分：条款实质变更时前端 DISCLAIMER_VERSION 递增，
旧签署对新版本不算数（accepted_version != 当前版本 → 视为未签，需重新确认）。

纯 stdlib（json/os/time），无 ROLE、无 DB 依赖。端点在 router/endpoints/system.py。
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional


def _config_dir() -> Optional[str]:
    """config 文件所在目录（复用 activation 的候选路径逻辑）。取不到返回 None。"""
    try:
        from sentinel_platform.core.config import _first_existing, _config_candidates
        cfg_path = _first_existing(_config_candidates())
        if cfg_path:
            return os.path.dirname(cfg_path)
    except Exception:
        pass
    return None


def _marker_candidates() -> list:
    """签署标记文件候选（与 .activation_key 同目录策略，多处兜底保证可写）。"""
    d = _config_dir()
    return [
        os.path.join(d, ".disclaimer_accepted") if d else "",
        os.path.join(os.getcwd(), ".disclaimer_accepted"),
        "/tmp/.sentinel_disclaimer_accepted",
    ]


def get_status() -> Dict[str, Any]:
    """读签署状态。返回 {accepted, accepted_version, accepted_at}。
    读不到任何标记文件 → accepted=False（未签署）。"""
    for fp in _marker_candidates():
        if fp and os.path.isfile(fp):
            try:
                with open(fp, "r", encoding="utf-8") as fh:
                    data = json.loads(fh.read() or "{}")
                if data.get("accepted"):
                    return {
                        "accepted": True,
                        "accepted_version": str(data.get("accepted_version", "") or ""),
                        "accepted_at": str(data.get("accepted_at", "") or ""),
                    }
            except Exception:
                pass
    return {"accepted": False, "accepted_version": "", "accepted_at": ""}


def accept(version: str = "") -> Dict[str, Any]:
    """记录同意：写标记文件（首个可写候选即成功）。返回签署后的状态。
    version = 前端 DISCLAIMER_VERSION（条款版本），据此判断旧签署对新条款是否仍有效。"""
    payload = {
        "accepted": True,
        "accepted_version": str(version or ""),
        "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    blob = json.dumps(payload, ensure_ascii=False)
    for fp in _marker_candidates():
        if not fp:
            continue
        try:
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            tmp = fp + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(blob)
            os.replace(tmp, fp)
            return payload
        except Exception:
            continue
    # 全部候选都写不进（极端只读环境）：不抛错，返回 accepted 但标记未持久化
    return {**payload, "persisted": False}
