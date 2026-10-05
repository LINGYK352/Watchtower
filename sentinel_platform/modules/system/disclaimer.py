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


def _marker_candidates() -> list:
    """签署标记文件候选路径（**写和读共用这一份，杜绝路径打架**）。
    顺序即优先级——**config 目录排第一且必含**：docker 部署下 config 是挂载卷（宿主机 docker/config），
    容器重建/关机重启都不丢（治"VM 关机后容器 recreate 签署丢失、每次重弹"）。
    其余（当前目录/tmp）仅作极端不可写时的兜底。所有候选枚举 _config_candidates 的每个目录，
    保证 _config_dir 动态返回不同值时写读仍落在同一集合内（治"写A读B"）。"""
    candidates = []
    try:
        from sentinel_platform.core.config import _config_candidates
        for cfg_path in _config_candidates():
            if cfg_path:
                p = os.path.join(os.path.dirname(cfg_path), ".disclaimer_accepted")
                if p not in candidates:
                    candidates.append(p)
    except Exception:
        pass
    cwd_path = os.path.join(os.getcwd(), ".disclaimer_accepted")
    if cwd_path not in candidates:
        candidates.append(cwd_path)
    tmp_path = "/tmp/.sentinel_disclaimer_accepted"
    if tmp_path not in candidates:
        candidates.append(tmp_path)
    return candidates


def get_status() -> Dict[str, Any]:
    """读签署状态。返回 {accepted, accepted_version, accepted_at}。
    读不到任何标记文件 → accepted=False（未签署）。

    与 accept() 共用 _marker_candidates() 同一份路径列表（写读一致，杜绝"写A读B"）。
    """
    # 遍历统一候选路径，找到第一个有效签署（与 accept 写入用同一列表）
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
    """记录同意：向**所有可写候选路径都写一份**（冗余持久化）。返回签署后的状态。
    version = 前端 DISCLAIMER_VERSION（条款版本），据此判断旧签署对新条款是否仍有效。

    **根治"签署后立即读不到/重启丢失"**：
    - 写和读共用 _marker_candidates() 同一列表（config 目录持久卷排第一）；
    - **写所有可写候选**（不止第一个）——多处冗余，get_status 任一命中即算已签，
      不再有"写A删B/写A读B"的路径打架（旧 _cleanup_stale_markers 会误删唯一签署文件，已移除）。
    """
    payload = {
        "accepted": True,
        "accepted_version": str(version or ""),
        "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    blob = json.dumps(payload, ensure_ascii=False)

    ok_count = 0
    for fp in _marker_candidates():
        if not fp:
            continue
        try:
            d = os.path.dirname(fp)
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = fp + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(blob)
            os.replace(tmp, fp)
            ok_count += 1
        except Exception:
            continue

    # 一个都没写进（极端只读环境）：不抛错，返回 accepted 但标记未持久化
    return {**payload, "persisted": ok_count > 0}


