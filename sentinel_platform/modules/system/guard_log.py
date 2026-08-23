"""system/guard_log —— 智能闸刀拦截日志（capped 环形集合，固定容量 + FIFO 覆盖最早）。

闸刀（AI 渗透出站请求的放行/拦截）是**正常业务事件**，不该塞进 log_monitor（那是 WARNING+
程序报错日志，会被污染）。单独写 `guard_log` 集合，用 MongoDB capped collection 实现
「固定大小 + 满了自动覆盖最早」，无需手写轮转。容量可调（默认 500MB）。

**无 ROLE**（纯业务叶子）：经 registry 以字符串键 `"guard_log_service"` 注册（照
log_service/audit_service 先例），router `endpoints/guard_log.py` + 未来 ai_pentest 闸刀取用。
不放 HTTP 路由。`record` 供闸刀经 registry 调写事件（接口先立，非孤岛）。

迁移来源：app/services/guard_log.py（capped 生命周期 + record + list + stat）。净室重写。
capped 需 db 级命令（create_collection/collMod/collstats），经 `get_repo().collection(x).database`
取 pymongo Database；无 pymongo 的测试环境（fake repo 无 .database）优雅降级——insert/list 仍走 fake。

**禁止硬限制参数**：list `size` 客户端定不砍上限（缺省 30 仅默认）；容量 set_size_mb 只保物理下限
（capped 必须 >0，floor 1MB）不设人为上限（用户自主决定磁盘占用）。
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

COLL = Collections.GUARD_LOG
META = Collections.GUARD_LOG_META
DEFAULT_SIZE_MB = 500
MIN_SIZE_MB = 1                         # 物理下限（capped 容量必须 >0），非人为业务限制
# 注：不设 MAX 上限（守禁止硬限制参数——用户自主决定磁盘占用）

_ensured: Dict[str, int] = {"size_bytes": 0}   # 进程内缓存，避免每次插入都查 collstats


def _coll():
    return get_repo().collection(COLL)


def _db():
    """取 pymongo Database（capped 命令用）；fake repo/无 pymongo 时返回 None（降级）。"""
    try:
        return _coll().database
    except Exception:
        return None


def get_size_mb() -> int:
    """当前 capped 容量配置（MB），下限 1，无上限。库不可用降级默认。"""
    try:
        doc = get_repo().collection(META).find_one({"name": "default"}) or {}
        return max(MIN_SIZE_MB, int(doc.get("size_mb", DEFAULT_SIZE_MB)))
    except (TypeError, ValueError):
        return DEFAULT_SIZE_MB
    except Exception:
        return DEFAULT_SIZE_MB


def _current_capped_size() -> int:
    """guard_log 当前 capped 容量(字节)；非 capped/不存在/无 db 返回 0。"""
    db = _db()
    if db is None:
        return 0
    try:
        st = db.command("collstats", COLL)
        if st.get("capped"):
            return int(st.get("maxSize") or st.get("storageSize") or 0)
    except Exception:
        pass
    return 0


def _resize(size_bytes: int) -> None:
    """调整 capped 容量：优先 collMod cappedSize(MongoDB 6.0+)，失败则重建(丢旧记录可接受)。"""
    db = _db()
    if db is None:
        return
    try:
        db.command("collMod", COLL, cappedSize=size_bytes)
        return
    except Exception:
        pass
    try:
        db.drop_collection(COLL)
        db.create_collection(COLL, capped=True, size=size_bytes)
    except Exception:
        logger.exception("guard_log resize(recreate) failed")


def ensure_capped(size_bytes: Optional[int] = None) -> None:
    """确保 guard_log 是 capped 且容量=配置值。幂等 + 进程内缓存。异常吞掉不反噬业务。
    无 db（fake repo/无 pymongo）时直接返回——insert 仍能落 fake，测试无碍。"""
    size_bytes = size_bytes or get_size_mb() * 1024 * 1024
    if _ensured["size_bytes"] == size_bytes:
        return
    db = _db()
    if db is None:
        _ensured["size_bytes"] = size_bytes
        return
    try:
        names = db.list_collection_names()
        if COLL not in names:
            db.create_collection(COLL, capped=True, size=size_bytes)
        else:
            cur = _current_capped_size()
            if not cur:
                try:
                    db.command("convertToCapped", COLL, size=size_bytes)
                except Exception:
                    pass
            elif abs(cur - size_bytes) > 1024 * 1024:   # 容量变了(差超 1MB)才调整
                _resize(size_bytes)
        _ensured["size_bytes"] = size_bytes
    except Exception:
        logger.exception("guard_log ensure_capped failed")


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class GuardLogServiceImpl:
    """拦截日志能力（无 ROLE，字符串键 guard_log_service 注册）。"""

    def record(self, method: str, url: str, mode: str, allow: bool, level: str,
               reason: str = "", session_id: str = "", site: str = "") -> None:
        """写一条闸刀事件到拦截日志（capped，满了自动覆盖最早）。**异常吞掉绝不反噬业务**。

        供未来 ai_pentest 闸刀经 `get_registry().get("guard_log_service").record(...)` 调。
        level：safe/danger/ambiguous/ai_safe/ai_danger；mode：src/redteam/conservative。
        """
        try:
            ensure_capped()
            _coll().insert_one({
                "method": (method or "").upper(),
                "url": (url or "")[:500],
                "mode": mode,
                "allow": bool(allow),
                "level": level,
                "reason": (reason or "")[:300],
                "session_id": session_id,
                "site": site,
                "save_date": _now_str(),
                "ts": int(time.time()),
            })
        except Exception:
            pass    # 闸刀日志绝不反噬业务

    def list_logs(self, allow: Any = None, mode: str = "", level: str = "",
                  page: int = 1, size: int = 30) -> Dict[str, Any]:
        """拦截日志列表（capped $natural 倒序=最新在前 + 过滤 + 分页）。
        size 缺省 30 仅默认，客户端传多大都透传不砍（禁硬限制参数）。库不可用降级空。"""
        try:
            page = max(1, int(page or 1))
            size = max(1, int(size or 30))
        except (TypeError, ValueError):
            page, size = 1, 30
        q: Dict[str, Any] = {}
        if allow is not None:
            q["allow"] = bool(allow)
        if mode:
            q["mode"] = mode
        if level:
            q["level"] = level
        try:
            coll = _coll()
            total = coll.count_documents(q)
            items = []
            for d in coll.find(q).sort("$natural", -1).skip((page - 1) * size).limit(size):
                d["_id"] = str(d["_id"])
                items.append(d)
            return {"items": items, "total": total, "page": page, "size": size}
        except Exception as exc:
            logger.debug("guard_log: list failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "size": size}

    def stat(self) -> Dict[str, Any]:
        """拦截日志统计：总数/拦截/放行 + 当前容量配置。库不可用降级 0。"""
        try:
            coll = _coll()
            return {
                "total": coll.count_documents({}),
                "blocked": coll.count_documents({"allow": False}),
                "allowed": coll.count_documents({"allow": True}),
                "size_mb": get_size_mb(),
                "default_size_mb": DEFAULT_SIZE_MB,
            }
        except Exception as exc:
            logger.debug("guard_log: stat failed: %s", exc)
            return {"total": 0, "blocked": 0, "allowed": 0,
                    "size_mb": get_size_mb(), "default_size_mb": DEFAULT_SIZE_MB}

    def set_size_mb(self, mb: Any) -> int:
        """设置拦截日志容量(MB)。运行时生效；改容量可能清空历史。下限 1MB(物理)，无上限(用户自主)。"""
        try:
            mb = max(MIN_SIZE_MB, int(mb))
        except (TypeError, ValueError):
            mb = DEFAULT_SIZE_MB
        try:
            get_repo().collection(META).update_one(
                {"name": "default"}, {"$set": {"size_mb": mb, "update_date": _now_str()}}, upsert=True)
            _ensured["size_bytes"] = 0      # 强制下次 ensure 重新校准
            ensure_capped(mb * 1024 * 1024)
        except Exception as exc:
            logger.debug("guard_log: set_size failed: %s", exc)
        return get_size_mb()

    def get_size_mb(self) -> int:
        return get_size_mb()


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = GuardLogServiceImpl()


def get_service() -> GuardLogServiceImpl:
    return _service

