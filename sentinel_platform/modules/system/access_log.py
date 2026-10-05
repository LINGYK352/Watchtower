"""system/access_log —— 系统访问日志 + 操作日志（审计）。

零侵入审计：router 网关 before/after_request 钩子对每个 /api 请求调 record()——谁(username)、
何时、从哪(ip)、访问什么(method+path)、结果(status)、耗时(elapsed_ms)。写方法(POST/PUT/DELETE/PATCH)
标 is_write=True 即"操作日志"（增删改审计）；GET 即普通访问日志。集合 `access_log`。

对外（供 router endpoints 挂 /api/access_log/* + gateway 写）：
  record(**entry)                 记一条（gateway 钩子调；异常吞掉绝不反噬业务）
  should_record(path, method)     是否记录（跳日志接口自身/文档/预检，防刷屏递归）
  list_access(...) -> dict        分页 + 过滤（is_write/username/path/status）。**不设 size 硬上限**（禁硬限制参数）
  stat_access() -> dict           统计：总量/写操作/今日/错误(4xx+)

注册：字符串键 `"audit_service"`（照 gateway user_service/rbac_service 先例，不进冻结 ROLE）。gateway 经此写审计。
迁移来源：app/services/access_log.py + main.py before/after_request。依赖：仅 stdlib（time/datetime/re），**无新增 vendor**。
不放 HTTP 路由（端点在 router/endpoints/access_log.py）；TTL 保留天数属 log_retention（log_monitor 叶子），本模块留 ensure_ttl_index 钩子不硬编码天数。
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

_WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
# 不记录的路径前缀（防刷屏/递归/噪音）：日志接口自身、文档、截图静态。
_SKIP_PREFIXES = ("/api/access_log", "/api/log_monitor", "/api/doc", "/api/swagger", "/api/image", "/api/meta/health")
_DEFAULT_RETENTION_DAYS = 14   # 仅 ensure_ttl_index 缺省；实际天数由 log_retention 配（不硬编码进写入路径）


def _coll():
    return get_repo().collection(Collections.ACCESS_LOG)


def should_record(path: str, method: str) -> bool:
    """是否记录该请求：只记 /api 业务请求，跳过日志接口自身/文档/预检（防递归刷屏）。"""
    if (method or "").upper() == "OPTIONS":
        return False
    if not (path or "").startswith("/api"):
        return False
    return not any(path.startswith(p) for p in _SKIP_PREFIXES)


def record(method: str = "GET", path: str = "", status: int = 0, username: str = "",
           ip: str = "", elapsed_ms: int = 0, **_ignore: Any) -> None:
    """记一条访问/操作日志。写方法标 is_write。异常吞掉不反噬业务（日志系统绝不拖垮请求）。"""
    try:
        m = (method or "GET").upper()
        doc = {
            "method": m,
            "path": (path or "")[:300],
            "status": int(status) if str(status).isdigit() else 0,
            "username": username or "-",
            "ip": ip or "",
            "is_write": m in _WRITE_METHODS,
            "elapsed_ms": int(elapsed_ms) if str(elapsed_ms).isdigit() else 0,
            "save_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "_ttl": datetime.utcnow(),   # 仅供 TTL 索引，list 输出时 pop（避免 JSON 序列化 datetime 报错）
        }
        _coll().insert_one(doc)
    except Exception:
        pass  # 审计失败绝不影响业务


def list_access(is_write: Optional[bool] = None, username: str = "", path: str = "",
                status: str = "", page: int = 1, size: int = 20) -> Dict[str, Any]:
    """访问/操作日志列表（分页 + 过滤，按时间倒序）。is_write=True 即操作日志。

    **禁硬限制参数**：size 由调用方决定，不加 `min(size,N)` 硬上限；仅对非法值兜底为默认，
    size<=0 视为不分页（全量，供导出/审计需要）。page<1 归 1。
    """
    q: Dict[str, Any] = {}
    if is_write is not None:
        q["is_write"] = bool(is_write)
    if username:
        q["username"] = username
    if path:
        q["path"] = {"$regex": re.escape(path), "$options": "i"}
    if status:
        try:
            q["status"] = int(status)
        except (TypeError, ValueError):
            pass
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 20
    if page < 1:
        page = 1
    try:
        coll = _coll()
        total = coll.count_documents(q)
        cursor = coll.find(q).sort("_id", -1)
        if size and size > 0:                 # size<=0 → 全量（不硬限），否则按页
            cursor = cursor.skip((page - 1) * size).limit(size)
        items = []
        for d in cursor:
            d["_id"] = str(d.get("_id", ""))
            d.pop("_ttl", None)
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        logger.debug("access_log list degraded: %s", exc)
        return {"items": [], "total": 0, "page": page, "size": size}


def stat_access() -> Dict[str, Any]:
    """统计：总量/写操作/今日/错误(4xx+)。读库失败降级零值（不抛）。"""
    try:
        coll = _coll()
        today = datetime.now().strftime("%Y-%m-%d")
        return {
            "total": coll.count_documents({}),
            "writes": coll.count_documents({"is_write": True}),
            "today": coll.count_documents({"save_date": {"$regex": "^" + today}}),
            "errors": coll.count_documents({"status": {"$gte": 400}}),
        }
    except Exception as exc:
        logger.debug("access_log stat degraded: %s", exc)
        return {"total": 0, "writes": 0, "today": 0, "errors": 0}


def ensure_ttl_index(days: Optional[int] = None) -> bool:
    """建 TTL 索引（_ttl 字段按 days 过期）。days 由 log_retention 配（log_monitor 叶子）；
    缺省 _DEFAULT_RETENTION_DAYS，**不硬编码进写入路径**（写入永不受此限）。部署/log_monitor 调。失败吞掉返 False。"""
    try:
        d = int(days) if days else _DEFAULT_RETENTION_DAYS
        _coll().create_index("_ttl", expireAfterSeconds=d * 86400)
        return True
    except Exception as exc:
        logger.debug("access_log ensure_ttl_index skip: %s", exc)
        return False


class AuditServiceImpl:
    """审计服务。注册字符串键 "audit_service"（gateway after_request 经此写审计）。"""

    def record(self, **entry: Any) -> None:
        record(**entry)

    def should_record(self, path: str, method: str) -> bool:
        return should_record(path, method)

    def list_access(self, **kwargs: Any) -> Dict[str, Any]:
        return list_access(**kwargs)

    def stat_access(self) -> Dict[str, Any]:
        return stat_access()


_service = AuditServiceImpl()


def get_service() -> AuditServiceImpl:
    return _service
