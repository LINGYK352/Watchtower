"""system/log_monitor —— 日志监测 + 运营日志保留 + 资源监控。

三块能力（对应前端 pages/logs/LogMonitor.vue + api/logMonitor.ts）：
  ①程序报错日志（集合 `log_monitor`，WARNING+）：MongoLogHandler 采集 + list/stat/delete/clear。
  ②运营日志保留（集合 `log_retention`）：get/set 各日志集合 TTL 天数（access_log/log_monitor 等），
    collMod 运行时即时生效。**闭合 access_log 叶子留的 retention 遗留**（access_log 的 _ttl 天数由此配）。
  ③资源监控（集合 `resource_history`）：sample_resource 采样 CPU/内存/磁盘（**dash 读它**，闭合其依赖），
    get_resource_level / query_resource_history。

注册：字符串键 `"log_service"`（照 gateway user_service 先例，不进冻结 ROLE）。端点 router/endpoints/log_monitor.py。
迁移来源：routes/log_monitor.py + services/log_retention.py + services/resource_monitor.py + utils/log_handler.py。
依赖：psutil（**dash 已同步 vendor/wheels/psutil-5.7.2.tar.gz**，本模块惰性 import + 缺失降级，不重复下载）。
**禁硬限制参数**：日志 list size<=0 返全量、retention 去掉 MAX_DAYS 上限（仅保 days>=1 防"0天即删"脚手枪）、
resource 查询天数不设上限。guard/* 拦截日志属 `system/guard_log` 叶子（不越界）。并发推荐(recommend_*)依赖 celery/ai_config，归 orchestration。
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_logger, get_config
from sentinel_platform.contracts import Collections

logger = get_logger()

_LEVELS = ("ERROR", "WARNING", "CRITICAL")
RESOURCE_HISTORY = "resource_history"

# 兼容默认值；均可由 RESOURCE 配置覆盖。默认值是资源建议，不是目标数/结果数上限。
_TH_LOW, _TH_HIGH, _TH_CRIT = 60, 80, 90
_DEFAULT_BUDGETS = {
    "relaxed": {"task_slots": 5, "io_concurrency": 16, "scan_parallelism": 6},
    "normal": {"task_slots": 3, "io_concurrency": 10, "scan_parallelism": 4},
    "tight": {"task_slots": 1, "io_concurrency": 5, "scan_parallelism": 2},
    "critical": {"task_slots": 0, "io_concurrency": 2, "scan_parallelism": 1},
}

# 水位系数：task_slots 按「可用资源」算基准容量后，用水位系数调激进/保守（水位是调度核心，只当系数）。
# critical 恒 0（停投保命）。见 待办-task_slots资源感知.md。
_SLOT_FACTOR = {"relaxed": 1.0, "normal": 0.7, "tight": 0.3, "critical": 0.0}
_TASK_MEM_GB_DEFAULT = 1.5   # 每任务内存预算(GB)，对齐 ai_config.recommend_concurrency；可配 RESOURCE.TASK_MEM_GB


def _recommend_task_slots(level: str) -> Optional[int]:
    """按实际可用内存 × 水位系数算 task_slots（废写死档位魔数，真资源调度）。
    base = (可用内存+swap空闲)/每任务预算GB；slots = round(base × 水位系数)。
    critical 恒 0；非 critical 有资源则至少 1；不设人为固定上限（worker -c 执行侧天然封顶）。
    psutil 不可用返回 None → 调用方回退旧档位值（不崩）。"""
    factor = _SLOT_FACTOR.get(level, 0.7)
    if factor <= 0:
        return 0                                     # critical：停投
    try:
        import psutil
        avail = psutil.virtual_memory().available
        try:
            avail += psutil.swap_memory().free       # swap 兜底（对齐 recommend_concurrency）
        except Exception:
            pass
        per_gb = _resource_float("TASK_MEM_GB", _TASK_MEM_GB_DEFAULT)
        base = (avail / (1024 ** 3)) / max(0.25, per_gb)
        slots = int(round(base * factor))
        return max(1, slots)                         # 非 critical 有资源不饿死
    except Exception:
        return None                                  # 回退旧档位

# ========== ① 程序报错日志采集 ==========

def record_log(level: str, message: str, module: str = "", logger_name: str = "",
               process_type: str = "", host: str = "") -> None:
    """写一条程序日志到 log_monitor 集合。异常吞掉不反噬业务。"""
    try:
        get_repo().collection(Collections.LOG_MONITOR).insert_one({
            "level": (level or "").upper(),
            "message": str(message)[:2000],
            "module": module or "",
            "logger_name": logger_name or "",
            "process_type": process_type or "",
            "host": host or "",
            "save_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "update_date": datetime.utcnow(),   # TTL 索引字段（保留天数由 log_retention 配）
        })
    except Exception:
        pass


class MongoLogHandler(logging.Handler):
    """logging.Handler：把 WARNING+ 日志写进 log_monitor 集合。挂到平台 logger 上（install_log_capture）。
    不改冻结的 core/log.py，运行时附加；handler 内异常自吞（logging.Handler.emit 约定）。"""
    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno < logging.WARNING:
                return
            record_log(level=record.levelname, message=record.getMessage(),
                       module=getattr(record, "filename", ""), logger_name=record.name)
        except Exception:
            pass


def install_log_capture(target_logger: Optional[logging.Logger] = None) -> bool:
    """把 MongoLogHandler 挂到平台 logger（幂等，不重复挂）。router/orchestration 启动时调。"""
    lg = target_logger or logging.getLogger("sentinel_platform")
    for h in lg.handlers:
        if isinstance(h, MongoLogHandler):
            return False
    h = MongoLogHandler(level=logging.WARNING)
    lg.addHandler(h)
    return True


def list_logs(level: str = "", message: str = "", module: str = "", process_type: str = "",
              logger_name: str = "", host: str = "", page: int = 1, size: int = 20) -> Dict[str, Any]:
    """程序日志列表（分页 + 过滤，时间倒序）。**禁硬限制参数**：size<=0 返全量，无 min(size,N) 硬顶。"""
    import re
    q: Dict[str, Any] = {}
    if level:
        q["level"] = level.upper()
    for f, v in (("module", module), ("process_type", process_type), ("logger_name", logger_name), ("host", host)):
        if v:
            q[f] = v
    if message:
        q["message"] = {"$regex": re.escape(message), "$options": "i"}
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 20
    try:
        coll = get_repo().collection(Collections.LOG_MONITOR)
        total = coll.count_documents(q)
        cur = coll.find(q).sort("_id", -1)
        if size and size > 0:
            cur = cur.skip((page - 1) * size).limit(size)
        items = []
        for d in cur:
            d["_id"] = str(d.get("_id", ""))
            d.pop("update_date", None)   # datetime 不输出（避免 JSON 序列化报错）
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        logger.debug("log list degraded: %s", exc)
        return {"items": [], "total": 0, "page": page, "size": size}


def stat_logs() -> Dict[str, int]:
    """按级别统计。读库失败降级零值。"""
    try:
        coll = get_repo().collection(Collections.LOG_MONITOR)
        s = {lv: coll.count_documents({"level": lv}) for lv in _LEVELS}
        s["total"] = coll.count_documents({})
        return s
    except Exception:
        return {lv: 0 for lv in _LEVELS} | {"total": 0}


def _oid(_id: str):
    """把字符串 _id 转 ObjectId（生产）；bson 缺失或非法（测试/普通字符串键）则原样返回，兼容两态。"""
    try:
        from bson import ObjectId
        return ObjectId(_id)
    except Exception:
        return _id


def delete_logs(ids: List[str]) -> Dict[str, Any]:
    """按 _id 列表删除。返回删除数。_id 兼容 ObjectId（生产）与字符串（测试/无 bson）。"""
    n = 0
    try:
        coll = get_repo().collection(Collections.LOG_MONITOR)
        for _id in (ids or []):
            try:
                n += coll.delete_one({"_id": _oid(_id)}).deleted_count
            except Exception:
                continue
    except Exception as exc:
        return {"error": str(exc), "deleted": n}
    return {"deleted": n}


def clear_logs() -> Dict[str, Any]:
    """清空全部程序日志。"""
    try:
        r = get_repo().collection(Collections.LOG_MONITOR).delete_many({})
        return {"delete_cnt": r.deleted_count}
    except Exception as exc:
        return {"error": str(exc), "delete_cnt": 0}


# ========== ② 运营日志保留（log_retention）==========
# 每类日志：集合名、TTL 索引字段、默认天数、标签。access_log 的 _ttl 由此配（闭合其遗留）。
RETENTION_DEFS = {
    "log_monitor": {"coll": Collections.LOG_MONITOR, "ttl_field": "update_date", "default_days": 7, "label": "日志监测(程序报错)"},
    "access_log": {"coll": Collections.ACCESS_LOG, "ttl_field": "_ttl", "default_days": 14, "label": "访问/操作日志"},
}
_RETENTION_MIN_DAYS = 1   # 防"0 天=即删"脚手枪的安全floor（非数据帽）；**无上限**（禁硬限制参数，想留 3 年随意）


def get_retention() -> Dict[str, Any]:
    """各类日志当前保留天数（无配置用默认）。对齐前端 LogRetention。"""
    try:
        doc = get_repo().collection(Collections.LOG_RETENTION).find_one({"name": "default"}) or {}
    except Exception:
        doc = {}
    return {k: {"label": d["label"], "coll": d["coll"],
                "days": int(doc.get(k, d["default_days"])), "default_days": d["default_days"]}
            for k, d in RETENTION_DEFS.items()}


def _apply_ttl(coll_name: str, ttl_field: str, days: int) -> bool:
    """collMod 改 TTL 过期秒数；索引不存在则创建。运行时即时生效。失败吞掉返 False。"""
    seconds = int(days) * 86400
    try:
        coll = get_repo().collection(coll_name)
        try:
            coll.database.command("collMod", coll_name,
                                  index={"keyPattern": {ttl_field: 1}, "expireAfterSeconds": seconds})
            return True
        except Exception:
            coll.create_index(ttl_field, expireAfterSeconds=seconds, name=ttl_field + "_1")
            return True
    except Exception as exc:
        logger.debug("apply_ttl skip %s: %s", coll_name, exc)
        return False


def set_retention(updates: Dict[str, Any]) -> Dict[str, Any]:
    """更新保留天数（只改传入项）。**禁硬限制参数**：无天数上限，仅 days>=1 防即删脚手枪（非法/过小的按 floor 兜底，不设 MAX）。"""
    to_set: Dict[str, int] = {}
    for key, days in (updates or {}).items():
        if key not in RETENTION_DEFS:
            continue
        try:
            days = int(days)
        except (TypeError, ValueError):
            continue
        if days < _RETENTION_MIN_DAYS:      # 防 0/负数即删；不设上限
            days = _RETENTION_MIN_DAYS
        d = RETENTION_DEFS[key]
        _apply_ttl(d["coll"], d["ttl_field"], days)
        to_set[key] = days
    if to_set:
        try:
            get_repo().collection(Collections.LOG_RETENTION).update_one(
                {"name": "default"}, {"$set": to_set}, upsert=True)
        except Exception as exc:
            return {"error": str(exc)}
    return get_retention()


def apply_all_retention() -> None:
    """启动时按已存配置应用各 TTL（让 collMod 覆盖默认）。orchestration/部署调，异常吞掉。"""
    try:
        doc = get_repo().collection(Collections.LOG_RETENTION).find_one({"name": "default"}) or {}
        for key, d in RETENTION_DEFS.items():
            _apply_ttl(d["coll"], d["ttl_field"], int(doc.get(key, d["default_days"])))
    except Exception:
        pass


# ========== ③ 资源监控（resource_history，dash 读）==========

def get_memory_percent() -> Optional[float]:
    """当前内存使用率。实时读取失败时尝试最近采样；仍不可用返回 None（按 normal 处理）。"""
    try:
        import psutil
        return float(psutil.virtual_memory().percent)
    except Exception:
        try:
            row = get_repo().collection(RESOURCE_HISTORY).find_one({}, sort=[("ts", -1)])
            return float(row.get("memory")) if row and row.get("memory") is not None else None
        except Exception:
            return None


def _resource_int(key: str, default: int) -> int:
    try:
        value = get_config().section("RESOURCE", key, default=default)
        return int(default if value is None else value)
    except (TypeError, ValueError):
        return default


def _resource_float(key: str, default: float) -> float:
    try:
        value = get_config().section("RESOURCE", key, default=default)
        return float(default if value is None else value)
    except (TypeError, ValueError):
        return default


def get_resource_level() -> str:
    """资源水位 relaxed/normal/tight/critical。不可观测时保守降级 normal，不误判 relaxed。"""
    mem = get_memory_percent()
    if mem is None:
        return "normal"
    low = _resource_int("MEMORY_LOW", _TH_LOW)
    high = _resource_int("MEMORY_HIGH", _TH_HIGH)
    critical = _resource_int("MEMORY_CRITICAL", _TH_CRIT)
    if mem >= critical:
        return "critical"
    if mem >= high:
        return "tight"
    if mem < low:
        return "relaxed"
    return "normal"


def get_resource_budget() -> Dict[str, Any]:
    """返回当前水位预算。配置只调并发宽度/在途槽位，不截断任务或目标总数。
    task_slots（2026-08 改）：默认按「可用内存 × 水位系数」资源感知算（_recommend_task_slots，废写死档位魔数）；
    若显式配了 `<LEVEL>_TASK_SLOTS` 则优先用配置值（用户想固定就固定）；psutil 不可用回退旧档位默认值。"""
    level = get_resource_level()
    defaults = _DEFAULT_BUDGETS[level]
    prefix = level.upper()
    # task_slots：config 显式值优先 → 否则资源感知计算 → 都没有则旧档位默认
    cfg_slots = get_config().section("RESOURCE", prefix + "_TASK_SLOTS", default=None) if _has_config() else None
    if cfg_slots is not None:
        try:
            task_slots = max(0, int(cfg_slots))
        except (TypeError, ValueError):
            task_slots = defaults["task_slots"]
    else:
        rec = _recommend_task_slots(level)
        task_slots = rec if rec is not None else defaults["task_slots"]
    return {
        "level": level,
        "task_slots": task_slots,
        "io_concurrency": max(1, _resource_int(prefix + "_IO_CONCURRENCY", defaults["io_concurrency"])),
        "scan_parallelism": max(1, _resource_int(prefix + "_SCAN_PARALLELISM", defaults["scan_parallelism"])),
    }


def _has_config() -> bool:
    """get_config 是否可用（避免无 config 环境下探 config 抛异常）。"""
    try:
        get_config()
        return True
    except Exception:
        return False


def sample_resource() -> Dict[str, Any]:
    """采样 CPU/内存/磁盘写入 resource_history（scheduler 周期调；dash 读）。返回本次样本。异常降级不抛。"""
    try:
        import psutil
        import time
        sample = {"ts": int(time.time()), "cpu": psutil.cpu_percent(interval=0),
                  "memory": psutil.virtual_memory().percent, "disk": psutil.disk_usage("/").percent}
        get_repo().collection(RESOURCE_HISTORY).insert_one(dict(sample))
        return sample
    except Exception as exc:
        logger.debug("sample_resource degraded: %s", exc)
        return {}


def query_resource_history(days: int = 1) -> List[Dict[str, Any]]:
    """最近 N 天资源采样（按天数降采样控制点数，**不限制 days 上限**——降采样是分辨率非数据截断，覆盖全时段）。"""
    import time
    try:
        days = max(1, int(days))
    except (TypeError, ValueError):
        days = 1
    since = int(time.time()) - days * 86400
    # 降采样步长（分钟）：天数越大步长越大，点数受控但覆盖全程
    step = 1 if days <= 1 else (5 if days <= 7 else (30 if days <= 30 else (120 if days <= 180 else 240)))
    try:
        cur = get_repo().collection(RESOURCE_HISTORY).find({"ts": {"$gte": since}}).sort("ts", 1)
    except Exception:
        return []
    points, last_ts = [], 0
    for d in cur:
        ts = d.get("ts", 0)
        if ts - last_ts >= step * 60:
            points.append({"ts": ts, "cpu": round(d.get("cpu", 0), 1),
                           "memory": round(d.get("memory", 0), 1), "disk": round(d.get("disk", 0), 1)})
            last_ts = ts
    return points


def ensure_resource_history_index(retention_days: int = 400) -> bool:
    """建 resource_history 的 ts 索引 + TTL（默认留 400 天）。部署/orchestration 调。失败吞掉。"""
    try:
        coll = get_repo().collection(RESOURCE_HISTORY)
        names = [i.get("name") for i in coll.list_indexes()]
        if "ts_1" not in names:
            coll.create_index("ts")
        if "ts_ttl" not in names:
            coll.create_index("ts", name="ts_ttl", expireAfterSeconds=int(retention_days) * 86400)
        return True
    except Exception:
        return False


# ========== 服务门面 ==========

class LogServiceImpl:
    """日志监测服务。注册字符串键 "log_service"。"""
    def list_logs(self, **kw: Any) -> Dict[str, Any]:
        return list_logs(**kw)

    def stat_logs(self) -> Dict[str, int]:
        return stat_logs()

    def delete_logs(self, ids: List[str]) -> Dict[str, Any]:
        return delete_logs(ids)

    def clear_logs(self) -> Dict[str, Any]:
        return clear_logs()

    def get_retention(self) -> Dict[str, Any]:
        return get_retention()

    def set_retention(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        return set_retention(updates)

    def get_resource_level(self) -> str:
        return get_resource_level()

    def get_resource_budget(self) -> Dict[str, Any]:
        return get_resource_budget()

    def sample_resource(self) -> Dict[str, Any]:
        return sample_resource()

    def query_resource_history(self, days: int = 1) -> List[Dict[str, Any]]:
        return query_resource_history(days)


_service = LogServiceImpl()


def get_service() -> LogServiceImpl:
    return _service


