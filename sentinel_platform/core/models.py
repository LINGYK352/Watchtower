"""平台领域枚举与轻量类型（替代 app.modules 的枚举契约，净室重写）。

值与旧内核一致（字符串常量），保证与既有 Mongo 数据/调度器/引擎的状态判断兼容。
数据「记录模型」（domain/ip/site 等结构）属于 sentinel_engine 的产出契约，平台按需从
Mongo 读原始 dict 即可，不在此重复定义领域记录类。
"""
from __future__ import annotations


class TaskStatus:
    WAITING = "waiting"
    DONE = "done"
    ERROR = "error"
    STOP = "stop"
    PROXY_PAUSED = "proxy_paused"
    PREEMPTED = "preempted"


class TaskPriority:
    T0 = 0
    T1 = 1
    T2 = 2
    DEFAULT = 2
    ALL = (0, 1, 2)

    @staticmethod
    def normalize(v):
        try:
            iv = int(v)
        except (TypeError, ValueError):
            return TaskPriority.DEFAULT
        return iv if iv in TaskPriority.ALL else TaskPriority.DEFAULT


class TaskType:
    IP = "ip"
    DOMAIN = "domain"
    RISK_CRUISING = "risk_cruising"
    ASSET_SITE_UPDATE = "asset_site_update"
    FOFA = "fofa"
    ASSET_SITE_ADD = "asset_site_add"
    ASSET_WIH_UPDATE = "asset_wih_update"


class TaskTag:
    TASK = "task"
    MONITOR = "monitor"
    RISK_CRUISING = "risk_cruising"


class CollectSource:
    DOMAIN_BRUTE = "domain_brute"
    BAIDU = "baidu"
    ALTDNS = "alt_dns"
    ARL = "arl"          # 兼容既有数据的历史来源值（数据字段值，非代码依赖）
    SITESPIDER = "site_spider"
    SEARCHENGINE = "search_engine"
    MONITOR = "monitor"
    FOFA = "fofa"
    WIH = "wih"


class TaskSyncStatus:
    WAITING = "waiting"
    RUNNING = "running"
    ERROR = "error"
    DEFAULT = "default"


class TaskScheduleStatus:
    DONE = "done"
    SCHEDULED = "scheduled"
    STOP = "stop"
    ERROR = "error"


class SchedulerStatus:
    RUNNING = "running"
    STOP = "stop"


class SiteAutoTag:
    ENTRY = "入口"
    INVALID = "无效"
