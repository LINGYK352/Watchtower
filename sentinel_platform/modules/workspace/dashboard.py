"""workspace/dashboard —— 态势总览（工作台落地页后端能力）。

前端 Dashboard.vue 的**设备监控**部分（CPU/内存/磁盘卡片 + 资源趋势图）由本叶子供数：
  - device_info()：实时 psutil 快照（扁平字段，对齐前端 `api/console.ts` ConsoleInfo）。
  - resource_history(days)：**只读** `resource_history` 集合（采样/写入方是 system/log_monitor，
    本叶子不写——数据契约非 import），按天数降采样返回趋势点。

**职责边界**（不做代理，守高内聚）：漏洞/会话/token/代理出口等 stat 由前端各自直接调
  FINDING/PENTEST_DISPATCH/aiConfig/PROXY 各模块接口，dashboard 后端**不聚合转发**（避免变成
  什么都依赖的胖节点，也避免与各叶子的 stat 口径漂移）。本叶子只负责本机设备监控。

无 ROLE（纯查询叶子）：经 registry 以字符串键 `"dashboard_service"` 注册（照 gateway
  user_service/api_keys_service 先例），router `endpoints/workspace.py` 取用。不放 HTTP 路由。
psutil 惰性 import（对齐 core 惰性依赖范式）：缺失/取失败降级默认值，不崩。
迁移来源：app/routes/console.py + app/utils/device.py + app/services/resource_monitor.query_resource_history。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

# 哨兵平台进程启动时间戳（模块首次 import≈进程启动，用于"哨兵系统运行时间"而非操作系统 uptime）。
_PROC_START = time.time()

# 直连出口 IP 进程内缓存（态势总览设备卡提速：出口 IP 秒级不变，不必每次实探外网 4~6s）。
# 非阻塞模型：device_info 立即读 ip（含空），probing 标记防并发重复探测，后台线程刷新。
# ts>0 且 TTL 内视为新鲜（成功/失败都记时间戳，失败也不频繁重探）。
_DIRECT_IP_CACHE = {"ts": 0.0, "ip": "", "probing": False}
_DIRECT_IP_TTL = 120


def _psutil():
    """惰性取 psutil；未安装/导入失败返回 None（调用方降级）。"""
    try:
        import psutil
        return psutil
    except Exception:
        return None


class DashboardServiceImpl:
    """态势总览设备监控能力（无 ROLE，字符串键注册）。"""

    def device_info(self) -> Dict[str, Any]:
        """实时设备信息（扁平字段，对齐前端 ConsoleInfo.device_info）。psutil 缺失降级 0/空。

        返回 `{cpu_percent, memory_percent, disk_percent, disk_usage{}, memory_total, memory_used,
        memory_total_gb, memory_used_gb, cpu_count, uptime_seconds(哨兵进程), os_uptime_seconds,
        exit_ip, proxy_ok}`。字段扁平——旧代码曾因嵌套 cpu.percent 前端读扁平永远 0（踩坑）。
        uptime_seconds=哨兵平台运行时间（进程启动至今），非操作系统 uptime（用户要求）。
        """
        ps = _psutil()
        info: Dict[str, Any] = {
            "cpu_percent": 0.0, "memory_percent": 0.0, "disk_percent": 0.0,
            "disk_usage": {}, "memory_total": 0, "memory_used": 0,
            "memory_total_gb": 0.0, "memory_used_gb": 0.0,
            "cpu_count": 0, "uptime_seconds": int(time.time() - _PROC_START),
            "os_uptime_seconds": 0, "psutil": bool(ps),
        }
        # 出口 IP（代理正常显代理出口；异常/未启用显实际直连出口）——用户要求代理异常时显真实出口
        info.update(self._exit_ip_info())
        if not ps:
            return info
        try:
            cnt = ps.cpu_count() or 0
            info["cpu_count"] = cnt
            # CPU 稳健采样：单次 0.3s 瞬时窗口对整机太短、读数在 0~1% 抖动不代表真实负载。
            # 用 0.6s 采样 + 结合 1 分钟 loadavg 派生的利用率取较能反映负载者（loadavg/核数×100，
            # 封顶 100）。loadavg 仅 Linux 有；缺失则退回瞬时采样值。
            inst = ps.cpu_percent(interval=0.6)
            load1 = 0.0
            try:
                import os as _os
                if hasattr(_os, "getloadavg") and cnt:
                    load1 = round(min(_os.getloadavg()[0] / cnt * 100.0, 100.0), 1)
                    info["load_avg"] = round(_os.getloadavg()[0], 2)
            except Exception:
                pass
            # 取瞬时与 loadavg 派生的较大者作展示值（避免瞬时窗口恰好落在空闲期显示 0）
            info["cpu_percent"] = round(max(inst, load1), 1)
            info["cpu_percent_inst"] = round(inst, 1)
        except Exception as exc:
            logger.debug("dashboard: cpu read failed: %s", exc)
        try:
            vm = ps.virtual_memory()
            info["memory_percent"] = vm.percent
            info["memory_total"] = getattr(vm, "total", 0)
            info["memory_used"] = getattr(vm, "used", 0)
            _g = 1024.0 ** 3
            info["memory_total_gb"] = round(info["memory_total"] / _g, 1)
            info["memory_used_gb"] = round(info["memory_used"] / _g, 1)
        except Exception as exc:
            logger.debug("dashboard: mem read failed: %s", exc)
        try:
            disk = ps.disk_usage("/")
            info["disk_percent"] = disk.percent
            info["disk_usage"] = {"total": disk.total, "used": disk.used,
                                  "free": disk.free, "percent": disk.percent}
        except Exception as exc:
            logger.debug("dashboard: disk read failed: %s", exc)
        # 哨兵进程运行时间已在 info 初始化时算好（_PROC_START）；OS uptime 单列 os_uptime_seconds 供参考
        try:
            info["os_uptime_seconds"] = int(time.time() - ps.boot_time())
        except Exception:
            pass
        return info

    def _exit_ip_info(self) -> Dict[str, Any]:
        """出口 IP：代理启用且健康→代理出口；否则（未启用/代理异常）→ 实际直连出口 IP。
        经 registry 取 PROXY.status（缺失/异常降级空），不硬依赖代理叶子。"""
        out = {"exit_ip": "", "proxy_ok": False, "proxy_enabled": False}
        try:
            from sentinel_platform.contracts import get_registry, ROLE
            svc = get_registry().get(ROLE.PROXY)
            st = svc.status() if (svc and hasattr(svc, "status")) else {}
            if isinstance(st, dict):
                out["proxy_enabled"] = bool(st.get("enabled"))
                out["proxy_ok"] = bool(st.get("last_health_ok"))
                # 代理启用且健康 → 用代理出口 IP；否则回落直连出口
                if out["proxy_enabled"] and out["proxy_ok"] and st.get("last_exit_ip"):
                    out["exit_ip"] = st.get("last_exit_ip", "")
        except Exception as exc:
            logger.debug("dashboard: proxy status degraded: %s", exc)
        # 代理未启用或异常 → 探真实直连出口 IP（用户要求代理异常显实际出口）
        if not out["exit_ip"]:
            out["exit_ip"] = self._direct_exit_ip()
        return out

    def _direct_exit_ip(self) -> str:
        """直连出口 IP（不走代理）。**非阻塞：永远立即返回缓存值（含空），探测在后台线程刷新**。

        根治「态势总览设备卡加载 6s」——无外网环境探出口 IP 每次白等满超时会拖垮整个 device_info
        （CPU/内存/磁盘本是本地瞬时可得）。故此处不再同步等探测：
        - 缓存新鲜（TTL 内，无论成功/失败）→ 直接返回，不触发探测；
        - 缓存陈旧/首次 → **立即返回当前缓存值（可能空），并在后台线程发起探测**更新缓存；
        - 后台探测单次 3s、最多两端点，成功/失败都写缓存时间戳（失败也缓存空，避免每次重探）。
        代价：首次或出口变化后的一次展示可能短暂为空，下次轮询即补上——换设备卡永不卡顿。"""
        now = time.time()
        fresh = (now - _DIRECT_IP_CACHE["ts"]) < _DIRECT_IP_TTL and _DIRECT_IP_CACHE["ts"] > 0
        if not fresh and not _DIRECT_IP_CACHE.get("probing"):
            _DIRECT_IP_CACHE["probing"] = True
            self._spawn_exit_ip_probe()
        return _DIRECT_IP_CACHE["ip"]

    @staticmethod
    def _spawn_exit_ip_probe() -> None:
        """后台线程探直连出口 IP，写入缓存（成功/失败都更新时间戳，失败缓存空）。守护线程不阻塞请求。"""
        import threading

        def _worker():
            ip = ""
            try:
                import urllib.request
                for url in ("https://api.ipify.org", "http://ifconfig.me/ip"):
                    try:
                        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                        with urllib.request.urlopen(req, timeout=3) as r:
                            v = (r.read().decode("utf-8", "ignore") or "").strip()
                            if v:
                                ip = v
                                break
                    except Exception:
                        continue
            finally:
                _DIRECT_IP_CACHE["ip"] = ip            # 成功=IP；失败=空（下次 TTL 后再探）
                _DIRECT_IP_CACHE["ts"] = time.time()
                _DIRECT_IP_CACHE["probing"] = False

        try:
            threading.Thread(target=_worker, daemon=True).start()
        except Exception:
            _DIRECT_IP_CACHE["probing"] = False

    def resource_history(self, days: int = 1) -> Dict[str, Any]:
        """资源采样趋势（只读 resource_history 集合，按天数降采样）。返回 {days, points[], count}。

        降采样步长：≤1天全量 / ≤7天每5分钟 / ≤30天每30分钟 / ≤180天每2小时 / 更久每4小时。
        集合空/库不可用降级 points=[]（不崩）。写入方是 system/log_monitor 采样器。
        """
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 1
        days = max(1, min(days, 360))
        step_min = 1 if days <= 1 else 5 if days <= 7 else 30 if days <= 30 else 120 if days <= 180 else 240
        since = int(time.time()) - days * 86400
        points: List[Dict[str, Any]] = []
        try:
            coll = get_repo().collection(Collections.RESOURCE_HISTORY)
            cursor = coll.find({"ts": {"$gte": since}}).sort("ts", 1)
            last_ts = 0
            for doc in cursor:
                ts = doc.get("ts", 0)
                if ts - last_ts >= step_min * 60:
                    points.append({
                        "ts": ts,
                        "cpu": round(doc.get("cpu", 0), 1),
                        "memory": round(doc.get("memory", 0), 1),
                        "disk": round(doc.get("disk", 0), 1),
                    })
                    last_ts = ts
        except Exception as exc:
            logger.debug("dashboard: resource_history query failed: %s", exc)
        return {"days": days, "points": points, "count": len(points)}


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = DashboardServiceImpl()


def get_service() -> DashboardServiceImpl:
    return _service
