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

# 瞭望塔平台进程启动时间戳（模块首次 import≈进程启动，用于"瞭望塔系统运行时间"而非操作系统 uptime）。
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
        memory_total_gb, memory_used_gb, cpu_count, uptime_seconds(瞭望塔进程), os_uptime_seconds,
        exit_ip, proxy_ok}`。字段扁平——旧代码曾因嵌套 cpu.percent 前端读扁平永远 0（踩坑）。
        uptime_seconds=瞭望塔平台运行时间（进程启动至今），非操作系统 uptime（用户要求）。
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
        # 瞭望塔进程运行时间已在 info 初始化时算好（_PROC_START）；OS uptime 单列 os_uptime_seconds 供参考
        try:
            info["os_uptime_seconds"] = int(time.time() - ps.boot_time())
        except Exception:
            pass
        # 资源分数 + 运行可靠性（像网络质量一样实时评估：当前资源是否适合系统运行）
        info["resource"] = self._resource_score(info)
        return info

    def _resource_score(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """资源健康评分 + 运行可靠性研判 —— **需求导向**（评"当前空闲资源够不够跑平台实际工作负载"，
        不是抽象"用了百分之几"）。分数越高=越能随时接活；空闲=健康不扣分，快见底才扣。

        三维各回答一个"够不够"的问题，档位与**真实并发调度逻辑同源**（不再仪表盘一套、调度另一套）：
        - **内存**（最关键，真实并发闸）：不看用量%，看 **get_resource_budget().task_slots =「当前可用内存
          还能起几个并发任务」**（调度器真实准入口径，按 可用内存/每任务预算×水位系数 算）。0 个=起不了
          新任务=告急，这才是"收缩并发保命"该出现的地方。
        - **CPU**（吞吐非硬闸，I/O 密集平台 CPU 少是瓶颈）：看 **loadavg1/核数**（真实排队压力），
          不看瞬时 cpu%（抖动且不代表能否接活）。缺 loadavg（非 Linux）回退瞬时 cpu%。
        - **磁盘**（产出写入底线）：以**绝对剩余 GB 为主**、用量% 为辅，取更差者。平台一直写扫描结果/
          截图/报告/mongo/镜像/日志，一次大扫描产出可达 1~2GB——"剩 5.9GB"是真风险，同样 77% 在 500GB
          盘上却没事，故绝对余量比百分比更务实（阈值可配 DISK_FREE_*_GB）。
        headline 取三维**短板**（木桶效应，弱项决定可靠性）；verdict 按短板是谁+性质给可操作建议。
        """
        cpu_pct = float(info.get("cpu_percent", 0) or 0)
        disk_pct = float(info.get("disk_percent", 0) or 0)
        disk_free_gb = float((info.get("disk_usage", {}) or {}).get("free", 0) or 0) / (1024.0 ** 3)
        cores = int(info.get("cpu_count", 0) or 0) or 1

        def _cfg_num(key, default, cast=float):
            try:
                from sentinel_platform.core import get_config
                v = get_config().section("RESOURCE", key, default=None)
                return cast(v) if v is not None else default
            except Exception:
                return default

        # 档位分锚点：充裕92 / 良好70 / 偏紧45 / 告急18（档内线性平滑，读数连续不跳变）
        def _grade(value, excellent_at, good_at, tight_at, crit_at, higher_is_better=True):
            """把一个"容量指标"映射成 0-100 分。higher_is_better=True 时 value 越大越健康
            （如 task_slots、剩余GB）；False 时越小越健康（如 load/核数、用量%）。四个锚点按方向排序。"""
            pts = [(excellent_at, 92), (good_at, 70), (tight_at, 45), (crit_at, 18)]
            if higher_is_better:
                if value >= excellent_at:
                    return min(100, int(round(92 + (value - excellent_at) / max(excellent_at, 1) * 8)))
                for i in range(len(pts) - 1):
                    hi_v, hi_s = pts[i]; lo_v, lo_s = pts[i + 1]
                    if value >= lo_v:
                        frac = (value - lo_v) / max(hi_v - lo_v, 1e-6)
                        return int(round(lo_s + (hi_s - lo_s) * max(0.0, min(1.0, frac))))
                return max(3, int(round(18 * value / max(crit_at, 1e-6))))
            else:
                if value <= excellent_at:
                    return min(100, int(round(92 + (excellent_at - value) / max(excellent_at, 1) * 8)))
                for i in range(len(pts) - 1):
                    hi_v, hi_s = pts[i]; lo_v, lo_s = pts[i + 1]
                    if value <= lo_v:
                        frac = (lo_v - value) / max(lo_v - hi_v, 1e-6)
                        return int(round(lo_s + (hi_s - lo_s) * max(0.0, min(1.0, frac))))
                return max(3, int(round(18 * crit_at / max(value, 1e-6))))

        # —— 内存维：真实并发容量（能起几个任务）——
        task_slots = None
        try:
            from sentinel_platform.contracts import get_registry
            svc = get_registry().get("log_service")
            if svc and hasattr(svc, "get_resource_budget"):
                task_slots = int((svc.get_resource_budget() or {}).get("task_slots"))
        except Exception:
            task_slots = None
        if task_slots is None:
            # 降级：按可用内存/每任务预算粗算（psutil 缺失再退回内存%档）
            try:
                import psutil
                avail_gb = (psutil.virtual_memory().available + getattr(psutil.swap_memory(), "free", 0)) / (1024.0 ** 3)
                per = _cfg_num("TASK_MEM_GB", 1.5)
                task_slots = int(avail_gb / max(0.25, per))
            except Exception:
                task_slots = None
        if task_slots is not None:
            # slots≥3 充裕 / 2 良好 / 1 偏紧 / 0 告急（对齐 _DEFAULT_BUDGETS：relaxed5 normal3 tight1 critical0）
            mem_s = _grade(task_slots, 3, 2, 1, 0, higher_is_better=True)
        else:
            mem_pct = float(info.get("memory_percent", 0) or 0)
            mem_s = _grade(mem_pct, _cfg_num("MEMORY_LOW", 60), _cfg_num("MEMORY_HIGH", 80),
                           (_cfg_num("MEMORY_HIGH", 80) + _cfg_num("MEMORY_CRITICAL", 90)) / 2,
                           _cfg_num("MEMORY_CRITICAL", 90), higher_is_better=False)

        # —— CPU 维：loadavg/核数（真实排队压力）——
        load1 = None
        try:
            import os as _os
            if hasattr(_os, "getloadavg"):
                load1 = _os.getloadavg()[0]
        except Exception:
            load1 = None
        if load1 is not None:
            load_ratio = load1 / max(1, cores)
            cpu_s = _grade(load_ratio, 0.7, 1.0, 2.0, 3.0, higher_is_better=False)
        else:
            cpu_s = _grade(cpu_pct, 60, 85, 90, 95, higher_is_better=False)

        # —— 磁盘维：绝对剩余 GB 为主 + 用量% 为辅，取更差 ——
        free_excellent = _cfg_num("DISK_FREE_EXCELLENT_GB", 20.0)
        free_good = _cfg_num("DISK_FREE_GOOD_GB", 8.0)
        free_tight = _cfg_num("DISK_FREE_TIGHT_GB", 3.0)
        free_crit = _cfg_num("DISK_FREE_CRIT_GB", 1.5)
        disk_gb_s = _grade(disk_free_gb, free_excellent, free_good, free_tight, free_crit, higher_is_better=True)
        disk_pct_s = _grade(disk_pct, 60, 85, 90, 95, higher_is_better=False)
        disk_s = min(disk_gb_s, disk_pct_s)   # 取更差：绝对空间和百分比谁更告急听谁的

        dims = {"cpu": cpu_s, "memory": mem_s, "disk": disk_s}

        # ===== 三维加权融合 + 物理见底硬闸（v1.21.157-50 重构）=====
        # 治两个真 bug（VM 实证 idle 机磁盘 5.7GB/78% 却恒 99「充裕」）：
        #  ① 旧「水位档定 [lo,hi] 区间 + cap_short 线性落位」两层模型自我打架——relaxed 档地板 85
        #     把量程压成 [85,100]，CPU/内存怎么动分数都钉在 99~100（"不实时动态"的根因）；
        #  ② 磁盘被踢出总分（治恒76 的过度矫正）→ 算出磁盘维=58、disk_note 报"偏紧"，总分却无视 → headline 自相矛盾。
        # 新模型：总分 = 三维加权(连续 0-100，任一维变化实时体现) 与 最弱维分 融合(弱项拖低总分、
        # 不被均值稀释成"充裕")；再叠加物理"见底硬闸"守告急红线——磁盘绝对见底会写失败、内存 0 slots
        # 停投，这类硬风险加权表达不了，必须封顶（守禁删信号维铁律，不重演恒22/恒76）。
        W_CPU, W_MEM, W_DISK = 0.35, 0.35, 0.30
        weighted = W_CPU * cpu_s + W_MEM * mem_s + W_DISK * disk_s
        raw = 0.6 * weighted + 0.4 * float(min(cpu_s, mem_s, disk_s))   # 加权主体 + 最弱维拖低

        # 取真实水位档（仅用于 critical 停投硬闸 + 展示 wl_level，不再定分数区间）
        wl = ""
        try:
            from sentinel_platform.contracts import get_registry
            svc = get_registry().get("log_service")
            if svc and hasattr(svc, "get_resource_level"):
                wl = str(svc.get_resource_level() or "")
        except Exception:
            wl = ""
        wl = wl if wl in ("relaxed", "normal", "tight", "critical") else "normal"

        # 物理见底硬闸（只封顶不抬升；用绝对量而非维分，与回归 GB 阈值对齐）：
        cap = 100
        if disk_free_gb < free_crit or disk_pct >= 95:        # 磁盘绝对见底 → 告急封顶
            cap = 39
        elif disk_free_gb < free_tight or disk_pct >= 90:     # 磁盘偏紧 → 偏紧封顶
            cap = 64
        if task_slots == 0 or wl == "critical":               # 内存 0 slots 停投 / 综合 critical → 告急
            cap = min(cap, 39)
        score = max(3, min(100, int(round(min(raw, cap)))))

        # 档映射（前端 rv- 样式类保留 excellent/good/tight/critical）
        if score >= 85:
            rel_level, rel_text = "excellent", "资源充裕"
        elif score >= 65:
            rel_level, rel_text = "good", "运行良好"
        elif score >= 40:
            rel_level, rel_text = "tight", "资源偏紧"
        else:
            rel_level, rel_text = "critical", "资源告急"

        # 短板 = 三维最弱者（verdict 据此给可操作建议）
        weakest = "cpu" if (cpu_s <= mem_s and cpu_s <= disk_s) else ("memory" if mem_s <= disk_s else "disk")
        # critical 成因优先判"停投/写失败"物理红线（回归：wl critical/0 slots 必含"收缩并发保命"）
        mem_stall = (task_slots == 0 or wl == "critical")
        disk_bottom = (disk_free_gb < free_crit or disk_pct >= 95)

        # verdict：物理红线（停投/写失败）优先表达，其次按短板给可操作建议。
        # "收缩并发保命" 严格绑 mem_stall（0 slots / 综合 critical=真停投），不滥用。
        _slot_txt = "（当前可起 {} 个并发任务）".format(task_slots) if task_slots is not None else ""
        if mem_stall:
            verdict = "内存告急，已无法启动新任务（可起 {} 个），系统已收缩并发保命，建议扩容或减负".format(
                task_slots if task_slots is not None else 0)
        elif disk_bottom:
            verdict = "磁盘仅剩 {:.1f}GB（{:.0f}%），请立即清理，否则扫描产出/报告/数据库可能写入失败".format(disk_free_gb, disk_pct)
        elif rel_level == "excellent":
            verdict = "资源充足，系统可高并发稳定运行" + _slot_txt
        elif rel_level == "good":
            verdict = "资源良好，适合系统正常运行" + _slot_txt
        elif weakest == "disk":
            verdict = "磁盘剩余 {:.1f}GB（{:.0f}%）偏紧，建议清理旧镜像/日志/扫描产物".format(disk_free_gb, disk_pct)
        elif weakest == "memory":
            verdict = "可用内存偏紧，当前仅够起 {} 个并发任务，系统已降低并发保稳定".format(
                task_slots if task_slots is not None else "少量")
        else:  # cpu
            _lr = "（负载 {:.1f}×核数）".format(load1 / max(1, cores)) if load1 is not None else ""
            verdict = "CPU 负载偏高{}，任务响应可能变慢".format(_lr)

        # 磁盘单列提示（无论是否短板，偏紧都提醒，便于运维）——按绝对余量
        if disk_free_gb < free_tight or disk_pct >= 95:
            disk_note = "磁盘仅剩 {:.1f}GB（{:.0f}%），请尽快清理释放空间".format(disk_free_gb, disk_pct)
        elif disk_free_gb < free_good or disk_pct >= 85:
            disk_note = "磁盘剩余 {:.1f}GB（{:.0f}%）偏紧，建议清理旧镜像/日志/临时产物".format(disk_free_gb, disk_pct)
        else:
            disk_note = ""

        return {
            "score": score,
            "level": rel_level,
            "level_text": rel_text,
            "verdict": verdict,
            "dims": dims,
            "task_slots": task_slots,       # 当前可起并发任务数（内存维依据）
            "disk_free_gb": round(disk_free_gb, 1),
            "disk_note": disk_note,
            "wl_level": wl,                 # 真实水位档（评分档位的骨架，与并发调度同源）
        }

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

    def resource_alert(self) -> Dict[str, Any]:
        """当前资源水位明细（供前端弹窗轮询）。判定逻辑在 system/log_monitor（单一事实源），
        经 registry 取 log_service 调用——不 import 叶子内部，守解耦。服务缺失/psutil 不可用降级
        {level:'normal', dims:[]}（前端据此不弹窗）。"""
        try:
            from sentinel_platform.contracts import get_registry
            svc = get_registry().get("log_service")
            if svc and hasattr(svc, "get_resource_alert"):
                return svc.get_resource_alert() or {}
        except Exception as exc:
            logger.debug("dashboard: resource_alert degraded: %s", exc)
        return {"level": "normal", "dims": []}


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = DashboardServiceImpl()


def get_service() -> DashboardServiceImpl:
    return _service
