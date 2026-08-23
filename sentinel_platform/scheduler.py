"""Scheduler 进程入口 —— 轮询把 WAITING 任务投递执行（补 task_create 降级留下的 WAITING）。

部署（Linux，与 worker 并列一个进程）：
    python -m sentinel_platform.scheduler

职责（对齐旧 scheduler 的核心 tick，框架无关）：
  - 每 tick 调 orchestration.run_waiting_tasks()：扫 status=waiting 的任务逐个 submit_task 投出去
    （web 端 task_create 派发降级时任务落 WAITING，celery 未装时也靠这里线程执行器推进；装了 celery
     则投 worker）。running 不重投（run_waiting_tasks 只捡 waiting）。
  - 计划任务（task_schedule/github_scheduler 周期任务）到点触发：读 next_run 到期的，置 WAITING 交上面投递。

装配：先 bootstrap.bootstrap() 装模块能力（scheduler 内经 orchestration 调 RECON 等）。
tick 间隔从 config `SCHEDULE.TICK_SECONDS` 读，默认 30s（禁硬编码：可配，非写死魔数）。
协作式：orchestration 侧已有 status 自检，本轮询只负责"捡 waiting 投递"，不做取消判定。
"""
from __future__ import annotations

import time

from sentinel_platform.core import get_config, get_logger

logger = get_logger()

# —— L2 资源水位连续 critical 计数（模块级，跨 tick 保持）——
_critical_streak = 0
_L2_THRESHOLD = 3  # 连续 N 个 tick critical 才触发 L2 暂停

# —— GitHub 执行防线程堆积（GitHub 限速 sleep 长，一轮没跑完不再起新线程）——
_github_running = False

# —— 代理出口健康检测节流（每 10 分钟一次，按时间戳判定，不受 tick 周期变化影响）——
_last_proxy_health = 0.0
_PROXY_HEALTH_INTERVAL = 600  # 秒；代理失效检测周期（用户要求每 10 分钟检测代理出口）
# —— 公共代理池定时验活（刷新 delay，让 pick_best 持续选最优，类内核自动选优）——
_last_pool_verify = 0.0
_POOL_VERIFY_INTERVAL = 900  # 秒；默认 15 分钟验活一次（免费代理存活短，需定期刷新；仅池非空时跑）


def _tick_seconds() -> int:
    try:
        return int(get_config().section("SCHEDULE", "TICK_SECONDS", default=30) or 30)
    except (TypeError, ValueError):
        return 30


def tick() -> dict:
    """单次调度 tick：投递 WAITING 任务 + 僵尸回收 + 到期计划任务 + 恢复渗透会话 + 漏洞情报 + 资源采样。"""
    from sentinel_platform.modules.kernel import orchestration
    result = {"waiting": {}, "due_schedules": 0, "sessions": {}, "stalled": 0, "vuln_feed": False}
    try:
        result["waiting"] = orchestration.run_waiting_tasks()   # 资源感知限速投递（非硬上限）
    except Exception as exc:
        logger.warning("scheduler tick run_waiting_tasks degraded: %s", exc)
    try:
        result["stalled"] = _reclaim_stalled_tasks()
    except Exception as exc:
        logger.debug("scheduler tick reclaim_stalled degraded: %s", exc)
    result["due_schedules"] = _promote_due_schedules()
    result["sessions"] = _tick_sessions()
    # GitHub 任务/监控执行（后台线程，不阻塞 tick——GitHub 限速 sleep 长）
    try:
        result["github"] = _tick_github()
    except Exception as exc:
        logger.debug("scheduler tick github degraded: %s", exc)
    # 资产监控执行（域名监控到期→建扫描任务；轻量 DB 操作，真正侦察由 orchestration 异步跑）
    try:
        result["monitors"] = _tick_monitors()
    except Exception as exc:
        logger.debug("scheduler tick monitors degraded: %s", exc)
    # 代理内核维护（自愈拉起 + 节点 failover + 流量采样；对齐旧 proxy_health_monitor）
    try:
        result["proxy"] = _tick_proxy()
    except Exception as exc:
        logger.debug("scheduler tick proxy degraded: %s", exc)
    # 漏洞情报定时拉取（按 interval 自判是否到期，tick 只管每轮检查）
    try:
        result["vuln_feed"] = _tick_vuln_feed()
    except Exception:
        pass
    # 网络质量体检（30 分钟一次，首次/无数据立即跑；后台线程不阻塞 tick）
    try:
        result["netcheck"] = _tick_netcheck()
    except Exception:
        pass
    # 资源采样（每 tick 写一次 resource_history，dashboard 读）
    try:
        from sentinel_platform.modules.system.log_monitor import sample_resource
        sample_resource()
    except Exception:
        pass
    # L2 资源水位检查：critical 连续 3tick → 暂停低优先级会话
    try:
        result["l2"] = _check_resource_l2()
    except Exception:
        pass
    return result


# 会话恢复参数（可配，非硬编码魔数；对齐旧平台 §13.5 tick_paused_sessions/promote_queued/watchdog）
def _sess_cfg(key: str, default: int) -> int:
    try:
        return int(get_config().section("PENTEST", key, default=default) or default)
    except (TypeError, ValueError):
        return default


def _task_stall_seconds() -> int:
    """任务僵尸判定阈值（秒）。可配 SCHEDULE.TASK_STALL_SECONDS，默认 7200（2h）。"""
    try:
        return int(get_config().section("SCHEDULE", "TASK_STALL_SECONDS", default=7200) or 7200)
    except (TypeError, ValueError):
        return 7200


_QUEUED_ORPHAN_SECONDS = 180   # queued 中间态超此秒数无进展 = 投递进程崩溃的孤儿，回滚 waiting 重投
_MAX_TASK_RECLAIM = 3          # running 僵尸重投续扫上限：超此次数仍僵死 = 真坏任务，标 error 防无限重投


def _reclaim_stalled_tasks() -> int:
    """回收孤儿任务，两类（治「状态永挂、占 in_flight 槽位、无人回收」）：
      ① running 僵尸：running 但 start_time/update_date 超 TASK_STALL_SECONDS 无变化 → 标 error 释放。
         无任何时间戳的 running（异常落库）也按孤儿处理（宽限后回收，防永挂）。
      ② queued 孤儿：_claim_task 切 queued 后投递进程在 delay/spawn 前崩溃 → 永停 queued
         （run_waiting_tasks 只捡 waiting、running 僵尸回收够不着它），且占 in_flight 槽位。
         queued_at 超 _QUEUED_ORPHAN_SECONDS → 回滚 waiting 让下轮重新投递（自愈）。
    不影响正常任务：正常 queued 秒级转 running；正常长任务由 handler 正确收尾 done/error。"""
    from sentinel_platform.core import get_repo
    import time as _t
    stall_sec = _task_stall_seconds()
    reclaimed = 0
    try:
        coll = get_repo().collection("task")
        now_epoch = _t.time()

        def _age(ts_str):
            if not ts_str or ts_str == "-":
                return None
            try:
                return now_epoch - _t.mktime(_t.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S"))
            except (ValueError, TypeError):
                return None

        # ① running 僵尸：心跳(update_date)超时 = worker 死/被重启打断。
        #    改为「回 waiting 重投续扫」而非直接标 error——recon 有断点续扫(_load_checkpoint 跳过已完成
        #    阶段)，重投不重扫、不丢已归集数据。热更新触发 gunicorn reload/worker 重启打断的扫描任务由此自愈。
        #    带 reclaim_count 上限：连续重投仍死(真坏任务，非临时中断)才标 error，防无限重投空转。
        for doc in coll.find({"status": "running"},
                             {"_id": 1, "start_time": 1, "update_date": 1, "reclaim_count": 1}):
            age = _age(doc.get("update_date") or doc.get("start_time") or "")
            if age is None:
                age = stall_sec + 1   # running 但无时间戳（异常落库）：宽限一周期后按孤儿处理
            if age > stall_sec:
                rc = int(doc.get("reclaim_count", 0) or 0)
                if rc >= _MAX_TASK_RECLAIM:
                    # 已重投 N 次仍僵死 → 真坏任务，标 error 释放槽位（不再无限重投）
                    coll.update_one({"_id": doc["_id"], "status": "running"}, {"$set": {
                        "status": "error",
                        "error": "任务超时回收：重投 {} 次仍僵死（running {}s 无心跳），判定无法完成".format(rc, int(age))
                    }})
                    logger.info("scheduler: task %s reclaimed %d times still stalled → error", doc["_id"], rc)
                else:
                    # 心跳超时 → 回 waiting，下轮 run_waiting_tasks 重投，recon 断点续扫接续
                    coll.update_one({"_id": doc["_id"], "status": "running"}, {"$set": {
                        "status": "waiting", "reclaim_count": rc + 1,
                        "dispatch_error": "worker 中断，第 {} 次重投续扫（running {}s 无心跳）".format(rc + 1, int(age))
                    }})
                    logger.info("scheduler: stalled running task %s → waiting (retry %d, age=%ds)", doc["_id"], rc + 1, int(age))
                reclaimed += 1

        # ② queued 孤儿：回滚 waiting 重投（原子条件 status=queued 防竞态覆盖已转 running 的）
        for doc in coll.find({"status": "queued"}, {"_id": 1, "queued_at": 1}):
            age = _age(doc.get("queued_at") or "")
            if age is None:
                age = _QUEUED_ORPHAN_SECONDS + 1   # 无 queued_at（旧版遗留）也按孤儿回滚
            if age > _QUEUED_ORPHAN_SECONDS:
                r = coll.update_one({"_id": doc["_id"], "status": "queued"}, {"$set": {
                    "status": "waiting",
                    "dispatch_error": "queued 孤儿回收（滞留 {}s，投递进程疑似崩溃，回滚重投）".format(int(age))
                }})
                if getattr(r, "modified_count", 0):
                    reclaimed += 1
                    logger.info("scheduler: reclaimed queued orphan task %s (age=%ds) → waiting", doc["_id"], int(age))
    except Exception as exc:
        logger.debug("reclaim_stalled_tasks degraded: %s", exc)
    return reclaimed


def _session_cap() -> int:
    """会话并发上限：经 ai_config_service.effective_concurrency（0/异常→默认 4，禁硬编码但给安全兜底）。"""
    try:
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("ai_config_service")
        if svc and hasattr(svc, "effective_concurrency"):
            v = int(svc.effective_concurrency() or 0)
            return v if v > 0 else 4
    except Exception:
        pass
    return 4


def _tick_sessions() -> dict:
    """恢复搁浅的 AI 渗透会话（全自动无人值守自愈，对齐旧平台 §13.5）：
      - queued：待接管 → 投执行（promote_queued）
      - paused_transient：LLM 瞬时错误暂停，retry_count < MAX 才重投（tick_paused_sessions，超上限降级 manual 防失效 key 无限撞）
      - running 但心跳(update_date)超 STALL 秒无更新：worker 死 → 重投（watchdog_stalled）
    非阻塞：经 orchestration.submit_session 投执行器（celery/线程）。禁硬限制：不砍会话数。"""
    from sentinel_platform.core import get_repo
    from sentinel_platform.modules.kernel import orchestration
    import time as _t
    max_retry = _sess_cfg("MAX_TRANSIENT_RETRY", 5)
    stall_sec = _sess_cfg("STALL_SECONDS", 900)   # 15min 无心跳判死
    out = {"queued": 0, "resumed": 0, "stalled": 0, "degraded": 0}
    try:
        coll = get_repo().collection("intel_pentest_session")
        now_epoch = _t.time()
        # ① 回收 running 心跳超时：只回到 queued，稍后与其他候选共享槽位
        for s in coll.find({"status": "running"}, {"_id": 1, "update_date": 1}):
            ud = s.get("update_date", "") or ""
            try:
                age = now_epoch - _t.mktime(_t.strptime(ud, "%Y-%m-%d %H:%M:%S"))
            except (ValueError, TypeError):
                age = 0
            if age > stall_sec:
                coll.update_one({"_id": s["_id"], "status": "running"}, {"$set": {"status": "queued"}})
                out["stalled"] += 1

        # ② running + dispatching 共同占用槽位；paused 和 queued 共享剩余槽位
        cap = _session_cap()
        occupied = coll.count_documents({"status": {"$in": ["running", "dispatching"]}})
        slots = max(0, cap - occupied)
        if slots <= 0:
            return out

        paused = list(coll.find({"status": "paused_transient"}, {"_id": 1, "retry_count": 1, "priority": 1}))
        candidates = []
        for s in paused:
            rc = int(s.get("retry_count", 0) or 0)
            if rc >= max_retry:
                coll.update_one({"_id": s["_id"], "status": "paused_transient"},
                                {"$set": {"status": "paused_manual"}})
                out["degraded"] += 1
            else:
                candidates.append((0, -int(s.get("priority", 0) or 0), s, "paused_transient"))
        for s in coll.find({"status": "queued"}, {"_id": 1, "priority": 1}):
            candidates.append((1, -int(s.get("priority", 0) or 0), s, "queued"))
        candidates.sort(key=lambda item: (item[0], item[1]))  # 恢复优先，同类高价值优先
        for _, _, s, source_status in candidates[:slots]:
            r = orchestration.submit_session(str(s["_id"]), from_status=source_status) or {}
            # 兼容测试/旧门面返回 None：生产新门面会明确 submitted=False 表示认领失败。
            if r and not r.get("submitted"):
                continue
            if source_status == "paused_transient":
                out["resumed"] += 1
            else:
                out["queued"] += 1
    except Exception as exc:
        logger.debug("tick_sessions degraded: %s", exc)
    return out


def _promote_due_schedules() -> int:
    """到期计划任务执行（补净室迁移丢失的执行闭环）：经 task_schedule_service.run_due 复用 task_create
    真建扫描任务 + 按 cron 推进 next_run（future_scan 跑一次转 stopped）。经 registry 取服务（缺失降级）。
    返回本轮真触发的计划数。此前只 run_number++ 不建任务（计划任务形同虚设，已修）。"""
    try:
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("task_schedule_service")
        if svc and hasattr(svc, "run_due"):
            r = svc.run_due() or {}
            return int(r.get("ran", 0) or 0)
    except Exception as exc:
        logger.debug("promote_due_schedules degraded: %s", exc)
    return 0


def _tick_vuln_feed() -> bool:
    """漏洞情报定时拉取：检查距上次拉取是否超过 interval（默认 6h），到期则触发。
    首次安装（从未拉取过）也会立即触发一次。返回是否执行了拉取。"""
    import time as _t
    try:
        from sentinel_platform.modules.risk_intel._feed import run_feed, get_feed_interval
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        meta = get_repo().collection(Collections.VULN_FEED_META).find_one({"name": "default"}) or {}
        last_fetch = meta.get("last_fetch") or ""
        interval = get_feed_interval()
        now = _t.time()
        # 解析 last_fetch 时间字符串为 epoch
        if last_fetch:
            try:
                last_ts = _t.mktime(_t.strptime(str(last_fetch), "%Y-%m-%d %H:%M:%S"))
            except (ValueError, TypeError):
                last_ts = 0
        else:
            last_ts = 0
        if now - last_ts < interval:
            return False
        # 到期或首次 → 后台线程拉取（不阻塞 scheduler tick）
        import threading
        threading.Thread(target=run_feed, daemon=True).start()
        logger.info("scheduler: vuln_feed triggered (last=%s, interval=%ss)", last_fetch or "never", interval)
        return True
    except Exception as exc:
        logger.debug("tick_vuln_feed degraded: %s", exc)
        return False


# 网络质量体检周期（默认 30 分钟；可配 SCHEDULE.NETCHECK_INTERVAL，非写死魔数）
_NETCHECK_INTERVAL_DEFAULT = 1800


def _netcheck_interval() -> int:
    try:
        return int(get_config().section("SCHEDULE", "NETCHECK_INTERVAL",
                                        default=_NETCHECK_INTERVAL_DEFAULT) or _NETCHECK_INTERVAL_DEFAULT)
    except Exception:
        return _NETCHECK_INTERVAL_DEFAULT


def _tick_netcheck() -> bool:
    """网络质量体检定时监测：距上次体检超过 interval（默认 30min）则跑；首次/无数据立即触发一次。
    后台线程跑（体检含多次 ping + HTTP 探测，耗时几十秒，绝不阻塞 scheduler tick）。返回是否触发。"""
    import time as _t
    try:
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import get_registry
        doc = get_repo().collection("netcheck_result").find_one({"name": "latest"}) or {}
        last_ts = float(doc.get("checked_ts") or 0)
        interval = _netcheck_interval()
        if _t.time() - last_ts < interval:
            return False
        svc = get_registry().get("network_check_service")
        if not (svc and hasattr(svc, "run_and_save_quality")):
            return False
        import threading
        threading.Thread(target=svc.run_and_save_quality, daemon=True).start()
        logger.info("scheduler: netcheck triggered (last=%s, interval=%ss)",
                    doc.get("checked_at") or "never", interval)
        return True
    except Exception as exc:
        logger.debug("tick_netcheck degraded: %s", exc)
        return False


def _tick_github() -> dict:
    """GitHub 任务/监控执行入口（补净室迁移丢失的执行闭环）：
      - github_task 一次性搜索任务：run_waiting 扫 waiting 逐个执行；
      - github_monitor 周期监控：run_due 扫到期 cron 任务执行。
    经 registry 取服务（缺失降级）。后台 daemon 线程跑（GitHub 严格限速，sleep 长，不阻塞 tick）；
    模块级 _github_running 防线程堆积（一轮没跑完不起新线程）。"""
    global _github_running
    if _github_running:
        return {"skipped": "prev_run_in_progress"}

    def _run():
        global _github_running
        _github_running = True
        try:
            from sentinel_platform.contracts import get_registry
            reg = get_registry()
            task_svc = reg.get("github_task_service")
            if task_svc and hasattr(task_svc, "run_waiting"):
                task_svc.run_waiting()
            mon_svc = reg.get("github_monitor_service")
            if mon_svc and hasattr(mon_svc, "run_due"):
                mon_svc.run_due()
        except Exception as exc:
            logger.debug("github tick run degraded: %s", exc)
        finally:
            _github_running = False

    import threading
    threading.Thread(target=_run, daemon=True).start()
    return {"dispatched": True}


def _tick_monitors() -> dict:
    """资产监控执行入口（补净室迁移丢失的执行闭环）：域名监控到期→经 monitor_service.run_due
    复用 task_create 建监控扫描任务。经 registry 取服务（缺失降级）。轻量（只扫 DB + 建任务，
    真正侦察由 orchestration 异步执行），直接跑不占后台线程。站点/WIH diff 引擎未移植（run_due 内诚实降级）。"""
    try:
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("monitor_service")
        if svc and hasattr(svc, "run_due"):
            return svc.run_due()
    except Exception as exc:
        logger.debug("tick_monitors degraded: %s", exc)
    return {}


def _tick_proxy() -> dict:
    """代理内核维护（补净室迁移丢失的 proxy_health_monitor）：内核自愈拉起(发布重启/崩溃后) +
    节点验活failover + 流量采样。经 registry 取 ROLE.PROXY.maintain（缺失降级）。仅代理启用时真动作。
    另每 10 分钟主动 check_health() 探一次真实出口——否则 last_health_ok 永不更新，代理失效仍显正常
    （用户实测：代理失效但状态一直正常，根因=从不定时检测出口）。"""
    global _last_proxy_health
    out = {}
    try:
        from sentinel_platform.contracts import get_registry, ROLE
        # 一次性自愈：旧 config(allow-lan=false)在容器模式下代理端口只监听 127.0.0.1→跨容器连不通。
        # 检测到即重生成 config + controller reload(不重启容器、代理不中断、不影响任务)。仅本进程首轮跑一次。
        _maybe_heal_mihomo_config()
        svc = get_registry().get(ROLE.PROXY)
        if svc and hasattr(svc, "maintain"):
            out = svc.maintain() or {}
        # 每 10 分钟主动探一次出口健康（写回 last_health_ok/error/exit_ip，前端据此显示正常/异常）
        now = time.time()
        if svc and hasattr(svc, "check_health") and (now - _last_proxy_health) >= _PROXY_HEALTH_INTERVAL:
            _last_proxy_health = now
            try:
                hr = svc.check_health()
                if isinstance(out, dict):
                    out["health"] = hr
            except Exception as exc:
                logger.debug("tick_proxy check_health degraded: %s", exc)
        # 公共代理池定时验活（刷新 delay→pick_best 持续选最优，类内核自动选优）。仅池非空时跑，
        # 后台线程（免费代理慢，并发验活也可能几十秒，绝不阻塞 tick）。
        _maybe_verify_pool(now)
    except Exception as exc:
        logger.debug("tick_proxy degraded: %s", exc)
    return out


def _maybe_verify_pool(now: float) -> None:
    """公共代理池到期验活（按 _POOL_VERIFY_INTERVAL）。池空则跳过（不浪费）。后台线程不阻塞 tick。"""
    global _last_pool_verify
    if (now - _last_pool_verify) < _POOL_VERIFY_INTERVAL:
        return
    try:
        from sentinel_platform.contracts import get_registry
        pool = get_registry().get("proxy_pool_service")
        if not (pool and hasattr(pool, "verify") and hasattr(pool, "stats")):
            return
        st = pool.stats() or {}
        if not (st.get("total") or 0):
            return   # 池空，无需验活
        _last_pool_verify = now
        import threading
        threading.Thread(target=pool.verify, daemon=True).start()
        logger.info("scheduler: proxy pool verify triggered (total=%s)", st.get("total"))
    except Exception as exc:
        logger.debug("maybe_verify_pool degraded: %s", exc)


_mihomo_config_healed = False


def _maybe_heal_mihomo_config() -> None:
    """一次性修正旧 mihomo config：容器模式下若运行时 config 是旧的 allow-lan=false（代理端口只
    监听 127.0.0.1、业务容器跨容器连不通），重生成 config + controller reload 修正。
    只在本进程首轮 tick 检测一次（_mihomo_config_healed 标志）；reload 不重启容器、代理不中断、不影响任务。
    存量用户经热更新拿到本代码后，scheduler 首轮 tick 自动修好——无需用户手动重启内核。"""
    global _mihomo_config_healed
    if _mihomo_config_healed:
        return
    _mihomo_config_healed = True   # 无论成败只尝试一次，避免反复
    try:
        from sentinel_platform.modules.system import _mihomo
        if not _mihomo._is_container_mode():
            return   # 仅容器模式需要（本地模式端口本就 127.0.0.1 够用）
        import os, yaml
        cfg_path = _mihomo._paths().get("config", "")
        if not (cfg_path and os.path.exists(cfg_path)):
            return   # 无 config 文件，等正常 start_core 生成
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        # 旧 config 特征：allow-lan 非 True（端口只绑本地）→ 需修正
        if data.get("allow-lan") is True:
            return   # 已是新 config，无需自愈
        r = _mihomo.start_core()   # 重生成正确 config(allow-lan=True) + controller reload
        logger.info("scheduler: healed stale mihomo config (allow-lan) → reloaded=%s", (r or {}).get("reloaded"))
    except Exception as exc:
        logger.debug("maybe_heal_mihomo_config degraded: %s", exc)


def _check_resource_l2() -> dict:
    """L2 资源水位管控（核心链路 §6.4）：
    critical 连续 ≥ 3 tick → 按优先级从低→高暂停 running 会话（paused_resource）；
    回落 normal → 按优先级高→低恢复。防毛刺：单次尖峰不动手。"""
    global _critical_streak
    out = {"level": "", "paused": 0, "resumed": 0}
    try:
        from sentinel_platform.modules.system.log_monitor import get_resource_level
        level = get_resource_level()
        out["level"] = level
    except Exception:
        _critical_streak = 0
        return out

    if level == "critical":
        _critical_streak += 1
    else:
        # 非 critical（连续 critical 被打断）→ 重置计数（防毛刺=连续/consecutive，非累计）。
        # 水位回落到 <80%（normal 或更空闲的 relaxed，设计 §6.4「回落 normal(<80%)」）→ 恢复。
        # tight(80-90%) 仍有压力不恢复，只重置计数不动已暂停会话。
        if level in ("normal", "relaxed"):
            out["resumed"] = _resume_paused_resource()
        _critical_streak = 0
        return out

    # 连续 critical 未达阈值 → 不动手
    if _critical_streak < _L2_THRESHOLD:
        return out

    # L2 触发：暂停最低优先级的 running 会话
    out["paused"] = _pause_lowest_priority_session()
    return out


def _pause_lowest_priority_session() -> int:
    """暂停优先级最低的一个 running 会话 → paused_resource。每 tick 最多暂停一个（渐进式降级）。"""
    try:
        from sentinel_platform.core import get_repo
        coll = get_repo().collection("intel_pentest_session")
        # 找 running 中优先级最低的一个（priority 升序排第一个 = 最低优先级）
        candidate = coll.find_one({"status": "running"}, sort=[("priority", 1)])
        if not candidate:
            return 0
        r = coll.update_one(
            {"_id": candidate["_id"], "status": "running"},
            {"$set": {"status": "paused_resource", "update_date": time.strftime("%Y-%m-%d %H:%M:%S")}})
        if getattr(r, "modified_count", 0):
            logger.info("L2 paused session %s (priority=%s) due to critical resource",
                        candidate["_id"], candidate.get("priority", 0))
            return 1
    except Exception as exc:
        logger.debug("_pause_lowest_priority_session degraded: %s", exc)
    return 0


def _resume_paused_resource() -> int:
    """水位回落 normal → 恢复 paused_resource 会话（优先级高→低，每 tick 恢复一个）。"""
    try:
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.kernel import orchestration
        coll = get_repo().collection("intel_pentest_session")
        # 找 paused_resource 中优先级最高的一个（priority 降序排第一个 = 最高优先级）
        candidate = coll.find_one({"status": "paused_resource"}, sort=[("priority", -1)])
        if not candidate:
            return 0
        r = orchestration.submit_session(str(candidate["_id"]), from_status="paused_resource")
        if r and r.get("submitted"):
            logger.info("L2 resumed session %s (priority=%s) after resource recovery",
                        candidate["_id"], candidate.get("priority", 0))
            return 1
    except Exception as exc:
        logger.debug("_resume_paused_resource degraded: %s", exc)
    return 0


def _install_celery_delivery() -> None:
    """scheduler 侧装 celery 投递：submit_task/submit_session → 投 worker 异步执行。
    #7 根治：不装则 scheduler tick 恢复会话/投任务时在**自己进程内起线程跑 run_agent**，
    一次 LLM 调用(timeout 300s)阻塞就拖慢/卡死整个 tick（实测 provider 挂时 scheduler 冻 27min、
    僵尸会话无人回收）。对齐 wsgi/worker——投递方都要装 executor，scheduler 只投递不进程内执行。
    best-effort：celery 未装/broker 不可达（开发/离线）降级线程执行器，不阻断启动。"""
    try:
        broker = (get_config().section("CELERY", "BROKER_URL", default="")
                  or "amqp://guest:guest@127.0.0.1:5672//")
        from sentinel_platform.modules.kernel import _celery_adapter
        _celery_adapter.make_celery(broker)   # 建 app + 注册 sentinel.run_task/run_session（供 .delay 投递）
        installed = _celery_adapter.install_celery_executor()
        logger.info("scheduler celery delivery installed=%s broker=%s", installed, broker)
    except ImportError:
        logger.warning("scheduler: celery 未装，submit 降级线程执行器（开发/离线可，生产应装 celery）")
    except Exception as exc:
        logger.warning("scheduler: celery delivery 安装降级: %s", exc)


def run_forever() -> None:
    """scheduler 主循环（进程入口）。装配 + celery 投递 + 周期 tick。"""
    from sentinel_platform import bootstrap
    try:
        bootstrap.bootstrap(with_indexes=False)
    except Exception as exc:
        logger.warning("scheduler bootstrap degraded: %s", exc)
    _install_celery_delivery()   # #7：装 celery 投递，会话/任务投 worker 跑，不在 scheduler 进程内起线程
    interval = _tick_seconds()
    logger.info("sentinel scheduler started, tick=%ss", interval)
    while True:
        try:
            r = tick()
            if r["waiting"].get("submitted") or r["due_schedules"]:
                logger.info("scheduler tick: %s", r)
        except Exception as exc:
            logger.warning("scheduler tick error: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    run_forever()
