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

# —— 报告模板异步学习兜底（worker 崩溃致学习线程死 → 心跳超时的 learning 模板重跑；防线程堆积）——
_tpl_learn_running = False

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
    # 会话台后台回合 crash 兜底（独立于自动会话；只清 console_running 死锁 + 按 pending 重投，不碰 status）
    try:
        result["console_sessions"] = _tick_console_sessions()
    except Exception as exc:
        logger.debug("scheduler tick console_sessions degraded: %s", exc)
    # 链式更新看门狗：续跑子进程被 docker restart web 连带杀死→无人推进→progress 永停 applying 时，
    # scheduler（独立容器不随 web 重启）检测停滞、清陈旧锁、兜底重派下一跳。非攀爬中零副作用。
    try:
        from sentinel_platform.modules.about._updater import tick_chain_watchdog
        result["chain_update"] = tick_chain_watchdog()
    except Exception as exc:
        logger.debug("scheduler tick chain_update degraded: %s", exc)
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
    # 报告模板异步学习兜底：捡心跳超时仍 learning 的模板（worker 崩溃线程死）重跑
    try:
        result["tpl_learn"] = _tick_template_learn()
    except Exception as exc:
        logger.debug("scheduler tick tpl_learn degraded: %s", exc)
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
    # 资源采样（每 tick 写一次 resource_history，dashboard 读）+ 多维水位告警推送
    try:
        from sentinel_platform.modules.system.log_monitor import sample_resource, check_and_alert_resource
        sample_resource()
        # 采样后立即判定：内存/CPU/磁盘任一达 tight+ → notify 渠道推送（带 10min 去重节流，回落自动解除）。
        # 前端弹窗侧独立轮询 get_resource_alert 自判（仅 critical 弹），推送与弹窗解耦。
        result["res_alert"] = check_and_alert_resource()
    except Exception:
        pass
    # L2 资源水位检查：critical 连续 3tick → 暂停低优先级会话
    try:
        result["l2"] = _check_resource_l2()
    except Exception:
        pass
    # L3 工具资源清理：每 10 个 tick 清理一次僵尸资源（约 5 分钟）
    global _tick_count
    _tick_count = globals().get("_tick_count", 0) + 1
    if _tick_count % 10 == 0:
        try:
            from sentinel_platform.modules.ai_pentest.tool_resources import cleanup_stale_resources
            cleaned = cleanup_stale_resources()
            if cleaned > 0:
                result["tool_res_cleaned"] = cleaned
        except Exception as exc:
            logger.debug("cleanup_stale_resources degraded: %s", exc)
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


def _heartbeat_age(doc: dict, now_epoch: float) -> float:
    """据 update_date 心跳算距今秒数（AUD-08）。缺失/无法解析 → 返 inf（视为无心跳=可回收）。"""
    ud = (doc.get("update_date") or doc.get("start_time") or "").strip()
    if not ud:
        return float("inf")
    try:
        return now_epoch - time.mktime(time.strptime(ud, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        return float("inf")


def _reclaim_on_startup() -> dict:
    """**scheduler 启动回收被打断的 running 任务/会话——但只回收心跳已过期的（AUD-08）**。
    修复前假设"scheduler 启动 = worker 也重启了"，无条件回收所有 running。但当前 compose 是
    **独立容器**（worker / scheduler 各自独立进程，可单独重启/热更）——若只 scheduler 重启、worker
    仍在跑，无条件回收会把**正在被活着的 worker 执行**的任务/会话回收重投 → 重复扫描/重复 LLM 调用/
    checkpoint 竞争覆盖。
    修法（复用既有心跳，与周期 watchdog 同口径）：running 任务/会话的 update_date 是每轮 checkpoint
    刷新的心跳；启动时只回收**心跳已 stale**（worker 真死）的，心跳新鲜的（worker 还活着在跑）**不动**，
    交给周期 watchdog 按 STALL 阈值判。启动回收阈值取 max(3×tick, 90s)——比周期 STALL 短，让 scheduler
    单独重启后能较快接管真死的，又不会误回收心跳仍在刷新的活任务。
    **区分用户手动停止**：只动 running/dispatching + 排除 stop_requested，天然不碰手动停止的。
    续跑数据不丢：扫描 recon 断点续扫、会话 checkpoint 接续。重投上限沿用（reclaim_count）。"""
    from sentinel_platform.core import get_repo
    now_epoch = time.time()
    # 启动回收心跳阈值：足够短以便 scheduler 单独重启后快速接管真死实例，又长于几个 checkpoint 周期
    # （避免把心跳刚好在刷新间隙的活任务误判死）。
    stale_th = max(_tick_seconds() * 3, 90)
    out = {"tasks": 0, "sessions": 0, "kept_alive": 0}
    try:
        tcoll = get_repo().collection("task")
        for doc in tcoll.find({"status": "running"}, {"_id": 1, "reclaim_count": 1,
                                                       "update_date": 1, "start_time": 1}):
            if _heartbeat_age(doc, now_epoch) < stale_th:
                out["kept_alive"] += 1        # 心跳新鲜=worker 还在跑，不回收（AUD-08 核心）
                continue
            rc = int(doc.get("reclaim_count", 0) or 0)
            r = tcoll.update_one({"_id": doc["_id"], "status": "running"}, {"$set": {
                "status": "waiting", "reclaim_count": rc + 1,
                "dispatch_error": "调度器启动检测到中断且心跳已过期（worker 疑似已终止），回收续扫（第 {} 次）".format(rc + 1)}})
            out["tasks"] += getattr(r, "modified_count", 0)
    except Exception as exc:
        logger.debug("startup reclaim tasks degraded: %s", exc)
    try:
        scoll = get_repo().collection("intel_pentest_session")
        # running/dispatching 会话 → queued，但同样只回收心跳过期的；stop_requested 绝不续跑。
        for doc in scoll.find({"status": {"$in": ["running", "dispatching"]},
                               "stop_requested": {"$ne": True}},
                              {"_id": 1, "update_date": 1, "start_time": 1}):
            if _heartbeat_age(doc, now_epoch) < stale_th:
                out["kept_alive"] += 1
                continue
            r = scoll.update_one({"_id": doc["_id"], "status": {"$in": ["running", "dispatching"]},
                                  "stop_requested": {"$ne": True}},
                                 {"$set": {"status": "queued"}})
            out["sessions"] += getattr(r, "modified_count", 0)
    except Exception as exc:
        logger.debug("startup reclaim sessions degraded: %s", exc)
    # 会话台后台回合（v1.21.157-62）：启动时清心跳过期的 console_running 死锁（worker 崩溃残留）；
    # 有 pending 的由周期 _tick_console_sessions 重投。此处只解锁，不续跑半截回合（防重复工具执行）。
    try:
        ccoll = get_repo().collection("intel_pentest_session")
        for doc in ccoll.find({"console_created": True, "console_running": True},
                              {"_id": 1, "console_update": 1}):
            if _heartbeat_age({"update_date": doc.get("console_update", "")}, now_epoch) < stale_th:
                continue                     # 心跳新鲜=worker 还在跑该回合，不动
            ccoll.update_one({"_id": doc["_id"], "console_running": True},
                             {"$set": {"console_running": False}})
            out["console_unlocked"] = out.get("console_unlocked", 0) + 1
    except Exception as exc:
        logger.debug("startup reclaim console degraded: %s", exc)
    if out["tasks"] or out["sessions"] or out["kept_alive"]:
        logger.info("scheduler 启动回收：心跳过期任务 %d→waiting、会话 %d→queued 续跑；"
                    "心跳新鲜（worker 仍在跑）保留不动 %d 个（AUD-08 防独立 worker 拓扑下误回收）",
                    out["tasks"], out["sessions"], out["kept_alive"])
    return out


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
    max_retry = _sess_cfg("MAX_TRANSIENT_RETRY", 12)   # v1.21.157-48 加长中断重试轮次(5→12)，中断会话更耐心自愈
    stall_sec = _sess_cfg("STALL_SECONDS", 900)   # 15min 无心跳判死
    # dispatching 停滞回收阈值：正常亚秒级转 running，超此秒数仍 dispatching = 派发消息丢失
    # (rabbitmq recreate / consumers 掉线) 或 worker 起转前崩。默认 max(3×tick,90s)，远长于正常 dispatch。
    dispatch_stall = _sess_cfg("DISPATCH_STALL_SECONDS", max(_tick_seconds() * 3, 90))
    max_dispatch_reclaim = _sess_cfg("MAX_DISPATCH_RECLAIM", 3)   # 连续派发都起不来的降级上限，防无限抖动
    out = {"queued": 0, "resumed": 0, "stalled": 0, "degraded": 0, "revived": 0}
    try:
        coll = get_repo().collection("intel_pentest_session")
        now_epoch = _t.time()
        # ① 回收 running 心跳超时：只回到 queued，稍后与其他候选共享槽位
        for s in coll.find({"status": "running", "console_created": {"$ne": True}}, {"_id": 1, "update_date": 1}):
            ud = s.get("update_date", "") or ""
            try:
                age = now_epoch - _t.mktime(_t.strptime(ud, "%Y-%m-%d %H:%M:%S"))
            except (ValueError, TypeError):
                age = 0
            if age > stall_sec:
                coll.update_one({"_id": s["_id"], "status": "running"}, {"$set": {"status": "queued"}})
                out["stalled"] += 1

        # ①.5 回收 dispatching 停滞：周期 watchdog 此前只管 running，dispatching 卡死只能靠 scheduler 重启的
        # _reclaim_on_startup，中间会一直占槽不动（实测 rabbitmq recreate 丢消息后会话永卡 dispatching）。
        # dispatch 心跳(update_date，由 _claim_session 进 dispatching 时盖)超 dispatch_stall 且非 stop_requested
        # → 回 queued 重新派发；连续回收超 MAX_DISPATCH_RECLAIM 次仍起不来(如 provider 失效/run_agent 起转即崩)
        # → 降级 paused_manual(由 ②.5 隔 MANUAL_RETRY_SECONDS 延迟自愈)，别无限 queued↔dispatching 抖动占槽。
        for s in coll.find({"status": "dispatching", "stop_requested": {"$ne": True},
                            "console_created": {"$ne": True}},
                           {"_id": 1, "update_date": 1, "dispatch_reclaim_count": 1}):
            if _heartbeat_age(s, now_epoch) <= dispatch_stall:
                continue
            drc = int(s.get("dispatch_reclaim_count", 0) or 0)
            if drc >= max_dispatch_reclaim:
                # 降级时盖 update_date=now：让 paused_manual 是「新鲜」的，20min MANUAL_RETRY 计时从头算，
                # 否则携带派发前的旧心跳会被同 tick 的 ②.5 立即复活成 paused_transient，抵消「延迟自愈」本意。
                coll.update_one({"_id": s["_id"], "status": "dispatching", "stop_requested": {"$ne": True}},
                                {"$set": {"status": "paused_manual",
                                          "update_date": _t.strftime("%Y-%m-%d %H:%M:%S"),
                                          "dispatch_error": "dispatching 停滞回收 {} 次仍起不来，降级延迟自愈".format(drc)}})
                out["degraded"] += 1
            else:
                coll.update_one({"_id": s["_id"], "status": "dispatching", "stop_requested": {"$ne": True}},
                                {"$set": {"status": "queued"}, "$inc": {"dispatch_reclaim_count": 1}})
                out["stalled"] += 1

        # ② running + dispatching 共同占用槽位；paused 和 queued 共享剩余槽位
        cap = _session_cap()
        occupied = coll.count_documents({"status": {"$in": ["running", "dispatching"]}})
        slots = max(0, cap - occupied)
        if slots <= 0:
            return out

        # ②.5 需人工处理的会话隔 N 分钟自行再拉起（用户 2026-09-21）：paused_manual 是「自愈耗尽/永久错误」
        # 的搁浅态，此前只能人工 resume。现对**非会话台**的 paused_manual，距上次活动≥MANUAL_RETRY_SECONDS
        # （默认 1200s=20min）就复活回 paused_transient（清 retry_count 重走自愈）——中转站恢复/额度回充/
        # 网络恢复后能自动跑起来，不必人工干预。**绝不碰 console_created 会话台会话**（它天生 paused_manual、
        # 自动拉起会用错提示词跑飞，见 console_create_session 设计）；也不碰 stop_requested（用户显式停的不复活）。
        manual_retry_sec = _sess_cfg("MANUAL_RETRY_SECONDS", 1200)
        for s in coll.find({"status": "paused_manual", "console_created": {"$ne": True},
                            "stop_requested": {"$ne": True}},
                           {"_id": 1, "update_date": 1}):
            if _heartbeat_age(s, now_epoch) < manual_retry_sec:
                continue   # 未到 20min 间隔，跳过（下个 tick 再看）
            r = coll.update_one({"_id": s["_id"], "status": "paused_manual"},
                                {"$set": {"status": "paused_transient", "retry_count": 0,
                                          "update_date": _t.strftime("%Y-%m-%d %H:%M:%S")}})
            if getattr(r, "modified_count", 0):
                out["revived"] = out.get("revived", 0) + 1

        # 候选查询排除 stop_requested（与 _claim_session 的 stop_requested!=True 认领过滤同口径）：
        # 停掉的会话卡在 paused_transient/queued 时，若进候选并排到前面，会白占 slot 预算认领失败，
        # 饿死后面健康候选（实测顽疾：3 个 stop_requested 的 paused_transient 排最前堵死 10 个健康 queued）。
        # console_created 会话绝不进自动派发（run_agent）候选——它是会话台人工会话，由 _tick_console_sessions
        # 与人工接管管理；误纳入会被当自动会话重投、与人工回合双跑冲突（用户报的「恢复导致重投」根治）。
        paused = list(coll.find({"status": "paused_transient", "stop_requested": {"$ne": True},
                                 "console_created": {"$ne": True}},
                                {"_id": 1, "retry_count": 1, "priority": 1}))
        candidates = []
        for s in paused:
            rc = int(s.get("retry_count", 0) or 0)
            if rc >= max_retry:
                coll.update_one({"_id": s["_id"], "status": "paused_transient"},
                                {"$set": {"status": "paused_manual"}})
                out["degraded"] += 1
            else:
                candidates.append((0, -int(s.get("priority", 0) or 0), s, "paused_transient"))
        for s in coll.find({"status": "queued", "stop_requested": {"$ne": True},
                            "console_created": {"$ne": True}}, {"_id": 1, "priority": 1}):
            candidates.append((1, -int(s.get("priority", 0) or 0), s, "queued"))
        candidates.sort(key=lambda item: (item[0], item[1]))  # 恢复优先，同类高价值优先
        # 填满 slots 个**成功派发**（而非切前 slots 个尝试）：认领失败(竞态/被停/状态漂移)不占 slot 预算，
        # 继续尝试下一个健康候选——否则前 slots 个恰好都认领失败时，这一轮一个都提不上、健康候选被饿死。
        promoted = 0
        for _, _, s, source_status in candidates:
            if promoted >= slots:
                break
            r = orchestration.submit_session(str(s["_id"]), from_status=source_status) or {}
            # 兼容测试/旧门面返回 None：生产新门面会明确 submitted=False 表示认领失败。
            if not r.get("submitted"):
                continue                       # 认领失败不计入 promoted，slot 预算留给下一个健康候选
            promoted += 1
            if source_status == "paused_transient":
                out["resumed"] += 1
            else:
                out["queued"] += 1
    except Exception as exc:
        logger.debug("tick_sessions degraded: %s", exc)
    return out


def _tick_console_sessions() -> dict:
    """会话台后台回合 crash 兜底（v1.21.157-62，**独立于 _tick_sessions，绝不碰 status/run_agent**）：
    console 回合跑在 worker（run_console_agent），worker 崩溃会留下 console_running=True 的死锁 +
    未消费的 pending_user_msgs。本 watchdog 查心跳（console_update）超 STALL 的 console_running 会话：
      → 清 console_running（解死锁）；
      → 若 pending_user_msgs 非空 → submit_console_turn 重投（捞回用户排队指令，幂等 CAS 认领）；
      → **不自动续跑半截回合**（避免重复工具执行），符合「回合丢了就靠 pending 重投/等用户」。"""
    from sentinel_platform.core import get_repo
    from sentinel_platform.modules.kernel import orchestration
    import time as _t
    stall_sec = _sess_cfg("STALL_SECONDS", 900)
    out = {"unlocked": 0, "resubmitted": 0}
    try:
        coll = get_repo().collection("intel_pentest_session")
        now_epoch = _t.time()
        for s in coll.find({"console_created": True, "console_running": True},
                           {"_id": 1, "console_update": 1, "pending_user_msgs": 1}):
            ud = s.get("console_update", "") or ""
            try:
                age = now_epoch - _t.mktime(_t.strptime(ud, "%Y-%m-%d %H:%M:%S"))
            except (ValueError, TypeError):
                age = stall_sec + 1   # 无心跳时间戳 → 视为超时（保守解锁）
            if age <= stall_sec:
                continue
            # 心跳超时 = worker 死/回合卡死 → 解锁
            coll.update_one({"_id": s["_id"], "console_running": True},
                            {"$set": {"console_running": False}})
            out["unlocked"] += 1
            # 有排队指令 → 重投一个新回合（submit_console_turn 内 CAS 认领，幂等）
            if s.get("pending_user_msgs"):
                r = orchestration.submit_console_turn(str(s["_id"])) or {}
                if r.get("submitted"):
                    out["resubmitted"] += 1
    except Exception as exc:
        logger.debug("tick_console_sessions degraded: %s", exc)
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
        from sentinel_platform.core import get_repo, get_config
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
        # 到期或首次 → 后台线程拉取（不阻塞 scheduler tick）。
        # 中心化（UPDATE.INTEL_PULL 默认开且已配 SOURCE_URL/KEY）：从分发系统拉外部源情报，
        # 本地仅跑 arl_npoc/nuclei（本地可执行情报，反映本实例能力）；中心不可达 → 降级本地全 8 源直拉。
        intel_pull_on = bool(get_config().section("UPDATE", "INTEL_PULL", default=True))
        try:
            from sentinel_platform.modules.system import activation
            has_source = bool(activation.source_url()) and bool(activation.read_key())
        except Exception:
            has_source = False
        central = intel_pull_on and has_source

        def _job():
            # 外部开源 CVE 情报：只从云端拉取（本系统不再本地爬外部源）。中心不可达则本轮暂缺、下轮重试。
            if central:
                try:
                    from sentinel_platform.modules.risk_intel import intel_pull
                    r = intel_pull.pull_and_upsert() or {}
                    if r.get("ok"):
                        logger.info("scheduler: vuln_feed central pull %s", r)
                    else:
                        logger.warning("scheduler: 云端情报拉取未成功(%s)，外部情报本轮暂缺，下轮重试", r.get("reason"))
                except Exception as exc:
                    logger.warning("scheduler: intel_pull 异常: %s", exc)
            # 本地可执行能力源（arl_npoc/nuclei）始终本地跑（per-instance，非外部爬取）
            run_feed()

        import threading
        threading.Thread(target=_job, daemon=True).start()
        logger.info("scheduler: vuln_feed triggered (central=%s, last=%s, interval=%ss)",
                    central, last_fetch or "never", interval)
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


def _tick_template_learn() -> dict:
    """报告模板异步学习兜底：正常学习在 web worker 内 daemon 线程几分钟内完成；worker 崩溃/重启会让
    线程死、模板永久卡 learning。本 tick 捡心跳(update_date)超时仍 learning 的模板重跑（同步跑完）。
    经 registry 取 INTEL 服务的 run_pending_learn（缺失降级）。后台 daemon 线程跑（LLM 慢，不阻塞 tick）；
    模块级 _tpl_learn_running 防线程堆积。"""
    global _tpl_learn_running
    if _tpl_learn_running:
        return {"skipped": "prev_run_in_progress"}

    def _run():
        global _tpl_learn_running
        _tpl_learn_running = True
        try:
            from sentinel_platform.contracts import get_registry, ROLE
            svc = get_registry().get(ROLE.INTEL)
            if svc and hasattr(svc, "run_pending_learn"):
                try:
                    stale = int(get_config().section("REPORT_TEMPLATE", "LEARN_STALE_SEC", default=600) or 600)
                except (TypeError, ValueError):
                    stale = 600   # 心跳超时阈值（可配，默认 10min）
                svc.run_pending_learn(stale_seconds=stale)
        except Exception as exc:
            logger.debug("tpl_learn tick run degraded: %s", exc)
        finally:
            _tpl_learn_running = False

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
    # 启动即回收被打断的 running 任务/会话，立即续跑（不等 2h/15min 僵尸阈值）。scheduler 启动=上轮进程
    # 已终止(重启/热更/容器recreate)，残留 running 必是中断态。手动停止(stop/stopped)不在 running 天然不误续。
    try:
        _reclaim_on_startup()
    except Exception as exc:
        logger.warning("scheduler startup reclaim degraded: %s", exc)
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
