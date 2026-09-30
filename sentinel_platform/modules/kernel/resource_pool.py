"""kernel/resource_pool —— 通用工具动态内存派发系统（共享基础设施，见 MODULES.md 铁律2 例外三）。

**下沉自 ai_pentest/tool_resources.py（v1.21.157-21，问题11）**：原为 ai_pentest 私有，现下沉为
kernel 共享基础设施——AI 渗透(dispatch)、侦察(recon 经注入)、扫描/截图/poc 统一走这一个内存池。
`ai_pentest/tool_resources.py` 保留为兼容 shim（re-export 本模块），历史调用点零改动。

**设计（用户多轮讨论敲定）**：取消静态槽位表，改成**实时内存动态派发**。工具执行前判定：

    实时可用内存(psutil available+swap.free, 微秒级 cheap 读, 绝不测 CPU 百分比)
      − Σ在途工具预留峰值(仅 ramp 窗口内的 holder, 从 MongoDB 共享账本读)
      − HEADROOM(可用内存的百分比, 有绝对下限, 治瞬时尖峰)
      ≥ 本工具预留峰值 ?  放行+登记预留 : resource_busy(非error) / 按优先级抢占

**预留峰值 = 自学习（无静态表）**：每工具记录历史真实内存峰值(执行前后测 available 差值)，
取滚动 p95 作为下次预留；冷启动/首次/自扩展工具无历史 → 保守默认(TOOL_DEFAULT_PEAK_MB)。
预留峰值 < 免池阈值(TOOL_LIGHT_MB) 的轻量工具(http/query 等)直接放行不进账本。

**优先级带（问题11 扩容）**：
  PRIORITY_MANUAL(10**6) 人工会话 > AI 自动会话(_asset_priority≥0) > PRIORITY_RECON(-1) 侦察/扫描/截图。
  recon 恒最低：既被动让位(gate 阻塞等待)，也被 AI 主动逻辑抢占(_preempt_recon_band)。

**三件套**：
  1. 预留账本(MongoDB TOOL_RESOURCES 共享，跨进程 fresh 读，绝不进程内缓存——多 worker 一致性铁律)：
     派发瞬间登记预留峰值；ramp 窗口(TOOL_RAMP_SEC≈2采样周期)后预留"成熟"——成熟后真实内存已反映它,
     判定时不再叠加成熟预留(否则与实测重复扣)。
  2. HEADROOM 安全余量：治瞬时尖峰(留缓冲，不派发到最后一点内存)。
  3. 实测可用做分母：工具运行中内存膨胀 → 实时可用自动缩小 → 自然不再放行新工具(不给工具装实时监控)。

**抢占/防永久排队**：
  • 人工会话(priority 最高)内存不足时抢占低优先级自动会话预留(踢账本记录，逻辑插队，非 kill 进程——
    跨进程做不到，下一轮生效)。
  • 任何非-recon 申请者(所有 AI)内存不足时抢占 recon 带预留(recon 恒让位 AI)。
  • 纯超时抢占：holder 持有超 TOOL_HOLD_TIMEOUT_SEC 视为僵尸直接踢，**不看会话状态**
    (治崩溃卡 running → 令牌永不清理 → 永久排队)。

**铁律**：禁硬编码上限(参数全可配且有物理意义)；状态落 MongoDB fresh 读；派发判定零阻塞(只读
virtual_memory)；resource_busy 非 error；降级 fail-safe(psutil 缺失保守放行但方向安全)。
"""
import time
from typing import Any, Dict, List, Optional, Tuple

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

# 人工会话优先级（最高；自动会话继承任务优先级，通常 0~若干）——人工永不被拒且可抢占自动。
PRIORITY_MANUAL = 10 ** 6

# 侦察/扫描/截图优先级：恒低于任何 AI 自动会话(_asset_priority≥0)与人工会话(PRIORITY_MANUAL)。
# 负值保证 recon 永远让位 AI（AI 抢内存时可逻辑抢占 recon 预留，见 acquire 抢占分支）。
PRIORITY_RECON = -1

# ── 可配参数默认（有物理意义，非魔数；全部可由 config RESOURCE.* 覆盖）──
_DEFAULTS = {
    "TOOL_DEFAULT_PEAK_MB": 400.0,   # 冷启动/无历史工具的保守预留(≈一个 chromium)
    "TOOL_LIGHT_MB": 50.0,           # 免池阈值：预留<此值的轻量工具(http/query)直接放行不进账本
    "TOOL_HEADROOM_PCT": 0.15,       # 安全余量：可用内存的百分比(治瞬时尖峰)
    "TOOL_HEADROOM_MIN_MB": 512.0,   # 安全余量绝对下限(小机器不能只留 15%)
    "TOOL_RAMP_SEC": 60.0,           # 预留成熟窗口(≈2 个 30s 采样周期)：过此真实内存已反映，撤预留避免重复扣
    "TOOL_HOLD_TIMEOUT_SEC": 300.0,  # 僵尸抢占：holder 超此时长直接踢(不看会话状态，治崩溃永久排队)
    "TOOL_PEAK_HISTORY": 20,         # 每工具保留最近 N 次真实峰值样本(算 p95)
    "TOOL_MEM_DOC_ID": "_mempool",   # 内存池账本文档 _id(与旧 browser 令牌文档隔离)
    "TOOL_PEAK_DOC_ID": "_toolpeaks",  # 自学习峰值文档 _id
    "LEARN_MAX_CONCURRENCY": 1,      # 自学习只在并发 holder ≤ 此值时记样本(防并发污染 p95，问题11)
    "LEARN_OUTLIER_FACTOR": 4.0,     # 离谱样本丢弃：> 默认峰值 × 此系数的 delta 不记(防单次污染毒 p95)
}


def _cfg(key: str) -> Any:
    """读 RESOURCE.<key>，缺失/异常回退内置默认。"""
    dflt = _DEFAULTS[key]
    try:
        from sentinel_platform.core import get_config
        v = get_config().section("RESOURCE", key)
        if v is None:
            return dflt
        return type(dflt)(v)
    except Exception:
        return dflt


def _coll():
    return get_repo().collection(Collections.TOOL_RESOURCES)


# ============================================================================
# 内存探测（cheap，零阻塞——只读 /proc/meminfo，绝不测 CPU 百分比）
# ============================================================================

def _available_mb() -> Optional[float]:
    """实时可用内存 MB = virtual_memory().available + swap.free。psutil 不可用返回 None(调用方降级)。"""
    try:
        import psutil
        avail = psutil.virtual_memory().available
        try:
            avail += psutil.swap_memory().free
        except Exception:
            pass
        return avail / (1024 ** 2)
    except Exception:
        return None


def _used_mb_now() -> Optional[float]:
    """当前进程可见的已用内存 MB(用于自学习：工具执行前后各测一次算增量)。"""
    try:
        import psutil
        vm = psutil.virtual_memory()
        return (vm.total - vm.available) / (1024 ** 2)
    except Exception:
        return None


# ============================================================================
# 自学习峰值（每工具历史真实增量峰值 → p95 作预留）
# ============================================================================

def _peak_doc() -> Dict[str, Any]:
    try:
        d = _coll().find_one({"_id": _cfg("TOOL_PEAK_DOC_ID")})
        return d or {}
    except Exception:
        return {}


def learned_peak_mb(tool: str) -> float:
    """工具预留峰值：历史真实增量样本的 p95；无历史 → 保守默认。"""
    default = float(_cfg("TOOL_DEFAULT_PEAK_MB"))
    doc = _peak_doc()
    samples = (doc.get("peaks") or {}).get(tool) or []
    if not samples:
        return default
    vals = sorted(float(x) for x in samples if x is not None)
    if not vals:
        return default
    # p95（样本少时取最大值，保守）
    idx = max(0, int(round(0.95 * (len(vals) - 1))))
    p95 = vals[idx]
    # 学到的峰值可能比默认小(轻量工具)也可能大(重工具)；至少给一点余量防低估
    return max(1.0, p95)


def record_peak(tool: str, delta_mb: float) -> None:
    """回写工具本次真实内存增量样本(执行前后 used 差值)，滚动保留最近 N 次。
    delta 为负(工具期间别的进程释放了内存)→ 记 0(本工具没吃)。
    **离谱样本丢弃**(问题11)：delta > 默认峰值 × LEARN_OUTLIER_FACTOR 视为并发污染的毒样本，不记
    (防一次污染把 p95 拉高永久锁死后续派发)。"""
    if not tool:
        return
    try:
        delta = max(0.0, float(delta_mb))
        outlier = float(_cfg("TOOL_DEFAULT_PEAK_MB")) * float(_cfg("LEARN_OUTLIER_FACTOR"))
        if delta > outlier:
            logger.debug("record_peak %s 丢弃离谱样本 %.0fMB(>%0.fMB，疑并发污染)", tool, delta, outlier)
            return
        keep = int(_cfg("TOOL_PEAK_HISTORY"))
        did = _cfg("TOOL_PEAK_DOC_ID")
        c = _coll()
        # 追加样本 + 截断到最近 keep 个（$push + $slice，原子）
        c.update_one(
            {"_id": did},
            {"$push": {"peaks." + tool: {"$each": [round(delta, 1)], "$slice": -keep}}},
            upsert=True,
        )
    except Exception as exc:
        logger.debug("record_peak %s failed: %s", tool, exc)


# ============================================================================
# 预留账本（MongoDB 共享，跨进程 fresh 读）
# ============================================================================

def _ensure_pool_doc() -> None:
    try:
        _coll().update_one(
            {"_id": _cfg("TOOL_MEM_DOC_ID")},
            {"$setOnInsert": {"_id": _cfg("TOOL_MEM_DOC_ID"), "holders": [], "rev": 0}},
            upsert=True,
        )
        # 存量文档补 rev 字段（CAS 需要，AUD-06）：老库无 rev → 一次性置 0，之后随每次登记 $inc。
        _coll().update_one(
            {"_id": _cfg("TOOL_MEM_DOC_ID"), "rev": {"$exists": False}},
            {"$set": {"rev": 0}},
        )
    except Exception:
        pass


def _read_holders() -> List[Dict[str, Any]]:
    try:
        d = _coll().find_one({"_id": _cfg("TOOL_MEM_DOC_ID")})
        return list((d or {}).get("holders") or [])
    except Exception:
        return []


def _read_pool() -> Tuple[List[Dict[str, Any]], int]:
    """读账本 (holders, rev)。rev 供 CAS 原子准入（AUD-06）；缺失视为 0。"""
    try:
        d = _coll().find_one({"_id": _cfg("TOOL_MEM_DOC_ID")}) or {}
        return list(d.get("holders") or []), int(d.get("rev", 0) or 0)
    except Exception:
        return [], 0


def _sweep_stale(now: float) -> List[Dict[str, Any]]:
    """超时抢占：踢掉持有超 TOOL_HOLD_TIMEOUT_SEC 的僵尸 holder(不看会话状态)。返回被踢列表。"""
    timeout = float(_cfg("TOOL_HOLD_TIMEOUT_SEC"))
    holders = _read_holders()
    stale = [h for h in holders if (now - float(h.get("acquired_at", now))) > timeout]
    if stale:
        stale_ids = [h.get("hid") for h in stale]
        try:
            _coll().update_one(
                {"_id": _cfg("TOOL_MEM_DOC_ID")},
                {"$pull": {"holders": {"hid": {"$in": stale_ids}}}},
            )
            for h in stale:
                logger.warning("工具资源超时抢占僵尸 holder: tool=%s session=%s 持有=%.0fs",
                               h.get("tool"), h.get("session_id"), now - float(h.get("acquired_at", now)))
        except Exception as exc:
            logger.debug("_sweep_stale failed: %s", exc)
    return stale


def _reserved_active_mb(holders: List[Dict[str, Any]], now: float) -> float:
    """在途且未成熟(ramp 窗口内)的预留之和。成熟的预留不叠加(真实内存已反映，避免重复扣)。"""
    ramp = float(_cfg("TOOL_RAMP_SEC"))
    total = 0.0
    for h in holders:
        age = now - float(h.get("acquired_at", now))
        if age < ramp:
            total += float(h.get("reserve_mb", 0.0))
    return total


# ============================================================================
# 对外：acquire / release（挂 dispatch + recon 注入 gate）
# ============================================================================
def acquire(tool: str, session_id: str, priority: int = 0) -> Dict[str, Any]:
    """工具执行前申请内存额度。返回：
      {"ok": True, "hid": <holder_id>, "reserve_mb": R, "light": bool}  → 放行(light=免池未登记账本)
      {"ok": False, "status": "resource_busy", ...}                     → 内存不足，AI 下轮重试/recon gate 等待

    判定：实时可用 − Σ未成熟预留 − HEADROOM ≥ 本工具预留。
    抢占：人工(PRIORITY_MANUAL)不足时抢占低优先；任何非-recon(>PRIORITY_RECON)不足时抢占 recon 带。
    """
    now = time.time()
    reserve = learned_peak_mb(tool)
    light_th = float(_cfg("TOOL_LIGHT_MB"))

    # 免池：轻量工具(预留<阈值)直接放行，不进账本、不占额度、不查内存(零开销)
    if reserve < light_th:
        return {"ok": True, "hid": "", "reserve_mb": reserve, "light": True}

    _ensure_pool_doc()
    _sweep_stale(now)   # 每次申请先清僵尸(治永久排队)

    avail = _available_mb()
    if avail is None:
        # psutil 不可用：fail-safe——保守放行(不因资源模块拖垮全站)，但登记预留以便后续统计
        hid = _register(tool, session_id, priority, reserve, now)
        logger.debug("psutil 不可用，工具 %s 保守放行(未做内存判定)", tool)
        return {"ok": True, "hid": hid, "reserve_mb": reserve, "light": False, "degraded": True}

    headroom = max(float(_cfg("TOOL_HEADROOM_MIN_MB")), avail * float(_cfg("TOOL_HEADROOM_PCT")))

    # ===== CAS 原子准入（AUD-06）：读账本 rev → 算预算 → 仅当 rev 未变才 CAS 登记；
    #       rev 已变（别的 worker 抢先登记）→ 重采样重试。杜绝两个 worker 读同一空账本各自获批超预算。=====
    # 修复前：_read_holders 读预算 → 判定 → 独立 $push 登记，三步非原子，多 worker TOCTOU 超额。
    _CAS_RETRIES = 5
    for _attempt in range(_CAS_RETRIES):
        now = time.time()
        holders, rev = _read_pool()
        reserved = _reserved_active_mb(holders, now)
        budget = avail - reserved - headroom

        if budget >= reserve:
            hid = _register_cas(tool, session_id, priority, reserve, now, rev)
            if hid:
                return {"ok": True, "hid": hid, "reserve_mb": reserve, "light": False}
            continue   # CAS 冲突：账本被改，重采样重判

        # 内存不足：人工优先级尝试抢占低优先自动会话的预留（最宽——抢所有低于自己的）
        if priority >= PRIORITY_MANUAL:
            freed = _preempt_lower(holders, priority, needed=(reserve - budget), now=now)
            if freed > 0:
                holders2, rev2 = _read_pool()
                if (avail - _reserved_active_mb(holders2, now) - headroom) >= reserve:
                    hid = _register_cas(tool, session_id, priority, reserve, now, rev2)
                    if hid:
                        return {"ok": True, "hid": hid, "reserve_mb": reserve, "light": False, "preempted": True}
                    continue

        # 任何非-recon 申请者(所有 AI，含自动会话)内存不足时，抢占 recon 带预留(recon 恒让位 AI，问题11)。
        # 仅抢 recon 带(priority<=PRIORITY_RECON)，不动 AI-vs-AI(避免自动会话互抢，保持既有语义)。
        elif priority > PRIORITY_RECON:
            freed = _preempt_recon_band(holders, needed=(reserve - budget), now=now)
            if freed > 0:
                holders2, rev2 = _read_pool()
                if (avail - _reserved_active_mb(holders2, now) - headroom) >= reserve:
                    hid = _register_cas(tool, session_id, priority, reserve, now, rev2)
                    if hid:
                        return {"ok": True, "hid": hid, "reserve_mb": reserve, "light": False, "preempted": "recon"}
                    continue   # CAS 冲突，重采样重试

        # 本轮内存确实不足且抢占未腾出/CAS 反复冲突 → 跳出重试循环，返回 resource_busy
        break

    return {
        "ok": False,
        "status": "resource_busy",
        "resource_type": "memory",
        "reserve_mb": round(reserve, 1),
        "avail_mb": round(avail, 1),
        "reserved_mb": round(reserved, 1),
        "headroom_mb": round(headroom, 1),
        "message": "系统可用内存不足以安全运行本工具，请先探测其他轻量攻击面(http_request/collect_js/查询类)，下一轮再试",
        "note": "这不是错误，是内存资源调度。下一轮其他工具释放后可能就绪。",
    }


def _register(tool: str, session_id: str, priority: int, reserve_mb: float, now: float) -> str:
    """登记一个预留 holder，返回 holder id（非 CAS，用于 psutil 不可用的 fail-safe 保守放行路径）。"""
    hid = "{}_{}_{}".format(session_id or "?", tool, int(now * 1000))
    try:
        _coll().update_one(
            {"_id": _cfg("TOOL_MEM_DOC_ID")},
            {"$push": {"holders": {
                "hid": hid, "tool": tool, "session_id": session_id,
                "priority": int(priority), "reserve_mb": float(reserve_mb), "acquired_at": now,
            }}, "$inc": {"rev": 1}},
            upsert=True,
        )
    except Exception as exc:
        logger.debug("_register failed: %s", exc)
    return hid


def _register_cas(tool: str, session_id: str, priority: int, reserve_mb: float,
                  now: float, expect_rev: int) -> Optional[str]:
    """CAS 原子登记（AUD-06）：仅当账本 rev 仍等于预算判定时读到的 expect_rev 才登记（$inc rev）。
    rev 已变（别的 worker 抢先改了账本）→ matched_count=0 返回 None，调用方重采样重试。
    登记本身失败（异常/未匹配）绝不返回 hid，杜绝"登记失败仍报已获额度"。"""
    hid = "{}_{}_{}".format(session_id or "?", tool, int(now * 1000))
    try:
        r = _coll().update_one(
            {"_id": _cfg("TOOL_MEM_DOC_ID"), "rev": expect_rev},
            {"$push": {"holders": {
                "hid": hid, "tool": tool, "session_id": session_id,
                "priority": int(priority), "reserve_mb": float(reserve_mb), "acquired_at": now,
            }}, "$inc": {"rev": 1}},
        )
        if getattr(r, "matched_count", 0) == 1:
            return hid
        return None   # rev 已变，CAS 冲突
    except Exception as exc:
        logger.debug("_register_cas failed: %s", exc)
        return None


def _preempt_lower(holders: List[Dict[str, Any]], my_priority: int, needed: float, now: float) -> float:
    """人工抢占：踢掉优先级低于 my_priority 的 holder(逻辑插队，非 kill 进程)，直到腾出 needed。
    返回腾出的预留 MB。"""
    ramp = float(_cfg("TOOL_RAMP_SEC"))
    # 只抢未成熟(仍在占预留额度)的低优先 holder；按优先级升序先抢最低的
    victims = sorted(
        [h for h in holders
         if int(h.get("priority", 0)) < my_priority and (now - float(h.get("acquired_at", now))) < ramp],
        key=lambda h: int(h.get("priority", 0)),
    )
    return _kick_victims(victims, needed)


def _preempt_recon_band(holders: List[Dict[str, Any]], needed: float, now: float) -> float:
    """AI 抢占 recon 带：踢掉 priority<=PRIORITY_RECON 的 holder(recon 恒让位 AI，问题11)。
    只抢 recon 带，不碰 AI-vs-AI。返回腾出的预留 MB。"""
    ramp = float(_cfg("TOOL_RAMP_SEC"))
    victims = sorted(
        [h for h in holders
         if int(h.get("priority", 0)) <= PRIORITY_RECON and (now - float(h.get("acquired_at", now))) < ramp],
        key=lambda h: int(h.get("priority", 0)),
    )
    return _kick_victims(victims, needed)


def _kick_victims(victims: List[Dict[str, Any]], needed: float) -> float:
    """从 victims 里逐个踢直到腾出 needed 预留(逻辑插队，下轮生效)。返回腾出 MB。"""
    freed = 0.0
    kicked = []
    for h in victims:
        if freed >= needed:
            break
        freed += float(h.get("reserve_mb", 0.0))
        kicked.append(h.get("hid"))
    if kicked:
        try:
            _coll().update_one(
                {"_id": _cfg("TOOL_MEM_DOC_ID")},
                {"$pull": {"holders": {"hid": {"$in": kicked}}}},
            )
            logger.info("抢占 %d 个低优先工具预留，腾出 %.0fMB(逻辑插队，下轮生效)", len(kicked), freed)
        except Exception as exc:
            logger.debug("_kick_victims failed: %s", exc)
    return freed


def release(hid: str, tool: str = "", used_delta_mb: Optional[float] = None) -> None:
    """工具执行后释放预留 + 回写真实峰值供自学习。light 工具(hid 空)只回写学习不动账本。
    **自学习防并发污染(问题11)**：仅在当前并发 holder 数 ≤ LEARN_MAX_CONCURRENCY 时记样本
    (并发时 used 差值被别的工具污染，不记以免毒 p95)。"""
    if used_delta_mb is not None and tool:
        try:
            # 并发污染防护：释放发生在 $pull 之前，_read_holders 仍含本 holder。
            # total(含自己) ≤ LEARN_MAX_CONCURRENCY(默认1=独占) 才记样本——有别的在途工具时
            # used 差值被污染，跳过以免毒 p95。
            max_conc = int(_cfg("LEARN_MAX_CONCURRENCY"))
            total = len(_read_holders()) or 1   # 至少算自己(light 工具 hid 空未登记时兜底 1)
            if total <= max_conc:
                record_peak(tool, used_delta_mb)
            else:
                logger.debug("release %s 跳过自学习(并发 %d holder，样本不纯)", tool, total)
        except Exception:
            record_peak(tool, used_delta_mb)   # 防护本身异常不该吞掉学习
    if not hid:
        return
    try:
        _coll().update_one(
            {"_id": _cfg("TOOL_MEM_DOC_ID")},
            {"$pull": {"holders": {"hid": hid}}},
        )
    except Exception as exc:
        logger.debug("release %s failed: %s", hid, exc)


def release_session_all(session_id: str) -> None:
    """会话结束/停止：释放该会话所有预留。run_agent finally / recon run_recon finally 调。"""
    if not session_id:
        return
    try:
        _coll().update_many(
            {},
            {"$pull": {"holders": {"session_id": session_id}}},
        )
    except Exception as exc:
        logger.debug("release_session_all %s failed: %s", session_id, exc)


# ============================================================================
# 兜底清理（scheduler 周期调）+ 统计（监控）
# ============================================================================

def cleanup_stale_resources() -> int:
    """scheduler 周期兜底：超时抢占僵尸 holder(不看会话状态，治崩溃永久排队)。返回清理数。"""
    try:
        return len(_sweep_stale(time.time()))
    except Exception as exc:
        logger.error("cleanup_stale_resources failed: %s", exc)
        return 0


def get_resource_stats() -> Dict[str, Any]:
    """资源池统计(监控/调试用)。"""
    now = time.time()
    holders = _read_holders()
    avail = _available_mb()
    ramp = float(_cfg("TOOL_RAMP_SEC"))
    active_reserve = _reserved_active_mb(holders, now)
    return {
        "available_mb": round(avail, 1) if avail is not None else None,
        "headroom_mb": (round(max(float(_cfg("TOOL_HEADROOM_MIN_MB")), avail * float(_cfg("TOOL_HEADROOM_PCT"))), 1)
                        if avail is not None else None),
        "active_reserve_mb": round(active_reserve, 1),
        "holders": [{"tool": h.get("tool"), "session_id": h.get("session_id"),
                     "priority": h.get("priority"), "reserve_mb": h.get("reserve_mb"),
                     "age_sec": round(now - float(h.get("acquired_at", now)), 1),
                     "mature": (now - float(h.get("acquired_at", now))) >= ramp}
                    for h in holders],
    }
