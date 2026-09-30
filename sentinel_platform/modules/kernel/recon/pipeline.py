"""recon pipeline —— 多阶段侦察编排（把 T*/N*/E* 工具串成真实扫描流）。

替换 recon_bridge 现最小 4 阶段：域名任务 = 子域名(被动+爆破)→解析→端口→证书→站点→爬取→
文件泄漏→vhost→服务识别→弱口令→漏扫；IP 任务省"子域名/解析"两阶段。

**完全自包含**（recon 子包铁律：不 import core/contracts/app）——只依赖同子包 tools/native/
models/context + stdlib。每阶段：工具 `available()` 否则跳过（降级不阻断）、只读上游中间态写自己
产物、边界调 `cancel_check` 协作式取消。**禁硬限制**：并发/字典/端口范围来自 options 透传，
不写死上限；无输入的阶段自然跳过。

阶段解耦：加/减/换阶段只改 `_domain_stages()/_ip_stages()` 列表，不改 Pipeline 驱动逻辑。
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .base import ToolCancelled
from .context import ReconContext, StageResult, StoppedException, CancelCheck, OnStage
from .models import DomainRec, IPRec, SiteRec, PortInfo
from .tools import Subfinder, Massdns, Dnsx, Naabu, NmapService, Httpx, Nuclei, WeakBrute
from .tools.katana import Katana
from .native.certfetch import CertFetcher
from .native.fileleak import FileLeakScanner
from .native.icmp import IcmpPing
from .native.vhost import VhostFinder
from .webinfo import WebInfoHunter
from .native.screenshot import Screenshot
from .native.chromium_shot import ChromiumShot
from .enrich import build_enricher


def _pick_screenshotter():
    """截图引擎选择（问题11）：chromium-first（能渲染 ES6 SPA，phantomjs 老 WebKit 对 SPA 黑屏）→
    phantomjs 兜底 → 都不可用则各自 available() 返 False，阶段 skip（诚实降级）。
    构造轻量（不启动浏览器），available() 才做真探测。"""
    try:
        cs = ChromiumShot()
        if cs.available():
            return cs
    except Exception:
        pass
    return Screenshot()


class Tools:
    """工具持有器（懒实例化 + 可注入替身供测试）。每工具一实例，pipeline 各阶段共享。
    `io_concurrency`（>0）随资源水位注入 native IO 工具（fileleak/vhost/certfetch）的并发度，缺省用各自默认。"""

    def __init__(self, io_concurrency: int = 0, cancel_check: "CancelCheck" = None,
                 resource_gate=None, **overrides):
        self._o = overrides
        self._io = max(0, int(io_concurrency or 0))
        #: 取消回调：注入每个工具实例，使外部工具（subfinder 等）的阻塞执行能被协作式取消穿透中断
        #: （根治「工具卡网络→取消到不了阶段边界→任务停不掉」）。None 时工具走原阻塞执行。
        self._cancel_check = cancel_check
        #: 资源门（recon_bridge 注入的纯 callable）：内存重工具(截图/nuclei/service)执行前经它申请内存额度、
        #: 让位 AI（问题11）。注入每个有 resource_gate 属性的工具实例。None 时工具走原无门控执行。
        self._resource_gate = resource_gate

    def _inject_cancel(self, inst):
        """给外部工具实例挂 cancel_check（有该属性才挂；native/替身无则跳过）。"""
        if self._cancel_check is not None and hasattr(inst, "cancel_check"):
            try:
                inst.cancel_check = self._cancel_check
            except Exception:
                pass
        return inst

    def _inject_gate(self, inst):
        """给工具实例挂 resource_gate（有该属性才挂；无则跳过——只有内存重工具声明该属性）。"""
        if self._resource_gate is not None and hasattr(inst, "resource_gate"):
            try:
                inst.resource_gate = self._resource_gate
            except Exception:
                pass
        return inst

    def _get(self, key, factory):
        if key in self._o:
            return self._o[key]
        inst = factory()
        self._o[key] = inst
        return self._inject_gate(self._inject_cancel(inst))

    def _get_io(self, key, cls):
        """native IO 工具：水位 >0 则用它作 concurrency，否则用类默认（不注入 = 保持默认）。"""
        if key in self._o:
            return self._o[key]
        inst = cls(concurrency=self._io) if self._io > 0 else cls()
        self._o[key] = inst
        return self._inject_gate(self._inject_cancel(inst))

    @property
    def subfinder(self): return self._get("subfinder", Subfinder)
    @property
    def massdns(self): return self._get("massdns", Massdns)
    @property
    def dnsx(self): return self._get("dnsx", Dnsx)
    @property
    def naabu(self): return self._get("naabu", Naabu)
    @property
    def nmap(self): return self._get("nmap", NmapService)
    @property
    def httpx(self): return self._get("httpx", Httpx)
    @property
    def katana(self): return self._get("katana", Katana)
    @property
    def certfetch(self): return self._get_io("certfetch", CertFetcher)
    @property
    def fileleak(self): return self._get_io("fileleak", FileLeakScanner)
    @property
    def vhost(self): return self._get_io("vhost", VhostFinder)
    @property
    def icmp(self): return self._get_io("icmp", IcmpPing)
    @property
    def nuclei(self): return self._get("nuclei", Nuclei)
    @property
    def weakbrute(self): return self._get("weakbrute", WeakBrute)
    @property
    def webinfo(self): return self._get("webinfo", WebInfoHunter)
    @property
    def screenshot(self): return self._get("screenshot", _pick_screenshotter)
    @property
    def enricher(self): return self._get("enricher", build_enricher)


def _avail(tool) -> bool:
    try:
        return bool(tool.available())
    except Exception:
        return False


# —— 各阶段（签名统一 (ctx, tools)->StageResult；工具缺失/无输入 skipped）——

def _stage_seed_intake(ctx: ReconContext, t: Tools) -> StageResult:
    """种子入线（铜钱 gate=always，所有 collect_mode 都跑）：下发目标/反查种子/已知资产无条件入
    ctx.hosts+domains——它们本身就是确定要处理的资产，绝不能因"跳枚举"被一起丢掉。
    **根治 single 卡死**：旧 _stage_subdomain 在 collect_mode=single 时直接 return，把这段种子入线也跳了
    → ctx.hosts 空 → site 阶段 fallback 到 ctx.targets 全量 httpx 探 → 卡死。拆成独立铜钱后 single 也入线。
    与"枚举扩散"(subfinder/massdns，见 _stage_subdomain)正交：入线是确定资产，枚举是扩散发现。"""
    roots = ctx.targets
    if not roots:
        return StageResult("seed_intake", skipped=True)
    from .models import DomainRec as _DR
    added = 0
    existing = {d.domain for d in ctx.domains}
    for _root in roots:
        _r = (_root or "").strip().lower().rstrip(".")
        if _r and _r not in existing:
            ctx.domains.append(_DR(domain=_r, record=[], type="SEED", ips=[], source="seed"))
            existing.add(_r)
            if _r not in ctx.hosts:
                ctx.hosts.append(_r)
            added += 1
    return StageResult("seed_intake", count=added, skipped=not added)


def _stage_subdomain(ctx: ReconContext, t: Tools) -> StageResult:
    """子域名**枚举扩散**（铜钱 gate=collect_mode∈{multi_passive,multi_brute}；single 不串本铜钱）——
      multi_passive= 多源被动枚举（subfinder），不爆破（跳 massdns，省资源/不惊动目标）；
      multi_brute  = 被动枚举 + 字典爆破（subfinder + massdns），默认档，覆盖最全。
    种子入线已由 _stage_seed_intake（gate=always）负责，本铜钱只做"在种子之上扩散发现新子域名"。
    net：single→只有种子(seed_intake)；passive→种子+subfinder；brute→种子+subfinder+massdns。"""
    roots = ctx.targets
    scope = set(roots)
    found = {}
    # 第三方收集源有效判据（FOFA 原生采集 或 subfinder API 增强源有凭据）：非空即有效。
    # 用户规则：第三方源有效时**不启用 subfinder 公共被动枚举**（跑全部内置默认源，逐域名串行、
    # 慢且与已知资产重复——卡死元凶，见 §卡死诊断）。第三方源已把资产捞回，只用它们即可；
    # 只有无任何第三方源时才退回公共枚举兜底（不丢子域发现能力）。
    _has_third_party = bool(ctx.options.get("_collection_source_credentials")) \
        or callable(ctx.options.get("_fofa_collector"))
    if _avail(t.subfinder):
        if not _has_third_party:
            # 无第三方源 → subfinder 公共被动枚举兜底
            for r in t.subfinder.enumerate(roots, scope=scope):
                found[r.domain] = r
        else:
            logging.getLogger(__name__).info(
                "子域枚举：检测到第三方收集源有效（FOFA/API 源），跳过 subfinder 公共被动枚举"
                "（省时/避免多域名串行卡死），仅用第三方源")
        # 策略页勾选的 API 增强源：凭据由 bridge fresh 读后仅在内存注入；subfinder 用临时 0600
        # provider-config 精确运行这些来源（Hunter 走此路，精准快）。失败只降级增强源。
        credentials = ctx.options.get("_collection_source_credentials") or {}
        if credentials and hasattr(t.subfinder, "enumerate_sources"):
            try:
                for r in t.subfinder.enumerate_sources(roots, credentials, scope=scope):
                    found.setdefault(r.domain, r)
            except ToolCancelled:
                raise
            except Exception as exc:
                logging.getLogger(__name__).warning("配置 API 子域来源降级: %s", exc)
    # FOFA 使用平台原生 key-only API 客户端（subfinder 的 FOFA 要 email:key，不能破坏存量配置）。
    fofa_collector = ctx.options.get("_fofa_collector")
    if callable(fofa_collector):
        try:
            for domain in fofa_collector(roots) or []:
                found.setdefault(domain, DomainRec(domain=domain, record=[], type="SUBDOMAIN",
                                                     ips=[], source="fofa"))
        except Exception as exc:
            logging.getLogger(__name__).warning("FOFA 广域子域来源降级: %s", exc)
    # 爆破门控（两重）：① collect_mode=multi_passive 明确「只被动不爆破」→ 绝不跑 massdns（不管
    # domain_brute，语义优先）；② multi_brute 下再看 domain_brute（前端「不爆破」下拉，缺失=兼容旧默认爆破）。
    _mode = (ctx.options.get("collect_mode") or "multi_brute").lower()
    _brute_on = (_mode == "multi_brute") and ctx.options.get("domain_brute", True)
    if _brute_on:
        words = ctx.options.get("brute_words") or []
        resolvers = ctx.options.get("resolvers", "")
        if words and resolvers and _avail(t.massdns):
            for root in roots:
                for r in t.massdns.brute(root, words, resolvers=resolvers, scope=scope):
                    found.setdefault(r.domain, r)
    if not found:
        return StageResult("subdomain", skipped=True)
    existing = {d.domain for d in ctx.domains}
    for d, rec in found.items():
        if d in existing:                       # 种子已入线的用枚举到的更全记录覆盖
            ctx.domains = [rec if x.domain == d else x for x in ctx.domains]
        else:
            ctx.domains.append(rec)
        if d not in ctx.hosts:
            ctx.hosts.append(d)
    dropped = _apply_blacklist_domains(ctx)   # 数据卫生：滤 WAF/CDN 泛域名/黑产（默认开可关）
    return StageResult("subdomain", count=len(found),
                       reason=("黑名单滤除 {} 域名".format(dropped) if dropped else ""))


def _stage_resolve(ctx: ReconContext, t: Tools) -> StageResult:
    """DNS 解析：dnsx 把 hosts（子域名 + 原始域名）解析成 A/CNAME，收集 IP。"""
    hosts = ctx.hosts or list(ctx.targets)
    if not hosts or not _avail(t.dnsx):
        return StageResult("resolve", skipped=True)
    # 与 massdns 共用 resolver 文件：不传则 dnsx 用内置境外默认 resolver，某些网络全超时→解析恒空。
    resolvers = ctx.options.get("resolvers", "")
    recs = t.dnsx.resolve(hosts, concurrency=ctx.io_concurrency(200), resolvers=resolvers)
    if not recs:
        return StageResult("resolve", skipped=True)
    byd = {d.domain: d for d in ctx.domains}
    for r in recs:
        byd[r.domain] = r                       # 解析结果覆盖被动枚举的空壳
    ctx.domains = list(byd.values())
    return StageResult("resolve", count=len(recs))


def _stage_resolve_ip_seed(ctx: ReconContext, t: Tools) -> StageResult:
    """域名任务：把 resolve 解析出的公网 IP 保底灌进 ctx.ips（问题5 修复，不受 port_scan 门控）。
    **负优化根因**：_stage_resolve 只把 IP 存进 ctx.domains[].ips（域名档），从不进 ctx.ips；而 ctx.ips
    才是落 ip 集合/算 ip_cnt 的来源。port_scan=false 时 portscan disabled → 域名解析出的 IP 蒸发
    （domain.ips 有值但 ip_cnt=0）。此阶段无条件把解析 IP 入 ctx.ips（公网+去重），不扫端口也显示 IP。"""
    if ctx.task_type != "domain":
        return StageResult("resolve_ip_seed", skipped=True)
    import ipaddress
    existing = {getattr(r, "ip", "") for r in ctx.ips}
    added = 0
    for d in (ctx.domains or []):
        for ip in (getattr(d, "ips", None) or []):
            ip = (ip or "").strip()
            try:
                v = ipaddress.ip_address(ip)
                if v.is_private or v.is_loopback or v.is_reserved or v.is_link_local or v.is_multicast:
                    continue
            except (ValueError, TypeError):
                continue
            if ip and ip not in existing:
                ctx.ips.append(IPRec(ip=ip))
                existing.add(ip)
                added += 1
    return StageResult("resolve_ip_seed", count=added, skipped=not added)


def _stage_ip_seed(ctx: ReconContext, t: Tools) -> StageResult:
    """IP 种子保底入库（IP 任务内置必跑，不受 port_scan 策略门控）。
    **负优化根因**：IP 任务(如单位反查的 13 个 IP)的 targets 本身是确定资产，但原来只有 portscan 阶段
    把 IP 灌进 ctx.ips；策略 port_scan=false 时 portscan 整个 disabled→IP 从没进 ctx.ips→ip 集合空、
    后续 site/归集拿不到→13 个反查 IP 全丢。种子 IP 是确定资产,不该因"不扫端口"就蒸发。
    此阶段把 targets 里的公网 IP 无条件建 IPRec 入 ctx.ips(按 IP 去重,与后续 portscan 若开则补端口不冲突)。"""
    if ctx.task_type != "ip":
        return StageResult("ip_seed", skipped=True)
    import ipaddress
    existing = {getattr(r, "ip", "") for r in ctx.ips}
    added = 0
    for tgt in ctx.targets:
        ip = (tgt or "").strip()
        try:
            v = ipaddress.ip_address(ip)
            if v.is_private or v.is_loopback or v.is_reserved or v.is_link_local or v.is_multicast:
                continue
        except (ValueError, TypeError):
            continue
        if ip and ip not in existing:
            ctx.ips.append(IPRec(ip=ip))
            existing.add(ip)
            added += 1
    return StageResult("ip_seed", count=added, skipped=not added)


def _stage_portscan(ctx: ReconContext, t: Tools) -> StageResult:
    """端口扫描：naabu。IP 任务扫 targets；域名任务扫解析出的 IP（无则回退 hosts）。"""
    if ctx.task_type == "ip":
        targets = list(ctx.targets)
    else:
        targets = ctx.ip_list() or ctx.hosts or list(ctx.targets)
    if not targets or not _avail(t.naabu):
        return StageResult("portscan", skipped=True)
    ports = ctx.options.get("ports", "top-1000")
    recs = t.naabu.scan(targets, ports=ports, concurrency=ctx.io_concurrency(500))
    if not recs:
        return StageResult("portscan", skipped=True)
    ctx.ips.extend(recs)
    return StageResult("portscan", count=len(recs))


def _stage_cert(ctx: ReconContext, t: Tools) -> StageResult:
    """SSL 证书抓取：对 ip:port 取证书（纯 Python，无外部二进制依赖）。"""
    pairs = []
    for ipr in ctx.ips:
        ip = getattr(ipr, "ip", "")
        for p in getattr(ipr, "ports", []) or []:
            pid = p.get("port_id") if isinstance(p, dict) else getattr(p, "port_id", None)
            if ip and pid:
                pairs.append("{}:{}".format(ip, pid))
    if not pairs or not _avail(t.certfetch):
        return StageResult("cert", skipped=True)
    recs = t.certfetch.fetch(pairs)
    ctx.certs.extend(recs)
    return StageResult("cert", count=len(recs), skipped=not recs)


def _stage_icmp(ctx: ReconContext, t: Tools) -> StageResult:
    """主机存活探测（native ICMP echo + TCP 降级）：对 hosts + ips 探活，产 AliveRec 存 ctx.alives。
    低危读探测（不改目标）；worker 有 NET_RAW 走 ICMP，无则降级 TCP。供主机/混合入口任务补充存活事实。"""
    targets = list(ctx.hosts)
    for ipr in ctx.ips:
        ip = getattr(ipr, "ip", "")
        if ip:
            targets.append(ip)
    if not targets:
        targets = list(ctx.targets)
    if not targets or not _avail(t.icmp):
        return StageResult("icmp", skipped=True)
    recs = t.icmp.ping(targets)
    ctx.alives.extend(recs)
    alive_n = sum(1 for r in recs if getattr(r, "alive", False))
    return StageResult("icmp", count=alive_n, skipped=not recs,
                       reason="探活 {} 台存活/{} 台".format(alive_n, len(recs)) if recs else "")


def _stage_site(ctx: ReconContext, t: Tools) -> StageResult:
    """站点探测 + 指纹：httpx 对 hosts + ip:port 探测存活站点。
    **分批探测**（防批量卡死）：目标切块逐批 probe，一批卡在慢目标不拖垮全部；配合 base.run 的
    cancel_check 穿透（httpx 子进程收到停止即被杀）。批大小随 io_concurrency，单批内 httpx 自身并发。"""
    targets = list(ctx.hosts)
    for ipr in ctx.ips:
        ip = getattr(ipr, "ip", "")
        for p in getattr(ipr, "ports", []) or []:
            pid = p.get("port_id") if isinstance(p, dict) else getattr(p, "port_id", None)
            if ip and pid:
                targets.append("{}:{}".format(ip, pid))
    if not targets:
        targets = list(ctx.targets)
    if not targets or not _avail(t.httpx):
        return StageResult("site", skipped=True)
    conc = ctx.io_concurrency(100)
    # 批大小 = 并发的若干倍（给 httpx 一批内充分并发），且设下限防批太小、不设死上限（禁硬 cap）。
    batch = max(conc * 2, 50)
    total_new = 0
    dropped = 0
    bl_on = ctx.options.get("blacklist_filter", True)
    seen_sites = {site.url for site in ctx.sites}

    def _accept_site(record):
        nonlocal total_new, dropped
        kept = _filter_site_batch([record]) if bl_on else [record]
        if not kept:
            dropped += 1
            return
        if record.url in seen_sites:
            return
        seen_sites.add(record.url)
        ctx.sites.append(record)
        total_new += 1
        ctx.emit_batch("site")

    probe_failed = 0
    for i in range(0, len(targets), batch):
        chunk = targets[i:i + batch]
        # 网络瞬时失败(ToolFailed)不该中止整个 site 阶段丢掉剩余目标(源查询在网络不稳时"只派发部分"的根因)：
        # 本批最多重试 3 次(退避)，全失败才计数、跳过本批、继续后续批——剩余目标仍能探通→落库→派发。
        recs = None
        for attempt in range(3):
            try:
                if callable(getattr(t.httpx, "probe_stream", None)):
                    t.httpx.probe_stream(chunk, on_record=_accept_site, concurrency=conc)
                    recs = []            # 流式经 _accept_site 已入列(seen_sites 去重)，无返回列表
                else:
                    recs = t.httpx.probe(chunk, concurrency=conc)
                break
            except Exception as exc:
                if attempt < 2:
                    logging.getLogger(__name__).warning(
                        "site 探测批次失败(第 %d/3 次，%ds 后重试): %s", attempt + 1, 2 * (attempt + 1), str(exc)[:150])
                    time.sleep(2 * (attempt + 1))
                    continue
                probe_failed += len(chunk)
                logging.getLogger(__name__).warning(
                    "site 探测批次重试 3 次仍失败，跳过本批 %d 目标(继续后续批): %s", len(chunk), str(exc)[:150])
        if recs is None:                 # 3 次全失败 → 跳过本批
            continue
        if not recs:                     # 流式路径(recs=[]) 或本批无结果
            continue
        # AUD-15：黑名单在**本批 emit 前**过滤——黑名单站点从不进 ctx.sites、不落库、不派发。
        # 修复前是全部批次探完+落库+派发后才 _apply_blacklist_sites(只改内存列表，已落库/已派发的收不回)。
        if bl_on:
            before = len(recs)
            recs = _filter_site_batch(recs)
            dropped += before - len(recs)
            if not recs:
                continue
        ctx.sites.extend(recs)
        total_new += len(recs)
        # 目标级流式：本批（已过滤）站点探通即触发增量落库+归集派发（不等全探完；幂等不重派）。
        ctx.emit_batch("site")
    reason = "黑名单滤除 {} 站点".format(dropped) if dropped else ""
    if probe_failed:
        reason = (reason + "；" if reason else "") + "网络失败跳过 {} 目标(未探测)".format(probe_failed)
    return StageResult("site", count=len(ctx.sites), skipped=not ctx.sites, reason=reason)


def _stage_enrich(ctx: ReconContext, t: Tools) -> StageResult:
    """对 IP/站点补 GeoIP、CDN、标签和主域；结果按物理标识暂存，序列化时合并。"""
    if not ctx.ips and not ctx.sites:
        return StageResult("enrich", skipped=True)
    enricher = t.enricher
    ip_rows = [asdict(r) if hasattr(r, "__dataclass_fields__") else dict(r) for r in ctx.ips]
    site_rows = [asdict(r) if hasattr(r, "__dataclass_fields__") else dict(r) for r in ctx.sites]
    enricher.enrich_ips(ip_rows)
    enricher.enrich_sites(site_rows)
    ctx.ip_enrichment.update({r.get("ip", ""): r for r in ip_rows if r.get("ip")})
    ctx.site_enrichment.update({(r.get("url") or r.get("site") or ""): r for r in site_rows
                                if r.get("url") or r.get("site")})
    return StageResult("enrich", count=len(ip_rows) + len(site_rows))


def _stage_screenshot(ctx: ReconContext, t: Tools) -> StageResult:
    """对存活站点截图；PhantomJS 不可用时诚实跳过。"""
    sites = ctx.site_urls()
    if not sites or not _avail(t.screenshot):
        return StageResult("screenshot", skipped=True)
    captured = t.screenshot.capture(sites, ctx.task_id)
    for site, path in (captured or {}).items():
        ctx.site_enrichment.setdefault(site, {})["screenshot"] = path
    return StageResult("screenshot", count=len(captured), skipped=not captured)


def _stage_webinfo(ctx: ReconContext, t: Tools) -> StageResult:
    """从站点 HTML/JS 提取接口、域名、IP、邮箱及敏感线索。"""
    sites = ctx.site_urls()
    if not sites or not _avail(t.webinfo):
        return StageResult("webinfo", skipped=True)
    recs = t.webinfo.hunt(sites)
    ctx.wih.extend(recs)
    return StageResult("webinfo", count=len(recs), skipped=not recs)


def _stage_crawl(ctx: ReconContext, t: Tools) -> StageResult:
    """爬虫：katana 爬已发现站点收集 URL。"""
    sites = ctx.site_urls()
    if not sites or not _avail(t.katana):
        return StageResult("crawl", skipped=True)
    recs = t.katana.crawl(sites)
    ctx.urls.extend(recs)
    return StageResult("crawl", count=len(recs), skipped=not recs)


def _stage_fileleak(ctx: ReconContext, t: Tools) -> StageResult:
    """文件泄漏：对站点做字典探测（纯 Python）。字典来自 options，无则用扫描器内置默认。"""
    sites = ctx.site_urls()
    if not sites or not _avail(t.fileleak):
        return StageResult("fileleak", skipped=True)
    recs = t.fileleak.scan(sites, wordlist=ctx.options.get("fileleak_words"))
    ctx.fileleaks.extend(recs)
    return StageResult("fileleak", count=len(recs), skipped=not recs)


def _stage_vhost(ctx: ReconContext, t: Tools) -> StageResult:
    """vhost 碰撞：同 IP 多域名探测补站点。用解析出的 hostname 集对每个 IP 试。
    **IP 分桶并行**：跨 IP 并行（不同 IP 是不同主机，互不限速）、同 IP 内 vhost.find 串行（其内部线程池已控）。
    并行宽度随 scan_parallelism（资源水位）；单 IP 时退化串行零开销。"""
    if not ctx.ips or not ctx.hosts or not _avail(t.vhost):
        return StageResult("vhost", skipped=True)
    ips = [getattr(ipr, "ip", "") for ipr in ctx.ips]
    ips = [ip for ip in ips if ip]
    if not ips:
        return StageResult("vhost", skipped=True)
    par = min(ctx.scan_parallelism(4), len(ips))
    if par <= 1 or len(ips) == 1:                    # 单 IP/低并发退化串行
        collected = [t.vhost.find(ip, ctx.hosts) for ip in ips]
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=par) as pool:  # 跨 IP 并行
            collected = list(pool.map(lambda ip: t.vhost.find(ip, ctx.hosts), ips))
    extra = 0
    for recs in collected:
        if recs:
            ctx.sites.extend(recs)
            extra += len(recs)
    return StageResult("vhost", count=extra, skipped=not extra)


def _stage_service(ctx: ReconContext, t: Tools) -> StageResult:
    """服务/版本识别：nmap -sV 回填各 IP 端口的 service_name/version/product。"""
    if not ctx.ips or not _avail(t.nmap):
        return StageResult("service", skipped=True)
    n = 0
    for ipr in ctx.ips:
        ip = getattr(ipr, "ip", "")
        pinfos = getattr(ipr, "ports", []) or []
        pids = [(p.get("port_id") if isinstance(p, dict) else getattr(p, "port_id", None)) for p in pinfos]
        pids = [x for x in pids if x]
        if not ip or not pids:
            continue
        detected = t.nmap.detect(ip, pids)
        # AUD-11：资源门超时降级 → 本阶段"根本没执行"，返回非终态 deferred_resource（不进 done_steps），
        # 恢复资源后重投会重跑，不把资源不足误报成"执行了无发现"（completed_empty 终态跳过续扫）。
        if isinstance(detected, dict) and detected.get("__degraded__"):
            return StageResult("service", count=0, ok=True, status="deferred_resource",
                               reason="资源门超时，服务识别未执行，待资源恢复后重扫")
        for p in pinfos:
            pid = p.get("port_id") if isinstance(p, dict) else getattr(p, "port_id", None)
            d = detected.get(pid)
            if d:
                if isinstance(p, dict):
                    p["service_name"] = getattr(d, "service_name", "") or p.get("service_name", "")
                    p["version"] = getattr(d, "version", "") or p.get("version", "")
                    p["product"] = getattr(d, "product", "") or p.get("product", "")
                else:                               # PortInfo dataclass：属性赋值回填
                    for attr in ("service_name", "version", "product"):
                        val = getattr(d, attr, "")
                        if val:
                            setattr(p, attr, val)
                n += 1
    return StageResult("service", count=n, skipped=not n)


def _stage_weakbrute(ctx: ReconContext, t: Tools) -> StageResult:
    """弱口令：对识别出的服务端口爆破（nmap NSE）。"""
    if not ctx.ips or not _avail(t.weakbrute):
        return StageResult("weakbrute", skipped=True)
    n = 0
    for ipr in ctx.ips:
        ip = getattr(ipr, "ip", "")
        for p in getattr(ipr, "ports", []) or []:
            pid = p.get("port_id") if isinstance(p, dict) else getattr(p, "port_id", None)
            svc = (p.get("service_name") if isinstance(p, dict) else getattr(p, "service_name", "")) or ""
            if not ip or not pid:
                continue
            recs = t.weakbrute.brute(ip, pid, svc or "http")
            if recs:
                ctx.vulns.extend(recs)
                n += len(recs)
    return StageResult("weakbrute", count=n, skipped=not n)


def _stage_poc(ctx: ReconContext, t: Tools) -> StageResult:
    """漏扫：nuclei 对存活站点扫。"""
    sites = ctx.site_urls() or list(ctx.targets)
    if not sites or not _avail(t.nuclei):
        return StageResult("poc", skipped=True)
    recs = t.nuclei.scan(sites, concurrency=ctx.io_concurrency(25))
    ctx.nuclei.extend(recs)
    return StageResult("poc", count=len(recs), skipped=not recs)


# ══════════════════════════════════════════════════════════════════════════════
# 铜钱串线（§十二）：每个能力=一枚铜钱 StageSpec，策略勾选→gate 决定串不串。
# 组装器 assemble_stages 按 gate 过滤 + 按 requires 拓扑排序，替代固定 _domain_stages/_ip_stages
# 与散落门控 _STAGE_OPTION/_stage_policy。加能力=加一枚 StageSpec，不动组装器/别的铜钱。
# ══════════════════════════════════════════════════════════════════════════════

# gate 辅助：策略开关型（缺失=默认跑，兼容旧任务；显式 False 才 off——对齐旧 _STAGE_OPTION 语义）
def _opt_on(key: str):
    def g(ctx: "ReconContext"):
        v = ctx.options.get(key, True)          # 缺失默认 True（旧任务/内部调用兼容）
        return (True, "") if bool(v) else (False, "policy {} disabled".format(key))
    return g


def _collect_enum_on(ctx: "ReconContext"):
    """子域名枚举扩散：collect_mode∈{multi_passive,multi_brute} 才串；single 不串（只入种子）。"""
    mode = (ctx.options.get("collect_mode") or "multi_brute").lower()
    return (True, "") if mode in ("multi_passive", "multi_brute") else (False, "collect_mode=single 不枚举子域名")


def _weakbrute_on(ctx: "ReconContext"):
    if "brute_config" in ctx.options and not (ctx.options.get("brute_config") or []):
        return (False, "brute_config empty")
    return (True, "")


def _disabled_active_scan(ctx: "ReconContext"):
    """全局禁用主动扫描（用户明令 2026-08-28）：poc(nuclei)/weakbrute 铜钱无论策略是否勾选都不串。
    nuclei 类主动漏扫/弱口令爆破极易触发目标防火墙记录、IP 封禁，全局禁绝。AI 工具层同步全局禁
    （_tools._ACTIVE_SCAN_TOOLS），底层 recon_bridge 三方法加硬保险。将来恢复：把下方 STAGE_SPECS
    里 poc/weakbrute 的 gate 换回 _opt_on("nuclei_scan")/_weakbrute_on 即可（原 gate 函数保留未删）。"""
    return (False, "主动扫描已全局禁用（易触发防火墙/封IP，用户明令）")


def _always(ctx: "ReconContext"):
    return (True, "")


def _icmp_on(ctx: "ReconContext"):
    """ICMP 主机存活探测串线条件：仅按显式策略开关 icmp_ping 判（勾了才探）；缺省不探（保守，不改旧任务行为）。"""
    v = ctx.options.get("icmp_ping")
    return (True, "") if bool(v) else (False, "policy icmp_ping disabled")


@dataclass
class StageSpec:
    """一枚铜钱：name 唯一名、run 执行体(签名不变 (ctx,t)->StageResult)、requires 依赖前序铜钱、
    gate 串线条件(返回 (on:bool, reason))、applies 适用任务类型(domain/ip/both)。"""
    name: str
    run: Callable[["ReconContext", "Tools"], StageResult]
    requires: tuple = ()
    gate: Callable[["ReconContext"], tuple] = _always
    applies: str = "both"          # domain / ip / both


# 铜钱注册表（声明顺序 = 同依赖层的稳定序，与旧固定列表一致）。gate 默认态精确对齐旧 _STAGE_OPTION：
# portscan/cert/... 缺失开关=跑（兼容旧任务），显式 false 才 off。唯一行为变更=single 修正(种子入线)。
STAGE_SPECS: List[StageSpec] = [
    StageSpec("seed_intake", _stage_seed_intake, (), _always, "domain"),          # 域名种子入线(single也跑)
    StageSpec("subdomain", _stage_subdomain, ("seed_intake",), _collect_enum_on, "domain"),
    StageSpec("resolve", _stage_resolve, ("seed_intake",), _always, "domain"),     # 有域名才有产出(自然skip)
    StageSpec("resolve_ip_seed", _stage_resolve_ip_seed, ("resolve",), _always, "domain"),  # 解析IP保底入线(问题5:不扫端口也显示IP)
    StageSpec("ip_seed", _stage_ip_seed, (), _always, "ip"),                       # IP种子入线
    StageSpec("icmp", _stage_icmp, ("seed_intake", "ip_seed"), _icmp_on),           # 主机存活探测(host/hybrid入口)
    StageSpec("portscan", _stage_portscan, (), _opt_on("port_scan")),
    StageSpec("cert", _stage_cert, ("portscan",), _opt_on("ssl_cert")),
    StageSpec("site", _stage_site, ("resolve", "resolve_ip_seed", "portscan", "ip_seed", "seed_intake"), _always),  # 默认串(归集入口)
    StageSpec("enrich", _stage_enrich, ("site",), _always),                        # 零外呼富化
    StageSpec("screenshot", _stage_screenshot, ("site",), _opt_on("site_capture")),
    StageSpec("webinfo", _stage_webinfo, ("site",), _opt_on("web_info_hunter")),
    StageSpec("crawl", _stage_crawl, ("site",), _opt_on("site_spider")),
    StageSpec("fileleak", _stage_fileleak, ("site",), _opt_on("file_leak")),
    StageSpec("vhost", _stage_vhost, ("site",), _opt_on("findvhost")),
    StageSpec("service", _stage_service, ("portscan",), _opt_on("service_detection")),
    StageSpec("weakbrute", _stage_weakbrute, ("service",), _disabled_active_scan),  # 全局禁(原 _weakbrute_on)
    StageSpec("poc", _stage_poc, ("site",), _disabled_active_scan),                 # 全局禁(原 _opt_on("nuclei_scan"))
]

_SPEC_BY_NAME = {s.name: s for s in STAGE_SPECS}


def assemble_stages(ctx: "ReconContext") -> tuple:
    """按 task_type 适用性 + gate 过滤出「串上的铜钱」，再按 requires 稳定拓扑排序。
    返回 (selected_specs, disabled)：selected 进执行链；disabled=[(name,reason)] 供 summary 记 disabled
    （前端可见性：gate=off 的阶段仍显示"跳过"，不静默消失）。"""
    ttype = ctx.task_type or "domain"
    all_names = [spec.name for spec in STAGE_SPECS]
    if len(set(all_names)) != len(all_names):
        raise ValueError("铜钱注册表存在重复阶段名")
    for spec in STAGE_SPECS:
        if any(name not in all_names for name in spec.requires):
            raise ValueError("铜钱 {} 声明了不存在的依赖".format(spec.name))
    selected, disabled = [], []
    for spec in STAGE_SPECS:
        if spec.applies not in ("both", ttype):
            continue                              # 不适用当前任务类型（如 ip 任务不串 subdomain）
        on, reason = spec.gate(ctx)
        if on:
            selected.append(spec)
        else:
            disabled.append((spec.name, reason))
    # 稳定拓扑排序：按声明顺序遍历，依赖未满足的往后推（依赖已被 gate 滤掉的忽略——不阻塞）
    ordered, placed = [], set()
    pool = list(selected)
    sel_names = {s.name for s in selected}
    guard = 0
    while pool and guard <= len(selected):
        guard += 1
        progressed = False
        rest = []
        for spec in pool:
            deps = [d for d in spec.requires if d in sel_names]   # 只等仍在选中集里的依赖
            if all(d in placed for d in deps):
                ordered.append(spec); placed.add(spec.name); progressed = True
            else:
                rest.append(spec)
        pool = rest
        if not progressed:
            raise ValueError("铜钱依赖存在环：{}".format(", ".join(spec.name for spec in pool)))
    return ordered, disabled


def _apply_blacklist_domains(ctx: ReconContext) -> int:
    """滤黑名单域名（策略 blacklist_filter 默认开；关则跳过）。缺模块/异常降级不阻断。"""
    if not ctx.options.get("blacklist_filter", True):
        return 0
    try:
        from . import blacklist
        return blacklist.filter_domains(ctx)
    except Exception:
        return 0


def _filter_site_batch(recs: list) -> list:
    """滤本批黑名单站点（AUD-15：落库/派发前过滤）。缺模块/异常降级=不过滤（返回原批，不阻断探测）。"""
    try:
        from . import blacklist
        return blacklist.filter_site_batch(recs)
    except Exception:
        return recs


# _stage_policy 已被铜钱 gate 取代（组装期决定串不串，见 assemble_stages/STAGE_SPECS）。


class Pipeline:
    """按阶段列表驱动一次侦察。协作式取消（cancel_check 边界查，见停止抛 Stopped，不吞）；
    单阶段异常隔离——记 StageResult(ok=False) 后继续（一个阶段挂不整体崩），Stopped 例外直接抛。

    **断点续扫**：ctx.done_steps 里的阶段跳过不重扫（重投时 bridge 从 task.checkpoint 载入）。
    **流式回调**：每阶段完成后调 on_stage(ctx, stage_name)——供 bridge 增量落库 + 边探边派渗透。"""

    def __init__(self, stages: List, cancel_check: CancelCheck = None, on_stage: OnStage = None,
                 budget_provider: Optional[Callable[[], Dict[str, Any]]] = None,
                 resource_gate=None):
        self.stages = stages
        self.cancel_check = cancel_check
        self.on_stage = on_stage
        self.budget_provider = budget_provider
        self.resource_gate = resource_gate

    def _check_cancel(self, stage_name: str) -> None:
        if self.cancel_check:
            try:
                stopped = self.cancel_check()
            except Exception:
                stopped = False
            if stopped:
                raise StoppedException("pipeline stopped before stage {}".format(stage_name))

    def run(self, ctx: ReconContext, tools: Tools) -> ReconContext:
        # 批级流式：把 on_stage 注入 ctx.on_batch，供 site 阶段每批探通即触发增量落库+派发
        # （目标级流式——一批站点探通就派 AI，不等整阶段所有目标探完；幂等派发保证不重派）。
        if self.on_stage:
            ctx.on_batch = self.on_stage
        if self.resource_gate is not None:      # 资源门也暴露到 ctx，供阶段函数直接取用（问题11）
            ctx.resource_gate = self.resource_gate
        # self.stages 现为已组装的 StageSpec 列表（gate 已在组装期过滤，进这里的都是该串的铜钱）。
        # 兼容：也接受裸函数（旧调用/测试），此时用函数名。
        for stage in self.stages:
            run_fn = getattr(stage, "run", stage)
            name = getattr(stage, "name", None) or getattr(stage, "__name__", "stage").replace("_stage_", "")
            if ctx.is_done(name):                    # 断点续扫：已完成阶段跳过不重扫
                continue
            self._check_cancel(name)                # 阶段边界协作式取消
            if self.budget_provider:
                try:
                    budget = self.budget_provider() or {}
                    if budget.get("io_concurrency"):
                        ctx.options["io_concurrency"] = int(budget["io_concurrency"])
                        tools._io = int(budget["io_concurrency"])
                    if budget.get("scan_parallelism"):
                        ctx.options["scan_parallelism"] = int(budget["scan_parallelism"])
                except Exception:
                    pass
            try:
                r = run_fn(ctx, tools)
            except StoppedException:
                raise                                # 取消直接上抛，不当失败
            except ToolCancelled as exc:
                # 外部工具执行中被协作式取消穿透中断（子进程已杀）→ 转停止上抛，不当 stage 失败
                raise StoppedException("pipeline stopped in stage {} ({})".format(name, exc)) from exc
            except Exception as exc:
                r = StageResult(name, ok=False, error=str(exc)[:300])
            ctx.add_result(r)
            if self.on_stage:                        # 流式回调：增量落库 + 边探边派（异常不反噬扫描）
                try:
                    self.on_stage(ctx, name)
                except Exception as exc:
                    logging.getLogger(__name__).warning("on_stage callback failed [%s]: %s", name, exc)
                    pass
        return ctx


def _restore_context(ctx: ReconContext, records: Dict[str, Any]) -> None:
    """从同一 task 的持久化记录恢复阶段中间态；只恢复已完成阶段的成品数据。"""
    def _port(value):
        if isinstance(value, PortInfo):
            return value
        if not isinstance(value, dict):
            return None
        try:
            return PortInfo(port_id=int(value.get("port_id") or value.get("port") or 0),
                            service_name=value.get("service_name", ""), version=value.get("version", ""),
                            protocol=value.get("protocol", "tcp"), product=value.get("product", ""))
        except (TypeError, ValueError):
            return None

    for row in records.get("domain", []) or []:
        if not isinstance(row, dict) or not row.get("domain"):
            continue
        rec = DomainRec(domain=str(row["domain"]), record=list(row.get("record") or []),
                        type=row.get("type", "A"), ips=list(row.get("ips") or []),
                        source=row.get("source", "recon"))
        ctx.domains.append(rec)
        if rec.domain not in ctx.hosts:
            ctx.hosts.append(rec.domain)
    for row in records.get("ip", []) or []:
        if not isinstance(row, dict) or not row.get("ip"):
            continue
        ports = [_port(p) for p in (row.get("ports") or row.get("port_info") or [])]
        ctx.ips.append(IPRec(ip=str(row["ip"]), ports=[p for p in ports if p],
                            domains=list(row.get("domains") or row.get("domain") or [])))
    for row in records.get("site", []) or []:
        if not isinstance(row, dict):
            continue
        url = row.get("site") or row.get("url")
        if not url:
            continue
        ctx.sites.append(SiteRec(url=str(url), hostname=row.get("hostname", ""), ip=row.get("ip", ""),
                                 title=row.get("title", ""), status=int(row.get("status") or 0),
                                 headers=row.get("headers", ""), http_server=row.get("http_server", ""),
                                 body_length=int(row.get("body_length") or 0), finger=list(row.get("finger") or []),
                                 favicon=dict(row.get("favicon") or {})))
        extra = {k: row[k] for k in ("tag", "fld", "screenshot") if row.get(k) not in (None, "", [])}
        if extra:
            ctx.site_enrichment[str(url)] = extra


def run_pipeline(task_id: str, task_type: str, target: Any, options: Optional[Dict[str, Any]] = None,
                 tools: Optional[Tools] = None, cancel_check: CancelCheck = None,
                 on_stage: OnStage = None, done_steps: Optional[List[str]] = None,
                 budget_provider: Optional[Callable[[], Dict[str, Any]]] = None,
                 initial_records: Optional[Dict[str, Any]] = None,
                 resource_gate=None) -> Dict[str, Any]:
    """侦察入口：建 ReconContext → 选 domain/ip 阶段列表 → Pipeline.run → 返回摘要 dict。

    返回 {result: done|stopped|error, task_id, task_type, stages, skipped, counts, records, error}。
    协作式取消 → result=stopped（保留已跑阶段产物）。工具全缺 → 各阶段 skipped，result=done（空产物）。
    **断点续扫**：done_steps 里的阶段跳过。**流式**：on_stage(ctx,stage) 每阶段后调（bridge 增量落库+派发）。
    """
    targets = [target] if isinstance(target, str) else [str(t) for t in (target or [])]
    targets = [t.strip().lower() for t in targets if t and str(t).strip()]
    ctx = ReconContext(task_id=task_id, task_type=task_type or "domain",
                       targets=targets, options=options or {},
                       done_steps=list(done_steps or []))
    if initial_records:
        _restore_context(ctx, initial_records)
    # 铜钱串线：按策略 gate 组装出本次要串的铜钱（+ 拓扑排序），替代固定 _domain_stages/_ip_stages。
    stages, disabled = assemble_stages(ctx)
    # gate=off 的铜钱记进 ctx（前端可见性：策略未勾的阶段显示"跳过"，不静默消失）。
    for _name, _reason in disabled:
        ctx.add_result(StageResult(_name, skipped=True, status="disabled", reason=_reason))
    pl = Pipeline(stages, cancel_check=cancel_check, on_stage=on_stage,
                  budget_provider=budget_provider, resource_gate=resource_gate)
    out: Dict[str, Any] = {"result": "done", "task_id": task_id, "task_type": ctx.task_type,
                           "stages": [], "skipped": [], "counts": {}, "stage_status": {},
                           "records": {}, "error": None}
    try:
        # 建默认 Tools 时注入 cancel_check：使外部工具阻塞执行能被协作式取消穿透中断
        # （传入的 tools 若已构造则沿用其自身 cancel_check 配置，不覆盖）。
        pl.run(ctx, tools or Tools(io_concurrency=ctx.io_concurrency(0),
                                   cancel_check=cancel_check, resource_gate=resource_gate))
    except StoppedException as e:
        out["result"] = "stopped"
        out["error"] = str(e)
    summ = ctx.summary()
    out["stages"] = summ["stages"]
    out["skipped"] = summ["skipped"]
    out["counts"] = summ["counts"]
    out["stage_status"] = summ["stage_status"]
    # 单个（可选）阶段失败不冒泡成整任务 error——§11.4 设计：阶段 skip/降级是正常行为。
    # 只有「全程零资产产出」（所有阶段都没拿到任何记录）才算致命失败判 error；
    # 否则记为 done + 记录 failed_stages（降级告警），任务照常收尾（回填 end_time）。
    # 治「naabu 失败即把已产出 site/wih 的任务误判 error 且 end_time 不回填」。
    failed = [name for name, state in summ["stage_status"].items() if state.get("status") == "failed"]
    total_records = sum(len(v) for v in summ.get("records", {}).values())
    out["failed_stages"] = failed
    if failed and out["result"] == "done":
        if total_records == 0:
            # 致命：一个资产都没产出（下发目标本身解析/探活全挂）→ 真 error
            out["result"] = "error"
            out["error"] = "failed stages (no assets produced): {}".format(",".join(failed))
        else:
            # 有产出：可选阶段失败降级为告警，任务算完成，不阻断收尾
            out["error"] = None
            out["degraded"] = "failed stages (degraded, task still done): {}".format(",".join(failed))
    # records 转 list[dict]（对齐 §0.3 可序列化；dataclass→dict），并合并富化/截图扩展字段。
    records = {}
    for key, values in summ["records"].items():
        rows = []
        for value in values:
            row = asdict(value) if hasattr(value, "__dataclass_fields__") else dict(value)
            if key == "ip":
                row.update(ctx.ip_enrichment.get(row.get("ip", ""), {}))
            elif key == "site":
                site_key = row.get("url") or row.get("site") or ""
                row.update(ctx.site_enrichment.get(site_key, {}))
                if "url" in row and "site" not in row:
                    row["site"] = row["url"]
            rows.append(row)
        if rows:
            records[key] = rows
    out["records"] = records
    return out

