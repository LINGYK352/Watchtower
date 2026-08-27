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
from dataclasses import asdict
from typing import Any, Callable, Dict, List, Optional

from .context import ReconContext, StageResult, StoppedException, CancelCheck, OnStage
from .models import DomainRec, IPRec, SiteRec, PortInfo
from .tools import Subfinder, Massdns, Dnsx, Naabu, NmapService, Httpx, Nuclei, WeakBrute
from .tools.katana import Katana
from .native.certfetch import CertFetcher
from .native.fileleak import FileLeakScanner
from .native.vhost import VhostFinder
from .webinfo import WebInfoHunter
from .native.screenshot import Screenshot
from .enrich import build_enricher


class Tools:
    """工具持有器（懒实例化 + 可注入替身供测试）。每工具一实例，pipeline 各阶段共享。
    `io_concurrency`（>0）随资源水位注入 native IO 工具（fileleak/vhost/certfetch）的并发度，缺省用各自默认。"""

    def __init__(self, io_concurrency: int = 0, **overrides):
        self._o = overrides
        self._io = max(0, int(io_concurrency or 0))

    def _get(self, key, factory):
        if key in self._o:
            return self._o[key]
        inst = factory()
        self._o[key] = inst
        return inst

    def _get_io(self, key, cls):
        """native IO 工具：水位 >0 则用它作 concurrency，否则用类默认（不注入 = 保持默认）。"""
        if key in self._o:
            return self._o[key]
        inst = cls(concurrency=self._io) if self._io > 0 else cls()
        self._o[key] = inst
        return inst

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
    def nuclei(self): return self._get("nuclei", Nuclei)
    @property
    def weakbrute(self): return self._get("weakbrute", WeakBrute)
    @property
    def webinfo(self): return self._get("webinfo", WebInfoHunter)
    @property
    def screenshot(self): return self._get("screenshot", Screenshot)
    @property
    def enricher(self): return self._get("enricher", build_enricher)


def _avail(tool) -> bool:
    try:
        return bool(tool.available())
    except Exception:
        return False


# —— 各阶段（签名统一 (ctx, tools)->StageResult；工具缺失/无输入 skipped）——

def _stage_subdomain(ctx: ReconContext, t: Tools) -> StageResult:
    """子域名发现：按 collect_mode 三档分流（对齐策略 policy.collect_mode / 记忆 dengta-v2758 语义）——
      single       = 只打下发目标，不做子域名枚举（不 subfinder 不 massdns）；
      multi_passive= 多源被动枚举（subfinder），不爆破（跳 massdns，省资源/不惊动目标）；
      multi_brute  = 被动枚举 + 字典爆破（subfinder + massdns），默认档，覆盖最全。
    净室迁移曾丢此分流：collect_mode 存在 policy 却无人消费，三档执行完全一样（single 不跳枚举、
    passive 照样爆破）。缺省 multi_brute 兼容存量/内部调用。"""
    collect_mode = (ctx.options.get("collect_mode") or "multi_brute").lower()
    if collect_mode == "single":
        return StageResult("subdomain", skipped=True, status="disabled",
                           reason="collect_mode=single 只打下发目标，不枚举子域名")
    roots = ctx.targets
    scope = set(roots)
    found = {}
    # **种子域名（下发目标/单位反查种子）无条件先入 found —— 它们本身就是确定要扫的资产，绝不能只留
    # subfinder 枚举结果而丢掉种子本身**（负优化根因：原来只 found=subfinder结果，种子若没被被动源枚举到
    # 就整个丢失。实测单位反查 34 域名里 .cn 系列 subfinder 没返回→全丢，只剩 subfinder 枚举到的 12 个 .com。
    # 种子能解析的后续 resolve 出 IP/建站，解析不出的至少保留 domain 记录，不静默蒸发）。
    from .models import DomainRec as _DR
    for _root in roots:
        _r = (_root or "").strip().lower().rstrip(".")
        if _r:
            found[_r] = _DR(domain=_r, record=[], type="SEED", ips=[], source="unit_seed")
    if _avail(t.subfinder):
        for r in t.subfinder.enumerate(roots, scope=scope):
            found[r.domain] = r   # subfinder 枚举结果覆盖/追加（种子若被枚举到则用更全的记录）
    # 爆破门控（2026-08 两档简化后）：domain_brute=False（前端「不爆破」下拉，policy 归一落盘）时绝不跑 massdns，
    # 保证"前端选不爆破=后台真不跑"。domain_brute 缺失=兼容旧任务默认爆破。广域目标默认爆破+被动都做。
    if ctx.options.get("domain_brute", True):
        words = ctx.options.get("brute_words") or []
        resolvers = ctx.options.get("resolvers", "")
        if words and resolvers and _avail(t.massdns):
            for root in roots:
                for r in t.massdns.brute(root, words, resolvers=resolvers, scope=scope):
                    found.setdefault(r.domain, r)
    if not found:
        return StageResult("subdomain", skipped=True)
    for d, rec in found.items():
        ctx.domains.append(rec)
        if d not in ctx.hosts:
            ctx.hosts.append(d)
    dropped = _apply_blacklist_domains(ctx)   # 数据卫生：滤 WAF/CDN 泛域名/黑产（默认开可关）
    return StageResult("subdomain", count=len(ctx.hosts),
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


def _stage_site(ctx: ReconContext, t: Tools) -> StageResult:
    """站点探测 + 指纹：httpx 对 hosts + ip:port 探测存活站点。"""
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
    recs = t.httpx.probe(targets, concurrency=ctx.io_concurrency(100))
    ctx.sites.extend(recs)
    dropped = _apply_blacklist_sites(ctx)     # 数据卫生：滤黑名单站点（默认开可关）
    return StageResult("site", count=len(ctx.sites), skipped=not ctx.sites,
                       reason=("黑名单滤除 {} 站点".format(dropped) if dropped else ""))


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


def _domain_stages() -> List:
    """域名任务阶段列表（子域名→解析→端口→证书→站点→爬取→泄漏→vhost→服务→弱口令→漏扫）。"""
    return [_stage_subdomain, _stage_resolve, _stage_portscan, _stage_cert, _stage_site,
            _stage_enrich, _stage_screenshot, _stage_webinfo, _stage_crawl, _stage_fileleak,
            _stage_vhost, _stage_service, _stage_weakbrute, _stage_poc]


def _ip_stages() -> List:
    """IP 任务阶段列表（省"子域名/解析",IP种子保底入库→端口→…）。
    _stage_ip_seed 打头：IP 种子无条件入 ctx.ips(内置必跑,不受 port_scan 门控)，防 portscan 关时 IP 全丢。"""
    return [_stage_ip_seed, _stage_portscan, _stage_cert, _stage_site, _stage_enrich, _stage_screenshot,
            _stage_webinfo, _stage_crawl, _stage_fileleak, _stage_vhost, _stage_service,
            _stage_weakbrute, _stage_poc]


# 策略展开后为扁平 options。字段缺失表示旧任务/内部调用，保持兼容执行；显式 False 才关闭。
# 策略开关 → 阶段门控映射。**site 站点探测阶段刻意不在此**：站点探测(httpx 探活+基础指纹)是
# 内置必跑能力（对齐 ARL 原版 run()：fetch_site 无条件调用，只有 site_identify 指纹层受开关控）。
# 净室曾误把 site 探测绑死在 site_identify 上 → 关掉"站点识别"连站点都不发现 → site 集合空 →
# 归集 0 资产 → AI 渗透无目标（实测单位名任务 domain=12/resolve=11 却 site=0 asset=0 的直接原因）。
# httpx 已带 -tech-detect 一次性出指纹随 site 落库给 AI，ARL 的 web_analyze 额外指纹层净室未迁移，
# 故 site_identify 当前无独立执行体（保留字段兼容前端/schema，未来迁 web_analyze 补充指纹层再挂）。
_STAGE_OPTION = {
    "portscan": "port_scan", "cert": "ssl_cert",
    "screenshot": "site_capture", "webinfo": "web_info_hunter", "crawl": "site_spider",
    "fileleak": "file_leak", "service": "service_detection", "poc": "nuclei_scan",
}


def _apply_blacklist_domains(ctx: ReconContext) -> int:
    """滤黑名单域名（策略 blacklist_filter 默认开；关则跳过）。缺模块/异常降级不阻断。"""
    if not ctx.options.get("blacklist_filter", True):
        return 0
    try:
        from . import blacklist
        return blacklist.filter_domains(ctx)
    except Exception:
        return 0


def _apply_blacklist_sites(ctx: ReconContext) -> int:
    """滤黑名单站点（策略 blacklist_filter 默认开；关则跳过）。缺模块/异常降级不阻断。"""
    if not ctx.options.get("blacklist_filter", True):
        return 0
    try:
        from . import blacklist
        return blacklist.filter_sites(ctx)
    except Exception:
        return 0


def _stage_policy(ctx: ReconContext, stage_name: str) -> Optional[StageResult]:
    """策略已关闭时返回终态，确保对应目标请求不会发生。"""
    key = _STAGE_OPTION.get(stage_name)
    if key and key in ctx.options and not bool(ctx.options.get(key)):
        return StageResult(stage_name, skipped=True, status="disabled",
                           reason="policy option {} disabled".format(key))
    if stage_name == "weakbrute" and "brute_config" in ctx.options and not (ctx.options.get("brute_config") or []):
        return StageResult(stage_name, skipped=True, status="disabled",
                           reason="policy brute_config empty")
    return None


class Pipeline:
    """按阶段列表驱动一次侦察。协作式取消（cancel_check 边界查，见停止抛 Stopped，不吞）；
    单阶段异常隔离——记 StageResult(ok=False) 后继续（一个阶段挂不整体崩），Stopped 例外直接抛。

    **断点续扫**：ctx.done_steps 里的阶段跳过不重扫（重投时 bridge 从 task.checkpoint 载入）。
    **流式回调**：每阶段完成后调 on_stage(ctx, stage_name)——供 bridge 增量落库 + 边探边派渗透。"""

    def __init__(self, stages: List, cancel_check: CancelCheck = None, on_stage: OnStage = None,
                 budget_provider: Optional[Callable[[], Dict[str, Any]]] = None):
        self.stages = stages
        self.cancel_check = cancel_check
        self.on_stage = on_stage
        self.budget_provider = budget_provider

    def _check_cancel(self, stage_name: str) -> None:
        if self.cancel_check:
            try:
                stopped = self.cancel_check()
            except Exception:
                stopped = False
            if stopped:
                raise StoppedException("pipeline stopped before stage {}".format(stage_name))

    def run(self, ctx: ReconContext, tools: Tools) -> ReconContext:
        for stage in self.stages:
            name = getattr(stage, "__name__", "stage").replace("_stage_", "")
            if ctx.is_done(name):                    # 断点续扫：已完成阶段跳过不重扫
                continue
            self._check_cancel(name)                # 阶段边界协作式取消
            policy_result = _stage_policy(ctx, name)
            if policy_result is not None:
                ctx.add_result(policy_result)
                if self.on_stage:
                    try:
                        self.on_stage(ctx, name)
                    except Exception as exc:
                        logging.getLogger(__name__).warning("on_stage callback failed [%s]: %s", name, exc)
                continue
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
                r = stage(ctx, tools)
            except StoppedException:
                raise                                # 取消直接上抛，不当失败
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
                 initial_records: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
    stages = _ip_stages() if ctx.task_type == "ip" else _domain_stages()
    pl = Pipeline(stages, cancel_check=cancel_check, on_stage=on_stage,
                  budget_provider=budget_provider)
    out: Dict[str, Any] = {"result": "done", "task_id": task_id, "task_type": ctx.task_type,
                           "stages": [], "skipped": [], "counts": {}, "stage_status": {},
                           "records": {}, "error": None}
    try:
        pl.run(ctx, tools or Tools(io_concurrency=ctx.io_concurrency(0)))
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

