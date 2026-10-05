"""ReconContext —— 一次侦察运行的共享上下文（pipeline 阶段间传递中间态）。

阶段解耦靠它：subfinder/massdns 往 domains 写、dnsx 读 hosts 写 domains、naabu 读 hosts/ips
写 ips、httpx 读 sites 目标写 sites……每阶段只读上游产物、写自己产物，不直接互相调用。

**完全自包含**（对齐 recon 子包铁律：不 import core/contracts/app）——只依赖同子包 models +
stdlib。协作式取消用注入的 `cancel_check` callable（阶段边界调，见停止抛 StoppedException），
不碰 DB（DB 是消费方/orchestration 的事，pipeline 只算不落）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .models import (DomainRec, IPRec, SiteRec, CertRec, UrlRec, VulnRec,
                     NucleiRec, FileLeakRec)


class StoppedException(RuntimeError):
    """协作式取消：cancel_check 在阶段边界查到停止态时抛出，中止 pipeline（不吞，交调用方）。"""


@dataclass
class StageResult:
    """一个阶段的执行摘要（供运行报告 / 排障）。"""
    name: str
    count: int = 0                 # 本阶段产出记录数
    ok: bool = True
    skipped: bool = False          # 兼容旧调用；新代码以 status 表达具体原因
    error: str = ""
    status: str = ""               # completed/completed_empty/disabled/unavailable/not_applicable/failed
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status:
            return
        if not self.ok:
            self.status = "failed"
        elif self.skipped:
            self.status = "completed_empty"
        else:
            self.status = "completed" if self.count else "completed_empty"

    @property
    def terminal(self) -> bool:
        """除失败/资源延后外均为已判定终态，重投不再重复打目标。
        AUD-11：deferred_resource（资源门超时未执行）与 failed 一样**非终态**——不加进 done_steps，
        恢复资源后重投会重跑该阶段，不把"根本没执行"误当"执行了无发现"。"""
        return self.status not in ("failed", "deferred_resource")


@dataclass
class ReconContext:
    """侦察运行上下文。中间态字段由各阶段填充，下游读取；results 汇运行摘要。"""
    task_id: str = ""
    task_type: str = "domain"                       # domain / ip
    targets: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)

    # —— 阶段间中间态（各阶段读上游/写自己）——
    hosts: List[str] = field(default_factory=list)          # 待解析主机名（子域名枚举产出）
    domains: List[DomainRec] = field(default_factory=list)
    ips: List[IPRec] = field(default_factory=list)
    sites: List[SiteRec] = field(default_factory=list)
    certs: List[CertRec] = field(default_factory=list)
    urls: List[UrlRec] = field(default_factory=list)
    vulns: List[VulnRec] = field(default_factory=list)
    nuclei: List[NucleiRec] = field(default_factory=list)
    fileleaks: List[FileLeakRec] = field(default_factory=list)
    wih: List[Any] = field(default_factory=list)
    alives: List[Any] = field(default_factory=list)         # 主机存活探测结果（AliveRec，ICMP/TCP）

    # 富化字段（ip_type/geo/tag/fld）不在冻结 dataclass 上，按物理标识暂存在此，summary 时合并进 dict。
    ip_enrichment: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    site_enrichment: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    results: List[StageResult] = field(default_factory=list)

    # —— 断点续扫：已完成阶段集合（重投时跳过，不重扫）——
    done_steps: List[str] = field(default_factory=list)

    # —— 批级流式回调（Pipeline 注入）：站点阶段每批探通即调 on_batch(ctx, stage_name)，
    # 触发增量落库 + 归集派发（目标级流式：一批站点探通就派 AI，不等整阶段所有目标探完）。
    # 幂等派发保证多次触发不重派（asset_key upsert + skip_pentested）。None 时不回调（向后兼容）。
    on_batch: Optional[Callable[["ReconContext", str], None]] = None

    # —— 资源门（recon_bridge 从外部注入的纯 callable，守 recon 自包含铁律）——
    # gate(tool_name) 返回一个上下文管理器：内存足即放行、不足则阻塞等待并让位 AI（写 task.resource_wait
    # 徽标 + 轮询），超时/取消诚实降级。recon/ 内部只调这个注入的 callable，绝不 import 资源池（问题11）。
    # None 时不做资源门控（向后兼容/单测）。
    resource_gate: Optional[Callable[[str], Any]] = None

    def emit_batch(self, stage_name: str) -> None:
        """站点阶段批间调用：触发一次流式落库+派发。异常全吞（绝不反噬扫描，守 §0.4）。"""
        if self.on_batch is None:
            return
        try:
            self.on_batch(self, stage_name)
        except Exception:
            pass

    def add_result(self, r: StageResult) -> None:
        self.results.append(r)
        if r.terminal and r.name not in self.done_steps:
            self.done_steps.append(r.name)

    def is_done(self, stage_name: str) -> bool:
        """断点续扫：该阶段是否已在之前的运行中完成（重投时跳过）。"""
        return stage_name in self.done_steps

    # —— 并发水位（扫描侧，由 bridge 按 get_resource_level 注入 options）——
    def io_concurrency(self, default: int = 8) -> int:
        """native IO 阶段（fileleak/vhost/crawl）线程池宽度，随资源水位。0/缺省用 default。"""
        try:
            v = int(self.options.get("io_concurrency") or 0)
        except (TypeError, ValueError):
            v = 0
        return v if v > 0 else default

    def scan_parallelism(self, default: int = 4) -> int:
        """跨目标并行度（IP 分桶并行宽度），随资源水位。0/缺省用 default。"""
        try:
            v = int(self.options.get("scan_parallelism") or 0)
        except (TypeError, ValueError):
            v = 0
        return v if v > 0 else default

    # —— 便捷取值（阶段常用）——
    def site_urls(self) -> List[str]:
        """已发现站点的 URL 列表（crawl/fileleak/nuclei 阶段的目标）。"""
        out, seen = [], set()
        for s in self.sites:
            u = getattr(s, "site", "") or getattr(s, "url", "")
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def ip_list(self) -> List[str]:
        out, seen = [], set()
        for r in self.ips:
            ip = getattr(r, "ip", "")
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out

    def summary(self) -> Dict[str, Any]:
        """运行摘要 dict（recon_bridge 返回给调用方）。"""
        return {
            "task_id": self.task_id, "task_type": self.task_type,
            "stages": [r.name for r in self.results if r.status == "completed"],
            "skipped": [r.name for r in self.results if r.status not in ("completed", "failed")],
            "counts": {r.name: r.count for r in self.results},
            "stage_status": {r.name: {"status": r.status, "count": r.count,
                                              "reason": r.reason, "error": r.error}
                             for r in self.results},
            "records": {
                "domain": self.domains, "ip": self.ips, "site": self.sites,
                "cert": self.certs, "url": self.urls, "vuln": self.vulns,
                "nuclei_result": self.nuclei, "fileleak": self.fileleaks,
                "wih": self.wih,
            },
        }


# 取消检查回调类型：无参、返回 bool（True=已停止）；pipeline 在阶段边界调，True 则抛 StoppedException。
CancelCheck = Optional[Callable[[], bool]]

# 阶段完成回调类型：(ctx, stage_name)；pipeline 每阶段后调，供 bridge 增量落库 + 边探边派渗透 + 写 checkpoint。
OnStage = Optional[Callable[["ReconContext", str], None]]
