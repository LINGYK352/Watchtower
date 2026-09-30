"""侦察桥 recon_bridge —— 平台侦察能力出口（实现 RECON 接口）。

职责：把平台侦察需求转成对 external 工具对接层（kernel/recon）的调用，返回结构化
list[dict]（对齐 INTERFACES.md §二 ReconService 与 §0.3 返回规范）。平台其余模块经
ROLE.RECON 取本服务，不碰工具/引擎内部（守 MODULES.md 铁律 3/6）。

对接层已把 external 工具原始输出结构化为 models dataclass，本桥用 asdict 转 dict 交出，
消费方（intel/ai_pentest）零改动落库或读属性。工具缺失→返回空列表降级，不抛异常拖垮调用方。
"""
from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .recon import build_registry
from .recon.registry import (ROLE_HTTP_PROBE, ROLE_PORT_SCAN, ROLE_RESOLVE,
                             ROLE_VULN_SCAN, ROLE_WEAK_BRUTE, ROLE_WEBINFO,
                             ROLE_SERVICE_POC, ROLE_ICMP_PING)

from sentinel_platform.core import get_logger
logger = get_logger()          # 模块级 logger（resolver 探活等模块级函数用；原仅函数内局部定义 → NameError）

# 全局禁用主动扫描（用户明令 2026-08-28）：底层 RECON 的 nuclei_scan/run_poc/weak_brute 硬保险总开关。
# 上层已断所有调用方（AI 工具 _ACTIVE_SCAN_TOOLS 全局 blocked + pipeline poc/weakbrute 铜钱不串），
# 此常量是纵深防御——防将来有新调用方绕过上层直达底层能力。恢复主动扫描：置 False + 上层门控改回。
_ACTIVE_SCAN_DISABLED = True


# —— 字典供给（净室迁移缺口 D2/D4 补救）————————————————————————————————
# 净室重写把字典解耦成"运行时传参"（pipeline 读 ctx.options 的 brute_words/resolvers/
# fileleak_words），方向对，但解耦后从没建默认供给源 → 参数恒空 → 子域名爆破/文件泄露恒 skip。
# 这里按 dicts/ 默认字典补给：策略开关开(domain_brute/file_leak)且未显式传字典时，注入默认。
# **对齐链路 §11.4「subfinder被动+massdns爆破 / 字典探测」+「各阶段策略控制」**：
# 开关关→不注入→阶段自然 skip；策略传了自定义→尊重不覆盖（禁硬限制，默认≠上限）。
def _dicts_dir() -> str:
    """dicts 目录路径（项目根 <root>/dicts，与 read_vuln_playbook 约定一致）。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    d = os.path.join(root, "dicts")
    if os.path.isdir(d):
        return d
    return os.path.join(root, "sentinel_platform", "dicts")  # 新平台回退路径


_DICT_CACHE: Dict[str, List[str]] = {}   # 词表缓存（20k 词表避免每任务重读）


def _parse_lines(text: Any) -> List[str]:
    """把多行文本（策略自定义字典/resolvers 录入）解析成词表：每行一词，去空/注释/去重保序。"""
    if not text or not isinstance(text, str):
        return []
    out, seen = [], set()
    for line in text.splitlines():
        w = line.strip()
        if w and not w.startswith("#") and w not in seen:
            seen.add(w)
            out.append(w)
    return out


def _write_temp_resolvers(resolvers: List[str]) -> str:
    """把自定义 resolver IP 列表写临时文件（massdns -r 需文件路径）。同内容复用同文件（按哈希命名）。"""
    if not resolvers:
        return ""
    import hashlib, tempfile
    key = hashlib.md5(("\n".join(resolvers)).encode("utf-8")).hexdigest()[:12]
    path = os.path.join(tempfile.gettempdir(), "sentinel_resolvers_{}.txt".format(key))
    if not os.path.isfile(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(resolvers) + "\n")
        except Exception:
            return ""
    return path


def _load_wordlist(filename: str) -> List[str]:
    """加载 dicts/ 下的词表文件（每行一词，去空/注释）。缺失返空。带进程级缓存。"""
    if filename in _DICT_CACHE:
        return _DICT_CACHE[filename]
    path = os.path.join(_dicts_dir(), filename)
    words: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w)
    except Exception:
        words = []
    _DICT_CACHE[filename] = words
    return words


def _resolvers_path() -> str:
    """resolvers 文件绝对路径（massdns -r 需文件路径，非列表）。缺失返空串。
    **优先返回探活排序后的健康 resolver 临时文件**（当前网络真能通的 DNS 排前/剔除不通的），
    探活失败或无可用时降级返回原始 dnsserver.txt。治「表里某 DNS 在当前网络不通导致解析拖慢/失败」。"""
    healthy = _healthy_resolvers_file()
    if healthy:
        return healthy
    # 降级：探活全不通/异常 → 用去注释的纯 IP 表（dnsserver.txt 含 # 注释行，dnsx/massdns -r 不一定认，
    # 故经 _load_wordlist 去注释后重写临时文件，绝不把带注释的原文件直接喂工具）。
    servers = _load_wordlist("dnsserver.txt")
    return _write_temp_resolvers(servers) if servers else ""


# 探活结果进程级缓存（探活有网络开销，同一进程内 TTL 内复用；多 worker 各自探各自的，天然贴合各自网络）
_RESOLVER_CACHE = {"path": "", "ts": 0.0}
_RESOLVER_TTL = 600.0          # 10 分钟内复用探活结果（DNS 可达性变化慢）
_RESOLVER_PROBE_TIMEOUT = 2.0  # 单个 DNS 探活超时（秒），短超时防拖慢
_RESOLVER_PROBE_WORKERS = 8    # 并发探活宽度


def _probe_dns(server: str, timeout: float = _RESOLVER_PROBE_TIMEOUT) -> bool:
    """UDP/53 探测单个 DNS 是否可用：发一个标准 A 查询（baidu.com），收到应答即通。
    比 ping 更准（ping 通不代表 53 端口的 DNS 服务通，尤其容器 NAT 下 UDP 可能被挡）。"""
    import socket, struct, random
    try:
        tid = random.randint(0, 0xFFFF)
        pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        for part in b"baidu.com".split(b"."):
            pkt += bytes([len(part)]) + part
        pkt += b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(512)
            return len(data) >= 12 and data[:2] == pkt[:2]   # 事务ID匹配的应答=通
        finally:
            s.close()
    except Exception:
        return False


def _healthy_resolvers_file() -> str:
    """读 dnsserver.txt（去注释）→ 并发探活 → 通的排前（保原序）、不通的剔除 → 写临时文件返回路径。
    「DNS 表 + 失效顺延 + 回环」的落地：只把当前网络真能通的 DNS 交给 dnsx/massdns（它们本身多 resolver
    轮询失效自动跳下一个），故某个 DNS 挂了不影响解析。全部不通→降级返 ""（调用方回退原始表，不致解析全废）。
    进程级 TTL 缓存，避免每次扫描都探活拖慢启动。"""
    import time as _t
    now = _t.time()
    if _RESOLVER_CACHE["path"] and (now - _RESOLVER_CACHE["ts"] < _RESOLVER_TTL):
        p = _RESOLVER_CACHE["path"]
        if os.path.isfile(p):
            return p
    servers = _load_wordlist("dnsserver.txt")   # 已去注释/空行（_load_wordlist 处理）
    if not servers:
        return ""
    # 并发探活（短超时，别拖慢扫描）
    healthy = []
    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=_RESOLVER_PROBE_WORKERS) as ex:
            results = list(ex.map(lambda s: (s, _probe_dns(s)), servers))
        healthy = [s for s, ok in results if ok]   # 保 dnsserver.txt 原序（通的排前=原序过滤）
    except Exception as exc:
        logger.debug("resolver 探活降级: %s", exc)
        return ""
    if not healthy:
        logger.warning("resolver 探活：表内 %d 个 DNS 当前网络全不通，降级用原始表", len(servers))
        return ""
    logger.info("resolver 探活：%d/%d 个 DNS 可用（%s...）", len(healthy), len(servers), ",".join(healthy[:3]))
    path = _write_temp_resolvers(healthy)
    if path:
        _RESOLVER_CACHE["path"] = path
        _RESOLVER_CACHE["ts"] = now
    return path


def _supply_default_dicts(opts: Dict[str, Any]) -> None:
    """按策略开关 + 字典供给 pipeline 所需参数（原地改 opts）。优先级：
      策略自定义文本(subdomain_dict/resolvers_custom/fileleak_dict) > 默认内置字典。
    只在开关开时注入；策略勾了自定义就用自定义（B4），否则用 dicts/ 默认（B3）。禁硬限制：默认≠上限。"""
    # 子域名爆破（D2）：domain_brute 开 且 未传 brute_words → 自定义文本优先，否则 domain_2w 默认词表
    if opts.get("domain_brute", True) and not opts.get("brute_words"):
        custom = _parse_lines(opts.get("subdomain_dict"))
        opts["brute_words"] = custom if custom else _load_wordlist("domain_2w.txt")
    # resolvers（massdns 爆破 + dnsx resolve 都依赖）：无条件供给——dnsx 不传 -r 会用内置境外默认
    # resolver，某些网络全超时致解析恒空（single 模式不爆破但仍要 resolve，故不能再绑 brute_words）。
    # 自定义 IP 列表写临时文件优先，否则默认公共 DNS 文件 dnsserver.txt。
    if not opts.get("resolvers"):
        custom_r = _parse_lines(opts.get("resolvers_custom"))
        opts["resolvers"] = _write_temp_resolvers(custom_r) if custom_r else _resolvers_path()
    # 文件泄露（D4）：file_leak 开 且 未传 fileleak_words → 自定义文本优先，否则 file_top_2000 默认
    if opts.get("file_leak") and not opts.get("fileleak_words"):
        custom_f = _parse_lines(opts.get("fileleak_dict"))
        opts["fileleak_words"] = custom_f if custom_f else _load_wordlist("file_top_2000.txt")


class ReconBridge:
    """RECON 接口实现。工具经 registry 取（降级安全），结果统一 dict 化。"""

    def __init__(self, config: Any = None) -> None:
        self._reg = build_registry(config)

    # —— 漏扫（nuclei）——
    def nuclei_scan(self, targets: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        if _ACTIVE_SCAN_DISABLED:                        # 底层硬保险（纵深防御，见文件末常量）
            logger.info("nuclei_scan 已全局禁用（主动扫描禁绝），返空不执行")
            return []
        tool = self._reg.pick(ROLE_VULN_SCAN)
        if not tool:
            return []
        items = tool.scan(_as_list(targets), concurrency=kwargs.get("concurrency", 25))
        return [asdict(x) for x in items]

    # —— 端口扫描（naabu）——
    def port_scan(self, targets: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        tool = self._reg.pick(ROLE_PORT_SCAN)
        if not tool:
            return []
        items = tool.scan(_as_list(targets), ports=kwargs.get("ports", "top-1000"),
                          concurrency=kwargs.get("concurrency", 500))
        return [asdict(x) for x in items]

    # —— HTTP 探测（httpx）——
    def http_probe(self, targets: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        tool = self._reg.pick(ROLE_HTTP_PROBE)
        if not tool:
            return []
        items = tool.probe(_as_list(targets), concurrency=kwargs.get("concurrency", 100))
        return [asdict(x) for x in items]

    # —— 弱口令/未授权（nmap NSE）——
    def weak_brute(self, host: str, port: int, scheme: str, **kwargs: Any) -> List[Dict[str, Any]]:
        if _ACTIVE_SCAN_DISABLED:                        # 底层硬保险
            logger.info("weak_brute 已全局禁用（主动扫描禁绝），返空不执行")
            return []
        tool = self._reg.pick(ROLE_WEAK_BRUTE)
        if not tool:
            return []
        return [asdict(x) for x in tool.brute(host, int(port), scheme)]

    # —— run_poc：RECON 契约。有 plugins 走 npoc 服务级验证（未授权/弱口令/特定 PoC）；
    #    无 plugins 退化 nuclei_scan（模板漏扫）。修复旧实现丢弃 plugins 只转 nuclei 的契约缺口。——
    def run_poc(self, plugins: Any = None, targets: Any = None, **kwargs: Any) -> List[Dict[str, Any]]:
        if _ACTIVE_SCAN_DISABLED:                        # 底层硬保险（含 npoc + nuclei 降级两路）
            logger.info("run_poc 已全局禁用（主动扫描禁绝），返空不执行")
            return []
        plugin_list = _as_list(plugins)
        if plugin_list:
            tool = self._reg.pick(ROLE_SERVICE_POC)   # npoc(xing)；未装则降级 nuclei
            if tool:
                items = tool.run_poc(plugin_list, _as_list(targets),
                                     proxy=kwargs.get("proxy", ""))
                return [asdict(x) for x in items]
        return self.nuclei_scan(targets or [], **kwargs)

    # —— DNS 解析（dnsx）——
    def dns_query(self, domain: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        tool = self._reg.pick(ROLE_RESOLVE)
        if not tool:
            return []
        items = tool.resolve(_as_list(domain), concurrency=kwargs.get("concurrency", 200))
        return [asdict(x) for x in items]

    # —— JS/HTML 信息挖掘（native webinfohunter）——
    def collect_js(self, site: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        tool = self._reg.pick(ROLE_WEBINFO)
        if not tool:
            return []
        return [asdict(x) for x in tool.hunt(_as_list(site))]

    # —— 主机存活探测（native ICMP + TCP 降级）——
    def icmp_ping(self, target: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        tool = self._reg.pick(ROLE_ICMP_PING)
        if not tool:
            return []
        return [asdict(x) for x in tool.ping(_as_list(target))]

    # —— run_recon：侦察编排入口（RECON 契约主方法）——
    def run_recon(self, task_type: str, task_id: str, target: Any,
                  **kwargs: Any) -> Dict[str, Any]:
        """完整侦察编排：委托 recon/pipeline（多阶段：子域名→解析→端口→证书→站点→爬取→泄漏→
        vhost→服务→弱口令→漏扫；IP 任务省子域名/解析）。替换原最小 4 阶段（P1，2026-07-05）。

        pipeline 完全自包含（不 import core/contracts）纯计算，工具缺失的阶段自动跳过（降级不报错）；
        pipeline 只算不落库，**由本桥（RECON owner，可持 repo）把 records 落库**——records 的 key 即
        Mongo 集合名（domain/ip/site/cert/url/fileleak/service/vuln/nuclei_result/wih），按自然键 upsert
        + 补 task_id/save_date（重跑幂等）。落库后 _post_scan 归集才读得到（治"能扫成果全丢"）。
        协作式取消：orchestration 调时经 kwargs['cancel_check'] 传停止自检回调（缺省不检查）。
        返回 {result: done|stopped|error, task_id, task_type, stages, skipped, counts, records, error}。
        """
        from .recon import pipeline as _pipeline
        cancel_check = kwargs.pop("cancel_check", None)
        # use_checkpoint=False（unit 任务流式分块调用）：不复用/不写 checkpoint，每块=对本块种子的
        # 一次完整 fresh pipeline（阶段不被上一块的 done_steps 跳过）。默认 True，存量任务断点续扫不变。
        use_checkpoint = bool(kwargs.pop("use_checkpoint", True))
        # 断点续扫：载入上次已完成阶段（重投跳过不重扫）；流式分块调用时禁用，避免跳过新种子的阶段
        done_steps = _load_checkpoint(task_id) if use_checkpoint else []
        initial_records = _load_resume_records(task_id, done_steps) if use_checkpoint else {}
        budget_provider = _resource_budget
        budget = budget_provider()
        opts = dict(kwargs)
        opts.setdefault("io_concurrency", budget["io_concurrency"])
        opts.setdefault("scan_parallelism", budget["scan_parallelism"])
        # 广域 API 收集源：策略只持久化 source id；真实凭据在每次运行时从 API 密钥中心 fresh 读，
        # 仅以内存参数注入自包含 pipeline，绝不写入 task/options/checkpoint/日志。
        # collect_sources 缺失=存量策略，兼容为全部已配置源；显式 []=用户明确全部取消。
        if task_type == "domain" and str(opts.get("collect_mode") or "multi_brute").lower() != "single":
            try:
                from . import ext_source as _ext_source
                _selected_sources = opts.get("collect_sources") if "collect_sources" in opts else None
                _source_runtime = _ext_source.configured_collection_sources(_selected_sources)
                if _source_runtime.get("subfinder"):
                    opts["_collection_source_credentials"] = _source_runtime["subfinder"]
                if _source_runtime.get("fofa"):
                    opts["_fofa_collector"] = _ext_source.fofa_subdomains
            except Exception as exc:
                logger.debug("广域 API 收集源运行时解析降级: %s", exc)
        _supply_default_dicts(opts)   # D2/D4:按策略开关补默认字典(爆破/文件泄露),治恒 skip
        # 扫描出口代理（scan_proxy 两轨）：按策略注入 *_proxy env，扫描子进程/native 全走代理；finally 清除。
        _saved_egress = _apply_scan_egress(opts)
        # 流式：每阶段完成后增量落库 + 写 checkpoint + 站点产出阶段触发增量派发（边探边派）
        # save_checkpoint=use_checkpoint：流式分块调用不写 task.checkpoint（否则残留误导后续读取），
        # 仍照常落库 + 流式派发。
        streamer = _StreamPersister(task_id, save_checkpoint=use_checkpoint, cancel_check=cancel_check)
        # 资源门（问题11）：注入 recon，内存重工具(截图/nuclei/service)执行前申请内存、让位 AI。
        resource_gate = _build_resource_gate(task_id, cancel_check)
        try:
            out = _pipeline.run_pipeline(task_id, task_type, target,
                                         options=opts, cancel_check=cancel_check,
                                         on_stage=streamer.on_stage, done_steps=done_steps,
                                         budget_provider=budget_provider,
                                         initial_records=initial_records,
                                         resource_gate=resource_gate)
            # 收尾兜底：补落任何流式未覆盖的尾部记录（幂等 upsert）
            out["persisted"] = streamer.flush(out.get("records") or {})
            if cancel_check and cancel_check():
                out["result"] = "stopped"
            if out.get("result") != "stopped" and (streamer.persist_failed or streamer.pending_sites):
                out["result"] = "error"
                out["error"] = "流式链路未完成：落库失败={}，待派发站点={}".format(
                    sorted(streamer.persist_failed), len(streamer.pending_sites))
            return out
        except Exception as exc:                    # 内部捕获，异常态经 result 表达（守 §0.4）
            return {"result": "error", "task_id": task_id, "task_type": task_type,
                    "stages": [], "records": {}, "error": str(exc)}
        finally:
            _restore_scan_egress(_saved_egress)   # 清除扫描代理 env，防泄漏到下个任务
            # 资源门收尾（问题11）：释放本任务所有 recon 预留 + 清 resource_wait 徽标（防泄漏，
            # 镜像 AI run_agent finally 的 release_session_all）。
            try:
                from .resource_pool import release_session_all
                release_session_all(resource_gate.session_id)
            except Exception:
                pass
            _clear_resource_wait(task_id)

    # —— 工具可用性（健康检查/降级排查）——
    def tool_report(self) -> Dict[str, Dict[str, bool]]:
        return self._reg.report()


_SINGLETON: Optional[ReconBridge] = None


def get_service(config: Any = None) -> ReconBridge:
    """registry 注册入口：kernel/register.py 里 registry.register(ROLE.RECON, get_service())。"""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ReconBridge(config)
    return _SINGLETON


def _as_list(targets: Any) -> List[str]:
    if targets is None:
        return []
    if isinstance(targets, str):
        return [targets]
    return [str(t) for t in targets]


# 各集合自然键均带 task_id，避免不同任务互相覆盖；site 另兼容 url/site 字段。
_NATURAL_KEY = {
    "domain": ("task_id", "domain"), "ip": ("task_id", "ip"),
    "cert": ("task_id", "ip", "port"), "service": ("task_id", "service_name"),
    "fileleak": ("task_id", "url"), "url": ("task_id", "url"),
    "nuclei_result": ("task_id", "target", "template_id"),
    "vuln": ("task_id", "target", "plg_name"),
    "wih": ("task_id", "content", "record_type"), "npoc_service": ("task_id", "target"),
}


def _dataclass_rows(records: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """ctx 里的 dataclass 记录 → list[dict]（asdict）。pipeline 中间态是 dataclass，需转 dict 落库。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for coll_name, rows in (records or {}).items():
        conv = []
        for r in rows or []:
            if hasattr(r, "__dataclass_fields__"):
                conv.append(asdict(r))
            elif isinstance(r, dict):
                conv.append(r)
        if conv:
            out[coll_name] = conv
    return out


# ctx 字段名 → Mongo 集合名（流式落库用；与 summary().records 的 key 对齐）
_CTX_COLLECTIONS = {
    "domains": "domain", "ips": "ip", "sites": "site", "certs": "cert",
    "urls": "url", "vulns": "vuln", "nuclei": "nuclei_result", "fileleaks": "fileleak",
    "wih": "wih",
}
# 站点产出/更新阶段（完成后触发增量派发——边探边派，不等全扫完）
_SITE_STAGES = {"site", "vhost"}


class _StreamPersister:
    """流式落库 + 边探边派 + 断点写入 + statistic 实时更新。pipeline 每阶段后调 on_stage：
    ① 增量落库本阶段新增记录（按 offset 只写增量，避免 16 阶段重复 upsert 写放大）；
    ② 写 task.checkpoint.done_steps（断点续扫，重投跳过已完成阶段）；
    ③ 站点产出阶段（site/vhost）后触发 INTEL 增量归集派发（流式逐站派，治首会话延迟高/堆积）；
    ④ 更新 task.statistic（前端 TaskList/TaskDetail 读此字段展示域名/IP/站点数量）。
    异常全吞——绝不反噬扫描（守 §0.4）。"""

    def __init__(self, task_id: str, save_checkpoint: bool = True, cancel_check=None) -> None:
        self.task_id = task_id
        self._offset: Dict[str, int] = {}   # 各 ctx 字段已落库偏移
        self._save_checkpoint = save_checkpoint   # unit 流式分块调用置 False：只落库+派发，不写 checkpoint
        self.cancel_check = cancel_check
        self.persist_failed = set()
        self.pending_sites = {}

    def _dispatch_pending(self):
        if not self.pending_sites or (self.cancel_check and self.cancel_check()):
            return
        if _stream_dispatch(self.task_id, list(self.pending_sites.values())) is not False:
            self.pending_sites.clear()

    def _remember_sites(self, rows):
        for row in rows:
            url = row.get("site") or row.get("url")
            if url:
                self.pending_sites[url] = row

    def on_stage(self, ctx: Any, stage_name: str) -> None:
        # ① 增量落库（只写各字段 offset 之后的新记录）
        delta: Dict[str, List[Dict[str, Any]]] = {}
        for field, coll in _CTX_COLLECTIONS.items():
            rows = getattr(ctx, field, None) or []
            off = self._offset.get(field, 0)
            if len(rows) > off:
                delta[coll] = _dataclass_rows({coll: rows[off:]}).get(coll, [])
        if delta:
            written = _persist_records(self.task_id, delta)
            for field, coll in _CTX_COLLECTIONS.items():
                if coll not in delta:
                    continue
                if written.get(coll, 0) == len(delta[coll]):
                    self._offset[field] = len(getattr(ctx, field, None) or [])
                    self.persist_failed.discard(coll)
                    if coll == "site":
                        self._remember_sites(delta[coll])
                else:
                    self.persist_failed.add(coll)
        # 新增 site 即派发，不再硬编码只认名为 site/vhost 的铜钱；失败在下一回调/收尾重试。
        self._dispatch_pending()
        # ② 写断点（终态阶段含空结果/策略关闭，重投不重复打目标）；流式分块调用不写（save_checkpoint=False）
        if self._save_checkpoint and not self.persist_failed and not self.pending_sites:
            states = {r.name: {"status": r.status, "count": r.count,
                               "reason": r.reason, "error": r.error}
                      for r in (getattr(ctx, "results", []) or [])}
            _save_checkpoint(self.task_id, list(getattr(ctx, "done_steps", []) or []), states)
        # ③ 站点产出阶段 → 增量派发（边探边派）
        # ④ 更新 task.statistic（前端实时展示扫描进度数字）
        _update_statistic(self.task_id)

    def flush(self, final_records: Dict[str, Any]) -> Dict[str, int]:
        """收尾：补落流式未覆盖的尾部（幂等 upsert，二次落无害）。返回总写入摘要。"""
        records = _dataclass_rows(final_records)
        written = _persist_records(self.task_id, records)
        for coll, rows in records.items():
            if written.get(coll, 0) == len(rows):
                self.persist_failed.discard(coll)
                if coll == "site":
                    self._remember_sites(rows)
            else:
                self.persist_failed.add(coll)
        self._dispatch_pending()
        # 最终统计刷新（保证任务结束时 statistic 精确）
        _update_statistic(self.task_id)
        return written


def _load_resume_records(task_id: str, done_steps: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """只从同一 task_id 恢复后续阶段依赖的中间态，绝不混入跨任务历史。

    恢复范围按已完成阶段收敛：domain/resolve→domain，portscan/service→ip，site/vhost→site。
    其他叶子结果由 Mongo 已持久化，不必重新塞回 Context 才能驱动后续阶段。
    """
    needed = set()
    done = set(done_steps or [])
    if done & {"subdomain", "resolve"}:
        needed.add("domain")
    if done & {"portscan", "service"}:
        needed.add("ip")
    if done & {"site", "vhost", "enrich", "screenshot", "webinfo", "crawl", "fileleak", "poc"}:
        needed.add("site")
    if not needed:
        return {}
    try:
        from sentinel_platform.core import get_repo
        out: Dict[str, List[Dict[str, Any]]] = {}
        for name in needed:
            rows = []
            for item in get_repo().collection(name).find({"task_id": task_id}):
                row = dict(item)
                row.pop("_id", None)
                rows.append(row)
            if rows:
                out[name] = rows
        return out
    except Exception:
        return {}


def _res_cfg(key: str, default: float) -> float:
    """读 RESOURCE.<key>，缺失/异常回退默认（recon gate 节流/超时参数，物理意义非魔数）。"""
    try:
        from sentinel_platform.core import get_config
        v = get_config().section("RESOURCE", key)
        return float(v) if v is not None else float(default)
    except Exception:
        return float(default)


def _set_resource_wait(task_id: str, tool: str, res: Dict[str, Any]) -> None:
    """写 task.resource_wait 子状态（recon 工具因内存等待→前端显"资源等待"徽标，问题11）。recon 不碰 DB，由桥写。"""
    try:
        import time
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        get_repo().collection(Collections.TASK).update_one(
            {"_id": _task_oid(task_id)},
            {"$set": {"resource_wait": {
                "tool": tool, "since": time.strftime("%Y-%m-%d %H:%M:%S"),
                "avail_mb": res.get("avail_mb"), "reserve_mb": res.get("reserve_mb"),
                "reserved_mb": res.get("reserved_mb"), "headroom_mb": res.get("headroom_mb")}}})
    except Exception:
        pass


def _clear_resource_wait(task_id: str) -> None:
    """清 task.resource_wait（acquire 成功/退出/降级/收尾时调）。"""
    try:
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        get_repo().collection(Collections.TASK).update_one(
            {"_id": _task_oid(task_id)}, {"$unset": {"resource_wait": ""}})
    except Exception:
        pass


def _build_resource_gate(task_id: str, cancel_check):
    """构建注入 recon 的资源门 callable（问题11，守 recon 自包含——recon 只调返回的 callable，不 import 池）。
    gate(tool) → 上下文管理器：acquire 成功即放行并记账；内存不足则写 resource_wait 徽标 + 轮询等待、
    让位 AI；cancel_check 真 → 抛 recon 的 StoppedException；超 max_wait → degraded=True 诚实跳过。"""
    import time
    from .resource_pool import acquire, release, _used_mb_now, PRIORITY_RECON
    from .recon.context import StoppedException
    sid = "recon:" + str(task_id)
    poll = _res_cfg("RECON_GATE_POLL_SEC", 2.0)        # 轮询间隔（让位 AI 的检查周期）
    max_wait = _res_cfg("RECON_GATE_MAX_WAIT_SEC", 0)  # 0=无限等（默认让位到底）；>0 超时诚实降级跳过

    class _Holder:
        def __init__(self, tool):
            self.tool = tool
            self.hid = ""
            self._before = None
            self.degraded = False

        def __enter__(self):
            start = time.time()
            while True:
                if cancel_check and cancel_check():
                    raise StoppedException("recon stopped while waiting for memory (gate)")
                res = acquire(self.tool, sid, int(PRIORITY_RECON))
                if res.get("ok"):
                    self.hid = res.get("hid", "")
                    self._before = None if res.get("light") else _used_mb_now()
                    _clear_resource_wait(task_id)
                    return self
                _set_resource_wait(task_id, self.tool, res)
                if max_wait and (time.time() - start) > max_wait:
                    self.degraded = True
                    _clear_resource_wait(task_id)
                    return self
                time.sleep(poll)

        def __exit__(self, *exc):
            delta = None
            if self._before is not None:
                after = _used_mb_now()
                if after is not None:
                    delta = after - self._before
            try:
                release(self.hid, tool=self.tool, used_delta_mb=delta)
            except Exception:
                pass
            _clear_resource_wait(task_id)
            return False   # 不吞异常（StoppedException 等照常传播）

    def gate(tool):
        return _Holder(tool)
    gate.session_id = sid
    return gate


def _load_checkpoint(task_id: str) -> List[str]:
    """读 task.checkpoint.done_steps（断点续扫）。无/异常 → 空（从头扫）。"""
    try:
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        t = get_repo().collection(Collections.TASK).find_one({"_id": _task_oid(task_id)}) or {}
        return list(((t.get("checkpoint") or {}).get("done_steps")) or [])
    except Exception:
        return []


def _save_checkpoint(task_id: str, done_steps: List[str], stage_status: Optional[Dict[str, Any]] = None) -> None:
    """写 task.checkpoint；兼容旧 done_steps，并保存可诊断阶段状态。"""
    try:
        import time
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        get_repo().collection(Collections.TASK).update_one(
            {"_id": _task_oid(task_id)},
            {"$set": {"checkpoint.done_steps": done_steps,
                      "checkpoint.stage_status": stage_status or {},
                      "checkpoint.current_step": done_steps[-1] if done_steps else "",
                      "checkpoint.update_date": time.strftime("%Y-%m-%d %H:%M:%S")}})
    except Exception:
        pass


def _stream_dispatch(task_id: str, sites=None) -> bool:
    """站点阶段后增量归集派发（边探边派）。经 ROLE.INTEL 幂等归集 + 按 auto_pentest 派发；
    幂等（asset_key upsert + skip_pentested + 竞态防护），多次调不重派。缺失降级。"""
    try:
        from sentinel_platform.contracts import get_registry, ROLE
        svc = get_registry().get(ROLE.INTEL)
        if svc and hasattr(svc, "auto_collect_after_scan"):
            if sites is not None and hasattr(svc, "auto_collect_sites"):
                result = svc.auto_collect_sites(task_id, sites)
            else:
                result = svc.auto_collect_after_scan(task_id)
            if isinstance(result, dict):
                if result.get("error") or (result.get("collected") or {}).get("error") or (result.get("dispatched") or {}).get("error"):
                    return False
                if result.get("dispatch_pending"):
                    return False
            return True
    except Exception as exc:
        logger.warning("stream dispatch task=%s deferred: %s", task_id, type(exc).__name__)
    return False


def _update_statistic(task_id: str) -> None:
    """更新 task.statistic（前端 TaskList/TaskDetail 靠此字段展示域名/IP/站点/URL/漏洞/WIH 数量）。

    净室重写时遗失了此逻辑——旧系统在 commonTask 里每阶段 count_documents 写回 task.statistic，
    新平台 recon_bridge 只落库不更新统计，导致前端永远显示 0/"未发现资产"。
    按 task_id 各集合 count，写 task.statistic = {domain_cnt, ip_cnt, site_cnt, url_cnt, vuln_cnt, wih_cnt}。
    异常吞——绝不反噬扫描。
    """
    try:
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        repo = get_repo()
        q = {"task_id": task_id}
        stat = {
            "domain_cnt": repo.collection(Collections.DOMAIN).count_documents(q),
            "ip_cnt": repo.collection(Collections.IP).count_documents(q),
            "site_cnt": repo.collection(Collections.SITE).count_documents(q),
            "url_cnt": repo.collection(Collections.URL).count_documents(q),
            "vuln_cnt": (repo.collection(Collections.VULN).count_documents(q)
                         + repo.collection(Collections.NUCLEI_RESULT).count_documents(q)),
            "wih_cnt": repo.collection(Collections.WIH).count_documents(q),
        }
        repo.collection(Collections.TASK).update_one(
            {"_id": _task_oid(task_id)}, {"$set": {"statistic": stat}})
    except Exception:
        pass


def _task_oid(task_id: str) -> Any:
    try:
        from bson import ObjectId
        return ObjectId(task_id)
    except Exception:
        return task_id


# —— 扫描出口代理（scan_proxy 两轨，对齐旧 proxy_core.set_scan_egress + proxy_env）——
# 净室迁移曾丢：策略 scan_proxy 存了没人消费→扫描流量恒直连不走代理（红队暴露真 IP）。
# 移植旧机制：任务开头按 scan_proxy==proxy 解析代理 URL 注入 os.environ(*_proxy)，扫描子进程
# (subfinder/httpx/naabu/nuclei/massdns 继承 env) + native urllib(默认读 *_proxy env) 全覆盖；
# finally 清除防泄漏到下个任务（celery prefork 每进程一任务，同旧代码进程级语义）。
_SCAN_PROXY_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                        "http_proxy", "https_proxy", "all_proxy")


def _apply_scan_egress(opts: Dict[str, Any]) -> Dict[str, str]:
    """按扫描出口模式解析代理 URL 注入 os.environ（供扫描子进程 subfinder/httpx 等继承）。
    返回被改动的原值快照（供还原）。direct/无源 → 不注入（直连，默认），降级不阻断扫描。

    **4模式（2026-08）**：opts.scan_egress={mode, rule_id}——direct 不注入；global/rule/smart 经
    resolve_egress_url 解析出口 URL 注入（smart 含叠加降级）。**兼容旧字段** scan_proxy(proxy/direct)+
    proxy_source（存量任务/未迁移策略）。"""
    import os
    saved: Dict[str, str] = {}
    eg = opts.get("scan_egress") or {}
    mode = (eg.get("mode") if isinstance(eg, dict) else "") or ""
    rule_id = (eg.get("rule_id") if isinstance(eg, dict) else "") or ""
    try:
        from sentinel_platform.contracts import get_registry, ROLE
        svc = get_registry().get(ROLE.PROXY)
        if not (svc and hasattr(svc, "resolve_egress")):
            return saved
        if mode:
            if mode.lower() == "direct":
                return saved
            url = (svc.resolve_egress_url(mode, rule_id) if hasattr(svc, "resolve_egress_url")
                   else svc.resolve_egress(mode, rule_id)[0])
        else:
            # 旧字段兼容：scan_proxy!=proxy → 直连
            if str(opts.get("scan_proxy", "direct")).lower() != "proxy":
                return saved
            url, _force = svc.resolve_egress("proxy", source=opts.get("proxy_source", "subscription"))
        if not url:
            return saved
        # 先整体快照(再改),避免 Windows os.environ 大小写不敏感时先设 HTTP_PROXY 再读 http_proxy
        # 拿到刚注入值污染快照(Linux 大小写敏感无此问题,但快照优先保正确)。
        for k in _SCAN_PROXY_ENV_KEYS:
            saved[k] = os.environ.get(k, "\x00")   # \x00 哨兵=原本不存在
        for k in _SCAN_PROXY_ENV_KEYS:
            os.environ[k] = url
    except Exception:
        pass
    return saved


def _restore_scan_egress(saved: Dict[str, str]) -> None:
    """还原 os.environ 到注入前（清除本任务的扫描代理，防泄漏下个任务）。"""
    import os
    for k, v in (saved or {}).items():
        if v == "\x00":
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _resource_budget() -> Dict[str, Any]:
    """读取统一资源预算；不可用时按 normal 默认，不把不可观测误判为 relaxed。"""
    try:
        from sentinel_platform.contracts import get_registry
        svc = get_registry().get("log_service")
        if svc and hasattr(svc, "get_resource_budget"):
            value = svc.get_resource_budget() or {}
            return {"level": value.get("level", "normal"),
                    "io_concurrency": max(1, int(value.get("io_concurrency", 10) or 10)),
                    "scan_parallelism": max(1, int(value.get("scan_parallelism", 4) or 4))}
    except Exception:
        pass
    return {"level": "normal", "io_concurrency": 10, "scan_parallelism": 4}


def _resource_concurrency() -> tuple:
    """兼容既有调用/测试。"""
    budget = _resource_budget()
    return budget["io_concurrency"], budget["scan_parallelism"]


def _persist_records(task_id: str, records: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    """把 pipeline 产出的 records 落库（key=集合名）。补 task_id/save_date，按自然键 upsert。
    治「pipeline 只算不落库、成果全丢」。任何集合失败不影响其他（各自 try），返回 {集合:写入数}。"""
    if not records:
        return {}
    import time
    from sentinel_platform.core import get_repo, get_logger
    logger = get_logger()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    written: Dict[str, int] = {}
    repo = get_repo()
    for coll_name, rows in records.items():
        if not rows:
            continue
        n = 0
        try:
            coll = repo.collection(coll_name)
            keys = _NATURAL_KEY.get(coll_name)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                doc = dict(row)
                doc["task_id"] = task_id
                doc.setdefault("save_date", now)
                if coll_name == "site":
                    site = (doc.get("site") or doc.get("url") or "").strip()
                    if not site:
                        continue
                    doc["site"] = site
                    q = {"task_id": task_id, "$or": [{"site": site}, {"url": site}]}
                    coll.update_one(q, {"$set": doc}, upsert=True)
                elif keys and all(doc.get(k) not in (None, "") for k in keys):
                    q = {k: doc[k] for k in keys}
                    coll.update_one(q, {"$set": doc}, upsert=True)
                else:
                    coll.insert_one(doc)
                n += 1
            written[coll_name] = n
        except Exception as e:
            logger.warning("persist records[%s] error: %s", coll_name, e)
    return written
