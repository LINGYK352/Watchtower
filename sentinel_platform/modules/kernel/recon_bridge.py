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
                             ROLE_SERVICE_POC)


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
    """resolvers 文件绝对路径（massdns -r 需文件路径，非列表）。缺失返空串。"""
    path = os.path.join(_dicts_dir(), "dnsserver.txt")
    return path if os.path.isfile(path) else ""


def _supply_default_dicts(opts: Dict[str, Any]) -> None:
    """按策略开关 + 字典供给 pipeline 所需参数（原地改 opts）。优先级：
      策略自定义文本(subdomain_dict/resolvers_custom/fileleak_dict) > 默认内置字典。
    只在开关开时注入；策略勾了自定义就用自定义（B4），否则用 dicts/ 默认（B3）。禁硬限制：默认≠上限。"""
    # 子域名爆破（D2）：domain_brute 开 且 未传 brute_words → 自定义文本优先，否则 domain_2w 默认词表
    if opts.get("domain_brute", True) and not opts.get("brute_words"):
        custom = _parse_lines(opts.get("subdomain_dict"))
        opts["brute_words"] = custom if custom else _load_wordlist("domain_2w.txt")
    # resolvers（massdns 依赖）：自定义 IP 列表写临时文件优先，否则默认公共 DNS 文件
    if opts.get("brute_words") and not opts.get("resolvers"):
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
        tool = self._reg.pick(ROLE_WEAK_BRUTE)
        if not tool:
            return []
        return [asdict(x) for x in tool.brute(host, int(port), scheme)]

    # —— run_poc：RECON 契约。有 plugins 走 npoc 服务级验证（未授权/弱口令/特定 PoC）；
    #    无 plugins 退化 nuclei_scan（模板漏扫）。修复旧实现丢弃 plugins 只转 nuclei 的契约缺口。——
    def run_poc(self, plugins: Any = None, targets: Any = None, **kwargs: Any) -> List[Dict[str, Any]]:
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
        # 断点续扫：载入上次已完成阶段（重投跳过不重扫）
        done_steps = _load_checkpoint(task_id)
        initial_records = _load_resume_records(task_id, done_steps)
        budget_provider = _resource_budget
        budget = budget_provider()
        opts = dict(kwargs)
        opts.setdefault("io_concurrency", budget["io_concurrency"])
        opts.setdefault("scan_parallelism", budget["scan_parallelism"])
        _supply_default_dicts(opts)   # D2/D4:按策略开关补默认字典(爆破/文件泄露),治恒 skip
        # 扫描出口代理（scan_proxy 两轨）：按策略注入 *_proxy env，扫描子进程/native 全走代理；finally 清除。
        _saved_egress = _apply_scan_egress(opts)
        # 流式：每阶段完成后增量落库 + 写 checkpoint + 站点产出阶段触发增量派发（边探边派）
        streamer = _StreamPersister(task_id)
        try:
            out = _pipeline.run_pipeline(task_id, task_type, target,
                                         options=opts, cancel_check=cancel_check,
                                         on_stage=streamer.on_stage, done_steps=done_steps,
                                         budget_provider=budget_provider,
                                         initial_records=initial_records)
            # 收尾兜底：补落任何流式未覆盖的尾部记录（幂等 upsert）
            out["persisted"] = streamer.flush(out.get("records") or {})
            return out
        except Exception as exc:                    # 内部捕获，异常态经 result 表达（守 §0.4）
            return {"result": "error", "task_id": task_id, "task_type": task_type,
                    "stages": [], "records": {}, "error": str(exc)}
        finally:
            _restore_scan_egress(_saved_egress)   # 清除扫描代理 env，防泄漏到下个任务

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

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self._offset: Dict[str, int] = {}   # 各 ctx 字段已落库偏移

    def on_stage(self, ctx: Any, stage_name: str) -> None:
        # ① 增量落库（只写各字段 offset 之后的新记录）
        delta: Dict[str, List[Dict[str, Any]]] = {}
        for field, coll in _CTX_COLLECTIONS.items():
            rows = getattr(ctx, field, None) or []
            off = self._offset.get(field, 0)
            if len(rows) > off:
                delta[coll] = _dataclass_rows({coll: rows[off:]}).get(coll, [])
                self._offset[field] = len(rows)
        if delta:
            _persist_records(self.task_id, delta)
        # ② 写断点（终态阶段含空结果/策略关闭，重投不重复打目标）
        states = {r.name: {"status": r.status, "count": r.count,
                           "reason": r.reason, "error": r.error}
                  for r in (getattr(ctx, "results", []) or [])}
        _save_checkpoint(self.task_id, list(getattr(ctx, "done_steps", []) or []), states)
        # ③ 站点产出阶段 → 增量派发（边探边派）
        if stage_name in _SITE_STAGES:
            _stream_dispatch(self.task_id)
        # ④ 更新 task.statistic（前端实时展示扫描进度数字）
        _update_statistic(self.task_id)

    def flush(self, final_records: Dict[str, Any]) -> Dict[str, int]:
        """收尾：补落流式未覆盖的尾部（幂等 upsert，二次落无害）。返回总写入摘要。"""
        written = _persist_records(self.task_id, _dataclass_rows(final_records))
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


def _stream_dispatch(task_id: str) -> None:
    """站点阶段后增量归集派发（边探边派）。经 ROLE.INTEL 幂等归集 + 按 auto_pentest 派发；
    幂等（asset_key upsert + skip_pentested + 竞态防护），多次调不重派。缺失降级。"""
    try:
        from sentinel_platform.contracts import get_registry, ROLE
        svc = get_registry().get(ROLE.INTEL)
        if svc and hasattr(svc, "auto_collect_after_scan"):
            svc.auto_collect_after_scan(task_id)
    except Exception:
        pass


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
