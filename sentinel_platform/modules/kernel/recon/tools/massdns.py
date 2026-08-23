"""massdns 对接 —— 子域名**爆破**（GPL C 工具，最快最省内存；CLI arm's-length 不传染）。

与 T1 subfinder（被动枚举）互补，构成完整子域名发现层：subfinder 从公开源"查已知"，
massdns 用字典×主域"暴力试"存活子域。字典候选（word.<root>）喂 stdin，massdns 高并发 DNS
查询公共 resolver，`-o S` 简单文本输出（`domain. TYPE record` 每行一答）→ 结构化 DomainRec。

**与 JSON 类工具的关键差异**：massdns `-o S` 是**纯文本非 JSON**，故 override `structure()`
自己按行拆（base 只吃 JSON）。命令走 stdin 读候选 + `-w -` 写 stdout（不落临时文件，可管道化）。

**泛解析过滤（铁律）**：泛解析域名把任意子域都解析到同一 IP，会污染结果——把命中已知泛解析 IP
的记录丢弃（wildcard_ips 由上游 pipeline 探测：解析一个随机不存在子域，其 IP 即泛解析 IP）。

依赖：resolvers 文件（公共 DNS 列表，运行时配置非 Python 库）+ massdns 二进制（PATH 解析，
C 工具不 vendor，同 subfinder）。子域名爆破只跟公共 resolver 通信、不碰目标，无需走代理。
"""
from __future__ import annotations

from typing import Any, Iterable, Iterator, List, Optional, Set

from ..base import ExternalTool
from ..models import DomainRec


def _belongs(host: str, root: str) -> bool:
    if not root:
        return True
    host, root = host.strip(".").lower(), root.strip(".").lower()
    return host == root or host.endswith("." + root)


def gen_candidates(root: str, words: Iterable[str]) -> List[str]:
    """字典 × 主域 → 候选 FQDN。支持 `{fuzz}` 占位（如 `{fuzz}.a.com`），否则 `word.root`。"""
    root = (root or "").strip().strip(".").lower()
    if not root:
        return []
    is_fuzz = "{fuzz}" in root
    out, seen = [], set()
    for w in words:
        w = (w or "").strip().lower()
        if not w:
            continue
        cand = root.replace("{fuzz}", w) if is_fuzz else "{}.{}".format(w, root)
        if cand not in seen:
            seen.add(cand)
            out.append(cand)
    if not is_fuzz and root not in seen:
        out.append(root)                       # 主域自身也查一次
    return out


class Massdns(ExternalTool):
    binary = "massdns"
    adapter = "massdns"

    def build_argv(self, resolvers: str = "", concurrency: int = 1000, **kwargs: Any) -> List[str]:
        # -q 静默 / -r resolver 文件 / -o S 简单文本 / -w - 写 stdout / -s 并发 / 末尾 - 读 stdin
        try:
            s = int(concurrency)
        except (TypeError, ValueError):
            s = 1000
        return ["-q", "-r", str(resolvers), "-o", "S", "-w", "-", "-s", str(s), "-"]

    def parse_line(self, line: str, wildcard_ips: Optional[Set[str]] = None) -> Optional[DomainRec]:
        """massdns `-o S` 一行 `domain. TYPE record` → DomainRec；非三段/泛解析命中返 None。"""
        parts = line.split()
        if len(parts) != 3:
            return None
        domain, dtype, record = parts
        domain = domain.strip().strip(".").lower()
        record = record.strip().strip(".")
        if not domain or not record:
            return None
        if wildcard_ips and record in wildcard_ips:
            return None                        # 泛解析过滤
        ips = [record] if dtype == "A" else []
        return DomainRec(domain=domain, record=[record], type=dtype, ips=ips, source="domain_brute")

    def structure(self, output: str) -> Iterator[DomainRec]:
        """override：massdns `-o S` 是纯文本非 JSON，逐行文本解析（base 只吃 JSON 不适用）。"""
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            rec = self.parse_line(line)        # 泛解析/scope 过滤在 brute() 收口
            if rec is not None:
                yield rec

    def brute(self, root: str, words: Iterable[str], resolvers: str,
              wildcard_ips: Optional[Set[str]] = None, concurrency: int = 1000,
              scope: Optional[Set[str]] = None) -> List[DomainRec]:
        """爆破一个主域：生成候选→massdns 解析→泛解析/归属过滤→按域名去重合并 IP。
        存活子域（有解析记录即存活）返 DomainRec 列表。resolvers 必填（massdns 依赖）。"""
        candidates = gen_candidates(root, words)
        if not candidates or not resolvers:
            return []
        raw = self.run(stdin_lines=candidates, resolvers=resolvers, concurrency=concurrency)
        merged = {}
        wild = wildcard_ips or set()
        for r in raw:
            if r.type == "A" and r.record and r.record[0] in wild:
                continue                       # 泛解析过滤
            if not _belongs(r.domain, root):
                continue                       # 归属过滤（防越界）
            if scope and not any(_belongs(r.domain, s) for s in scope):
                continue
            cur = merged.get(r.domain)
            if cur is None:
                merged[r.domain] = DomainRec(domain=r.domain, record=list(r.record),
                                             type=r.type, ips=list(r.ips), source="domain_brute")
            else:                              # 同域多条：合并 record/ips 去重
                for x in r.record:
                    if x not in cur.record:
                        cur.record.append(x)
                for ip in r.ips:
                    if ip not in cur.ips:
                        cur.ips.append(ip)
        return list(merged.values())
