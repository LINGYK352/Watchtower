"""dnsx 对接 —— DNS 解析 / 存活探测（MIT / ProjectDiscovery）。

原始输出 JSON（一行一域名解析）→ 结构化 DomainRec（对齐 domain 集合）。
CNAME 优先记为 CNAME 链，否则记 A 记录；无解析结果的行丢弃。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..base import ExternalTool
from ..models import DomainRec


class Dnsx(ExternalTool):
    binary = "dnsx"
    adapter = "dnsx"

    def build_argv(self, concurrency: int = 200, **kwargs: Any) -> List[str]:
        return ["-silent", "-json", "-a", "-cname", "-resp", "-t", str(concurrency)]

    def parse_record(self, obj: Dict[str, Any]) -> Optional[DomainRec]:
        host = obj.get("host")
        if not isinstance(host, str) or not host:
            return None
        a = [ip for ip in (obj.get("a") or []) if isinstance(ip, str)]
        cname = [c for c in (obj.get("cname") or []) if isinstance(c, str)]
        if not a and not cname:
            return None
        domain = host.strip().lower()
        if cname:
            return DomainRec(domain=domain, record=cname, type="CNAME", ips=a, source="dns_resolve")
        return DomainRec(domain=domain, record=a, type="A", ips=a, source="dns_resolve")

    def resolve(self, hosts: Iterable[str], concurrency: int = 200) -> List[DomainRec]:
        return self.run(stdin_lines=hosts, concurrency=concurrency)
