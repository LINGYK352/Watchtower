"""naabu 对接 —— 端口扫描（MIT / ProjectDiscovery）。

原始输出 JSON（一行一开放端口）→ 按 IP 聚合成 IPRec（对齐 ip 集合）。
端口只给号，服务/版本识别由 nmap_service 对接回填。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..base import ExternalTool
from ..models import IPRec, PortInfo

_PORT_PRESET = {"top-100": "100", "top-1000": "1000"}


class Naabu(ExternalTool):
    binary = "naabu"
    adapter = "naabu"

    def build_argv(self, ports: str = "top-1000", concurrency: int = 500,
                   **kwargs: Any) -> List[str]:
        argv = ["-silent", "-json", "-rate", str(concurrency)]
        if ports == "full":
            argv += ["-p", "-"]
        elif ports in _PORT_PRESET:
            argv += ["-top-ports", _PORT_PRESET[ports]]
        else:
            argv += ["-p", ports]
        return argv

    def parse_record(self, obj: Dict[str, Any]) -> Optional[Tuple[str, PortInfo, str]]:
        ip = obj.get("ip")
        port = obj.get("port")
        if not ip or port is None:
            return None
        try:
            port_id = int(port)
        except (TypeError, ValueError):
            return None
        return (str(ip), PortInfo(port_id=port_id, protocol="tcp"), str(obj.get("host") or ""))

    def scan(self, targets: Iterable[str], ports: str = "top-1000",
             concurrency: int = 500) -> List[IPRec]:
        agg: Dict[str, IPRec] = {}
        for ip, port_rec, host in self.run(stdin_lines=targets, ports=ports, concurrency=concurrency):
            rec = agg.setdefault(ip, IPRec(ip=ip))
            if port_rec.port_id not in {p.port_id for p in rec.ports}:
                rec.ports.append(port_rec)
            if host and host not in rec.domains:
                rec.domains.append(host)
        return list(agg.values())
