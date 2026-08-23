"""nmap 服务/版本识别对接 —— 填补 naabu 只给端口号、无服务指纹的缺口。

naabu 端口扫描只产出开放端口号（PortInfo.port_id），无 service_name/version。用 nmap -sV
对已发现端口做服务/版本识别，回填 PortInfo.{service_name, version, product}，对齐 ip.port_info 结构。

nmap 是 GPL 工具，subprocess CLI arm's-length 调用（进程边界，许可不传染，见 GPL 插件边界）。
输出用 -oG（grepable）行内自解析，无需 XML 依赖——非 JSONL，故不走 base.ExternalTool 的 JSONL run，
自实现 locate/available/detect/parse（同 weakbrute 范式）。净室重写旧引擎 nmap_service.py，勿抄。

只依赖 core + stdlib(shutil/subprocess)，无第三方库。timeout/version_intensity 可配，无硬编码上限。
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

from ..models import IPRec, PortInfo


class NmapService:
    adapter = "nmap_service"

    def __init__(self, binary_path: str = "", timeout: int = 600, version_intensity: int = 2):
        self._path = binary_path or ""
        self.timeout = timeout
        # 0-9，越低越快；默认 2（够识别常见服务，省时）。可配非硬上限。
        self.version_intensity = version_intensity

    def locate(self) -> str:
        if self._path:
            return shutil.which(self._path) or self._path
        return shutil.which("nmap") or ""

    def available(self) -> bool:
        return bool(self.locate())

    def detect(self, ip: str, ports: List[int]) -> Dict[int, PortInfo]:
        """对 ip 的指定端口做 -sV，返回 {port_id: PortInfo(含 service/version)}。
        工具缺失/超时/无端口 → 返回 {}（降级不抛）。"""
        binary = self.locate()
        clean_ports = sorted({int(p) for p in (ports or []) if str(p).strip().isdigit() or isinstance(p, int)})
        if not binary or not clean_ports:
            return {}
        port_arg = ",".join(str(p) for p in clean_ports)
        argv = [binary, "-sV", "-Pn", "-T4",
                "--version-intensity", str(self.version_intensity),
                "-p", port_arg, "-oG", "-", str(ip)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout, encoding="utf-8", errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return {}
        return self.parse(proc.stdout or "")

    @staticmethod
    def parse(output: str) -> Dict[int, PortInfo]:
        """解析 -oG 'Ports:' 行。每端口段: port/state/proto/owner/service/rpc/version。
        只收 state=open；service→service_name，version 段→version（nmap 把 product+version 并在此段）。"""
        result: Dict[int, PortInfo] = {}
        for line in output.splitlines():
            if "Ports:" not in line:
                continue
            seg = line.split("Ports:", 1)[1]
            for entry in seg.split(","):
                fields = entry.strip().split("/")
                if len(fields) < 7:
                    continue
                try:
                    port_id = int(fields[0])
                except ValueError:
                    continue
                if fields[1] != "open":
                    continue
                proto = (fields[2] or "tcp").strip() or "tcp"
                service = fields[4].strip()
                version = fields[6].strip().replace("|", " ").strip()
                result[port_id] = PortInfo(port_id=port_id, service_name=service,
                                           version=version, protocol=proto)
        return result

    def enrich(self, ip_rec: IPRec) -> IPRec:
        """就地回填一个 IPRec（naabu 产出）的端口服务信息。返回同一 IPRec（链式）。"""
        if not ip_rec or not ip_rec.ports:
            return ip_rec
        found = self.detect(ip_rec.ip, [p.port_id for p in ip_rec.ports])
        for p in ip_rec.ports:
            hit = found.get(p.port_id)
            if hit:
                p.service_name = hit.service_name or p.service_name
                p.version = hit.version or p.version
                if hit.protocol:
                    p.protocol = hit.protocol
        return ip_rec
