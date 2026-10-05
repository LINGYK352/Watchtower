"""icmp —— 主机存活探测（native 纯 Python，raw socket ICMP + TCP 降级）。

对每个主机发 ICMP echo（raw socket，需 CAP_NET_RAW——worker 容器有；web/scheduler 无）；
**无权限（PermissionError/OSError）或探不通 → 降级 TCP connect 探活**（探常见端口 80/443/22，
连上任一即判存活）。这是「native 能力」非 external 工具：ICMP/socket 是通用技术，从零编写，
仅用标准库（socket/struct/select/concurrent），**无第三方依赖、无需 vendor**。恒可用（available() 恒真）。

同时服务两路：① AI 工具 icmp_ping（经 recon_bridge.icmp_ping）② 侦察 pipeline _stage_icmp（经 Tools.icmp）。
返回 List[AliveRec]（models.AliveRec：host/alive/rtt_ms/method）。
"""
from __future__ import annotations

import os
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional

from ..models import AliveRec

# registry 角色常量（主机存活探测）——与 recon/registry ROLE_* 同层语义，pipeline/bridge 经此取。
ROLE_ICMP_PING = "icmp_ping"

# TCP 降级探活的常见端口（raw ICMP 不可用/不通时用；连上任一即存活）。
_TCP_FALLBACK_PORTS = (443, 80, 22)
_ICMP_ECHO_REQUEST = 8


class IcmpPing:
    """主机存活探测器。ping(["1.2.3.4", "host", ...]) → List[AliveRec]。"""

    adapter = "native_icmp"

    def __init__(self, timeout: float = 2.0, concurrency: int = 30):
        self.timeout = float(timeout)
        self.concurrency = max(1, int(concurrency))   # 下限保护；非上限（不砍调用方请求量）

    def available(self) -> bool:
        return True                                    # 纯标准库 + TCP 降级，恒可用

    def ping(self, targets: Iterable[str]) -> List[AliveRec]:
        """targets: IP 或域名 可迭代。返回每个目标的 AliveRec（含存活与否，不跳过——探活结果都要）。
        **禁止硬限制参数**：不对 targets 数量设上限（并发度只是线程池宽度，非截断）。"""
        hosts = [str(t).strip() for t in (targets or []) if str(t).strip()]
        if not hosts:
            return []
        out: List[AliveRec] = []
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(hosts))) as pool:
            for rec in pool.map(self._probe_one, hosts):
                if rec is not None:
                    out.append(rec)
        return out

    def _probe_one(self, host: str) -> Optional[AliveRec]:
        # 先解析（域名→IP）；解析失败直接判不存活
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return AliveRec(host=host, ip="", alive=False, rtt_ms=0.0, method="dns_fail")
        # ① ICMP echo（raw socket，需 CAP_NET_RAW）
        rtt = self._icmp_echo(ip)
        if rtt is not None:
            return AliveRec(host=host, ip=ip, alive=True, rtt_ms=round(rtt, 1), method="icmp")
        # ② 降级 TCP connect 探活（无 NET_RAW 或 ICMP 被防火墙丢——政务站常禁 ping 但开 web）
        trtt = self._tcp_connect(ip)
        if trtt is not None:
            return AliveRec(host=host, ip=ip, alive=True, rtt_ms=round(trtt, 1), method="tcp")
        return AliveRec(host=host, ip=ip, alive=False, rtt_ms=0.0, method="none")

    def _icmp_echo(self, ip: str) -> Optional[float]:
        """发一个 ICMP echo，返回 RTT(ms) 或 None（无权限/超时/不通）。无 CAP_NET_RAW 抛 PermissionError → None。"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except (PermissionError, OSError):
            return None                                # 无 NET_RAW（web/scheduler 容器）→ 交 TCP 降级
        try:
            sock.settimeout(self.timeout)
            pkt_id = os.getpid() & 0xFFFF
            packet = self._build_icmp(pkt_id)
            start = time.time()
            sock.sendto(packet, (ip, 0))
            # 等回包（只要收到该 ip 的 ICMP 回应即判存活，不严格校验 id——降低误判）
            while True:
                remaining = self.timeout - (time.time() - start)
                if remaining <= 0:
                    return None
                sock.settimeout(remaining)
                try:
                    _data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    return None
                if addr and addr[0] == ip:
                    return (time.time() - start) * 1000.0
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _tcp_connect(self, ip: str) -> Optional[float]:
        """TCP connect 探活：常见端口连上任一即存活，返回 RTT(ms) 或 None。"""
        for port in _TCP_FALLBACK_PORTS:
            start = time.time()
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    return (time.time() - start) * 1000.0
            except Exception:
                continue
        return None

    @staticmethod
    def _build_icmp(pkt_id: int) -> bytes:
        """构造 ICMP echo request 包（type=8, code=0, 含校验和）。"""
        header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, pkt_id, 1)
        payload = b"sentinel-icmp-probe"
        chksum = IcmpPing._checksum(header + payload)
        header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, chksum, pkt_id, 1)
        return header + payload

    @staticmethod
    def _checksum(data: bytes) -> int:
        """ICMP 校验和（16 位反码求和）。"""
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF
