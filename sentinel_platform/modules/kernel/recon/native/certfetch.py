"""certfetch —— TLS 证书抓取（native 纯 Python，ssl + socket）。

对每个 `ip:port` 建 TLS 连接取对端证书，PEM 编码存入 `CertRec.cert`（对齐 cert 集合）。
**不校验证书**（目标常自签，仅取证不信任校验）、线程池并发、单连接超时。这是「native 能力」
非 external 工具：ssl 取证是通用技术，从零编写，仅用标准库（socket/ssl/concurrent），
**无第三方依赖、无需 vendor**。恒可用（available() 恒真）。

供 recon pipeline 的证书阶段调用（P1 未建时由 registry 注册待取，honest degrade）；
产出 CertRec → 消费方（pipeline/intel）落 cert 集合 → 前端 `/api/cert/`（asset/search）展示。
参照旧引擎 sentinel_engine/capabilities/native/certfetch.py 逻辑净室重写（字段对齐属数据契约）。
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional, Tuple

from ..models import CertRec

# registry 角色常量（证书抓取）——与 recon/registry ROLE_* 同层语义，pipeline 经此取。
ROLE_CERT_FETCH = "cert_fetch"


class CertFetcher:
    """TLS 证书抓取器。fetch(["ip:port", ...]) → List[CertRec]。"""

    adapter = "native_certfetch"

    def __init__(self, timeout: float = 5.0, concurrency: int = 15):
        self.timeout = timeout
        self.concurrency = max(1, int(concurrency))   # 下限保护；非上限（不砍调用方请求量）

    def available(self) -> bool:
        return True                                    # 纯标准库，恒可用

    def fetch(self, targets: Iterable[str]) -> List[CertRec]:
        """targets: "ip:port" 可迭代。返回成功取到证书的 CertRec 列表（取不到的跳过）。

        **禁止硬限制参数**：不对 targets 数量设上限，全量并发抓（并发度只是线程池宽度，非截断）。
        """
        parsed: List[Tuple[str, int]] = []
        for t in targets or []:
            hp = self._parse(t)
            if hp:
                parsed.append(hp)
        if not parsed:
            return []
        out: List[CertRec] = []
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(parsed))) as pool:
            for rec in pool.map(lambda hp: self._fetch_one(*hp), parsed):
                if rec is not None:
                    out.append(rec)
        return out

    def _fetch_one(self, ip: str, port: int) -> Optional[CertRec]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE               # 只取证不校验（目标常自签）
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            if not der:
                return None
            return CertRec(ip=ip, port=port, cert=ssl.DER_cert_to_PEM_cert(der))
        except Exception:
            return None                               # 连不上/非 TLS/超时 → 跳过不报错

    @staticmethod
    def _parse(target: str) -> Optional[Tuple[str, int]]:
        """"ip:port" → (ip, port)；非法（无端口/端口非数字）返回 None。"""
        if not isinstance(target, str) or ":" not in target:
            return None
        host, _, port = target.rpartition(":")
        host = host.strip()
        if not host:
            return None
        try:
            p = int(port)
        except ValueError:
            return None
        if not (0 < p < 65536):
            return None
        return host, p
