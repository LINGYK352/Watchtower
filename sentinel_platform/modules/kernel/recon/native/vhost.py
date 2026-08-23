"""vhost —— 虚拟主机（Host 头碰撞）发现（native 纯 Python，urllib + 基线对比）。

对一个 IP，用候选 hostname 逐个发 `Host` 头请求，与「随机不存在 Host 的基线」对比：
响应差异显著（状态不同 或 body 长度差 ≥64B）→ 该 hostname 在此 IP 上是独立 vhost →
产出 `SiteRec`（url=scheme://host/，hostname/ip/status/body_length；对齐 site 集合）。
补「站点发现」缺口：同 IP 上未被 DNS/证书暴露的旁站靠 Host 碰撞挖出。

这是「native 能力」非 external 工具：Host 碰撞是通用技术，从零编写、仅标准库
（urllib/ssl/concurrent），**无第三方依赖、无需 vendor**。恒可用（available() 恒真）。
线程池并发、单请求超时。**禁止硬限制参数**：candidate hostnames 不砍，并发度只是线程池宽度。

供 recon pipeline 的 vhost 阶段调用（P1 未建时经 registry 注册待取，honest degrade）；
产出 SiteRec → 消费方落 site 集合 → 前端 `/api/site/`（asset/search）展示。
参照旧引擎 sentinel_engine/capabilities/native/vhost.py 逻辑净室重写（字段对齐属数据契约）。
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional, Tuple

from ..models import SiteRec

# registry 角色常量（vhost 碰撞）
ROLE_VHOST = "vhost"

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
# 基线用的随机不存在 Host（与任何真实 vhost 都不同，取"默认响应"作对比基准）
_BASELINE_HOST = "sentinel-nonexist-host.invalid"
# 判为独立 vhost 的 body 长度差阈值（小于此且状态相同 → 视作同一默认响应）
_LEN_DELTA = 64


class VhostFinder:
    """Host 头碰撞发现器。find(ip, hostnames, scheme=) → List[SiteRec]。"""

    adapter = "native_vhost"

    def __init__(self, timeout: float = 8.0, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = max(1, int(concurrency))    # 下限保护；非上限
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE           # 目标常自签，不校验

    def available(self) -> bool:
        return True                                     # 纯标准库，恒可用

    def find(self, ip: str, hostnames: Iterable[str], scheme: str = "http",
             **kwargs) -> List[SiteRec]:
        """对一个 IP 用候选 hostnames 做 Host 碰撞。差异显著者判为独立 vhost。

        **禁止硬限制参数**：hostnames 数量不砍，全量并发探（并发度只是线程池宽度）。
        """
        ip = (ip or "").strip()
        hosts = [h.strip() for h in (hostnames or []) if h and h.strip()]
        if not ip or not hosts:
            return []
        base_url = "{}://{}/".format(scheme, ip)
        baseline = self._request(base_url, _BASELINE_HOST)   # 默认响应基线

        def _probe(host: str) -> Optional[SiteRec]:
            resp = self._request(base_url, host)
            if resp is None:
                return None
            status, length = resp
            # 与基线差异显著（状态不同 或 长度差 ≥阈值）→ 独立 vhost；基线取不到则一律收
            if baseline is None or status != baseline[0] or abs(length - baseline[1]) >= _LEN_DELTA:
                return SiteRec(url="{}://{}/".format(scheme, host), hostname=host,
                               ip=ip, status=status, body_length=length)
            return None

        out: List[SiteRec] = []
        seen = set()
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(hosts))) as pool:
            for rec in pool.map(_probe, hosts):
                if rec is not None and rec.hostname not in seen:
                    seen.add(rec.hostname)
                    out.append(rec)
        return out

    def _request(self, url: str, host: str) -> Optional[Tuple[int, int]]:
        """带 Host 头请求，返回 (status, body_length) 或 None（连不上/超时）。"""
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Host": host})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                body = resp.read(65536)
                return (getattr(resp, "status", 200) or 200, len(body))
        except urllib.error.HTTPError as e:              # 4xx/5xx 也拿状态判差异
            try:
                body = e.read(65536)
            except Exception:
                body = b""
            return (e.code, len(body))
        except Exception:
            return None
