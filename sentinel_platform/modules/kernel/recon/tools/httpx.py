"""httpx 对接 —— HTTP 探测（存活/标题/状态/server/指纹/favicon，MIT）。

原始输出 JSON（一行一站）→ 结构化 SiteRec（对齐 site 集合）。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from ..base import ExternalTool
from ..models import SiteRec


class Httpx(ExternalTool):
    binary = "httpx"
    adapter = "httpx"

    # 浏览器 UA（绕部分 WAF/防爬对默认 httpx UA 的拦截，治政务站「curl/httpx 被挡→误判不存活」漏探）。
    _BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    def build_argv(self, concurrency: int = 100, retries: int = 2,
                   timeout: int = 10, **kwargs: Any) -> List[str]:
        # -retries/-timeout 治「间歇性网络抖动→单次超时即误判目标不存活漏探」（对齐记忆
        # feedback-retry-not-cache-for-flaky-probe：间歇失败优先重试自愈，非缓存）。httpx 原生按
        # 目标重试（成功的不重探，比外层跨请求重试精准）；timeout 比默认(~5s)略宽容纳慢站。
        # 二者可经 kwargs/调用方覆盖，不写死上限（守 feedback-no-hard-limit-params）。
        return [
            "-silent", "-json", "-title", "-status-code", "-web-server",
            "-tech-detect", "-favicon", "-content-length",
            "-include-response-header", "-threads", str(concurrency),
            "-retries", str(retries), "-timeout", str(timeout),
            "-H", "User-Agent: " + self._BROWSER_UA,
        ]

    def parse_record(self, obj: Dict[str, Any]) -> Optional[SiteRec]:
        url = obj.get("url")
        if not isinstance(url, str) or not url:
            return None
        hostname = urlparse(url).hostname or ""
        ip = obj.get("host", "")
        if ip == hostname:
            ip = ""
        headers = obj.get("raw_header") or ""
        if not headers and isinstance(obj.get("header"), dict):
            headers = _headers_to_str(obj["header"])
        finger: List[Dict[str, Any]] = []
        tech = obj.get("tech") or obj.get("technologies") or []
        if isinstance(tech, list):
            finger = [{"name": t} for t in tech if isinstance(t, str)]
        favicon: Dict[str, Any] = {}
        fav = obj.get("favicon")
        if fav not in (None, ""):
            favicon = {"hash": fav}
        return SiteRec(
            url=url, hostname=hostname,
            ip=ip if isinstance(ip, str) else "",
            title=obj.get("title") or "", status=_safe_int(obj.get("status_code")),
            headers=headers if isinstance(headers, str) else "",
            http_server=obj.get("webserver") or obj.get("web_server") or "",
            body_length=_safe_int(obj.get("content_length")),
            finger=finger, favicon=favicon,
        )

    def probe(self, targets: Iterable[str], concurrency: int = 100) -> List[SiteRec]:
        # http/https 双探：裸目标（无 scheme，如 host 或 ip:port）默认只探一个协议会漏「443明文/
        # 仅HTTP通」类活站——同时喂 http:// 与 https://，任一探通即得站点。已带 scheme 的目标原样透传
        # （尊重上游显式意图，不重复展开）。httpx 按 URL 逐条输出，两个 scheme 各成一条 SiteRec 天然共存。
        return self.run(stdin_lines=_expand_schemes(targets), concurrency=concurrency)

    def probe_stream(self, targets: Iterable[str], on_record, concurrency: int = 100) -> List[SiteRec]:
        """探到一个站点即交付，不等同批慢目标或进程退出；probe 旧接口保持不变。"""
        return self.run(stdin_lines=_expand_schemes(targets), concurrency=concurrency, on_record=on_record)


def _expand_schemes(targets: Iterable[str]) -> List[str]:
    """裸目标（无 scheme）展开成 http:// + https:// 双探；已带 scheme 的原样透传。
    去重保序：同一展开结果不重复喂 httpx（省探测量，守禁硬 cap——只去重不截断）。"""
    out: List[str] = []
    seen = set()
    for raw in (targets or []):
        t = str(raw).strip()
        if not t:
            continue
        variants = [t] if "://" in t else ["http://" + t, "https://" + t]
        for v in variants:
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _headers_to_str(header: Dict[str, Any]) -> str:
    lines = []
    for key, value in header.items():
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        lines.append("{}: {}".format(key, value))
    return "\n".join(lines)
