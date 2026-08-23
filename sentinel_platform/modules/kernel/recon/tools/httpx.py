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

    def build_argv(self, concurrency: int = 100, **kwargs: Any) -> List[str]:
        return [
            "-silent", "-json", "-title", "-status-code", "-web-server",
            "-tech-detect", "-favicon", "-content-length",
            "-include-response-header", "-threads", str(concurrency),
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
        return self.run(stdin_lines=targets, concurrency=concurrency)


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
