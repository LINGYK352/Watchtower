"""WebInfoHunter —— 纯 Python 净室 JS/HTML 信息挖掘（collect_js 的实现）。

对站点抓 HTML + 引用的 JS，正则提取：接口路径 / URL / 域名 / IP / IP:port / 邮箱 /
手机号 / 常见密钥 → WihRec（对齐 wih 集合）。这是「native 能力」非 external 工具：
正则提取是通用技术，从零编写，不抄 ARL infoHunter、不调 external/wih 二进制。

仅用标准库（urllib/re/ssl/concurrent），无第三方依赖（故无需 vendor 库）。
资源可控：单文件读取字节上限（小机器内存保护）。
"""
from __future__ import annotations

import re
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Set
from urllib.parse import urljoin, urlparse

from .models import WihRec

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

_RE_JS = re.compile(r"""["'\(]\s*([^"'\(\)\s]+?\.js(?:\?[^"'\)\s]*)?)\s*["'\)]""", re.I)
_RE_DOMAIN = re.compile(r"""["']((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})["']""")
# 接口/端点提取：业界标准 **LinkFinder** 正则(MIT，公开算法，净室移植)。
# 覆盖：① 带 scheme 的 URL ② 以 / ./ ../ 开头的绝对/相对路径(**允许 ?query 尾部** —
# 治旧简化正则 `["'](/...)["']` 遇 `?page=1` 就整体失配、漏掉 /acb/2.0/bossManager/listVO?page=1 的回归)
# ③ 含目录且带扩展名的路径 ④ .php/.asp/.jsp/.do/.action 等动态接口文件。
_ENDPOINT_RE = re.compile(
    r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})"""
    r"""|((?:/|\.\./|\./)[^"'><,;| *()(%$^/\\\[\]][^"'><,;|()]{1,})"""
    r"""|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|))"""
    r"""|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|do)(?:\?[^"|']{0,}|)))(?:"|')""")
_RE_URL = re.compile(r"""https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+""")
# 端点噪音过滤(前端库/静态资源，非业务接口)。对齐旧 infoHunter._NOISE_SUBSTR。
_NOISE_SUBSTR = ("jquery", "bootstrap", "vue", "react", "angular", "layui", "polyfill",
                 "node_modules", ".min.js", ".css", ".png", ".jpg", ".jpeg", ".gif",
                 ".svg", ".woff", ".ttf", ".ico", "w3.org", "schema.org", "example.com")


def _is_noise_endpoint(ep: str) -> bool:
    low = ep.lower()
    return any(s in low for s in _NOISE_SUBSTR)
_RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_RE_IPPORT = re.compile(r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)):(\d{1,5})\b")
_RE_MAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")
_RE_MOBILE = re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)")
_RE_SECRETS = [
    ("aws_ak", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]
_STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".ico", ".woff",
               ".ttf", ".webp", ".mp4", ".map")


class WebInfoHunter:
    """站点 JS/HTML 信息挖掘。hunt() 返回结构化 WihRec 列表。"""

    adapter = "native_webinfohunter"

    def __init__(self, timeout: float = 10.0, max_bytes: int = 2 * 1024 * 1024,
                 concurrency: int = 5):
        self.timeout = timeout
        self.max_bytes = max_bytes          # 单文件字节上限（内存保护）
        self.concurrency = concurrency
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def available(self) -> bool:
        return True                          # 纯 Python，恒可用

    # —— 单站点挖掘 ——
    def hunt_site(self, site: str) -> List[WihRec]:
        html = self._fetch(site)
        out: List[WihRec] = []
        seen: Set[str] = set()

        def _add(rtype: str, content: str):
            key = rtype + "|" + content
            if content and key not in seen:
                seen.add(key)
                out.append(WihRec(record_type=rtype, content=content, site=site))

        # 静态轨 + PhantomJS 动态资源/XHR 轨；浏览器缺失时诚实退回静态轨。
        texts = [html] if html else []
        js_urls = set(_RE_JS.findall(html or ""))
        try:
            from .native.resources import DynamicResources
            dynamic = DynamicResources(timeout=int(max(1, self.timeout))).capture(site)
            if dynamic.get("dom"):
                texts.append(dynamic["dom"])
            for url in dynamic.get("js") or []:
                js_urls.add(url)
                _add("js", url)
            for url in dynamic.get("apis") or []:
                _add("api", url)
        except Exception:
            pass
        for js_ref in js_urls:
            js_url = js_ref if str(js_ref).startswith(("http://", "https://")) else urljoin(site, js_ref)
            if js_url.lower().endswith(_STATIC_EXT[:-1]):
                continue
            _add("js", js_url)
            body = self._fetch(js_url)
            if body:
                texts.append(body)
        if texts:
            self._extract("\n".join(texts), _add)
        return out

    def _extract(self, blob: str, add) -> None:
        # 接口/端点(LinkFinder)：group(1)=完整匹配段(可能带 ?query)。过静态/噪音，留业务接口。
        for mo in _ENDPOINT_RE.finditer(blob):
            ep = (mo.group(1) or "").strip()
            if not ep or len(ep) > 200 or _is_noise_endpoint(ep):
                continue
            # 纯静态资源(路径部分去 query 后以静态扩展名结尾)不当接口
            path_only = ep.split("?", 1)[0].split("#", 1)[0]
            if path_only.lower().endswith(_STATIC_EXT):
                continue
            add("url", ep)
        for m in set(_RE_URL.findall(blob)):
            add("url", m.rstrip("\"');,"))
        for m in set(_RE_DOMAIN.findall(blob)):
            if not m.lower().endswith(_STATIC_EXT):
                add("domain", m.lower())
        for ip, port in set(_RE_IPPORT.findall(blob)):
            add("ip_port", "{}:{}".format(ip, port))
        for m in set(_RE_IP.findall(blob)):
            add("ip", m)
        for m in set(_RE_MAIL.findall(blob)):
            add("mail", m)
        for m in set(_RE_MOBILE.findall(blob)):
            add("mobile", m)
        for label, rx in _RE_SECRETS:
            for m in set(rx.findall(blob)):
                add("secret", "{}:{}".format(label, m if isinstance(m, str) else m[0]))

    def _fetch(self, url: str) -> str:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return resp.read(self.max_bytes).decode("utf-8", errors="replace")
        except Exception:
            return ""

    # —— 多站点并发 ——
    def hunt(self, sites: Iterable[str]) -> List[WihRec]:
        site_list = [s for s in sites if s]
        if not site_list:
            return []
        results: List[WihRec] = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for recs in pool.map(self.hunt_site, site_list):
                results.extend(recs)
        return results
