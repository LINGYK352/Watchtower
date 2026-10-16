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
        return self.capture_site(site)[0]

    def capture_site(self, site: str):
        from .js_dependencies import discover
        import hashlib, time
        out, seen, fetched, queue = [], set(), set(), [site]
        metadata = {'source_url': site, 'capture_status': '', 'incomplete_reason': '', 'content_sha256': ''}
        deadline = time.monotonic() + max(15, self.timeout * 4)
        total_bytes = 0
        report = {'site':site,'files':[],'incomplete_reasons':[],
                  'static_requests':0,'browser_used':False,'complete_site_coverage':False}

        def _add(rtype: str, content: str):
            key = rtype + '|' + content
            if content and key not in seen:
                seen.add(key)
                out.append(WihRec(record_type=rtype, content=content, site=site, **metadata))

        def process():
            nonlocal total_bytes
            while queue and len(fetched) < 128 and total_bytes < 32 * 1024 * 1024 and time.monotonic() < deadline:
                url = queue.pop(0)
                if url in fetched: continue
                fetched.add(url)
                document = self._fetch_document(url)
                report['static_requests'] += 1
                report['files'].append({k:v for k,v in document.items() if k!='text'})
                total_bytes += document['bytes']
                metadata.update({'source_url': url, 'capture_status': document['state'],
                                 'incomplete_reason': document['reason'], 'content_sha256': document['sha256']})
                if url != site: _add('js', url)
                if not document['text'] or not 200 <= document['status'] < 300: continue
                discovery = discover(document['text'], document.get('url') or url, document_url=site)
                if discovery['incomplete_reasons']:
                    report['incomplete_reasons'].extend(discovery['incomplete_reasons'])
                    metadata['incomplete_reason'] = '; '.join(filter(None,[metadata['incomplete_reason'], ','.join(discovery['incomplete_reasons'])]))
                self._extract(document['text'], _add)
                for candidate in discovery['references']:
                    child = candidate['url']
                    if child in fetched or child in queue: continue
                    # Automatic reconstruction stays on the source origin. External
                    # candidates are retained for an explicit authorized follow-up.
                    a, b = urlparse(url), urlparse(child)
                    if (a.scheme,a.netloc) == (b.scheme,b.netloc): queue.append(child)
                    else:
                        saved = dict(metadata)
                        metadata.update({'capture_status':'candidate','incomplete_reason':'external_origin_requires_followup'})
                        _add('js',child); metadata.update(saved)

        process()
        # Preserve existing runtime/XHR coverage. This is supplemental observation,
        # not a guarantee of modern JS compatibility or complete SPA coverage.
        try:
            from .native.resources import DynamicResources
            adapter = DynamicResources(timeout=int(max(1,self.timeout)))
            report['runtime_adapter_available'] = adapter.available()
            dynamic = adapter.capture(site)
            report['browser_used'] = dynamic.get('ok') is True
            if dynamic.get('degraded') or not dynamic.get('ok'): report['incomplete_reasons'].append('runtime_adapter_unavailable_or_incomplete')
            metadata.update({'source_url':site,'capture_status':'runtime_observed',
                             'incomplete_reason':'runtime_observation_is_partial','content_sha256':''})
            if dynamic.get('dom'): self._extract(dynamic['dom'],_add)
            for url in dynamic.get('apis') or []: _add('api',url)
            for url in dynamic.get('js') or []:
                if url not in fetched and url not in queue: queue.append(url)
            process()
        except Exception: pass
        if queue:
            report['incomplete_reasons'].append('collection_budget_reached')
            metadata.update({'source_url':site,'capture_status':'candidate',
                             'incomplete_reason':'collection_budget_reached','content_sha256':''})
            for url in queue[:4096]: _add('js',url)
        report['incomplete_reasons']=sorted(set(report['incomplete_reasons']))
        return out, report

    def _fetch_document(self, url: str):
        import hashlib
        result = {'text':'','status':0,'state':'failed','reason':'','bytes':0,'sha256':'','url':url}
        try:
            class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    a,b=urlparse(req.full_url),urlparse(newurl)
                    if (a.scheme,a.netloc)!=(b.scheme,b.netloc): raise ValueError('external_origin_redirect_not_analyzed')
                    return super().redirect_request(req,fp,code,msg,headers,newurl)
            request = urllib.request.Request(url,headers={'User-Agent':_UA})
            opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=self._ctx),SameOriginRedirect())
            with opener.open(request,timeout=self.timeout) as response:
                data = response.read(self.max_bytes + 1)
                clipped = len(data) > self.max_bytes
                data = data[:self.max_bytes]
                status = response.getcode()
                result.update({'status':status,'url':response.geturl(),'bytes':len(data),
                               'sha256':hashlib.sha256(data).hexdigest(),
                               'state':'truncated' if clipped else 'fetched',
                               'reason':'file_byte_budget_reached' if clipped else ''})
                body = data.decode(response.headers.get_content_charset() or 'utf-8',errors='replace')
                if url != response.geturl() and urlparse(url).netloc != urlparse(response.geturl()).netloc:
                    result.update({'state':'redirected','reason':'external_origin_redirect_not_analyzed'});return result
                if re.search(r'\.(?:m?js|cjs)(?:[?]|$)',url,re.I) and re.match(r'\s*<(?:!doctype|html)\b',body,re.I):
                    result.update({'state':'not_javascript','reason':'javascript_url_returned_html'});return result
                result['text']=body
        except urllib.error.HTTPError as exc:
            result.update({'status':exc.code,'reason':'HTTP '+str(exc.code)})
        except Exception as exc:
            result['reason']=type(exc).__name__
        return result

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
