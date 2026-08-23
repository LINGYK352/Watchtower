"""fileleak —— 文件/路径泄漏探测（native 纯 Python，urllib + 基线去误报）。

对每个站点拼接字典路径请求，命中（2xx/206/403/500 且非误报）记为泄漏 → `FileLeakRec`
（对齐 fileleak 集合）。**基线去误报**：先请求一个随机不存在路径取基线状态/长度，命中若与
基线同状态且长度相近（<32B）判为泛响应（如统一 404 页/SPA 首页）跳过。线程池并发、单请求超时。

这是「native 能力」非 external 工具：字典爆破+基线去误报是通用做法，从零编写、仅标准库
（urllib/ssl/concurrent），**无第三方依赖、无需 vendor**。恒可用（available() 恒真）。
内置默认小字典，够用即止；生产可经 wordlist 注入完整字典（**不设条数上限，禁硬限制**）。

供 recon pipeline 的文件泄漏阶段调用（P1 未建时经 registry 注册待取，honest degrade）；
产出 FileLeakRec → 消费方落 fileleak 集合 → 前端 `/api/fileleak/`（asset/search）展示。
参照旧引擎 sentinel_engine/capabilities/native/fileleak.py 逻辑净室重写（字段对齐属数据契约）。
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urljoin

from ..models import FileLeakRec

# registry 角色常量（文件泄漏扫描）
ROLE_FILE_LEAK = "file_leak"

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

# 内置默认字典（小集，够用即止；生产可经 wordlist 注入完整字典）。
DEFAULT_WORDLIST = [
    ".git/config", ".git/HEAD", ".svn/entries", ".env", ".DS_Store",
    "backup.zip", "backup.sql", "web.config", "phpinfo.php", "robots.txt",
    ".gitignore", "config.php.bak", "www.zip", "test.php", "info.php",
    "server-status", "actuator/env", "actuator/health", ".bash_history",
    "WEB-INF/web.xml", "swagger.json", "swagger-ui.html", "druid/index.html",
]
# 命中候选状态码（其余视为未命中）
_HIT_STATUS = (200, 206, 403, 500)


class FileLeakScanner:
    """文件泄漏扫描器。scan(sites, wordlist=None) → List[FileLeakRec]。"""

    adapter = "native_fileleak"

    def __init__(self, timeout: float = 8.0, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = max(1, int(concurrency))   # 下限保护；非上限
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE          # 目标常自签，不校验

    def available(self) -> bool:
        return True                                    # 纯标准库，恒可用

    def scan(self, sites: Iterable[str], wordlist: Optional[List[str]] = None,
             **kwargs) -> List[FileLeakRec]:
        """对一批站点做文件泄漏探测。wordlist 注入则用它（**不砍条数**），否则内置默认集。"""
        words = [w for w in (wordlist or DEFAULT_WORDLIST) if w]
        out: List[FileLeakRec] = []
        for site in sites or []:
            if site:
                out.extend(self._scan_site(str(site), words))
        return out

    def _scan_site(self, site: str, words: List[str]) -> List[FileLeakRec]:
        base = site if site.endswith("/") else site + "/"
        baseline = self._request(urljoin(base, "sentinel_nonexist_a1b2c3d4"))  # 基线

        def _probe(path: str) -> Optional[FileLeakRec]:
            resp = self._request(urljoin(base, path))
            if resp is None:
                return None
            status, length, title = resp
            if status not in _HIT_STATUS:
                return None
            if baseline is not None:                    # 基线去误报
                b_status, b_len, _ = baseline
                if status == b_status and abs(length - b_len) < 32:
                    return None
            return FileLeakRec(site=site, url=urljoin(base, path), title=title,
                               status_code=status, content_length=length)

        hits: List[FileLeakRec] = []
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(words) or 1)) as pool:
            for rec in pool.map(_probe, words):
                if rec is not None:
                    hits.append(rec)
        return hits

    def _request(self, url: str) -> Optional[Tuple[int, int, str]]:
        """返回 (status, content_length, title) 或 None（连不上/超时）。"""
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                body = resp.read(65536)
                return (getattr(resp, "status", 200) or 200, len(body), _extract_title(body))
        except urllib.error.HTTPError as e:            # 403/404/500 等仍要拿状态判命中
            try:
                body = e.read(65536)
            except Exception:
                body = b""
            return (e.code, len(body), _extract_title(body))
        except Exception:
            return None


def _extract_title(body: bytes) -> str:
    try:
        text = body.decode("utf-8", "ignore")
    except Exception:
        return ""
    low = text.lower()
    i = low.find("<title>")
    if i == -1:
        return ""
    j = low.find("</title>", i)
    if j == -1:
        return ""
    return text[i + 7:j].strip()[:200]
