"""katana 对接 —— 站点 URL 爬虫（MIT / ProjectDiscovery）。

对站点做爬取（含 JS 里的链接），收集 URL 供后续文件泄漏/接口发现/漏扫用。站点 URL 列表喂 stdin，
katana `-silent -json` 每行一 URL 记录 → 结构化 UrlRec（对齐 url 集合 {site,url,title,status_code,content_length}）。

katana `-json` 输出形如 `{"timestamp":..,"request":{"endpoint":..},"response":{"status_code":..,"title":..}}`
或扁平 `{"endpoint":..}`——两种都吃。有响应元信息就回填 title/status_code/content_length。
katana 是 Go 二进制（PATH 解析，不 vendor，同 subfinder/massdns）；爬虫打目标故出口应由 pipeline 按策略控。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from ..base import ExternalTool
from ..models import UrlRec


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


class Katana(ExternalTool):
    binary = "katana"
    adapter = "katana"

    def build_argv(self, concurrency: int = 10, crawl_js: bool = True, depth: int = 0, **kwargs: Any) -> List[str]:
        # -silent 只出结果 / -json 结构化 / -jc 爬 JS 内链接 / -c 并发 / -d 深度(0=用katana默认不写死)
        argv = ["-silent", "-json", "-c", str(_to_int(concurrency) or 10)]
        if crawl_js:
            argv.append("-jc")
        d = _to_int(depth)
        if d > 0:                                  # 不写死深度上限：>0 才传，0=用 katana 自身默认
            argv += ["-d", str(d)]
        return argv

    def parse_record(self, obj: Dict[str, Any]) -> Optional[UrlRec]:
        endpoint = obj.get("endpoint")
        resp = obj.get("response") if isinstance(obj.get("response"), dict) else {}
        if not endpoint:
            req = obj.get("request")
            if isinstance(req, dict):
                endpoint = req.get("endpoint") or req.get("url")
        if not isinstance(endpoint, str) or not endpoint.strip():
            return None
        endpoint = endpoint.strip()
        status = _to_int(resp.get("status_code") or obj.get("status_code"))
        clen = _to_int(resp.get("content_length"))
        title = resp.get("title") if isinstance(resp.get("title"), str) else ""
        return UrlRec(site=endpoint, url=endpoint, title=title,
                      status_code=status, content_length=clen, source="site_spider")

    def crawl(self, sites: Iterable[str], concurrency: int = 10, crawl_js: bool = True,
              depth: int = 0) -> List[UrlRec]:
        """爬一批站点，按 url 去重（同一 URL 只留一条）。工具缺失/无产出返 []（调用方降级）。"""
        seen: Set[str] = set()
        out: List[UrlRec] = []
        for rec in self.run(stdin_lines=sites, concurrency=concurrency, crawl_js=crawl_js, depth=depth):
            if rec.url not in seen:
                seen.add(rec.url)
                out.append(rec)
        return out
