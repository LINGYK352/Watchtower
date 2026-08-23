"""risk_intel/vuln_intel 的抓取器辅助（同类别私有，主叶子 import 它，不对外）。

多源拉取漏洞情报 → 标准化 → 去重入库（经 vuln_intel.upsert_vuln）。周期拉取由
kernel/orchestration 调 run_feed（本文件不含调度循环，只提供能力）。

Fetcher 契约：无参函数返回 list[标准 dict]。标准字段：
  必填 title；关键 cve_id/severity/products；可选 poc_urls/in_kev/cvss/published_date；
  本地可执行 executable/exec_kind(arl_npoc|nuclei)/exec_ref；溯源 source/source_url/source_raw_id。
入库统一经 vuln_intel.upsert_vuln 去重聚合。新增源：写函数 + 加进 FETCHERS + SOURCE_PLATFORMS。

出口策略：境外源（CISA/NVD）可选经 ROLE.PROXY 出口（缺失/失败降级直连）；国内源与 GitHub
强制直连（代理节点多在境外反被拒/慢，读公开情报用真实 IP 可接受，非攻击目标）。

迁移来源：app/services/vuln_feed.py。
"""
from __future__ import annotations

import re
import json
import time
from typing import Any, Callable, Dict, List, Optional

from sentinel_platform.core import get_repo, get_config, get_logger
from sentinel_platform.core.http import http_req
from sentinel_platform.contracts import Collections, get_registry, ROLE

logger = get_logger()

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/known-exploited-vulnerabilities/main/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_FEED_INTERVAL = 6 * 3600  # 6h
_CVE_RE = re.compile(r"CVE[-_]\d{4}[-_]\d{4,}", re.I)
_SEV_CN = {"严重": "critical", "极危": "critical", "高危": "high", "中危": "medium", "低危": "low"}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _egress_proxies() -> Optional[Dict[str, str]]:
    """境外源出口：经 ROLE.PROXY 解析代理 URL；未注册/无代理→None（直连）。缺失降级。"""
    try:
        svc = get_registry().get(ROLE.PROXY)
        if not svc:
            return None
        res = svc.resolve_egress("smart", source="")
        url = res[0] if isinstance(res, (tuple, list)) else res
        return {"http": url, "https": url} if url else None
    except Exception:
        return None


def _is_transient(exc: Exception) -> bool:
    """瞬时错误判定（代理抖动/超时/5xx/429），词边界防误中 404/401。"""
    s = str(exc).lower()
    if any(k in s for k in ("timeout", "timed out", "proxy", "connection", "reset", "temporarily")):
        return True
    return bool(re.search(r"\b(429|500|502|503|504)\b", s))


def _retry(func: Callable, retries: int = 2, backoff=(2, 5), on_retry=None):
    """瞬时失败退避重试；非瞬时或次数用尽即抛。收口一处（对齐旧 utils.retry_on_transient）。"""
    attempt = 0
    while True:
        try:
            return func()
        except Exception as e:  # noqa
            if attempt >= retries or not _is_transient(e):
                raise
            wait = backoff[min(attempt, len(backoff) - 1)]
            if on_retry:
                on_retry(attempt + 1, wait, e)
            time.sleep(wait)
            attempt += 1


def _http_json(url: str, timeout: int = 40, params: Dict[str, Any] = None,
               use_proxy: bool = False) -> Any:
    """经 core.http 拉 JSON。use_proxy=True 时经 ROLE.PROXY 出口（降级直连）。失败抛异常由上层捕获。"""
    if params:
        from urllib.parse import urlencode
        url = url + ("&" if "?" in url else "?") + urlencode(params)
    kwargs: Dict[str, Any] = {"timeout": (10, timeout), "allow_redirects": True}
    if use_proxy:
        pr = _egress_proxies()
        if pr:
            kwargs["proxies"] = pr
    resp = http_req(url, "get", **kwargs)
    return json.loads(resp.content.decode("utf-8", "ignore"))


def _direct_get(url: str, method: str = "get", json_body=None, headers=None, timeout: int = 20):
    """直连请求（绕代理，国内源/GitHub 用）。返回 requests.Response。"""
    import requests  # 惰性
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if headers:
        h.update(headers)
    kw = {"headers": h, "timeout": (10, timeout), "proxies": {"http": None, "https": None}}
    if method == "post":
        return requests.post(url, json=json_body, **kw)
    return requests.get(url, **kw)


# ============================ 境外官方源（可选经代理） ============================
def fetch_cisa_kev(limit: int = 0) -> List[Dict[str, Any]]:
    """CISA KEV → 标准漏洞列表。每条 in_kev=True，products 取 vendor+product。主站失败 fallback GitHub 镜像。"""
    data = None
    for url in [CISA_KEV_MIRROR, CISA_KEV_URL]:
        try:
            data = _http_json(url, timeout=90, use_proxy=True)
            if data and data.get("vulnerabilities"):
                break
        except Exception:
            continue
    if not data or not data.get("vulnerabilities"):
        raise ValueError("CISA KEV fetch failed (both primary and mirror)")
    out = []
    rows = data.get("vulnerabilities") or []
    if limit and limit > 0:
        rows = rows[:limit]
    for v in rows:
        cve = v.get("cveID", "")
        vendor, product = v.get("vendorProject", ""), v.get("product", "")
        out.append({
            "cve_id": cve,
            "title": v.get("vulnerabilityName", "") or "{} {}".format(vendor, product),
            "severity": "high", "products": [p for p in (vendor, product) if p],
            "poc_urls": [], "in_kev": True, "source": "cisa_kev",
            "source_url": "https://nvd.nist.gov/vuln/detail/{}".format(cve) if cve else "",
            "source_raw_id": cve, "published_date": v.get("dateAdded", ""),
        })
    return out


def fetch_nvd_recent(days: int = 3, limit: int = 0) -> List[Dict[str, Any]]:
    """NVD 2.0 近 days 天发布的 CVE → 标准列表。按 API 游标分页；limit=0 拉到源端结束。"""
    from datetime import datetime, timedelta
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out = []
    offset = 0
    page_size = 2000
    while limit <= 0 or len(out) < limit:
        requested = page_size if limit <= 0 else min(page_size, limit - len(out))
        params = {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
                  "resultsPerPage": requested, "startIndex": offset}
        data = _http_json(NVD_API, params=params, use_proxy=True)
        rows = data.get("vulnerabilities") or []
        for item in rows:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            sev = "unknown"
            metrics = cve.get("metrics", {})
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(mk):
                    sev = (metrics[mk][0].get("cvssData", {}).get("baseSeverity", "")
                           or metrics[mk][0].get("baseSeverity", "") or "unknown").lower()
                    break
            products = set()
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 4:
                            if parts[3] and parts[3] != "*":
                                products.add(parts[3])
                            if parts[4] and parts[4] != "*":
                                products.add(parts[4])
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]
                    break
            out.append({
                "cve_id": cid, "title": desc or cid, "severity": sev,
                "products": sorted(products), "poc_urls": [], "in_kev": False, "source": "nvd",
                "source_url": "https://nvd.nist.gov/vuln/detail/{}".format(cid),
                "source_raw_id": cid, "published_date": cve.get("published", ""),
            })
        offset += len(rows)
        total = int(data.get("totalResults") or 0)
        if not rows or (total and offset >= total) or (not total and len(rows) < requested):
            break
    return out


# ============================ 本地可执行源（哨兵能直接打） ============================
def fetch_arl_npoc() -> List[Dict[str, Any]]:
    """哨兵本地 NPoC 插件（poc 集合）→ 情报（source=arl_npoc，executable=可直接执行）。

    poc 集合每条是「组件(app_name)→ 可执行验证手段(vul_name)」映射，纳入情报库，
    AI 查组件时能拿到本地直接能打的 PoC，而非只有外部 CVE 编号。
    """
    out = []
    try:
        docs = list(get_repo().collection(Collections.POC).find({}))
    except Exception as exc:
        logger.debug("fetch_arl_npoc read poc failed: %s", exc)
        return out
    for p in docs:
        app_name = p.get("app_name", "")
        if not app_name:
            continue
        plugin = p.get("plugin_name", "")
        out.append({
            "cve_id": "", "title": p.get("vul_name", "") or "{} 漏洞".format(app_name),
            "severity": "high", "products": [app_name], "poc_urls": [], "in_kev": False,
            "executable": True, "exec_kind": "arl_npoc", "exec_ref": plugin,
            "source": "arl_npoc", "source_url": "",
            "source_raw_id": "npoc:{}".format(plugin), "published_date": "",
        })
    return out


def _nuclei_templates_dir() -> str:
    """定位 nuclei 模板目录：配置 NUCLEI.TEMPLATES_DIR 优先，否则标准候选路径。缺失返回空。"""
    import os
    cfg_dir = ""
    try:
        cfg_dir = get_config().section("NUCLEI", "TEMPLATES_DIR", default="") or ""
    except Exception:
        cfg_dir = ""
    candidates = [cfg_dir, os.path.expanduser("~/nuclei-templates"),
                  os.path.expanduser("~/.config/nuclei-templates")]
    return next((c for c in candidates if c and os.path.isdir(c)), "")


def fetch_nuclei_templates(limit: int = 0) -> List[Dict[str, Any]]:
    """哨兵本地 nuclei 模板 → 情报（source=nuclei，executable=可直接扫）。模板目录不存在则跳过（返回空不报错）。"""
    import os
    import glob
    base = _nuclei_templates_dir()
    if not base:
        return []
    import yaml  # 惰性（vendor: PyYAML-5.4.1）
    out = []
    paths = glob.glob(os.path.join(base, "**", "*.yaml"), recursive=True)
    if limit and limit > 0:
        paths = paths[:limit]
    for fp in paths:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                tpl = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(tpl, dict):
            continue
        tid = tpl.get("id", "")
        info = tpl.get("info", {}) or {}
        tags = info.get("tags", "")
        tags_l = tags.split(",") if isinstance(tags, str) else (tags or [])
        out.append({
            "cve_id": tid if str(tid).upper().startswith("CVE") else "",
            "title": info.get("name", "") or tid,
            "severity": (info.get("severity", "") or "unknown").lower(),
            "products": tags_l, "poc_urls": [], "in_kev": False,
            "executable": True, "exec_kind": "nuclei", "exec_ref": tid,
            "source": "nuclei", "source_url": "",
            "source_raw_id": "nuclei:{}".format(tid), "published_date": "",
        })
    return out


# ============================ GitHub PoC 监听源（强制直连） ============================
POC_MONITOR_JSON = "https://raw.githubusercontent.com/sari3l/Poc-Monitor/main/update.json"


def fetch_poc_monitor() -> List[Dict[str, Any]]:
    """sari3l/Poc-Monitor update.json → 情报。每项是 GitHub PoC 仓库（name 常含 CVE）。"""
    out = []
    try:
        resp = _direct_get(POC_MONITOR_JSON, timeout=40)
        if resp.status_code != 200:
            logger.warning("fetch_poc_monitor http %s", resp.status_code)
            return out
        repos = resp.json()
    except Exception as e:
        logger.warning("fetch_poc_monitor failed: %s", e)
        return out
    for r in (repos if isinstance(repos, list) else []):
        name, full = r.get("name", "") or "", r.get("full_name", "") or ""
        html, desc = r.get("html_url", "") or "", r.get("description", "") or ""
        cve_m = _CVE_RE.search(name) or _CVE_RE.search(full) or _CVE_RE.search(desc)
        cve = cve_m.group(0).upper().replace("_", "-") if cve_m else ""
        out.append({
            "cve_id": cve, "title": (desc or full or name)[:200], "severity": "unknown",
            "products": [], "poc_urls": [html] if html else [], "in_kev": False,
            "source": "poc_monitor", "source_url": html,
            "source_raw_id": cve or full or name, "published_date": r.get("created_at", "") or "",
        })
    return out


# ============================ 国内源（移植 watchvuln，强制直连） ============================
def fetch_qianxin_ti() -> List[Dict[str, Any]]:
    """奇安信威胁情报中心 one-day 接口 → 当天新增漏洞。"""
    out = []
    try:
        resp = _direct_get("https://ti.qianxin.com/alpha-api/v2/vuln/one-day", method="post",
                           headers={"Referer": "https://ti.qianxin.com/", "Origin": "https://ti.qianxin.com"})
        data = resp.json().get("data", {}) or {}
    except Exception as e:
        logger.warning("fetch_qianxin_ti failed: %s", e)
        return out
    seen = set()
    for key in ("key_vuln_add", "vuln_add", "poc_exp_add"):
        for d in (data.get(key) or []):
            qvd = d.get("qvd_code", "") or str(d.get("id", ""))
            if qvd in seen:
                continue
            seen.add(qvd)
            cve = (d.get("cve_code", "") or "").strip()
            out.append({
                "cve_id": cve.upper() if cve else "",
                "title": d.get("vuln_name", "") or d.get("vuln_name_en", ""),
                "severity": _SEV_CN.get((d.get("rating_level", "") or "").strip(), "unknown"),
                "products": [], "poc_urls": [], "in_kev": False,
                "source": "qianxin_ti",
                "source_url": "https://ti.qianxin.com/vulnerability/detail/{}".format(d.get("id", "")),
                "source_raw_id": cve or "qvd:{}".format(qvd),
                "published_date": (d.get("publish_time", "") or "")[:10],
            })
    return out


def fetch_threatbook() -> List[Dict[str, Any]]:
    """微步在线漏洞通告 homePage 接口 → 高危/premium 漏洞。"""
    out = []
    try:
        resp = _direct_get("https://x.threatbook.com/v5/node/vul_module/homePage",
                           headers={"Referer": "https://x.threatbook.com/v5/vulIntelligence"})
        data = resp.json().get("data", {}) or {}
    except Exception as e:
        logger.warning("fetch_threatbook failed: %s", e)
        return out
    seen = set()
    for key in ("highrisk", "premium"):
        for v in (data.get(key) or []):
            vid = v.get("id", "")
            if not vid or vid in seen:
                continue
            seen.add(vid)
            cve_m = _CVE_RE.search(vid) or _CVE_RE.search(v.get("vuln_name_zh", ""))
            out.append({
                "cve_id": cve_m.group(0).upper().replace("_", "-") if cve_m else "",
                "title": v.get("vuln_name_zh", ""), "severity": "high",
                "products": [], "poc_urls": [], "in_kev": False, "source": "threatbook",
                "source_url": "https://x.threatbook.com/v5/vul/{}".format(vid),
                "source_raw_id": "xve:{}".format(vid),
                "published_date": (v.get("vuln_publish_time") or v.get("vuln_update_time") or "")[:10],
            })
    return out


def fetch_chaitin(pages: int = 2) -> List[Dict[str, Any]]:
    """长亭漏洞库 api/v2/vuln/list → 漏洞。CT- 为长亭标识。"""
    out = []
    sev_map = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
    for i in range(pages):
        url = "https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset={}&search=CT-".format(i * 15)
        try:
            resp = _direct_get(url, headers={"Referer": "https://stack.chaitin.com/vuldb/index",
                                             "Origin": "https://stack.chaitin.com"})
            lst = (resp.json().get("data", {}) or {}).get("list", []) or []
        except Exception as e:
            logger.warning("fetch_chaitin page %s failed: %s", i, e)
            break
        if not lst:
            break
        for d in lst:
            cve = d.get("cve_id") or ""
            refs = (d.get("references") or "").split("\n") if d.get("references") else []
            out.append({
                "cve_id": cve.upper() if cve else "", "title": d.get("title", ""),
                "severity": sev_map.get((d.get("severity") or "").lower(), "unknown"),
                "products": [], "poc_urls": [r.strip() for r in refs if r.strip().startswith("http")],
                "in_kev": False, "source": "chaitin",
                "source_url": "https://stack.chaitin.com/vuldb/detail/{}".format(d.get("id", "")),
                "source_raw_id": cve or "ct:{}".format(d.get("ct_id", "") or d.get("id", "")),
                "published_date": (d.get("disclosure_date") or (d.get("created_at") or "")[:10] or ""),
            })
    return out


def fetch_venustech(pages: int = 2) -> List[Dict[str, Any]]:
    """启明星辰漏洞通告列表页 → 漏洞（轻量版，不逐条爬详情）。微软月度/Oracle 季度「多个安全漏洞」跳过。"""
    out = []
    for i in range(1, pages + 1):
        url = "https://www.venustech.com.cn/new_type/aqtg/"
        if i > 1:
            url += "index_{}.html".format(i)
        try:
            resp = _direct_get(url, timeout=20)
            html = resp.content.decode("utf-8", "ignore")
        except Exception as e:
            logger.warning("fetch_venustech page %s failed: %s", i, e)
            break
        m = re.search(r"main-inner-bt(.*?)(?:main-inner|footer|</body)", html, re.S)
        block = m.group(1) if m else html
        items = re.findall(r'<li[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not items:
            break
        for href, raw_title in items:
            title = re.sub(r"<[^>]+>", "", raw_title).strip()
            title = re.sub(r"^【漏洞通告】", "", title).strip()
            if not title or "多个安全漏洞" in title:
                continue
            cve_m = _CVE_RE.search(title)
            date_m = re.search(r"/(\d{8})/", href)
            pub = ""
            if date_m:
                d = date_m.group(1)
                pub = "{}-{}-{}".format(d[:4], d[4:6], d[6:8])
            full_url = href if href.startswith("http") else "https://www.venustech.com.cn" + href
            out.append({
                "cve_id": cve_m.group(0).upper().replace("_", "-") if cve_m else "",
                "title": title, "severity": "high", "products": [], "poc_urls": [],
                "in_kev": False, "source": "venustech", "source_url": full_url,
                "source_raw_id": (cve_m.group(0) if cve_m else "") or "venus:{}".format(href),
                "published_date": pub,
            })
    return out


def fetch_seebug(pages: int = 2) -> List[Dict[str, Any]]:
    """Seebug 漏洞平台列表页 → 漏洞（HTML 解析）。触发 WAF 时解析为空、记 warning 不崩（已知限制）。"""
    out = []
    for p in range(1, pages + 1):
        url = "https://www.seebug.org/vuldb/vulnerabilities?page={}".format(p)
        try:
            resp = _direct_get(url, timeout=20)
            html = resp.content.decode("utf-8", "ignore")
        except Exception as e:
            logger.warning("fetch_seebug page %s failed: %s", p, e)
            break
        page_cnt = 0
        for r in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S):
            tds = re.findall(r"<td[^>]*>(.*?)</td>", r, re.S)
            if len(tds) != 6:
                continue
            href_m = re.search(r'href="([^"]+)"', tds[0])
            ssv = re.sub(r"<[^>]+>", "", tds[0]).strip()
            disclosure = re.sub(r"<[^>]+>", "", tds[1]).strip()
            sev_m = re.search(r'data-original-title="([^"]*)"', tds[2])
            sev = _SEV_CN.get((sev_m.group(1).strip() if sev_m else ""), "unknown")
            title = re.sub(r"<[^>]+>", "", tds[3]).strip()
            cve_m = _CVE_RE.search(tds[4])
            if not ssv or not title:
                continue
            page_cnt += 1
            out.append({
                "cve_id": cve_m.group(0).upper().replace("_", "-") if cve_m else "",
                "title": title, "severity": sev, "products": [], "poc_urls": [],
                "in_kev": False, "source": "seebug",
                "source_url": "https://www.seebug.org{}".format(href_m.group(1)) if href_m else "",
                "source_raw_id": (cve_m.group(0) if cve_m else "") or "ssv:{}".format(ssv),
                "published_date": disclosure,
            })
        if page_cnt == 0:
            logger.warning("fetch_seebug page %s 0 rows (可能触发 WAF)", p)
            break
    return out


# ============================ 源注册表 + 平台展示信息 ============================
# 新增源：写 fetch_xxx + 在此加一行 + SOURCE_PLATFORMS 加展示信息。
FETCHERS: Dict[str, Callable[[], List[Dict[str, Any]]]] = {
    "cisa_kev": fetch_cisa_kev,
    "nvd": fetch_nvd_recent,
    "arl_npoc": fetch_arl_npoc,
    "nuclei": fetch_nuclei_templates,
    "poc_monitor": fetch_poc_monitor,
    "qianxin_ti": fetch_qianxin_ti,
    "threatbook": fetch_threatbook,
    "chaitin": fetch_chaitin,
    "venustech": fetch_venustech,
    "seebug": fetch_seebug,
}

SOURCE_PLATFORMS = {
    "cisa_kev": {"label": "CISA KEV (美 CISA 在野利用目录)", "kind": "official",
                 "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    "nvd": {"label": "NVD (美 NIST 国家漏洞库)", "kind": "official", "url": "https://nvd.nist.gov/"},
    "arl_npoc": {"label": "哨兵本地 NPoC 插件", "kind": "local", "url": ""},
    "nuclei": {"label": "Nuclei 模板库", "kind": "local",
               "url": "https://github.com/projectdiscovery/nuclei-templates"},
    "poc_monitor": {"label": "Poc-Monitor (GitHub CVE PoC 监控)", "kind": "github",
                    "url": "https://github.com/sari3l/Poc-Monitor"},
    "qianxin_ti": {"label": "奇安信威胁情报中心 (国内,当天新增)", "kind": "cn", "url": "https://ti.qianxin.com/"},
    "threatbook": {"label": "微步在线 (国内,高危漏洞通告)", "kind": "cn",
                   "url": "https://x.threatbook.com/v5/vulIntelligence"},
    "chaitin": {"label": "长亭漏洞库 (国内)", "kind": "cn", "url": "https://stack.chaitin.com/vuldb/index"},
    "venustech": {"label": "启明星辰漏洞通告 (国内)", "kind": "cn",
                  "url": "https://www.venustech.com.cn/new_type/aqtg/"},
    "seebug": {"label": "Seebug 漏洞平台 (国内,知道创宇)", "kind": "cn", "url": "https://www.seebug.org/"},
}


def source_label(name: str) -> str:
    """源名 → 公开平台中文短名（展示用），未知源回退原名。"""
    return SOURCE_PLATFORMS.get(name, {}).get("label", name)


def _meta_coll():
    return get_repo().collection(Collections.VULN_FEED_META)


def get_feed_interval() -> int:
    """拉取间隔（秒），从 vuln_feed_meta 读，无则默认 6h，下限 10 分钟。"""
    try:
        doc = _meta_coll().find_one({"name": "default"}) or {}
        v = int(doc.get("interval_seconds") or DEFAULT_FEED_INTERVAL)
        return max(600, v)
    except (TypeError, ValueError):
        return DEFAULT_FEED_INTERVAL
    except Exception:
        return DEFAULT_FEED_INTERVAL


def set_feed_interval(seconds: Any) -> int:
    """设置拉取间隔（秒，下限 600）。返回落库值。"""
    seconds = max(600, int(seconds))
    _meta_coll().update_one({"name": "default"},
                            {"$set": {"interval_seconds": seconds}}, upsert=True)
    return seconds


def _notify_new_highrisk(new_highrisk: List[Dict[str, Any]]) -> None:
    """新增在野/严重漏洞经 ROLE.NOTIFY 汇总推送（可在 API 密钥>飞书>情报推送 开关控制）。"""
    if not new_highrisk:
        return
    # 检查情报推送开关（api_keys.feishu.vuln_feed_notify）
    try:
        from sentinel_platform.contracts import get_registry
        keys_svc = get_registry().get("api_keys_service")
        if keys_svc:
            feishu_cfg = keys_svc.get_key("feishu") if hasattr(keys_svc, "get_key") else {}
            if not feishu_cfg.get("vuln_feed_notify", True):
                return  # 用户关闭了情报推送
    except Exception:
        pass
    try:
        svc = get_registry().get(ROLE.NOTIFY)
        if not svc:
            return
        top = new_highrisk[:10]
        lines = ["漏洞情报库新增 {} 条在野/严重漏洞：".format(len(new_highrisk))]
        for v in top:
            tag = "[KEV]" if v.get("in_kev") else "[{}]".format(v.get("severity", ""))
            lines.append("{} {} {}".format(tag, v.get("cve_id") or "", (v.get("title") or "")[:60]))
        svc.notify("\n".join(lines), title="Sentinel · 漏洞情报更新", level="high")
    except Exception as exc:
        logger.debug("vuln_feed notify failed: %s", exc)


def run_feed(sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """拉取指定源（默认全部）→ 去重入库。返回每源 {fetched,new,merged,error}。

    单源瞬时失败退避重试，不一次失败干等下轮。每源结果 + 拉取时间持久化到 vuln_feed_meta。
    新增在野/严重漏洞经 NOTIFY 汇总推送（缺失降级）。
    """
    from .vuln_intel import upsert_vuln  # 同类别，主叶子数据层
    sources = sources or list(FETCHERS.keys())
    report: Dict[str, Any] = {}
    new_highrisk: List[Dict[str, Any]] = []
    for name in sources:
        fetcher = FETCHERS.get(name)
        if not fetcher:
            report[name] = {"error": "unknown source"}
            continue
        try:
            def _on_retry(attempt, wait, e, _n=name):
                logger.warning("vuln_feed %s 瞬时失败(第%s次),%ss 后重试: %s", _n, attempt, wait, str(e)[:120])
            vulns = _retry(fetcher, on_retry=_on_retry)
            new_cnt = merged_cnt = 0
            for v in vulns:
                action, _ = upsert_vuln(v)
                if action == "new":
                    new_cnt += 1
                    if v.get("in_kev") or (v.get("severity") or "").lower() == "critical":
                        new_highrisk.append(v)
                elif action == "merged":
                    merged_cnt += 1
            report[name] = {"fetched": len(vulns), "new": new_cnt, "merged": merged_cnt}
            logger.info("vuln_feed %s -> %s", name, report[name])
        except Exception as e:
            report[name] = {"error": str(e)[:200]}
            # 网络不可达（境外源被墙/DNS/代理超时）是本部署的预期常态，不该刷 ERROR+堆栈污染错误日志；
            # 降级为 WARNING 简报。仅真正非预期错误（解析/逻辑）才 ERROR+堆栈，保留真问题可见性。
            if _is_transient(e):
                logger.warning("vuln_feed source %s 网络不可达(预期,已跳过本轮): %s", name, str(e)[:120])
            else:
                logger.exception("vuln_feed source %s failed", name)
    _save_feed_meta(report)
    _notify_new_highrisk(new_highrisk)
    return report


def _save_feed_meta(report: Dict[str, Any]) -> None:
    """持久化拉取时间 + 每源结果到 vuln_feed_meta（单文档），前端展示用。失败静默。"""
    try:
        now = _now()
        coll = _meta_coll()
        doc = coll.find_one({"name": "default"}) or {"name": "default", "sources": {}}
        srcs = doc.get("sources", {})
        for name, r in report.items():
            srcs[name] = dict(r, last_fetch=now)
        coll.update_one({"name": "default"},
                        {"$set": {"sources": srcs, "last_fetch": now}}, upsert=True)
    except Exception as exc:
        logger.debug("vuln_feed save meta failed: %s", exc)


def feed_status() -> Dict[str, Any]:
    """拉取状态：上次拉取时间 + 各源健康（平台名/上次结果/有效性）+ 间隔。供前端可视化。"""
    try:
        doc = _meta_coll().find_one({"name": "default"}) or {}
    except Exception:
        doc = {}
    src_meta = doc.get("sources", {})
    sources = []
    for name in FETCHERS.keys():
        plat = SOURCE_PLATFORMS.get(name, {})
        m = src_meta.get(name, {})
        fetched = m.get("fetched", 0)
        err = m.get("error", "")
        if err:
            health = "error"
        elif m.get("last_fetch") and fetched > 0:
            health = "ok"
        elif m.get("last_fetch"):
            health = "empty"
        else:
            health = "unknown"
        sources.append({
            "name": name, "label": plat.get("label", name), "kind": plat.get("kind", ""),
            "url": plat.get("url", ""), "health": health, "fetched": fetched,
            "new": m.get("new", 0), "error": err, "last_fetch": m.get("last_fetch", ""),
        })
    interval = get_feed_interval()
    return {"last_fetch": doc.get("last_fetch", ""), "interval_seconds": interval,
            "interval_hours": round(interval / 3600, 1), "sources": sources}
