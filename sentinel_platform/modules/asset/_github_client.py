"""asset/_github_client —— GitHub 代码搜索客户端（github_task/github_monitor 同类别私有辅助）。

净室重写 app/services/githubSearch.py（读旧逻辑理解流程，不抄源码）：GitHub code search API 调用
+ 速率限制退避重试 + 内置规则组合扩大命中面 + 结果按 repo/path 哈希去重。
token 从统一 API 密钥中心取（经 registry 的 api_keys_service，缺失→抛错让上层标 error，不静默返 0）。
只依赖 core + contracts(registry) + stdlib。禁硬限制参数（翻页数可配，默认对齐 GitHub code search 上限）。
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from sentinel_platform.core import get_config, get_logger
from sentinel_platform.core.http import http_req
from sentinel_platform.contracts import get_registry

logger = get_logger()

_API_BASE = "https://api.github.com"
_BASE_SLEEP = 2.5   # 每次请求基础节流（GitHub code search 严格限速）

# 内置搜索规则（净室重写自旧 built_in_rules：按语言/扩展名扩展命中面，一轮跑多条规则并集去重）
_BUILT_IN_RULES = [
    'language:Dockerfile language:"Java Properties" language:"Protocol Buffer" language:Gradle language:"Maven POM"',
    'language:Python language:"Git Config" language:INI language:Shell language:"SSH Config"',
    "extension:java extension:js extension:json extension:sql extension:yaml extension:yml "
    "extension:conf extension:config extension:jsp",
    "extension:php extension:py extension:go extension:bat extension:cfg extension:env "
    "extension:exs extension:ini extension:pem extension:ppk extension:cs",
]


def _token() -> str:
    """GitHub token 从密钥中心取（api_keys_service.get_key('github').token）；缺失返空。"""
    try:
        svc = get_registry().get("api_keys_service")
        if svc and hasattr(svc, "get_key"):
            return str((svc.get_key("github") or {}).get("token", "") or "").strip()
    except Exception as exc:
        logger.debug("github token read failed: %s", exc)
    return ""


def _max_page() -> int:
    """最大翻页数（可配 GITHUB.MAX_PAGE，默认 3；GitHub code search 本身 ≤10 页/1000 条）。"""
    try:
        return int(get_config().section("GITHUB", "MAX_PAGE", default=3) or 3)
    except (TypeError, ValueError):
        return 3


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8", "ignore")).hexdigest()


def has_token() -> bool:
    return bool(_token())


def _client(url: str, params: Optional[Dict[str, Any]] = None, _cnt: int = 0) -> Dict[str, Any]:
    """调 GitHub API：带 token 鉴权 + 基础节流 + 速率限制退避（净室重写旧 github_client 的 rate-limit 处理）。
    非 200 且命中 abuse/rate-limit 提示 → 退避重试（≤3 次）；其余非 200 抛异常由上层标 error。"""
    token = _token()
    if not token:
        raise RuntimeError("GitHub token 未配置（系统设置 > API 密钥 > GitHub Token）")
    headers = {"Authorization": "Bearer {}".format(token),
               "Accept": "application/vnd.github.v3+json"}
    time.sleep(_BASE_SLEEP)
    resp = http_req(url, "get", params=params, headers=headers)
    try:
        data = resp.json()
    except Exception:
        raise RuntimeError("GitHub 响应非 JSON（status={}）".format(getattr(resp, "status_code", "?")))
    if getattr(resp, "status_code", 200) != 200:
        msg = str((data or {}).get("message", "GitHub 错误"))
        rate_hit = ("abuse detection" in msg or "rate limit exceeded" in msg
                    or "secondary rate limit" in msg)
        if rate_hit and _cnt < 3:
            sleep_s = 20 + 15 * (_cnt + 1)
            logger.info("github rate-limit 退避 %ss (第%d次): %s", sleep_s, _cnt + 1, msg[:80])
            time.sleep(sleep_s)
            return _client(url, params=params, _cnt=_cnt + 1)
        raise RuntimeError(msg)
    return data


def _search_code(query: str, page: int = 1, per_page: int = 100) -> Tuple[List[Dict[str, Any]], int]:
    """一次 code search 请求，返回 (结构化结果列表, total_count)。"""
    data = _client(_API_BASE + "/search/code",
                   params={"q": query, "order": "desc", "sort": "indexed",
                           "per_page": per_page, "page": page})
    items = []
    for it in (data.get("items") or []):
        repo = ((it.get("repository") or {}).get("full_name")) or ""
        path = it.get("path", "") or ""
        items.append({
            "git_url": it.get("git_url", ""),
            "html_url": it.get("html_url", ""),
            "repo": repo,
            "path": path,
            "hash_md5": _md5(repo + "/" + path),
        })
    return items, int(data.get("total_count", 0) or 0)


def search(keyword: str, cancel_check: Optional[Callable[[], bool]] = None) -> List[Dict[str, Any]]:
    """按 keyword 跑全部内置规则，翻页收集并按 hash_md5 去重。cancel_check 返 True 时提前停（协作式取消）。
    单条规则失败不中断其余规则（记 warning 继续）。返回去重后的结构化结果列表。"""
    seen, results = set(), []
    max_page = _max_page()
    for rule in _BUILT_IN_RULES:
        if cancel_check and cancel_check():
            break
        rule = rule.strip()
        if not rule:
            continue
        query = "{} {}".format(keyword, rule)
        try:
            page = 1
            rows, total = _search_code(query, page=page)
            while rows:
                for r in rows:
                    h = r.get("hash_md5")
                    if h and h not in seen:
                        seen.add(h)
                        results.append(r)
                if (total / 100) <= page or page >= max_page:
                    break
                if cancel_check and cancel_check():
                    break
                page += 1
                rows, total = _search_code(query, page=page)
        except Exception as exc:
            logger.warning("github search rule 失败(continue): %s | %s", str(exc)[:100], query[:60])
            continue
    logger.info("github search '%s' → %d 去重结果", keyword, len(results))
    return results
