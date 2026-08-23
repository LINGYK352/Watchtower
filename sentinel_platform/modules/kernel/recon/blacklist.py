"""recon/blacklist —— 侦察黑名单过滤（数据卫生，净室迁移补回）。

净室重写 app/utils/domain.py:check_domain_black + helpers/asset_site_monitor.py:is_black_asset_site
（读旧逻辑理解匹配语义，不抄源码）。旧代码 18 处调用做核心数据卫生，净室迁移时整个丢失 →
CDN 泛域名/WAF/黑产/运营商垃圾域名混入侦察结果，污染扫描和报告。

三档匹配（字典在 dicts/，用户可编辑；缺失→该档不过滤，不崩）：
  - blackdomain.txt：域名**后缀** endswith（如 `.aliyunwaf.com` / `.qzone.qq.com`，滤 WAF/CDN 泛域名）
  - blackhexie.txt：违规词**子串** in（如 google/facebook/openvpn，滤明显非目标资产的第三方服务域名）
  - black_asset_site.txt：站点 URL **前缀** startswith（如 `https://qiangzhan.qq.com`，滤已知无关站点）

**默认开可关**：黑名单是数据卫生非硬拦，pipeline 默认过滤；策略 `blacklist_filter=false` 可关（避免误杀
特殊场景，守禁硬限制精神）。字典是**默认示例可编辑**（旧字典带 qq.com 系是作者环境样本，用户按需增删），
不是硬编码目标知识——它过滤的是"明显不是资产的噪音"，非"目标业务判断"。

只依赖 stdlib + recon_bridge 的 dicts 目录约定。进程级缓存（字典不常变）。
"""
from __future__ import annotations

import os
from typing import List, Optional


# —— 进程级缓存（字典文件不常变；None=未加载）——
_black_domain: Optional[List[str]] = None      # 域名后缀
_black_word: Optional[List[str]] = None        # 违规词子串
_black_site: Optional[List[str]] = None        # 站点前缀


def _dicts_dir() -> str:
    """dicts 目录（项目根 <root>/dicts，与 recon_bridge._dicts_dir / read_vuln_playbook 一致）。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))))
    d = os.path.join(root, "dicts")
    if os.path.isdir(d):
        return d
    return os.path.join(root, "sentinel_platform", "dicts")


def _load(filename: str) -> List[str]:
    """加载黑名单字典（每行一项，去空/注释）。缺失返空列表（该档不过滤，不崩）。"""
    path = os.path.join(_dicts_dir(), filename)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except Exception:
        return []


def _ensure_loaded() -> None:
    global _black_domain, _black_word, _black_site
    if _black_domain is None:
        _black_domain = _load("blackdomain.txt")
    if _black_word is None:
        _black_word = _load("blackhexie.txt")
    if _black_site is None:
        _black_site = _load("black_asset_site.txt")


def reset_cache() -> None:
    """清缓存（字典更新后或测试用）。"""
    global _black_domain, _black_word, _black_site
    _black_domain = _black_word = _black_site = None


def is_black_domain(domain: str) -> bool:
    """域名是否命中黑名单：后缀 endswith 任一 blackdomain 项，或子串含任一 blackhexie 违规词。"""
    if not domain:
        return False
    _ensure_loaded()
    d = domain.strip().lower()
    for suffix in (_black_domain or []):
        if d.endswith(suffix.lower()):
            return True
    for word in (_black_word or []):
        if word.lower() in d:
            return True
    return False


def is_black_site(site_url: str) -> bool:
    """站点 URL 是否命中黑名单：前缀 startswith 任一 black_asset_site 项。"""
    if not site_url:
        return False
    _ensure_loaded()
    s = site_url.strip()
    for prefix in (_black_site or []):
        if s.startswith(prefix):
            return True
    return False


def filter_domains(ctx) -> int:
    """过滤 ctx.domains + ctx.hosts 里命中黑名单的域名（就地改）。返回过滤掉的数量。
    pipeline 子域名阶段后调（滤 WAF/CDN 泛域名混入）。策略关闭时 pipeline 不调本函数。"""
    before = len(ctx.hosts)
    kept_hosts = [h for h in ctx.hosts if not is_black_domain(h)]
    dropped = before - len(kept_hosts)
    if dropped:
        black = set(ctx.hosts) - set(kept_hosts)
        ctx.hosts[:] = kept_hosts
        ctx.domains[:] = [d for d in ctx.domains if getattr(d, "domain", "") not in black]
    return dropped


def filter_sites(ctx) -> int:
    """过滤 ctx.sites 里命中黑名单（域名黑 或 站点前缀黑）的站点（就地改）。返回过滤掉的数量。
    pipeline 站点阶段后调。策略关闭时不调。"""
    before = len(ctx.sites)
    kept = []
    for s in ctx.sites:
        url = getattr(s, "url", "") or ""
        host = getattr(s, "hostname", "") or ""
        if is_black_site(url) or is_black_domain(host):
            continue
        kept.append(s)
    dropped = before - len(kept)
    if dropped:
        ctx.sites[:] = kept
    return dropped
