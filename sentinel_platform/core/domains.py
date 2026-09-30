"""core/domains —— 主域(fld / eTLD+1)提取（共享约定，冻结底座）。

**为什么下沉 core**：历史上 fld 提取有三套各自维护的实现——`risk_intel/asset_intel._fld_of`、
`kernel/ext_source._main_domain`（建 unit_map 的 key）、`kernel/recon/enrich.extract_fld`（真正写
site.fld 的主路径）。三套二级后缀表**不一致**（enrich 有 com.au/net.au/com.sg/com.my/org.hk，
ext_source 有 mil.cn/com.mo/co.kr），导致同一域名在写入侧(enrich)和 unit_map 侧算出不同 fld →
**单位回填失灵**；且 `*.mil.cn` 被 enrich 削成 mil.cn → 不同单位资产打歪合并。

二级后缀表是**共享参考数据**（非业务能力），按「共享常量下沉 core」惯例（同 paths.py/components.py）
落这里，三处共用同一权威后缀集，fld 口径一致。**绝不上溯根域**：abc.gov.cn 原样返回（防打歪政府网段）。

零依赖（不引 tldextract/PSL，线上容器无第三方，纯 stdlib 走热更）。启发式：命中二级后缀取三段，否则末两段。
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

# 二级公共后缀权威表（合并原 asset_intel/ext_source/enrich 三套的并集，一次对齐口径）。
# 命中则主域取三段（abc.gov.cn → abc.gov.cn，不削成 gov.cn 打歪）；否则取末两段。
SECOND_LEVEL_SUFFIXES = frozenset((
    # 中国大陆
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    # 港澳台
    "com.hk", "net.hk", "org.hk", "gov.hk", "com.mo", "com.tw", "org.tw", "gov.tw",
    # 亚太/英/日韩/澳新等常见
    "co.jp", "co.kr", "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "com.sg", "com.my", "co.nz",
))


def extract_fld(host: str) -> str:
    """提取主域 fld（eTLD+1）。IP/空/单段 原样返回。**绝不上溯根域**（多级公共后缀取三段）。

    先剥协议头/路径/端口，IP 原样返回，再按共享二级后缀表切分。
    abc.gov.cn → abc.gov.cn（不削成 gov.cn）；www.a.com → a.com；1.2.3.4 → 1.2.3.4。
    """
    if not host or not isinstance(host, str):
        return ""
    d = host.strip().lower()
    if not d:
        return ""
    if "://" in d:
        d = urlsplit(d).hostname or ""
    d = d.split("/")[0].split(":")[0].strip(".")
    if not d:
        return ""
    # IP 原样返回（不做域名切分）
    try:
        ipaddress.ip_address(d)
        return d
    except ValueError:
        pass
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    if ".".join(parts[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])   # abc.gov.cn / a.com.cn
    return ".".join(parts[-2:])       # a.com
