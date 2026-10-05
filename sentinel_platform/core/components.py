"""core/components —— 组件名归一（共享参考数据 + 归一器，冻结底座）。

**为什么下沉 core**：历史上组件名归一有三套各自维护的表——`risk_intel/vuln_intel`(CVE 组件别名)、
`kernel/system_tags`(厂商别名子集)、`risk_intel/asset_intel.match_playbook`(压根没归一，只 lower+strip)。
三套词汇不互通 → 打法库存 "spring boot"、目标确认 "springboot" 就漏匹配；vuln 库还用双向子串匹配
短别名(tp/u8/c6/nc)导致 "tp" in "http" 之类海量误匹配。别名表是**共享参考数据**(非业务能力)，
按「共享常量/约定下沉 core」惯例(同 paths.py)落这里，vuln + playbook 共用同一权威归一器。

提供：
  canonical_component(name) -> str   组件名归一到规范名（组内第一个）；无别名组返回小写原名
  expand_aliases(name)     -> list   扩展到全组别名（含规范名），供漏洞库按组件查
  alias_match(a, b)        -> bool    两个组件名是否指同一组件（经归一比较，非子串）

**关键修复（缺陷3）**：不再用双向子串 `a in b or b in a`（短别名 tp/u8 会误命中 http/yonyounc）。
改为「精确相等 或 归一后同组」判定；子串仅对**长别名(≥4字符)**且**词边界**放行，杜绝短别名误匹配。
"""
from __future__ import annotations

import re
from typing import List

# 组件别名权威表（合并原 vuln_intel.COMPONENT_ALIASES + system_tags._VENDOR_ALIASES）。
# 每组互为别名，组内第一个为规范名。查任一别名归一到规范名 / 扩展到全组。
COMPONENT_ALIASES: List[List[str]] = [
    ["致远", "致远oa", "seeyon"],
    ["泛微", "泛微oa", "weaver", "ecology", "e-cology", "eoffice", "e-office"],
    ["通达", "通达oa", "tongda"],
    ["用友", "用友nc", "yonyou", "yonyounc", "nc-cloud", "u8"],
    ["金蝶", "kingdee", "eas"],
    ["蓝凌", "蓝凌oa", "landray"],
    ["金和", "金和oa", "jinher", "c6"],
    ["红帆", "红帆oa", "ioffice"],
    ["万户", "万户oa", "wanhu", "whir"],
    ["weblogic", "oracle weblogic", "wls"],
    ["struts", "struts2", "apache struts"],
    ["fastjson"],
    ["shiro", "apache shiro"],
    ["log4j", "log4j2", "log4shell"],
    ["spring", "springboot", "spring boot", "spring framework", "spring-boot"],
    ["jenkins"],
    ["confluence", "atlassian confluence"],
    ["jira"],
    ["nacos"],
    ["thinkphp", "tp"],
    ["nginx"],
    ["tomcat", "apache tomcat"],
    ["jboss"],
    ["coremail"],
    ["奇安信", "qianxin"],
    ["深信服", "sangfor"],
    ["华为", "huawei"],
    ["h3c", "新华三"],
    ["锐捷", "ruijie"],
]

# 短别名（≤3 字符）：只允许精确相等匹配，绝不做子串（防 tp∈http / u8∈yonyounc / c6 / nc 误命中）。
_SHORT_ALIAS_MAXLEN = 3

# 预建索引：别名(小写) -> 规范名。构建期一次性。
_ALIAS_INDEX = {}
for _group in COMPONENT_ALIASES:
    _canon = _group[0].strip().lower()
    for _a in _group:
        _ALIAS_INDEX[_a.strip().lower()] = _canon


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def canonical_component(name: str) -> str:
    """组件名归一到规范名（组内第一个）。无别名组则返回小写原名（去空白）。
    先精确查别名索引；未命中再按「长别名词边界」宽松匹配（短别名不参与宽松匹配，防误归）。"""
    low = _norm(name)
    if not low:
        return ""
    # ① 精确命中别名索引
    if low in _ALIAS_INDEX:
        return _ALIAS_INDEX[low]
    # ② 长别名(≥4字符)词边界匹配：如 "apache tomcat/9.0" → tomcat。短别名不参与（防 tp/u8 误命中）。
    for alias, canon in _ALIAS_INDEX.items():
        if len(alias) <= _SHORT_ALIAS_MAXLEN:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", low):
            return canon
    return low


def expand_aliases(name: str) -> List[str]:
    """把组件名扩展到所有别名（含规范名），用于漏洞库按组件查。
    归一到规范名后返回该组全部别名；无别名组返回 [自身]。绝不因短别名子串而跨组扩展。"""
    low = _norm(name)
    if not low:
        return []
    canon = canonical_component(low)
    for group in COMPONENT_ALIASES:
        if group[0].strip().lower() == canon:
            out = {g.strip().lower() for g in group}
            out.add(low)
            return sorted(x for x in out if x)
    return [low]


def alias_match(a: str, b: str) -> bool:
    """两个组件名是否指同一组件（经归一比较，非子串）。用于匹配判定。"""
    na, nb = _norm(a), _norm(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    return canonical_component(na) == canonical_component(nb)
