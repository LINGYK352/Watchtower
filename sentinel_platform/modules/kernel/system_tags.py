"""kernel/system_tags —— 系统命名 / 标签抽取（实现 SYSTEM_TAGS / SystemTagsService）。

给资产取系统主名 + 从指纹/标题/URL 抽多维加权标签（轴二跨单位借鉴的 key、去重/命名用）。
多维标签向量 + 加权相似度：同一套系统即使标题不同、指纹抖动，只要核心系统标签命中就能
跨单位关联；共享高权重标签越多 → 借鉴置信越高。

契约（冻结，见 INTERFACES.md §二 SYSTEM_TAGS）——本模块对外只暴露这两个纯函数：
  pick_system_name(asset: dict) -> str      取系统名，取不到返回 ""，无副作用
  extract_tags(data: dict) -> list[str]     抽标签（规范名列表），无则 []

模块级辅助（供未来轴二借鉴用；需跨模块访问时走接口变更提案，勿在 kernel 外直接 import）：
  extract_tags_detailed / classify_tag / canonical_name / tag_similarity / find_related_systems

迁移来源：app/services/system_tags.py。**净室解耦**：旧代码 `from app.services.vuln_intel import
COMPONENT_ALIASES` 是跨模块耦合；本模块自带厂商别名子集（系统命名用途），不 import 别的模块。
依赖：仅标准库 re + core/contracts，**无第三方库**（无需 vendor 下载）。
不放 HTTP 路由；被 registry 以 ROLE.SYSTEM_TAGS 注册。
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

# 标签类型权重（共享高权重标签 = 更可能同系统 = 借鉴更可信）。
TAG_WEIGHT = {"system": 10, "framework": 6, "component": 3, "tech": 1, "role": 2}

# —— 厂商别名子集（净室自带，系统命名用途；组内第一个为规范名）——
# 静态参考数据；与 risk_intel/vuln_intel 的 CVE 组件别名表是不同用途，各自维护不跨模块 import。
# 若未来需统一，走「共享参考数据」提案（候选落 dicts/ 数据文件），当前保持自包含。
_VENDOR_ALIASES: List[List[str]] = [
    ["致远", "致远oa", "seeyon"],
    ["泛微", "泛微oa", "weaver", "ecology", "e-cology", "eoffice", "e-office"],
    ["通达", "通达oa", "tongda"],
    ["用友", "用友nc", "yonyou", "yonyounc", "nc-cloud", "u8"],
    ["金蝶", "kingdee", "eas"],
    ["蓝凌", "蓝凌oa", "landray"],
    ["金和", "金和oa", "jinher", "c6"],
    ["红帆", "红帆oa", "ioffice"],
    ["万户", "万户oa", "wanhu", "whir"],
    ["coremail"],
    ["confluence", "atlassian confluence"],
    ["jira"],
]

# 指纹名 → 标签类型 关键词表（小写子串匹配）。
_TECH = {
    "iis", "apache", "nginx", "tomcat", "jetty", "php", "asp", "asp.net", "aspx",
    "jsp", "java", "python", "nodejs", "node.js", "openresty", "lighttpd",
    "microsoft asp.net", "alt-svc", "express", "kestrel", "litespeed",
}
_FRAMEWORK = {
    "struts", "struts2", "spring", "springboot", "spring boot", "thinkphp",
    "laravel", "django", "flask", "fastjson", "shiro", "log4j", "log4j2",
    "yii", "codeigniter", "beego", "gin", "ruby on rails", "rails", "vue",
    "react", "angular", "layui", "jquery", "bootstrap",
}
_COMPONENT = {
    "jenkins", "redis", "elasticsearch", "nacos", "confluence", "swagger",
    "宝塔", "bt.cn", "宝塔-bt.cn", "druid", "kibana", "solr", "zabbix", "grafana",
    "rabbitmq", "kafka", "mongodb", "mysql", "postgresql", "memcached", "consul",
    "harbor", "gitlab", "gitea", "phpmyadmin", "adminer", "kong", "apisix",
    "minio", "rocketmq", "xxl-job", "canal", "seata", "skywalking", "nexus",
}
# system 强特征词（含这些词的指纹名归 system）。
_SYSTEM_HINT = ("oa", "cms", "系统", "平台", "管理", "门户", "portal", "erp", "crm",
                "jira", "wordpress", "discuz", "dedecms", "phpcms", "邮件", "mail",
                "财务", "办公", "审批", "工单", "客服", "商城", "blog")
# canonical 命中即强制归 system（跨单位借鉴核心目标）。
_SYSTEM_VENDORS = {"致远", "泛微", "通达", "用友", "金蝶", "蓝凌", "金和", "红帆", "万户",
                   "coremail", "confluence", "jira"}
# title 作系统标签的强后缀 / 垃圾标题。
_TITLE_STRONG = ("系统", "平台", "管理", "门户", "portal", "oa", "erp", "crm", "后台", "console")
_TITLE_JUNK = ("loading", "403", "404", "forbidden", "not found", "error", "首页", "index",
               "home", "welcome", "test", "demo", "untitled", "page")
# 误报/无意义指纹，不进标签。
_TAG_NOISE = {"ibm-chassis-management", "alt-svc", ""}
# 前后台/作用 role 标签：从 URL 路径/标题推断。
_ROLE_HINTS = {
    "admin": ("admin", "manage", "manager", "后台", "管理后台", "console", "dashboard"),
    "login": ("login", "signin", "登录", "auth", "sso"),
    "api": ("api", "rest", "graphql", "swagger", "/v1/", "/v2/", "openapi"),
    "portal": ("portal", "门户", "index", "home", "首页"),
    "upload": ("upload", "file", "附件", "上传"),
}


def canonical_name(name: str) -> str:
    """指纹/组件名归一到规范名（组内第一个）。无别名组则返回小写原名。"""
    low = (name or "").strip().lower()
    if not low:
        return ""
    for group in _VENDOR_ALIASES:
        gl = [g.lower() for g in group]
        if any(low == g or low in g or g in low for g in gl):
            return gl[0]
    return low


def classify_tag(name: str) -> str:
    """指纹/组件名分类 → tech/framework/component/system。优先级：厂商→system；显式表；强特征；默认 component。"""
    low = (name or "").strip().lower()
    if not low:
        return "component"
    if canonical_name(low) in _SYSTEM_VENDORS:
        return "system"
    for kw in _TECH:
        if kw == low or kw in low or low in kw:
            return "tech"
    for kw in _FRAMEWORK:
        if kw == low or kw in low or low in kw:
            return "framework"
    for kw in _COMPONENT:
        if kw == low or kw in low or low in kw:
            return "component"
    if any(h in low for h in _SYSTEM_HINT):
        return "system"
    return "component"


def _fingers(data: Dict[str, Any]) -> List[str]:
    """从 asset/site dict 抽指纹名列表。兼容 finger=[{name}] / [str] / finger_names=[str]。"""
    out: List[str] = []
    for key in ("finger", "fingers", "finger_names"):
        val = data.get(key)
        if not val:
            continue
        for item in val:
            if isinstance(item, dict):
                nm = item.get("name") or item.get("tag") or ""
            else:
                nm = str(item)
            if nm:
                out.append(nm)
    return out


def _urls(data: Dict[str, Any]) -> List[str]:
    val = data.get("urls") or data.get("url") or []
    if isinstance(val, str):
        return [val]
    return [str(u) for u in val]


def extract_tags_detailed(data: Dict[str, Any]) -> List[Dict[str, str]]:
    """抽结构化标签 [{"tag": 规范名, "type": system/framework/component/tech/role}]（去重）。
    模块级辅助（保留旧语义，供轴二加权相似度用）。data 键：finger/finger_names、title、urls。"""
    seen: Dict[Tuple[str, str], Dict[str, str]] = {}
    for fn in _fingers(data):
        cn = canonical_name(fn)
        if not cn or cn in _TAG_NOISE:
            continue
        seen[(cn, classify_tag(fn))] = {"tag": cn, "type": classify_tag(fn)}
    tl = (data.get("title") or "").strip().lower()
    if (tl and len(tl) <= 30
            and any(h in tl for h in _TITLE_STRONG)
            and not any(j in tl for j in _TITLE_JUNK)):
        seen[(tl, "system")] = {"tag": tl, "type": "system"}
    blob = " ".join([data.get("title") or ""] + _urls(data)).lower()
    for role, hints in _ROLE_HINTS.items():
        if any(h in blob for h in hints):
            seen[(role, "role")] = {"tag": role, "type": "role"}
    return list(seen.values())


class SystemTagsServiceImpl:
    """SYSTEM_TAGS 实现。满足 contracts.SystemTagsService（结构化子类型，无需继承）。纯函数无副作用。"""

    def pick_system_name(self, asset: Dict[str, Any]) -> str:
        """选系统主名：按标签权重取最强信号指纹（排噪音）。取不到返回 ""（契约规定，不返回"未知系统"）。
        多指纹同权重时补最强次要特征作后缀区分（治两个 ASP 撞名）。asset 键：finger/finger_names、title。"""
        asset = asset or {}
        cands: List[Tuple[int, str]] = []
        for fn in _fingers(asset):
            cn = canonical_name(fn)
            if not cn or cn in _TAG_NOISE:
                continue
            cands.append((TAG_WEIGHT.get(classify_tag(fn), 1), cn))
        if not cands:
            return (asset.get("title") or "").strip()  # 无指纹回退标题；再空则 ""（契约）
        cands.sort(key=lambda x: (-x[0], x[1]))
        main = cands[0][1]
        sub = next((cn for _, cn in cands[1:] if cn != main), "")
        return "{} ({})".format(main, sub) if sub else main

    def extract_tags(self, data: Dict[str, Any]) -> List[str]:
        """抽标签规范名列表（契约返 list[str]，无则 []）。结构化版见 extract_tags_detailed。"""
        return [t["tag"] for t in extract_tags_detailed(data or {})]


_service = SystemTagsServiceImpl()


def get_service() -> SystemTagsServiceImpl:
    return _service


# —— 模块级辅助：加权相似度 + 相关系统检索（轴二借鉴，保留旧语义）——
RELATED_MIN_SCORE = 3
_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def tag_similarity(tags_a: List[Dict[str, str]], tags_b: List[Dict[str, str]]) -> Dict[str, Any]:
    """两组结构化标签的加权相似度 + 置信度。共享 system→high；framework 或 ≥2 component→medium；其余→low。"""
    sa = {(t["tag"], t["type"]) for t in (tags_a or [])}
    sb = {(t["tag"], t["type"]) for t in (tags_b or [])}
    shared = sa & sb
    if not shared:
        return {"score": 0, "shared": [], "confidence": "none"}
    score = sum(TAG_WEIGHT.get(t[1], 1) for t in shared)
    types = {t[1] for t in shared}
    n_comp = sum(1 for t in shared if t[1] == "component")
    conf = "high" if "system" in types else ("medium" if ("framework" in types or n_comp >= 2) else "low")
    return {"score": score,
            "shared": [{"tag": t[0], "type": t[1]} for t in sorted(shared, key=lambda x: -TAG_WEIGHT.get(x[1], 1))],
            "confidence": conf}


def find_related_systems(target_tags, exclude_system_id=None,
                         min_score: int = RELATED_MIN_SCORE, limit: int = 20) -> List[Dict[str, Any]]:
    """按标签相似度找相关系统（遍历 intel_system，score≥min_score 纳入，按 置信度/score 降序）。
    读库失败降级返回 []（不抛，守 §0.4）。"""
    out: List[Dict[str, Any]] = []
    try:
        cursor = get_repo().collection(Collections.INTEL_SYSTEM).find(
            {"tags": {"$exists": True, "$ne": []}})
        for s in cursor:
            sid = str(s.get("_id"))
            if exclude_system_id and sid == exclude_system_id:
                continue
            sim = tag_similarity(target_tags, s.get("tags", []))
            if sim["score"] < min_score:
                continue
            out.append({"system_id": sid, "name": s.get("name", ""),
                        "units_count": len(s.get("units", [])), "similarity": sim})
    except Exception as exc:
        logger.debug("find_related_systems failed: %s", exc)
        return []
    out.sort(key=lambda x: (_CONF_RANK.get(x["similarity"]["confidence"], 0), x["similarity"]["score"]),
             reverse=True)
    return out if limit is None or int(limit) <= 0 else out[:int(limit)]

