"""risk_intel/vuln_intel —— 漏洞情报库（实现 VULN_INTEL / VulnIntelService）。

定位（用户定调）：不是「关联资产自动复测」，而是一个**去重的漏洞情报库**——
AI 渗透识别出目标组件后，直接查「这个组件有哪些已知漏洞 + PoC」拿来打。

- 去重：多源抓同一漏洞归并成一条 + 聚合多源（sources/poc_urls/products），不简单删。
  有 CVE → 按归一 cve_id upsert；无 CVE（GitHub 0day/国内独有）→ fallback（来源+原始id / 标题哈希）。
- 组件匹配：AI 中文组件名 / CVE 英文产品名 / 瞭望塔指纹名 三套措辞不同，用别名表 + 双向模糊弥合。
- 抓取器（多源拉取 + 周期拉取 + 状态）在同类别私有辅助 `_feed.py`，本文件作 ROLE 入口 + 数据层。

迁移来源：app/services/vuln_intel.py（去重/查询/统计/列表）。
不放 HTTP 路由（路由在 router/）；被 registry 以 ROLE.VULN_INTEL 注册，供 ai_pentest 缺失降级调用。
"""
from __future__ import annotations

import re
import time
import hashlib
from typing import Any, Dict, List

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}

# 组件中英别名表：解决 AI 中文组件名 ↔ CVE/nuclei 英文产品名命名鸿沟。
# 每组互为别名，查任一个自动扩展到全组。常见国产 OA/中间件/厂商优先。
COMPONENT_ALIASES = [
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
    ["spring", "springboot", "spring boot", "spring framework"],
    ["jenkins"],
    ["confluence", "atlassian confluence"],
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


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _coll():
    return get_repo().collection(Collections.VULN_INTEL)


def _expand_aliases(component: str) -> List[str]:
    """把组件名扩展到所有别名（含自身），用于匹配。小写比对。"""
    comp = (component or "").strip().lower()
    expanded = {comp}
    for group in COMPONENT_ALIASES:
        low = [g.lower() for g in group]
        if any(comp == g or comp in g or g in comp for g in low):
            expanded.update(low)
    return [e for e in expanded if e]


# 漏洞类型关键词：中文标题里产品名在这些词之前（用于截取产品段）
_VULN_TYPE_KW = [
    "远程代码执行", "代码执行", "命令执行", "命令注入", "SQL注入", "SQL 注入", "注入",
    "反序列化", "任意文件读取", "任意文件上传", "任意文件下载", "文件读取", "文件上传",
    "文件下载", "路径遍历", "目录遍历", "权限提升", "本地提权", "提权", "越权",
    "信息泄露", "信息泄漏", "敏感信息", "缓冲区溢出", "堆溢出", "栈溢出", "溢出",
    "拒绝服务", "未授权访问", "未授权", "身份认证绕过", "认证绕过", "绕过", "XXE",
    "SSRF", "服务器端请求伪造", "跨站脚本", "XSS", "CSRF", "RCE", "安全漏洞", "漏洞",
    "Remote Code Execution", "Code Execution", "Command Execution", "SQL Injection",
    "Injection", "Deserialization", "Path Traversal", "Privilege Escalation",
    "Information Disclosure", "Buffer Overflow", "Overflow", "Denial of Service",
    "Authentication Bypass", "Bypass", "Vulnerability", "Security",
]
_PRODUCT_STOP = {"core", "server", "framework", "the", "and", "及", "和", "与", "多个"}


def extract_products_from_title(title: str) -> List[str]:
    """从中英漏洞标题提取产品/组件名（填 products，供组件匹配）。

    规律：标题多为「{产品名} {漏洞类型}漏洞(CVE-xxx)」，产品名在最前、类型词之前。
    例：'Apache ActiveMQ 远程代码执行漏洞(CVE-2026-42588)' → ['apache activemq','activemq']。
    返回小写去重的产品关键词列表。
    """
    if not title:
        return []
    t = title.strip()
    t = re.sub(r"[\(（][A-Za-z]+-[\d-]+[\)）]\s*$", "", t).strip()
    cut = len(t)
    for kw in _VULN_TYPE_KW:
        idx = t.find(kw)
        if 0 <= idx < cut:
            cut = idx
    product = t[:cut].strip(" -—:：的") if cut > 0 else ""
    if not product:
        return []
    product = product.strip()
    if len(product) > 60:
        return []
    out = set()
    for seg in re.split(r"\s*(?:和|与|及|、|&|,|，|/)\s*", product):
        seg = seg.strip().lower()
        if not seg:
            continue
        seg = re.sub(r"\s+(core|server|framework)$", "", seg).strip()
        if seg and seg not in _PRODUCT_STOP and len(seg) > 1:
            out.add(seg)
        parts = seg.split()
        if len(parts) > 1:
            last = parts[-1]
            if last and last not in _PRODUCT_STOP and len(last) > 1:
                out.add(last)
    return [p for p in out if p and p not in _PRODUCT_STOP and len(p) > 1]


def normalize_cve(cve_id: Any) -> str:
    """归一 CVE 编号：大写、去空格，提取 CVE-NNNN-NNNN 形态。非标准返回空。"""
    if not cve_id:
        return ""
    m = re.search(r"CVE[-_\s]?(\d{4})[-_\s]?(\d{4,})", str(cve_id), re.I)
    return "CVE-{}-{}".format(m.group(1), m.group(2)) if m else ""


def _dedup_key(vuln: Dict[str, Any]):
    """去重键：优先归一 CVE；无 CVE 用 来源+原始id；再无用标题归一哈希。"""
    cve = normalize_cve(vuln.get("cve_id"))
    if cve:
        return ("cve", cve)
    raw = (vuln.get("source_raw_id") or "").strip()
    src = (vuln.get("source") or "").strip()
    if raw:
        return ("raw", "{}:{}".format(src, raw))
    title = re.sub(r"\s+", "", (vuln.get("title") or "").lower())
    return ("title", hashlib.sha256(title.encode("utf-8")).hexdigest()[:24]) if title else ("none", "")


def _norm_products(products) -> List[str]:
    """产品/组件关键词归一：小写去空格去重，供模糊匹配。"""
    out = set()
    for p in products or []:
        p = (p or "").strip().lower()
        if p:
            out.add(p)
    return sorted(out)


def upsert_vuln(vuln: Dict[str, Any]):
    """去重入库：同一漏洞（同去重键）归并，多源聚合 sources/poc_urls/products。

    vuln 标准字段：cve_id, title, severity, cvss, products[], poc_urls[], in_kev(bool),
                   source, source_url, source_raw_id, published_date, executable/exec_kind/exec_ref。
    返回 (action, key)：action ∈ new/merged/skip。内部捕获异常，失败返回 ("error", "")。
    """
    try:
        keytype, keyval = _dedup_key(vuln)
        if not keyval:
            return ("skip", "")
        coll = _coll()
        now = _now()
        cve = normalize_cve(vuln.get("cve_id"))
        query = {"dedup_key": "{}:{}".format(keytype, keyval)}
        src_entry = {"name": vuln.get("source", ""), "url": vuln.get("source_url", ""),
                     "raw_id": vuln.get("source_raw_id", "")}
        existed = coll.find_one(query)
        if existed:
            set_fields: Dict[str, Any] = {"update_date": now}
            old_rank = SEVERITY_RANK.get((existed.get("severity") or "unknown").lower(), 0)
            new_rank = SEVERITY_RANK.get((vuln.get("severity") or "unknown").lower(), 0)
            if new_rank > old_rank:
                set_fields["severity"] = vuln.get("severity")
            if vuln.get("in_kev"):
                set_fields["in_kev"] = True
            # 外部 CVE 后来匹配到本地 PoC/nuclei 模板时升级为可执行
            if vuln.get("executable") and not existed.get("executable"):
                set_fields["executable"] = True
                set_fields["exec_kind"] = vuln.get("exec_kind", "")
                set_fields["exec_ref"] = vuln.get("exec_ref", "")
            incoming = _norm_products(vuln.get("products")) or extract_products_from_title(vuln.get("title"))
            set_fields["products"] = sorted(set(existed.get("products", [])) | set(incoming))
            update: Dict[str, Any] = {"$set": set_fields, "$addToSet": {"sources": src_entry}}
            push_pocs = [u for u in (vuln.get("poc_urls") or []) if u]
            if push_pocs:
                update["$addToSet"]["poc_urls"] = {"$each": push_pocs}
            coll.update_one(query, update)
            return ("merged", keyval)

        doc = {
            "dedup_key": "{}:{}".format(keytype, keyval),
            "cve_id": cve,
            "title": vuln.get("title", ""),
            "severity": (vuln.get("severity") or "unknown").lower(),
            "cvss": vuln.get("cvss", ""),
            "products": _norm_products(vuln.get("products")) or extract_products_from_title(vuln.get("title")),
            "poc_urls": [u for u in (vuln.get("poc_urls") or []) if u],
            "in_kev": bool(vuln.get("in_kev")),
            "executable": bool(vuln.get("executable")),
            "exec_kind": vuln.get("exec_kind", ""),
            "exec_ref": vuln.get("exec_ref", ""),
            "sources": [src_entry],
            "published_date": vuln.get("published_date", ""),
            "save_date": now,
            "update_date": now,
        }
        coll.insert_one(doc)
        return ("new", keyval)
    except Exception as exc:  # 库不可用等：不拖垮抓取循环
        logger.debug("vuln_intel upsert failed: %s", exc)
        return ("error", "")


def _project(d: Dict[str, Any]) -> Dict[str, Any]:
    """情报文档 → 对外精简 dict（query/list 共用主体字段）。"""
    return {
        "cve_id": d.get("cve_id", ""), "title": d.get("title", ""),
        "severity": d.get("severity", ""), "cvss": d.get("cvss", ""),
        "in_kev": d.get("in_kev", False),
        "executable": d.get("executable", False),
        "exec_kind": d.get("exec_kind", ""), "exec_ref": d.get("exec_ref", ""),
        "products": d.get("products", []), "poc_urls": d.get("poc_urls", []),
        "sources": [s.get("name", "") for s in d.get("sources", [])],
        "published_date": d.get("published_date", ""),
    }


def query_by_component(component: str, limit: int = 20) -> Dict[str, Any]:
    """【AI 渗透按组件查】给组件名，查情报库匹配的已知漏洞（别名扩展 + 双向模糊）。

    匹配：任一别名与 products/title 双向包含。排序：可执行 > 在野(in_kev) > severity 高。
    返回 {"component", "count", "vulns":[...]}；参数非法返回 {"error"}。
    """
    component = (component or "").strip().lower()
    if not component:
        return {"error": "component 必填", "component": "", "count": 0, "vulns": []}
    try:
        aliases = _expand_aliases(component)
        or_conds: List[Dict[str, Any]] = []
        for a in aliases:
            safe = re.escape(a)
            or_conds.append({"products": {"$regex": safe, "$options": "i"}})
            or_conds.append({"title": {"$regex": safe, "$options": "i"}})
        hits = []
        for d in _coll().find({"$or": or_conds}):
            prods = [p.lower() for p in d.get("products", [])]
            title = (d.get("title", "") or "").lower()
            if any(a in title or any(a in p or p in a for p in prods) for a in aliases):
                hits.append(d)
        hits.sort(key=lambda d: (d.get("executable", False), d.get("in_kev", False),
                                 SEVERITY_RANK.get(d.get("severity", "unknown"), 0)), reverse=True)
        selected = hits if limit is None or int(limit) <= 0 else hits[:int(limit)]
        return {"component": component, "count": len(selected),
                "vulns": [_project(d) for d in selected]}
    except Exception as exc:
        logger.debug("vuln_intel query_by_component failed: %s", exc)
        return {"component": component, "count": 0, "vulns": []}


def stat() -> Dict[str, Any]:
    """漏洞情报库统计：总数 + 在野(KEV) + 可执行 + 按 severity + 按来源。"""
    try:
        coll = _coll()
        by_sev = {s: coll.count_documents({"severity": s}) for s in ("critical", "high", "medium", "low")}
        by_source: Dict[str, int] = {}
        for d in coll.aggregate([{"$unwind": "$sources"},
                                 {"$group": {"_id": "$sources.name", "n": {"$sum": 1}}}]):
            by_source[d.get("_id") or "unknown"] = d.get("n", 0)
        return {"total": coll.count_documents({}), "in_kev": coll.count_documents({"in_kev": True}),
                "executable": coll.count_documents({"executable": True}),
                "by_severity": by_sev, "by_source": by_source}
    except Exception as exc:
        logger.debug("vuln_intel stat failed: %s", exc)
        return {"total": 0, "in_kev": 0, "executable": 0, "by_severity": {}, "by_source": {}}


def list_vulns(severity=None, source=None, in_kev=None, executable=None, keyword=None,
               sort=None, page: int = 1, size: int = 20) -> Dict[str, Any]:
    """漏洞情报列表（分页 + 过滤 + 排序），供前端漏洞情报页。

    sort：None/'default'/'exposure'=按曝光时间(published_date)新→旧（默认，最新曝光在前）；
          'kev'=在野优先+入库新→旧。
    """
    try:
        coll = _coll()
        q: Dict[str, Any] = {}
        if severity:
            q["severity"] = severity
        if source:
            q["sources.name"] = source
        if in_kev is not None:
            q["in_kev"] = bool(in_kev)
        if executable is not None:
            q["executable"] = bool(executable)
        if keyword:
            safe = re.escape(keyword)
            q["$or"] = [{"cve_id": {"$regex": safe, "$options": "i"}},
                        {"title": {"$regex": safe, "$options": "i"}},
                        {"products": {"$regex": safe, "$options": "i"}}]
        total = coll.count_documents(q)
        # 默认按曝光时间(published_date)新→旧（最新曝光在前）；'kev' 才用在野优先
        sort_spec = [("in_kev", -1), ("_id", -1)] if sort == "kev" else [("published_date", -1), ("_id", -1)]
        from ._feed import source_label  # 惰性，避免 import 期循环
        items = []
        for d in coll.find(q).sort(sort_spec).skip((max(1, page) - 1) * size).limit(size):
            src_names = [s.get("name", "") for s in d.get("sources", [])]
            item = _project(d)
            item.update({"_id": str(d["_id"]), "source_labels": [source_label(n) for n in src_names],
                         "fetched_date": d.get("save_date", "")})
            items.append(item)
        return {"items": items, "total": total}
    except Exception as exc:
        logger.debug("vuln_intel list failed: %s", exc)
        return {"items": [], "total": 0}


class VulnIntelServiceImpl:
    """VULN_INTEL 实现 + 本叶子对外 HTTP 能力门面。

    - `query`：跨模块 Protocol 契约（ai_pentest 经 registry 消费，见 contracts.VulnIntelService）。
    - 其余方法（stat/list_vulns/query_by_component/run_feed/feed_status/get|set_feed_interval）：
      本叶子自有 HTTP 能力，供 `router/endpoints/risk_intel.py` 经 registry 取本服务后调用
      （router 不 import 叶子内部，守解耦；契约见 INTERFACES §5.9）。抓取器相关委托私有 `_feed`。
    """

    # —— 跨模块 Protocol 契约 ——
    def query(self, keyword: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """按组件/关键词查已知漏洞。返回漏洞 dict 列表（无则 []）。纯查询无副作用。

        kwargs：limit:int（默认 20）。对齐 INTERFACES §二 VULN_INTEL。
        """
        limit = kwargs.get("limit", 20)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 20
        return query_by_component(keyword, limit=limit).get("vulns", [])

    # —— HTTP 能力门面（委托模块函数 / _feed，供 router 调）——
    def query_by_component(self, component: str, limit: int = 20) -> Dict[str, Any]:
        return query_by_component(component, limit=limit)

    def list_vulns(self, **kwargs: Any) -> Dict[str, Any]:
        return list_vulns(**kwargs)

    def stat(self) -> Dict[str, Any]:
        return stat()

    def run_feed(self, sources=None) -> Dict[str, Any]:
        from ._feed import run_feed as _run
        return _run(sources)

    def feed_status(self) -> Dict[str, Any]:
        from ._feed import feed_status as _status
        return _status()

    def get_feed_interval(self) -> int:
        from ._feed import get_feed_interval as _get
        return _get()

    def set_feed_interval(self, seconds: Any) -> int:
        from ._feed import set_feed_interval as _set
        return _set(seconds)


_service = VulnIntelServiceImpl()


def get_service() -> VulnIntelServiceImpl:
    return _service
