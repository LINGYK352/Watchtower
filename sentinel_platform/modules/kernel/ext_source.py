"""外部测绘源 ext_source —— FOFA / crt.sh / ICP 备案 的统一客户端（kernel 叶子，被调用）。

职责：封装第三方测绘/情报源的查询构造 + 响应解析 + 结果归一，供 asset/leak/intel 等
调用（本叶子无 ROLE，经 kernel 内 import 或后续提案角色化）。所有外部调用防御性处理：
网络/限速/解析失败返回空结果而非抛异常（守 §0.4）。

净室重写：查询构造/解析是通用技术，参考旧 app/services（fofaClient/crtshClient/icp_query）
的逻辑与踩坑，不 import app.*。HTTP 走 core.http.http_req（底层 requests，旧依赖已有，无需新增 vendor 库）。
密钥经 core.config 读取，日志脱敏不回显完整 key。
"""
from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from sentinel_platform.core import get_config, get_logger, get_repo
from sentinel_platform.core.http import http_req
from sentinel_platform.contracts import Collections, get_registry, ROLE

logger = get_logger()

ICP_CACHE_COLL = "icp_cache"


def _intel_proxies() -> Optional[Dict[str, str]]:
    """第三方测绘源（Hunter/FOFA/crtsh/ICP）出口：**固定走智能代理**（不受任务策略影响）——
    智能源可达则经代理，不可达则返 None 由 http_req 直连（trust_env=False 真直连）。
    这样反查代理挂了自动直连、不卡死（治单位名反查被代理劫持/挂死事故）。缺服务/无源→None 直连。"""
    try:
        svc = get_registry().get(ROLE.PROXY)
        if svc and hasattr(svc, "resolve_egress_url"):
            url = svc.resolve_egress_url("smart")   # smart 含叠加降级：可达返URL,不可达返""
            if url:
                return {"http": url, "https": url}
    except Exception as exc:
        logger.debug("_intel_proxies degraded: %s", exc)
    return None


def _apikey(key_id: str, field: str = "key") -> str:
    """从统一 API 密钥中心（`api_keys` 集合 default 文档）取某密钥字段（仅 enabled 时返值），
    与 notify 同源（直接读集合，非跨模块 import）。返空则调用方回退 config 段。

    治根因：密钥中心是运行时唯一密钥源（前端「API 密钥」页配），但消费方历史只读 config.yaml
    段（净室重写丢了旧 ensure_applied 的 Mongo→Config 推送）→「明明配了 apikey 却报未配置」。
    """
    try:
        doc = get_repo().collection(Collections.API_KEYS).find_one({"name": "default"}) or {}
        sub = doc.get(key_id) or {}
        if sub.get("enabled") and sub.get(field):
            return str(sub[field]).strip()
    except Exception as exc:
        logger.debug("ext_source read api_keys %s.%s failed: %s", key_id, field, exc)
    return ""

# 全角→半角：用户从文档/网页复制 FOFA 语句常带全角引号/运算符，FOFA 只认半角 → 语法错或 0 结果。
# 一处归一，所有入口受益（踩坑见记忆 dengta-fofa-fullwidth-normalize）。
_FOFA_FULLWIDTH = {
    "“": '"', "”": '"',        # 全角双引号 " "
    "‘": "'", "’": "'",        # 全角单引号 ' '
    "＆": "&", "｜": "|",        # 全角 ＆ ｜
    "＝": "=", "（": "(", "）": ")",  # 全角 ＝ （ ）
    "　": " ",                       # 全角空格
}


def normalize_fofa_query(query: Optional[str]) -> Optional[str]:
    """归一 FOFA 查询：全角引号/运算符/括号/空格→半角；去首尾空白；换行折空格。
    根治"复制带全角字符导致 &&/||/引号失效查不出"的常见事故。"""
    if not query:
        return query
    q = str(query)
    for k, v in _FOFA_FULLWIDTH.items():
        if k in q:
            q = q.replace(k, v)
    return " ".join(q.split())      # 折叠连续空白（含换行）为单空格 + 去首尾


# FOFA 已知字段名白名单（https://fofa.info/api/docs/）
_FOFA_KNOWN_FIELDS = {
    "domain", "host", "ip", "port", "protocol", "server", "title", "header",
    "body", "cert", "cert.subject", "cert.issuer", "cert.is_valid", "cert.subject.org",
    "icon_hash", "banner", "base_protocol", "os", "app", "type", "fid",
    "country", "country_name", "region", "city", "icp", "org", "as_number",
    "as_organization", "is_domain", "is_ipv6", "is_fraud", "is_honeypot",
    "after", "before", "status_code", "jarm", "product", "sdk_hash",
    "cname", "cname_domain", "js_name", "js_md5", "lastupdatetime",
}

import re as _re_mod
# 匹配 FOFA 查询中 field="value" 或 field=value 模式的字段名
_FOFA_FIELD_RE = _re_mod.compile(r'(?:^|[(&|!\s])(\w+)\s*=')


def validate_fofa_query(query: str) -> Optional[str]:
    """校验 FOFA 查询语句中的字段名是否合法。返回 None 表示通过，返回字符串为错误提示。"""
    if not query:
        return None
    # 先归一再校验
    q = normalize_fofa_query(query) or ""
    fields_used = _FOFA_FIELD_RE.findall(q)
    invalid = [f for f in fields_used if f.lower() not in _FOFA_KNOWN_FIELDS]
    if invalid:
        return "FOFA 查询包含无效字段: {}（是否拼写错误？常用字段: domain, host, ip, title, header, body, port, server, app, cert）".format(
            ", ".join(invalid))
    return None


class FofaClient:
    """FOFA 测绘源客户端。next 游标优先（拉更深），失败回退 page offset。"""

    def __init__(self, key: str, page_size: int = 2000, max_page: int = 0,
                 fields: str = "host,ip,port"):
        self.key = key
        self.page_size = page_size
        self.max_page = max_page
        self.fields = fields
        self.base_url = str(get_config().section("FOFA", "URL",
                            default="https://fofa.info")).rstrip("/")

    def search(self, query: str):
        """生成器：优先 next 游标翻页，不可用则回退 page offset。"""
        query = normalize_fofa_query(query)
        try:
            got = False
            for results in self._by_next(query):
                got = True
                if results:
                    yield results
            if got:
                return
        except Exception as e:
            logger.warning("FOFA next 游标不可用，回退 page 翻页: %s", _mask(str(e), self.key)[:120])
        yield from self._by_page(query)

    def _by_next(self, query: str):
        q64 = base64.b64encode(query.encode()).decode()
        next_id, count = "", 0
        while self.max_page <= 0 or count < self.max_page:
            params = {"qbase64": q64, "size": self.page_size, "fields": self.fields}
            if next_id:
                params["next"] = next_id
            data = self._api("/api/v1/search/next", params)
            results = data.get("results", [])
            if results:
                yield results
            next_id = data.get("next", "")
            count += 1
            if len(results) < self.page_size or not next_id:
                break
            time.sleep(0.2)

    def _by_page(self, query: str):
        page = 1
        while self.max_page <= 0 or page <= self.max_page:
            if page > 1:
                time.sleep(0.2)
            params = {"qbase64": base64.b64encode(query.encode()).decode(),
                      "page": page, "size": self.page_size, "fields": self.fields}
            data = self._api("/api/v1/search/all", params)
            results = data.get("results", [])
            if results:
                yield results
            if len(results) < self.page_size:
                break
            page += 1

    def _api(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(params)
        params["key"] = self.key
        conn = http_req(self.base_url + path, "get", params=params, proxies=_intel_proxies())
        if conn.status_code != 200:
            raise RuntimeError("{} http {}".format(path, conn.status_code))
        data = conn.json()
        if data.get("error") and data.get("errmsg"):
            raise RuntimeError(data["errmsg"])
        return data


def _mask(text: str, key: str) -> str:
    """日志脱敏：把 key 尾段替换成 ***，不回显完整密钥（守全局安全边界）。"""
    if key and len(key) > 10:
        return text.replace(key[10:], "***")
    return text


def fofa_query(query: str, fields: str = "host,ip,port",
               page_size: int = 0, max_page: int = 0) -> Any:
    """FOFA 查询。返回结果列表；未配 key/出错返回错误字符串（日志脱敏 key）。"""
    cfg = get_config()
    key = _apikey("fofa") or cfg.section("FOFA", "KEY", default="") or ""   # 密钥中心优先，回退 config
    if not key:
        return "please set FOFA.KEY in config"
    if page_size <= 0:
        page_size = int(cfg.section("FOFA", "PAGE_SIZE", default=2000) or 2000)
    # 0=不限，不能用 `or default` 把调用方/配置的 0 改回有限页数。
    if max_page <= 0:
        try:
            max_page = int(cfg.section("FOFA", "MAX_PAGE", default=0))
        except (TypeError, ValueError):
            max_page = 0
    ret: List[Any] = []
    try:
        client = FofaClient(key, page_size=page_size, max_page=max_page, fields=fields)
        for results in client.search(query):
            ret.extend(results)
        logger.info("fofa query %s result size: %d", query, len(ret))
        return ret
    except Exception as e:
        msg = _mask(str(e), key)
        if ret:
            logger.warning("fofa query partial, error: %s", msg)
            return ret
        return msg


def crtsh_search(domain: str) -> List[str]:
    """crt.sh 证书透明日志查子域名。返回归属 domain 的子域名去重列表；出错返回 []。"""
    names: List[str] = []
    try:
        conn = http_req("https://crt.sh/", "get",
                        params={"output": "json", "q": domain}, timeout=(30.1, 50.1),
                        proxies=_intel_proxies())
        for item in conn.json() or []:
            for name in (item.get("name_value") or "").split():
                name = name.strip().strip("*.").lower()
                if name.endswith("." + domain) or name == domain:
                    names.append(name)
        names = sorted(set(names))
        logger.info("crtsh %s -> %d", domain, len(names))
    except Exception as e:
        logger.warning("crtsh %s error: %s", domain, e)
    return names


# 常见二级后缀（fld 归约用）：这些后缀下真正的主域是"三段"（如 a.com.cn）。
# 零依赖启发式，覆盖 ICP 场景（国内备案域名主要落这些后缀）；未命中则取末两段。
_SECOND_LEVEL = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "com.hk", "com.tw", "com.mo", "co.jp", "co.kr", "co.uk", "org.uk", "gov.uk",
}


def _main_domain(domain: str) -> str:
    """归约到主域 fld（备案按主域登记，子域查不到独立备案 → www/sub.a.com 都映射 a.com）。
    先剥协议/路径/端口，再按常见后缀取二级/三级主域。"""
    d = (domain or "").strip().lower()
    if not d:
        return ""
    if "://" in d:
        d = urlsplit(d).hostname or ""
    d = d.split("/")[0].split(":")[0].strip(".")
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    last_two = ".".join(parts[-2:])
    if last_two in _SECOND_LEVEL:
        return ".".join(parts[-3:])     # a.com.cn
    return last_two                      # a.com


def icp_query(domain: str) -> Dict[str, str]:
    """域名→备案单位名。Hunter(company 字段)优先，FOFA(icp 号)兜底，结果缓存 icp_cache。
    返回 {"unit", "icp_no", "source"}；查不到返回空 unit（不抛异常）。"""
    dom = _main_domain(domain)
    if not dom:
        return {"unit": "", "icp_no": "", "source": ""}
    cached = _cache_get(dom)
    if cached:
        return {"unit": cached.get("unit", ""), "icp_no": cached.get("icp_no", ""),
                "source": cached.get("source", "cache")}
    result = _query_hunter(dom) or _query_fofa(dom) or {"unit": "", "icp_no": "", "source": ""}
    if result.get("unit") or result.get("icp_no"):
        _cache_set(dom, result)
    return result


def _cache_get(domain: str) -> Optional[Dict[str, Any]]:
    try:
        return get_repo().collection(ICP_CACHE_COLL).find_one({"domain": domain})
    except Exception:
        return None


def _cache_set(domain: str, result: Dict[str, str]) -> None:
    try:
        get_repo().collection(ICP_CACHE_COLL).update_one(
            {"domain": domain},
            {"$set": {"domain": domain, "unit": result.get("unit", ""),
                      "icp_no": result.get("icp_no", ""), "source": result.get("source", "")}},
            upsert=True)
    except Exception as e:
        logger.warning("icp cache set %s error: %s", domain, e)


def _query_hunter(domain: str) -> Optional[Dict[str, str]]:
    """鹰图 Hunter：search=`domain="x"` base64，company 字段=备案单位名。page_size=1 省积分。"""
    cfg = get_config()
    key = _apikey("hunter") or cfg.section("HUNTER", "KEY", default="") or ""   # 密钥中心优先
    if not key:
        return None
    try:
        search_b64 = base64.urlsafe_b64encode('domain="{}"'.format(domain).encode()).decode()
        url = str(cfg.section("HUNTER", "URL",
                  default="https://hunter.qianxin.com")).rstrip("/") + "/openApi/search"
        # timeout 必须 tuple（历史踩坑：传 int 崩 TypeError 被吞→hunter 恒失败）
        conn = http_req(url, "get", timeout=(10.1, 20),
                        params={"api-key": key, "search": search_b64,
                                "page": 1, "page_size": 1, "is_web": 1},
                        proxies=_intel_proxies())
        data = conn.json()
        if data.get("code") != 200:
            logger.warning("hunter icp %s code=%s", domain, data.get("code"))
            return None
        for item in (data.get("data") or {}).get("arr") or []:
            company = (item.get("company") or "").strip()
            if company:
                return {"unit": company,
                        "icp_no": (item.get("number") or item.get("icp") or "").strip(),
                        "source": "hunter"}
        return None
    except Exception as e:
        logger.warning("hunter icp %s error: %s", domain, e)
        return None


def _query_fofa(domain: str) -> Optional[Dict[str, str]]:
    """FOFA 兜底：取 icp 备案号（FOFA 标准字段无单位名，只拿号）。"""
    cfg = get_config()
    key = _apikey("fofa") or cfg.section("FOFA", "KEY", default="") or ""   # 密钥中心优先
    if not key:
        return None
    try:
        client = FofaClient(key, page_size=1, max_page=1, fields="icp,host")
        for results in client.search('domain="{}"'.format(domain)):
            for row in results:
                icp_no = (row[0] if isinstance(row, list) and row else "") or ""
                if icp_no:
                    return {"unit": "", "icp_no": icp_no.strip(), "source": "fofa"}
        return None
    except Exception as e:
        logger.warning("fofa icp %s error: %s", domain, _mask(str(e), key))
        return None


def _unit_max_page() -> int:
    """单位反查 Hunter 翻页上限（大单位备案域名可能上百）。可配 HUNTER.UNIT_MAX_PAGE，默认 10（=1000域名）。
    这是防烧额度/失控的领域安全阈值（非分页硬上限，可调 0=不限）。"""
    try:
        return int(get_config().section("HUNTER", "UNIT_MAX_PAGE", default=10) or 10)
    except (TypeError, ValueError):
        return 10


def _hunter_by_icp_name(unit: str) -> set:
    """鹰图 icp.name="单位全称" 反查该单位全部备案域名（翻页收集去重）。无 key/失败→空 set（静默降级）。
    净室重写 unit_collect._hunter_by_icp（备案维度精准，不扯第三方，不踩授权红线）。"""
    domains: set = set()
    cfg = get_config()
    key = _apikey("hunter") or cfg.section("HUNTER", "KEY", default="") or ""
    if not key or not unit:
        return domains
    url = str(cfg.section("HUNTER", "URL", default="https://hunter.qianxin.com")).rstrip("/") + "/openApi/search"
    search_b64 = base64.urlsafe_b64encode('icp.name="{}"'.format(unit).encode()).decode()
    page, max_page, page_size = 1, _unit_max_page(), 100
    while max_page <= 0 or page <= max_page:
        try:
            data = http_req(url, "get", timeout=(10.1, 20),
                            params={"api-key": key, "search": search_b64,
                                    "page": page, "page_size": page_size, "is_web": 1},
                            proxies=_intel_proxies()).json()
        except Exception as e:
            logger.warning("unit reverse hunter unit=%s page=%s error: %s", unit, page, e)
            break
        if data.get("code") != 200:
            logger.warning("unit reverse hunter unit=%s code=%s msg=%s",
                           unit, data.get("code"), data.get("message"))
            break
        arr = ((data.get("data") or {}).get("arr")) or []
        for item in arr:
            d = (item.get("domain") or "").strip().lower()
            if d:
                domains.add(d)
        if len(arr) < page_size:
            break
        page += 1
    logger.info("unit reverse hunter unit=%s domains=%d", unit, len(domains))
    return domains


def reverse_lookup_units(units: List[str]) -> Dict[str, Any]:
    """单位名 → 资产反查（种子收集）。Hunter icp.name 主力反查各单位备案域名。
    返回 {"seeds": [去重域名...], "unit_map": {fld: unit}}。查不到返空 seeds（不抛，交调用方降级）。
    净室重写 unit_collect.reverse_lookup_by_units：只拿种子不做探测，种子交 recon pipeline 统一处理。"""
    seeds: set = set()
    unit_map: Dict[str, str] = {}
    for unit in (units or []):
        u = (unit or "").strip()
        if not u:
            continue
        for d in _hunter_by_icp_name(u):
            seeds.add(d)
            fld = _main_domain(d)
            if fld and fld not in unit_map:   # fld→单位映射（四级目录归属，先到先得）
                unit_map[fld] = u
    return {"seeds": sorted(seeds), "unit_map": unit_map}
