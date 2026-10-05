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

# 反查网络重试（治容器系统 DNS/网络间歇抽风：单次 DNS 超时不该让整个反查归零，重试自愈——
# 对齐记忆铁律"间歇失败优先重试自愈"+ proxy._EXIT_IP_RETRY / update_check._REMOTE_RETRY 范式）。
_REVERSE_RETRY = 3       # 单页网络失败重试次数
_REVERSE_BACKOFF = 0.5   # 退避基数（秒），指数退避
# 鹰图翻页限流治理（治「上万命中因 QPS 限流翻页秒 break，只拉到零头」）：
#   页间主动节流(避免撞 QPS)；遇 429/请求太快 时强退避重试当前页（限流可恢复，绝不 break 放弃）。
_HUNTER_PAGE_SLEEP = 1.2         # 翻页间主动 sleep 秒（可配 HUNTER.PAGE_SLEEP，避开 QPS 限流）
_HUNTER_RL_RETRY = 5             # 单页遇限流(429/太快)的强退避重试次数（比网络重试更多，限流需更耐心）
_HUNTER_RL_BACKOFF = 2.0         # 限流退避基数（秒），指数退避 2/4/8/16/32


def _intel_proxies(prefer_proxy: bool = False) -> Optional[Dict[str, str]]:
    """第三方测绘源出口决策。返回 proxies dict 或 None（None=交 http_req 直连，trust_env=False 真直连）。

    **国内源（Hunter/FOFA/ICP 备案反查，prefer_proxy=False，默认）固定直连**：它们是国内服务，
    直连又快又稳；走境外机场节点纯负优化——实测 Hunter 对机场 IP 直接返 403，机场节点抖动还会
    ProxyError('Cannot connect to proxy') → 反查拿 0 域名 → 单位名任务误判"未发现资产"（实为鹰图有
    资产、只是反查被代理打回）。这也对齐 `代理出口规范.md`「第三方测绘源直连」（此前该轨标 ❌ 偏离）。
    注意 smart 的可达探针（gstatic）只证明"经代理能出境"，不证明"目标源接受该代理 IP"，探针通过≠反查能成。

    **境外源（crtsh 证书透明，prefer_proxy=True）保留走智能代理绕墙**：智能源可达则经代理、不可达降级
    直连（resolve_egress_url smart 叠加降级）。缺服务/无源 → None 直连。"""
    if not prefer_proxy:
        return None                                  # 国内测绘源固定直连（不读残留 env，不走机场节点）
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


# API 密钥页「资产测绘/情报」中可交给 subfinder 的来源映射。FOFA 例外：当前密钥中心只存
# API key，而 subfinder 要求 email:key 复合凭据，因此继续复用平台原生 FofaClient，避免让
# 已经可用的存量 FOFA 配置突然失效。ZoomEye 按官方要求显式选择中国区 API host。
_SUBFINDER_SOURCE_MAP = {
    "hunter": "hunter",
    "quake": "quake",
    "zoomeye": "zoomeyeapi",
    "securitytrails": "securitytrails",
    "virustotal": "virustotal",
    "chaos": "chaos",
    "passivetotal": "passivetotal",
}


def configured_collection_sources(selected: Optional[List[str]] = None) -> Dict[str, Any]:
    """解析策略选择中**当前确实已配置**的广域 API 收集源。

    selected=None 表示存量策略未带该字段，兼容为「全部已配置源」；显式 [] 表示用户全部取消。
    返回 {fofa: bool, subfinder: {provider_name: credential}}，调用方只拿临时凭据运行，不记录日志。
    """
    selected_set = None if selected is None else {
        str(x or "").strip().lower() for x in selected if str(x or "").strip()
    }

    def wanted(source_id: str) -> bool:
        return selected_set is None or source_id in selected_set

    out: Dict[str, Any] = {"fofa": False, "subfinder": {}}
    if wanted("fofa") and _apikey("fofa"):
        out["fofa"] = True

    credentials: Dict[str, str] = {}
    for source_id, provider_name in _SUBFINDER_SOURCE_MAP.items():
        if not wanted(source_id):
            continue
        if source_id == "quake":
            credential = _apikey(source_id, "token")
        elif source_id == "passivetotal":
            email = _apikey(source_id, "email")
            key = _apikey(source_id, "key")
            credential = "{}:{}".format(email, key) if email and key else ""
        elif source_id == "zoomeye":
            key = _apikey(source_id, "key")
            credential = "zoomeye.org:{}".format(key) if key else ""
        else:
            credential = _apikey(source_id, "key")
        if credential:
            credentials[provider_name] = credential
    out["subfinder"] = credentials
    return out


def fofa_subdomains(domains: List[str]) -> List[str]:
    """用平台原生 FOFA 客户端按主域补充子域名；失败只降级本来源，不阻断 recon 主链。

    只接收属于当前 root 的 hostname，丢弃 IP、跨域 CNAME、路径与端口，避免测绘结果把 scope
    扩到授权边界之外。查询结果仍交后续 dnsx/httpx 做真实探测，不把测绘命中直接当存活资产。
    """
    found = set()
    for raw_root in domains or []:
        root = str(raw_root or "").strip().lower().strip(".")
        if not root:
            continue
        result = fofa_query('domain="{}"'.format(root), fields="host,ip,port")
        if isinstance(result, str):
            logger.warning("FOFA 广域收集 %s 降级: %s", root, result[:120])
            continue
        for row in result or []:
            raw_host = str(row[0] or "").strip() if isinstance(row, (list, tuple)) and row else ""
            if not raw_host:
                continue
            value = raw_host if "://" in raw_host else "//" + raw_host
            try:
                host = (urlsplit(value).hostname or "").lower().strip(".")
            except Exception:
                host = ""
            if host and (host == root or host.endswith("." + root)):
                found.add(host)
    return sorted(found)

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


# 匹配查询里 domain="X" / domain=X 子句的值（Hunter/FOFA 同语法）。捕获引号内或裸值。
_DOMAIN_CLAUSE_RE = _re_mod.compile(r'domain\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s&|()!]+))', _re_mod.I)


def _extract_domain_roots(query: str) -> set:
    """从查询语句解析 domain="X" 子句 → 归属根集合（去引号/空白/前导点/尾点、小写）。
    多个 domain 子句取并集（如 `domain=".gov.cn"&&title="后台"||domain=".gov.cn"`→{gov.cn}）。
    无 domain 子句返回空集（调用方据此不过滤——尊重纯 title/app 查询意图，不臆想归属）。"""
    roots = set()
    for m in _DOMAIN_CLAUSE_RE.finditer(query or ""):
        val = (m.group(1) or m.group(2) or m.group(3) or "").strip().strip(".").lower()
        if val:
            roots.add(val)
    return roots


def _host_belongs_roots(host: str, roots: set) -> bool:
    """host 是否归属 roots 任一（DNS 标签边界：等于 root 或 .root 结尾）。roots 空→True（不过滤）。
    天然排除仿冒：`gov.cn.x.com`/`ctdwhsdds-gov-cn.y.cn` 都不 endswith `.gov.cn` → 拦截；
    真站 `jazx.gov.cn`/`zz.hnzwfw.gov.cn` endswith `.gov.cn` → 放行。绝不子串匹配。"""
    if not roots:
        return True
    h = (host or "").strip().strip(".").lower()
    if not h:
        return False
    return any(h == r or h.endswith("." + r) for r in roots)


def _filter_rows_by_domain_roots(rows: List[Dict[str, Any]], roots: set, src: str = "") -> List[Dict[str, Any]]:
    """按归属根过滤源返回行：有 host 的行须归属 roots；纯 IP 行（无 host）不受 domain 根过滤（保留）。
    roots 空则原样返回。落 warning 记过滤量（可观测确认生效）。"""
    if not roots:
        return rows
    kept, dropped = [], []
    for r in rows:
        host = (r.get("host") or "").strip().lower()
        if not host or _host_belongs_roots(host, roots):
            kept.append(r)
        else:
            dropped.append(host)
    if dropped:
        logger.warning("%s 归属过滤：滤除 %d 个不属于 %s 的仿冒/越界域名（示例 %s）",
                       src or "测绘源", len(dropped), sorted(roots), dropped[:5])
    return kept


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


# FOFA 限流信号（HTTP 429 / errmsg 含这些片段）：限流是瞬时抖动，应退避重试自愈，
# 不能当成查询结果直接甩给用户（守记忆铁律"间歇失败优先重试自愈"，非缓存/非直报）。
_FOFA_RATELIMIT_MARKS = ("速度过快", "too fast", "820000", "45012", "429", "请求过于频繁", "rate limit")
_FOFA_COUNT_RETRY = 4       # 限流重试次数
_FOFA_COUNT_BACKOFF = 2.0   # 退避基数（秒），指数退避 2/4/8...


def _is_fofa_ratelimit(status: int, errmsg: str) -> bool:
    """判定是否 FOFA 限流（HTTP 429 或 errmsg 命中限流码/关键词）。"""
    if status == 429:
        return True
    em = (errmsg or "").lower()
    return any(m.lower() in em for m in _FOFA_RATELIMIT_MARKS)


def fofa_count(query: str) -> Dict[str, Any]:
    """FOFA 命中总数预估（只打一次 search/all 读官方 size，不翻页/不拉全量，省额度）。

    返回结构化 dict（供"测试查询"用，取代原先"拉一批再数 len"的误导性预估）：
      {ok, size, error, errmsg, query}
      - ok=True + size：FOFA 官方声明的总命中数（size=0 就是真没匹配到，非"超上限"）。
      - ok=False + errmsg：FOFA 真实报错（语法错/额度不足等），如实透传。
    **限流(429/速度过快)退避重试自愈**：限流是瞬时抖动，不当结果直报（守记忆铁律
    [[feedback-retry-not-cache-for-flaky-probe]]）；重试仍限流才提示"稍后重试"。
    治「domain="gov.cn" 预估 0 条」的误导——domain 是精确主域匹配，gov.cn 是公共二级
    后缀本就 0 条命中（实测 beijing.gov.cn=1664/www.gov.cn=647 有命中，gov.cn=0），如实透出。
    """
    cfg = get_config()
    key = _apikey("fofa") or cfg.section("FOFA", "KEY", default="") or ""
    if not key:
        return {"ok": False, "size": 0, "error": True, "errmsg": "未配置 FOFA KEY", "query": query}
    q = normalize_fofa_query(query) or ""
    base = str(cfg.section("FOFA", "URL", default="https://fofa.info")).rstrip("/")
    q64 = base64.b64encode(q.encode()).decode()
    last_msg = "FOFA 查询失败"
    for attempt in range(_FOFA_COUNT_RETRY):
        try:
            conn = http_req(base + "/api/v1/search/all", "get",
                            params={"qbase64": q64, "size": 1, "fields": "host", "key": key},
                            proxies=_intel_proxies())
            status = conn.status_code
            data = conn.json() if status == 200 else {}
            errmsg = str(data.get("errmsg") or "") if data else ""
            # 限流 → 退避重试自愈（不直报）
            if _is_fofa_ratelimit(status, errmsg) or (status != 200 and status >= 500):
                last_msg = errmsg or "HTTP {}".format(status)
                if attempt < _FOFA_COUNT_RETRY - 1:
                    time.sleep(_FOFA_COUNT_BACKOFF * (2 ** attempt))
                    continue
                # 重试耗尽仍限流：明确提示是限流、稍后再试（而非笼统 429/会员上限）
                return {"ok": False, "size": 0, "error": True, "query": q,
                        "errmsg": "FOFA 请求频繁被限流，请稍后重试（已自动重试 {} 次）".format(_FOFA_COUNT_RETRY)}
            if status != 200:
                return {"ok": False, "size": 0, "error": True,
                        "errmsg": "HTTP {}".format(status), "query": q}
            if data.get("error"):
                # 非限流的真实报错（语法/额度等）如实透传（脱敏 key）
                return {"ok": False, "size": 0, "error": True,
                        "errmsg": _mask(errmsg or "FOFA 查询出错", key), "query": q}
            size = int(data.get("size") or 0)
            logger.info("fofa count %s -> size=%d", q, size)
            return {"ok": True, "size": size, "error": False, "errmsg": "", "query": q}
        except Exception as e:
            last_msg = _mask(str(e), key)[:160]
            if attempt < _FOFA_COUNT_RETRY - 1:
                time.sleep(_FOFA_COUNT_BACKOFF * (2 ** attempt))
                continue
    return {"ok": False, "size": 0, "error": True, "errmsg": last_msg, "query": q}


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


# —— 鹰图 Hunter 按任意语句查询（多源建任务用；区别于 _hunter_by_icp_name 的 icp.name 反查）——
_HUNTER_RATELIMIT_MARKS = ("请求太多", "频繁", "too many", "rate", "40204", "429", "积分")


def _hunter_query_max_page() -> int:
    """鹰图按语句查询（源查询建任务）翻页上限。默认 50（=5000 域名）——源查询常是宽查询（如 .gov.cn
    命中上万），不同于单位反查（特定单位备案域名，10 页够），故独立更大默认，避免上万命中只拉零头。
    限流已由页间节流 + 429 强退避治理（hunter_query），翻页不再撞死。可配 HUNTER.QUERY_MAX_PAGE
    （0=不限，全拉；但烧积分/耗时随命中线性增长，宽查询慎用 0）。禁硬编码魔数。"""
    try:
        v = get_config().section("HUNTER", "QUERY_MAX_PAGE", default=None)
        if v is not None:
            return int(v)
    except (TypeError, ValueError):
        pass
    return 50


def _hunter_page_sleep() -> float:
    """鹰图翻页间节流秒（可配 HUNTER.PAGE_SLEEP，默认 _HUNTER_PAGE_SLEEP）。主动避开 QPS 限流。"""
    try:
        v = get_config().section("HUNTER", "PAGE_SLEEP", default=None)
        return float(v) if v is not None else _HUNTER_PAGE_SLEEP
    except (TypeError, ValueError):
        return _HUNTER_PAGE_SLEEP


def hunter_count(query: str) -> Dict[str, Any]:
    """鹰图命中总数预估：只查首页读 data.total，省配额。限流退避重试自愈。
    返回 {ok, size, error, errmsg}。语义：鹰图 domain= 是模糊匹配（domain="gov.cn" 命中全部 *.gov.cn）。"""
    cfg = get_config()
    key = _apikey("hunter") or cfg.section("HUNTER", "KEY", default="") or ""
    if not key:
        return {"ok": False, "size": 0, "error": True, "errmsg": "未配置鹰图 KEY"}
    q = (query or "").strip()
    if not q:
        return {"ok": False, "size": 0, "error": True, "errmsg": "查询语句为空"}
    url = str(cfg.section("HUNTER", "URL", default="https://hunter.qianxin.com")).rstrip("/") + "/openApi/search"
    sb64 = base64.urlsafe_b64encode(q.encode()).decode()
    for attempt in range(_REVERSE_RETRY):
        try:
            data = http_req(url, "get", timeout=(10.1, 20),
                            params={"api-key": key, "search": sb64, "page": 1, "page_size": 1, "is_web": 3},
                            proxies=_intel_proxies()).json()
            code = data.get("code")
            msg = str(data.get("message") or "")
            if code == 200:
                total = int(((data.get("data") or {}).get("total")) or 0)
                logger.info("hunter count %s -> total=%d", q, total)
                return {"ok": True, "size": total, "error": False, "errmsg": ""}
            # 限流类 → 退避重试；其他确定性错（语法/积分不足）→ 直接返回
            if any(m in msg for m in _HUNTER_RATELIMIT_MARKS) and attempt < _REVERSE_RETRY - 1:
                time.sleep(_REVERSE_BACKOFF * (2 ** attempt))
                continue
            return {"ok": False, "size": 0, "error": True, "errmsg": "鹰图: {}".format(msg[:80] or code)}
        except Exception as e:
            if attempt < _REVERSE_RETRY - 1:
                time.sleep(_REVERSE_BACKOFF * (2 ** attempt))
                continue
            return {"ok": False, "size": 0, "error": True, "errmsg": _mask(str(e), key)[:120]}
    return {"ok": False, "size": 0, "error": True, "errmsg": "鹰图查询重试耗尽"}


def hunter_query(query: str, max_page: int = 0) -> Dict[str, Any]:
    """鹰图按任意语句查资产（翻页收集）。返回 {ok, total, rows:[{host,ip,port}], error}。
    rows: host=domain（无则空，用 ip 落目标）；ip=公网IPv4；port。翻页+网络重试自愈（同 _hunter_by_icp_name）。"""
    cfg = get_config()
    key = _apikey("hunter") or cfg.section("HUNTER", "KEY", default="") or ""
    if not key:
        return {"ok": False, "total": 0, "rows": [], "error": "未配置鹰图 KEY"}
    q = (query or "").strip()
    if not q:
        return {"ok": False, "total": 0, "rows": [], "error": "查询语句为空"}
    url = str(cfg.section("HUNTER", "URL", default="https://hunter.qianxin.com")).rstrip("/") + "/openApi/search"
    sb64 = base64.urlsafe_b64encode(q.encode()).decode()
    mp = max_page if max_page > 0 else _hunter_query_max_page()
    rows: List[Dict[str, Any]] = []
    total = 0
    page, page_size = 1, 100
    page_sleep = _hunter_page_sleep()
    while mp <= 0 or page <= mp:
        # 单页抓取：先网络重试拿到响应，再判限流(code=429/请求太快)——限流强退避重试**当前页**，
        # 绝不 break 放弃（治「上万命中撞 QPS 限流秒退出、只拉到零头」）。真结束/真错才停。
        data, rate_limited = None, False
        for attempt in range(_HUNTER_RL_RETRY):
            got = None
            for natt in range(_REVERSE_RETRY):        # 内层：网络异常重试
                try:
                    got = http_req(url, "get", timeout=(10.1, 20),
                                   params={"api-key": key, "search": sb64,
                                           "page": page, "page_size": page_size, "is_web": 3},
                                   proxies=_intel_proxies()).json()
                    break
                except Exception:
                    if natt < _REVERSE_RETRY - 1:
                        time.sleep(_REVERSE_BACKOFF * (2 ** natt))
            if got is None:                            # 网络彻底失败
                break
            code = got.get("code")
            msg = str(got.get("message") or "")
            if code == 200:
                data = got
                break
            # 限流(429 或 message 命中限流词) → 强退避重试当前页（限流可恢复，页间等更久）
            if (code == 429 or any(m in msg for m in _HUNTER_RATELIMIT_MARKS)) and attempt < _HUNTER_RL_RETRY - 1:
                rate_limited = True
                time.sleep(_HUNTER_RL_BACKOFF * (2 ** attempt))
                continue
            # 非限流的确定性错（语法/积分不足）→ 记 data 供下方统一处理
            data = got
            break
        if data is None:                               # 网络失败/限流重试耗尽：已拉到的照常返回，不清空
            if rate_limited:
                logger.warning("hunter query %s 第 %d 页限流重试耗尽，已收集 %d 行（部分结果）", q, page, len(rows))
            break
        if data.get("code") != 200:
            logger.warning("hunter query %s code=%s msg=%s", q, data.get("code"), data.get("message"))
            if not rows:
                return {"ok": False, "total": 0, "rows": [], "error": "鹰图: {}".format(str(data.get("message"))[:80])}
            break
        dd = data.get("data") or {}
        total = int(dd.get("total") or total)
        arr = dd.get("arr") or []
        for item in arr:
            host = (item.get("domain") or "").strip().lower()
            ip = (item.get("ip") or "").strip()
            port = str(item.get("port") or "").strip()
            rows.append({"host": host, "ip": ip if _is_ipv4(ip) else "", "port": port})
        if len(arr) < page_size:
            break
        page += 1
        if page_sleep > 0:                             # 页间主动节流，避开 QPS 限流（比撞了再退避更稳）
            time.sleep(page_sleep)
    # 归属过滤（治仿冒/域名混淆）：Hunter domain= 是模糊包含匹配，会返回 gov.cn.x.com / x-gov-cn.y.cn 等
    # 字面含 root 的仿冒域名。按查询里的 domain 子句根，用 DNS 标签边界过滤有 host 的行（无 domain 子句不过滤）。
    roots = _extract_domain_roots(q)
    rows = _filter_rows_by_domain_roots(rows, roots, src="鹰图")
    logger.info("hunter query %s -> total=%d rows=%d", q, total, len(rows))
    return {"ok": True, "total": total, "rows": rows, "error": ""}


def _dedup_source_rows(rows: List[Dict[str, Any]]) -> List[str]:
    """多源资产行 → 去重后的 target 列表（本方案去重键，宽进不误删）：
      有域名(host 非纯IP) → 按 hostname 去重（key=d:host），落 target=host（域名下发触发完整侦察）；
      纯IP(无 host 或 host 是 IP) → 按 ip+port 去重（key=p:ip|port），落 target=ip。
    不解析域名成IP、不用 title、不判 CDN（建任务前信息不全，避免 CDN 共享IP/子系统误合并）；
    精细去重复用下游策略层 session._dedup_key（扫描归集→派发时用完整信息）。"""
    seen = set()
    targets: List[str] = []
    for r in rows:
        host = (r.get("host") or "").strip().lower()
        ip = (r.get("ip") or "").strip()
        # 落 target：有域名(非纯IP)下发域名(触发完整侦察)，否则下发 IP。
        # 去重键=最终 target 字符串：域名按 hostname 去重；纯 IP 按 IP 去重
        # （同 IP 不同端口合并成一次 IP 任务——IP 侦察本就全端口扫，不按端口重复下发）。
        if host and not _is_ipv4(host):
            tgt = host
        elif ip:
            tgt = ip
        elif host:            # host 是纯 IP 字面量
            tgt = host
        else:
            continue
        if tgt in seen:
            continue
        seen.add(tgt)
        targets.append(tgt)
    return targets


def multi_source_targets(queries: Dict[str, str],
                         limits: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """多源查询合并去重（FOFA + 鹰图，各写各语法）。核心：源查询建任务的入口层合并。
    入参 queries={"fofa":"语句","hunter":"语句"}（只处理非空源）。
    limits={"fofa":N,"hunter":M}=各源抓取数量上限（正整数；缺省/<=0=无限制，守禁硬限制铁律）。
    各源各查 → 汇成 rows[{host,ip,port}] → _dedup_source_rows 去重 → targets。
    数量限制**按源、去重前**生效：翻页上界省额度 + 精确截断到 limit（去重后再截会破坏 per_source 口径）。
    返回 {ok, targets:[...], per_source:{fofa:N,hunter:M}, merged:T, errors:{...}}。"""
    import math
    queries = queries or {}
    limits = limits or {}
    rows: List[Dict[str, Any]] = []
    per_source: Dict[str, int] = {}
    errors: Dict[str, str] = {}

    def _lim(sid: str) -> int:
        try:
            v = int(limits.get(sid, 0) or 0)
        except (TypeError, ValueError):
            v = 0
        return v if v > 0 else 0        # <=0/非法 = 无限制

    # FOFA：fofa_query 返回 [[host,ip,port],...]
    fq = (queries.get("fofa") or "").strip()
    if fq:
        try:
            fl = _lim("fofa")
            # 有限制时按每页 2000 折算翻页上界，省额度（多抓的余量交给下方精确截断）
            fmp = int(math.ceil(fl / 2000.0)) if fl else 0
            res = fofa_query(normalize_fofa_query(fq), fields="host,ip,port", max_page=fmp)
            if isinstance(res, str):        # 错误字符串
                errors["fofa"] = res[:120]
                per_source["fofa"] = 0
            else:
                fofa_rows = []
                for row in res:
                    if isinstance(row, (list, tuple)) and row:
                        host = str(row[0] or "").strip().lower()
                        ip = str(row[1]).strip() if len(row) > 1 and row[1] else ""
                        port = str(row[2]).strip() if len(row) > 2 and row[2] else ""
                        # FOFA host 常带 scheme（http://x），剥掉
                        if "://" in host:
                            host = host.split("://", 1)[1]
                        host = host.split("/")[0]
                        # host 带端口 → 拆
                        if ":" in host and not _is_ipv4(host):
                            hp = host.rsplit(":", 1)
                            if hp[1].isdigit():
                                host, port = hp[0], port or hp[1]
                        fofa_rows.append({"host": host, "ip": ip, "port": port})
                # 归属过滤：按 FOFA 查询里的 domain 子句根过滤（FOFA domain= 虽是精确主域，仍统一兜底）
                fofa_rows = _filter_rows_by_domain_roots(fofa_rows, _extract_domain_roots(fq), src="FOFA")
                if fl:
                    fofa_rows = fofa_rows[:fl]       # 精确截断到 limit
                rows.extend(fofa_rows)
                per_source["fofa"] = len(fofa_rows)
        except Exception as e:
            errors["fofa"] = str(e)[:120]
            per_source["fofa"] = 0

    # 鹰图：hunter_query 返回 {rows:[{host,ip,port}]}
    hq = (queries.get("hunter") or "").strip()
    if hq:
        hl = _lim("hunter")
        hmp = int(math.ceil(hl / 100.0)) if hl else 0   # 鹰图每页 100
        hr = hunter_query(hq, max_page=hmp)
        if hr.get("ok"):
            hrows = hr.get("rows") or []
            if hl:
                hrows = hrows[:hl]                        # 精确截断到 limit
            rows.extend(hrows)
            per_source["hunter"] = len(hrows)
        else:
            errors["hunter"] = hr.get("error", "鹰图查询失败")
            per_source["hunter"] = 0

    targets = _dedup_source_rows(rows)
    ok = bool(targets) or not errors   # 有目标即成功；全空且有错则失败
    return {"ok": ok, "targets": targets, "per_source": per_source,
            "merged": len(targets), "errors": errors}


def crtsh_search(domain: str) -> List[str]:
    """crt.sh 证书透明日志查子域名。返回归属 domain 的子域名去重列表；出错返回 []。"""
    names: List[str] = []
    try:
        conn = http_req("https://crt.sh/", "get",
                        params={"output": "json", "q": domain}, timeout=(30.1, 50.1),
                        proxies=_intel_proxies(prefer_proxy=True))   # crtsh 境外源，保留智能代理绕墙
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
# 二级后缀表已下沉 core.domains.SECOND_LEVEL_SUFFIXES（三处 fld 共用，缺陷4 修复）。


def _main_domain(domain: str) -> str:
    """归约到主域 fld（备案按主域登记，子域查不到独立备案 → www/sub.a.com 都映射 a.com）。
    委托 core.domains.extract_fld（三处 fld 共用同一权威二级后缀表，缺陷4：治 unit_map key 与
    enrich 写入侧后缀表不一致导致的单位回填失灵）。"""
    from sentinel_platform.core import extract_fld as _core_fld
    return _core_fld(domain)


def icp_query(domain: str) -> Dict[str, str]:
    """域名→备案单位名。多源链：Hunter(company 字段，快/可批量/免验证码) 优先 →
    工信部官方 miit(权威/免积分，但有滑块验证码略慢) 兜底校准 → FOFA(仅 icp 号) 末位。
    结果缓存 icp_cache。返回 {"unit", "icp_no", "source"}；查不到返回空 unit（不抛异常）。

    官方源定位为**兜底**（对齐用户决策）：Hunter 拿到单位名即用，主链路批量归集不被验证码拖慢；
    仅 Hunter 未出单位名时才请官方补齐（权威且不烧鹰图积分）。官方源可用性受出口 IP 风控影响，
    失败静默降级到 FOFA（守 §0.4 外部源失败不抛异常）。"""
    dom = _main_domain(domain)
    if not dom:
        return {"unit": "", "icp_no": "", "source": ""}
    cached = _cache_get(dom)
    if cached:
        return {"unit": cached.get("unit", ""), "icp_no": cached.get("icp_no", ""),
                "source": cached.get("source", "cache")}
    # Hunter 优先：拿到单位名(unit)即采用（company 字段够用、快、免验证码）
    result = _query_hunter(dom)
    if not (result and result.get("unit")):
        # Hunter 没出单位名 → 官方 miit 兜底（权威、免积分；失败降级）
        miit = _query_miit(dom)
        if miit and (miit.get("unit") or miit.get("icp_no")):
            result = miit
        elif not result:
            result = _query_fofa(dom)     # 官方也没有 → FOFA 拿 icp 号兜底
    result = result or {"unit": "", "icp_no": "", "source": ""}
    if result.get("unit") or result.get("icp_no"):
        _cache_set(dom, result)
    return result


def _query_miit(domain: str) -> Optional[Dict[str, str]]:
    """工信部官方 ICP 查询兜底（对接模块经 _icp_miit，防腐层结构化）。失败/异常返回 None（静默降级）。"""
    try:
        from ._icp_miit import query_icp as _miit_query
        r = _miit_query(domain)
        return r if (r and (r.get("unit") or r.get("icp_no"))) else None
    except Exception as exc:
        logger.debug("icp _query_miit degraded: %s", exc)
        return None


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


def _hunter_by_icp_name(unit: str) -> Dict[str, set]:
    """鹰图 icp.name="单位全称" 反查该单位全部备案资产（翻页收集去重）。无 key/失败→空（静默降级）。
    净室重写 unit_collect._hunter_by_icp（备案维度精准，不扯第三方，不踩授权红线）。
    **返回 {"domains": set, "ips": set}**：Hunter 每条记录自带 domain + ip + port，两者都是资产、互补——
    有些主域无 A 记录（如 xxx.cn 只承载邮件/子域名）DNS 解析不出，但 Hunter 已给出可直接扫的 IP，不能丢
    （治"反查到资产却因主域解析不出→0 资产"）。IP 交 ip pipeline 直接 portscan/site，绕开 DNS 瓶颈。"""
    domains: set = set()
    ips: set = set()
    cfg = get_config()
    key = _apikey("hunter") or cfg.section("HUNTER", "KEY", default="") or ""
    if not key or not unit:
        return {"domains": domains, "ips": ips}
    url = str(cfg.section("HUNTER", "URL", default="https://hunter.qianxin.com")).rstrip("/") + "/openApi/search"
    search_b64 = base64.urlsafe_b64encode('icp.name="{}"'.format(unit).encode()).decode()
    page, max_page, page_size = 1, _unit_max_page(), 100
    while max_page <= 0 or page <= max_page:
        # 网络异常（连接/DNS/超时）重试自愈：容器系统 DNS 偶发抽风，单次失败不该让反查归零。
        # 拿到 HTTP 响应即跳出重试（含 code!=200 的确定性错，交下方判定，不重试）。
        data = None
        last_err = None
        for attempt in range(_REVERSE_RETRY):
            try:
                data = http_req(url, "get", timeout=(10.1, 20),
                                params={"api-key": key, "search": search_b64,
                                        "page": page, "page_size": page_size, "is_web": 1},
                                proxies=_intel_proxies()).json()
                break
            except Exception as e:
                last_err = e
                if attempt < _REVERSE_RETRY - 1:
                    time.sleep(_REVERSE_BACKOFF * (2 ** attempt))   # 0.5s / 1s 退避后重连
        if data is None:
            logger.warning("unit reverse hunter unit=%s page=%s 重试 %d 次仍失败: %s",
                           unit, page, _REVERSE_RETRY, last_err)
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
            ip = (item.get("ip") or "").strip()
            if _is_ipv4(ip):                  # 只收公网可扫的 IPv4，域名/内网/空一律不当 IP 种子
                ips.add(ip)
        if len(arr) < page_size:
            break
        page += 1
    logger.info("unit reverse hunter unit=%s domains=%d ips=%d", unit, len(domains), len(ips))
    return {"domains": domains, "ips": ips}


def _is_ipv4(v: str) -> bool:
    """判定是否为公网 IPv4（反查 IP 种子入 ip pipeline 前的守卫：内网/环回/非法一律排除）。"""
    try:
        import ipaddress
        ip = ipaddress.ip_address(v)
        return ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_reserved
                                        or ip.is_link_local or ip.is_multicast)
    except (ValueError, TypeError):
        return False


def _icp_official_reverse(unit: str) -> Dict[str, Any]:
    """工信部官方 ICP 按单位名反查备案域名/IP（对接模块经 _icp_miit，防腐层）。
    透传三态 status（问题9）：ok(有备案)/empty(权威说无备案)/unavailable(工具失效)。
    异常一律归 unavailable（工具失效，交上层降级第三方），**绝不当 empty**（防把故障误判成"无资产"）。"""
    try:
        from ._icp_miit import reverse_by_unit_miit
        r = reverse_by_unit_miit(unit) or {}
        return {"status": r.get("status", "unavailable"),
                "domains": r.get("domains") or set(), "ips": r.get("ips") or set()}
    except Exception as exc:
        logger.debug("icp official reverse degraded: %s", exc)
        return {"status": "unavailable", "domains": set(), "ips": set()}


# 多单位 ICP 官方源查询基础间隔（秒）；测试可置 0 关闭真实 sleep（避免单测被拖慢）。
_ICP_REVERSE_BASE_INTERVAL = 2.0


def _icp_reverse_throttle(unavail_streak: int, cancel_check=None) -> None:
    """多单位任务官方 ICP 源查询间自适应退避节流（问题9 风控防护，用户 2026-09-12 定调）。
    工信部官方源直连、受出口 IP 风控——多单位短时间连查极易触发。基础间隔 + 按已连续失效程度
    指数退避（失效越多退得越久，缓解风控），失效清零则回落基础间隔。非硬上限，只是查询节奏。"""
    base = _ICP_REVERSE_BASE_INTERVAL
    if base <= 0:                               # 测试/显式关闭：不 sleep
        return
    import time
    backoff = base * (2 ** min(unavail_streak, 4))   # 指数退避，min 仅防溢出非业务硬限（封顶 32×base）
    deadline = time.monotonic() + backoff
    while time.monotonic() < deadline:
        if cancel_check and cancel_check():
            return
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def reverse_lookup_units(units: List[str], on_unit=None, cancel_check=None) -> Dict[str, Any]:
    """单位名 → 资产反查（种子收集）。**ICP 官方源优先**（工信部一手权威），查不到才降级鹰图 icp.name。
    返回 {"seeds": [域名...], "ip_seeds": [公网IP...], "unit_map": {fld: unit}}。查不到返空（不抛，交调用方降级）。

    **流式回调（on_unit）**：每个单位反查完即 `on_unit(unit, domains:set, ips:set, fld_map:dict)` 外抛
    （fld_map=本单位 fld→unit 片段），供上层边反查边喂 recon（不等全部单位反查完，守流式派发铁律）。
    on_unit=None（默认）时行为完全不变，仍只在末尾一次性返回。回调异常吞掉，绝不打断反查主流程。

    **ICP 优先链路（用户确立）**：
      ① 先用工信部官方 ICP 反查该单位备案域名/IP → 查到就以 ICP 为权威种子（定"打谁"），
         再交 recon pipeline + 第三方工具富化详细资产（第三方有 IP/端口/指纹）。
      ② ICP 查不到该单位 → 降级鹰图 icp.name 反查（_hunter_by_icp_name）。
      ③ 冲突时 ICP 为准：ICP 查到就不再合并鹰图（鹰图说是备案但 ICP 没有的不采信，ICP 官方一手）。
    **6a 防打歪**：ICP/鹰图给的域名原样作种子（seeds.add(d) 不经 _main_domain 削减），
      绝不上溯根域（abc.gov.cn 原样，不削成 gov.cn 打歪整个政府网段）。unit_map 的 fld 用 _main_domain
      （它对 gov.cn/edu.cn 等二级公共后缀安全，见 _SECOND_LEVEL）。
    **域名 + IP 两类种子互补**：域名走 domain pipeline，IP 走 ip pipeline（绕开 DNS）。"""
    seeds: set = set()
    ip_seeds: set = set()
    unit_map: Dict[str, str] = {}
    unit_status: Dict[str, str] = {}       # 每单位最终判定：ok_icp / empty_icp / third_party / no_asset
    multi = len([u for u in (units or []) if (u or "").strip()]) > 1
    icp_unavail_streak = 0                 # 连续 ICP 工具失效计数（自适应风控判定，非硬编码阈值）
    icp_ok_or_empty = 0                    # ICP 成功答复次数（ok/empty 都算"官方源可用"）
    risk_suspected = False                 # 疑似风控：多单位下官方源持续失效则跳过官方源直连第三方
    cancelled = False
    callback_errors = []
    for idx, unit in enumerate(units or []):
        if cancel_check and cancel_check():
            cancelled = True
            break
        u = (unit or "").strip()
        if not u:
            continue
        # 【状态①/②/③分流，问题9 用户 2026-09-12 定调】
        # 风控自适应：多单位任务中官方源持续失效（且从未成功过）→ 判疑似风控，后续单位跳过官方源
        # 直连第三方，不再打工信部（避免继续触发更严风控）。非硬编码次数——"从未成功 + 连续失效"动态判。
        if multi and risk_suspected:
            found = _hunter_by_icp_name(u)
            src, status = "hunter_riskskip", "unavailable"
        else:
            # 多单位：官方源查询间自适应退避节流（首个不等，后续按已失效程度递增间隔，缓解风控）
            if multi and idx > 0:
                _icp_reverse_throttle(icp_unavail_streak, cancel_check=cancel_check)
            if cancel_check and cancel_check():
                cancelled = True
                break
            official = _icp_official_reverse(u)
            if cancel_check and cancel_check():
                cancelled = True
                break
            status = official.get("status", "unavailable")
            if status == "ok":                        # 状态①：ICP 有备案 → 只用 ICP，不合并第三方（越权丢弃）
                found, src = official, "icp_official"
                icp_unavail_streak = 0
                icp_ok_or_empty += 1
            elif status == "empty":                   # 状态②：ICP 权威说无备案 → 该单位无资产，不降级第三方
                unit_status[u] = "no_asset"
                icp_unavail_streak = 0
                icp_ok_or_empty += 1
                logger.info("reverse_lookup unit=%s ICP 权威判定无备案资产（不降级第三方，用户定调无资产结束）", u)
                continue
            else:                                     # 状态③：ICP 工具失效 → 降级第三方
                icp_unavail_streak += 1
                # 疑似风控判定：多单位 + 官方源从未成功 + 连续失效 → 后续跳过官方源（自适应，非魔数）
                if multi and icp_ok_or_empty == 0 and icp_unavail_streak >= 2:
                    risk_suspected = True
                    logger.warning("reverse_lookup 多单位任务官方 ICP 源连续 %d 次失效且从未成功，"
                                   "疑似出口 IP 被风控 → 后续单位跳过官方源直连第三方（防继续触发风控）",
                                   icp_unavail_streak)
                found = _hunter_by_icp_name(u)
                src = "hunter_fallback"
        got_d, got_ip = found.get("domains", set()), found.get("ips", set())
        unit_fld_map: Dict[str, str] = {}      # 本单位 fld→unit 片段（供流式回调 + 归集归属）
        for d in got_d:
            seeds.add(d)                       # 原样作种子，不上溯根域（6a）
            fld = _main_domain(d)
            if fld and fld not in unit_map:     # fld→单位映射（四级目录归属，先到先得）
                unit_map[fld] = u
                unit_fld_map[fld] = u
        ip_seeds.update(got_ip)
        unit_status[u] = {"icp_official": "ok_icp", "hunter_fallback": "third_party",
                          "hunter_riskskip": "third_party"}.get(src, "third_party")
        logger.info("reverse_lookup unit=%s source=%s status=%s domains=%d ips=%d",
                    u, src, status, len(got_d), len(got_ip))
        # 流式外抛：本单位反查完即回调，供上层边反查边喂 recon（回调异常不打断反查）
        if cancel_check and cancel_check():
            cancelled = True
            break
        if on_unit is not None and (got_d or got_ip):
            try:
                on_unit(u, set(got_d), set(got_ip), unit_fld_map)
            except Exception as exc:
                callback_errors.append({"unit": u, "error": type(exc).__name__})
                logger.warning("reverse_lookup on_unit callback error unit=%s: %s", u, type(exc).__name__)
    return {"seeds": sorted(seeds), "ip_seeds": sorted(ip_seeds), "unit_map": unit_map,
            "unit_status": unit_status, "risk_suspected": risk_suspected,
            "cancelled": cancelled, "callback_errors": callback_errors}
