"""system/_pool —— 公开抓取代理池（proxy 叶子的 phase-2 辅助，独立维护不进 mihomo）。

从 FOFA/Hunter 测绘平台搜公网开放代理 → 验活打分 → 供"攻击/扫描出口"选「公开抓取」源时取延时
最低的代理。与机场订阅（走 mihomo）是两套独立选择域，互不混（见 proxy 双轨）。

**安全边界（硬约束，守记忆铁律）**：免费代理=不可信中间人，只用于打目标的 HTTP 请求轨（轮换 IP
防 WAF 封），**绝不用于 LLM 访问轨**（轨一永远直连/机场，不碰本池）。

集合 proxy_pool：`{type(http/socks5),host,port,url,source(fofa/hunter/manual),country,delay(ms,-1失败,
None未验),fail_streak,enabled,last_check,exit_ip,save_date}`，去重键 type+host+port。
配置 proxy_pool_config：抓取 queries + limit。

**自包含**（system 类别叶子，不 import 别的叶子）：FOFA/Hunter 查询直接用 core.http + get_config
读 key（不跨类别 import kernel/ext_source）；socks5 验活用 requests+PySocks（缺失优雅降级标不可验）。
**禁硬限制**：list size 透传；limit 是每查询入池上限（用户可配，非结果硬顶）。经字符串键
`proxy_pool_service` 注册，endpoints/proxy.py 的 pool/* 调（proxy 作者注释已交接"落 system/_pool.py"）。
"""
from __future__ import annotations

import base64
import re
import time
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_config, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

COLL = Collections.PROXY_POOL


def _apikey(key_id: str, field: str = "key") -> str:
    """从统一 API 密钥中心（`api_keys` 集合 default 文档）取密钥字段（仅 enabled 时返值）。
    治「明明配了 apikey 却报未配置」：密钥中心是运行时唯一密钥源，消费方须优先读它再回退 config。
    直接读集合（数据访问，非跨叶子 import），同 notify 范式。"""
    try:
        doc = get_repo().collection(Collections.API_KEYS).find_one({"name": "default"}) or {}
        sub = doc.get(key_id) or {}
        if sub.get("enabled") and sub.get(field):
            return str(sub[field]).strip()
    except Exception as exc:
        logger.debug("pool read api_keys %s.%s failed: %s", key_id, field, exc)
    return ""
CONFIG_COLL = Collections.PROXY_POOL_CONFIG

_VERIFY_TIMEOUT = 10
_FAIL_DROP_THRESHOLD = 3
_PICK_CACHE_TTL = 15
_VERIFY_EXIT_URLS = [
    "http://myip.ipip.net/s", "http://members.3322.org/dyndns/getip",
    "http://ip.3322.net", "https://api.ipify.org",
]
_PICK_CACHE = {"url": "", "ts": 0.0}


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _coll():
    return get_repo().collection(COLL)


def _oid(v: Any):
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v
    except Exception:
        return v          # 非法 ObjectId 回退原值（对齐平台约定；生产真 ObjectId 库对字符串查不到，效果一致）


def _fetch_ip(proxies: Optional[Dict[str, str]], timeout: int = _VERIFY_TIMEOUT):
    """经代理请求出口 IP（国内端点优先）→ (ip, err)。proxies=None 直连。socks5 缺 PySocks→降级 err。"""
    import requests
    last = ""
    for url in _VERIFY_EXIT_URLS:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False, verify=False)
            if r.status_code < 400:
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r.text or "")
                if m:
                    return m.group(1), ""
                last = "no ip from {}".format(url)
            else:
                last = "status {} @ {}".format(r.status_code, url)
        except Exception as e:                       # 含 socks5 缺 PySocks 的 InvalidSchema
            last = str(e)[:120]
    return "", last


# —— 配置 ——
def default_config() -> Dict[str, Any]:
    return {
        "name": "default",
        "queries": [
            {"source": "fofa", "type": "socks5", "q": 'protocol="socks5"', "enabled": True},
            {"source": "hunter", "type": "socks5", "q": 'protocol=="socks5"', "enabled": False},
        ],
        "limit": 100, "updated_at": _now(),
    }


def get_config_pool() -> Dict[str, Any]:
    try:
        doc = get_repo().collection(CONFIG_COLL).find_one({"name": "default"})
        if not doc:
            doc = default_config()
            get_repo().collection(CONFIG_COLL).insert_one(dict(doc))
        doc["_id"] = str(doc.get("_id", ""))
        return doc
    except Exception as e:
        logger.debug("pool get_config failed: %s", e)
        return default_config()


def save_config_pool(data: Dict[str, Any]) -> Dict[str, Any]:
    update: Dict[str, Any] = {}
    if isinstance(data.get("queries"), list):
        clean = []
        for q in data["queries"]:
            src = (q.get("source") or "").lower()
            typ = (q.get("type") or "").lower()
            if src in ("fofa", "hunter") and typ in ("socks5", "http"):
                clean.append({"source": src, "type": typ, "q": (q.get("q") or "").strip(),
                              "enabled": bool(q.get("enabled", True))})
        update["queries"] = clean
    if "limit" in data:
        try:
            update["limit"] = max(0, int(data["limit"]))    # 0=不限；正数为用户期望总量
        except (TypeError, ValueError):
            pass
    update["updated_at"] = _now()
    try:
        get_repo().collection(CONFIG_COLL).update_one({"name": "default"}, {"$set": update}, upsert=True)
    except Exception as e:
        logger.debug("pool save_config failed: %s", e)
    return get_config_pool()


# —— 入池 + 抓取（FOFA/Hunter 自包含 HTTP，不跨类别）——
def _upsert_one(ptype: str, host: str, port: Any, source: str, country: str = "") -> bool:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    host = (host or "").strip()
    if not host or port <= 0 or port > 65535:
        return False
    coll = _coll()
    if coll.find_one({"type": ptype, "host": host, "port": port}):
        return False
    coll.insert_one({
        "type": ptype, "host": host, "port": port, "url": "{}://{}:{}".format(ptype, host, port),
        "source": source, "country": (country or "").strip(), "delay": None,
        "fail_streak": 0, "enabled": True, "last_check": "", "exit_ip": "", "save_date": _now(),
    })
    return True


def _crawl_fofa(query: str, ptype: str, limit: int):
    """FOFA 搜代理。2000 只是单页容量；按用户 limit 翻页，0=到源端结束。"""
    cfg = get_config()
    email = cfg.section("FOFA", "EMAIL", default="") or cfg.section("FOFA", "email", default="")
    key = _apikey("fofa") or cfg.section("FOFA", "KEY", default="") or cfg.section("FOFA", "key", default="")
    if not key:
        return 0, "fofa key 未配置"
    import requests
    try:
        qb64 = base64.b64encode(query.encode()).decode()
        added = fetched = 0
        page = 1
        while limit <= 0 or fetched < limit:
            page_size = 2000 if limit <= 0 else min(2000, limit - fetched)
            params = {"key": key, "qbase64": qb64, "fields": "ip,port,country_name",
                      "page": page, "size": page_size}
            if email:
                params["email"] = email
            r = requests.get("https://fofa.info/api/v1/search/all", params=params, timeout=(10, 30), verify=True)
            data = r.json()
            if data.get("error"):
                return added, str(data.get("errmsg", "fofa error"))[:120]
            rows = data.get("results") or []
            for row in rows:
                fetched += 1
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    country = row[2] if len(row) > 2 else ""
                    if _upsert_one(ptype, str(row[0]), row[1], "fofa", country):
                        added += 1
            if len(rows) < page_size:
                break
            page += 1
        return added, ""
    except Exception as e:
        return 0, str(e)[:120]


def _crawl_hunter(query: str, ptype: str, limit: int):
    """Hunter 搜代理。100 只是单页容量；按用户 limit 翻页，0=到源端结束。"""
    cfg = get_config()
    key = _apikey("hunter") or cfg.section("HUNTER", "KEY", default="") or cfg.section("HUNTER", "key", default="")
    if not key:
        return 0, "hunter key 未配置"
    import requests
    try:
        qb64 = base64.urlsafe_b64encode(query.encode()).decode()
        added = fetched = 0
        page = 1
        while limit <= 0 or fetched < limit:
            page_size = 100 if limit <= 0 else min(100, limit - fetched)
            params = {"api-key": key, "search": qb64, "page": page,
                      "page_size": page_size, "is_web": 3}
            r = requests.get("https://hunter.qianxin.com/openApi/search", params=params,
                             timeout=(10, 20), verify=True)
            data = r.json()
            if data.get("code") != 200:
                return added, "hunter code={} {}".format(data.get("code"), str(data.get("message", ""))[:80])
            rows = ((data.get("data") or {}).get("arr") or [])
            for item in rows:
                fetched += 1
                ip = (item.get("ip") or "").strip()
                if ip and item.get("port") and _upsert_one(ptype, ip, item["port"], "hunter",
                                                            (item.get("country") or "").strip()):
                    added += 1
            if len(rows) < page_size:
                break
            page += 1
        return added, ""
    except Exception as e:
        return 0, str(e)[:120]


def crawl() -> Dict[str, Any]:
    """按配置抓取代理入池。返回 {added, per_query, errors}。"""
    cfg = get_config_pool()
    limit = cfg.get("limit", 100)
    total, per_query, errors = 0, [], []
    for q in cfg.get("queries", []):
        if not q.get("enabled") or not q.get("q"):
            continue
        src, typ, query = q["source"], q["type"], q["q"]
        n, err = (_crawl_fofa if src == "fofa" else _crawl_hunter)(query, typ, limit) \
            if src in ("fofa", "hunter") else (0, "unknown source")
        total += n
        per_query.append({"source": src, "type": typ, "q": query, "added": n})
        if err:
            errors.append({"source": src, "q": query, "error": err})
    logger.info("proxy_pool crawl: added=%d errors=%d", total, len(errors))
    return {"added": total, "per_query": per_query, "errors": errors}


# —— 验活 / 选优 ——
def _verify_one(doc: Dict[str, Any], direct_ip: str):
    """验活单条：经该代理请求出口 IP，拿到 IP 且 ≠ 直连=可用记延时；失败累计达阈值剔除。"""
    coll = _coll()
    url = doc["url"]
    proxies = {"http": url, "https": url}
    t0 = time.time()
    ip, _err = _fetch_ip(proxies, timeout=_VERIFY_TIMEOUT)
    delay = int((time.time() - t0) * 1000)
    ok = bool(ip) and (not direct_ip or ip != direct_ip)
    if ok:
        coll.update_one({"_id": doc["_id"]}, {"$set": {
            "delay": delay, "fail_streak": 0, "last_check": _now(), "exit_ip": ip}})
        return True
    fs = int(doc.get("fail_streak", 0)) + 1
    if fs >= _FAIL_DROP_THRESHOLD:
        coll.delete_one({"_id": doc["_id"]})
        return False
    coll.update_one({"_id": doc["_id"]}, {"$set": {"delay": -1, "fail_streak": fs, "last_check": _now()}})
    return False


def verify(ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """验活（ids=None 验全部）。并发线程池（免费代理慢，串行会超时）。返回 {checked,alive,dropped}。"""
    from concurrent.futures import ThreadPoolExecutor
    coll = _coll()
    try:
        if ids:
            oids = [o for o in (_oid(i) for i in ids) if o is not None]
            docs = list(coll.find({"_id": {"$in": oids}}))
        else:
            docs = list(coll.find({}))
    except Exception as e:
        logger.debug("pool verify query failed: %s", e)
        return {"checked": 0, "alive": 0, "dropped": 0}
    if not docs:
        return {"checked": 0, "alive": 0, "dropped": 0}
    direct_ip, _ = _fetch_ip(None)                   # 直连基准
    before = len(docs)
    ids_all = [d["_id"] for d in docs]
    with ThreadPoolExecutor(max_workers=min(20, before)) as ex:   # 并发上限按需，非硬顶
        results = list(ex.map(lambda d: _verify_one(d, direct_ip), docs))
    alive = sum(1 for ok in results if ok)
    after = coll.count_documents({"_id": {"$in": ids_all}})
    _PICK_CACHE["ts"] = 0.0
    return {"checked": before, "alive": alive, "dropped": before - after}


def pick_best(use_cache: bool = True) -> str:
    """取延时最低可用代理 URL（enabled 且 delay≥0）。无则 ""。15s 缓存。"""
    now = time.time()
    if use_cache and _PICK_CACHE["url"] and (now - _PICK_CACHE["ts"] < _PICK_CACHE_TTL):
        return _PICK_CACHE["url"]
    try:
        doc = _coll().find_one({"enabled": True, "delay": {"$gte": 0}}, sort=[("delay", 1)])
    except Exception:
        doc = None
    url = doc["url"] if doc else ""
    _PICK_CACHE.update(url=url, ts=now)
    return url


# —— 列表 / 启停 / 删除 / 手动添加 / 统计 ——
def list_proxies(page: int = 1, size: int = 50, status: str = "") -> Dict[str, Any]:
    """分页列表。status: alive/dead/unchecked/空=全部。size 透传（禁硬限制）。"""
    try:
        page = max(1, int(page or 1))
        size = max(1, int(size or 50))
    except (TypeError, ValueError):
        page, size = 1, 50
    q: Dict[str, Any] = {}
    if status == "alive":
        q = {"delay": {"$gte": 0}}
    elif status == "dead":
        q = {"delay": -1}
    elif status == "unchecked":
        q = {"delay": None}
    try:
        coll = _coll()
        total = coll.count_documents(q)
        items = []
        for d in coll.find(q).sort([("delay", 1)]).skip((page - 1) * size).limit(size):
            d["_id"] = str(d["_id"])
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as e:
        logger.debug("pool list failed: %s", e)
        return {"items": [], "total": 0, "page": page, "size": size}


def set_enabled(ids: List[str], enabled: bool) -> Dict[str, Any]:
    oids = [o for o in (_oid(i) for i in (ids or [])) if o is not None]
    if not oids:
        return {"modified": 0}
    try:
        r = _coll().update_many({"_id": {"$in": oids}}, {"$set": {"enabled": bool(enabled)}})
        _PICK_CACHE["ts"] = 0.0
        return {"modified": r.modified_count}
    except Exception as e:
        logger.debug("pool set_enabled failed: %s", e)
        return {"modified": 0}


def delete_proxies(ids: List[str]) -> Dict[str, Any]:
    oids = [o for o in (_oid(i) for i in (ids or [])) if o is not None]
    if not oids:
        return {"deleted": 0}
    try:
        r = _coll().delete_many({"_id": {"$in": oids}})
        _PICK_CACHE["ts"] = 0.0
        return {"deleted": r.deleted_count}
    except Exception as e:
        logger.debug("pool delete failed: %s", e)
        return {"deleted": 0}


def add_manual(ptype: str, host: str, port: Any) -> Dict[str, Any]:
    ptype = (ptype or "").lower()
    if ptype not in ("http", "socks5"):
        return {"ok": False, "error": "type 须 http/socks5", "added": 0}
    ok = _upsert_one(ptype, (host or "").strip(), port, "manual")
    return {"ok": True, "added": 1 if ok else 0, "dup": not ok}


def stats() -> Dict[str, Any]:
    try:
        coll = _coll()
        return {
            "total": coll.count_documents({}), "alive": coll.count_documents({"delay": {"$gte": 0}}),
            "dead": coll.count_documents({"delay": -1}), "unchecked": coll.count_documents({"delay": None}),
            "enabled": coll.count_documents({"enabled": True}),
        }
    except Exception:
        return {"total": 0, "alive": 0, "dead": 0, "unchecked": 0, "enabled": 0}


class ProxyPoolServiceImpl:
    """公开代理池能力（无 ROLE，字符串键 proxy_pool_service）。endpoints/proxy.py 的 pool/* 调本门面。"""
    def list(self, page=1, size=50, status=""): return list_proxies(page, size, status)
    def stats(self): return stats()
    def crawl(self): return crawl()
    def verify(self, ids=None): return verify(ids)
    def enable(self, ids, enabled): return set_enabled(ids, enabled)
    def delete(self, ids): return delete_proxies(ids)
    def add(self, ptype, host, port): return add_manual(ptype, host, port)
    def get_config(self): return get_config_pool()
    def save_config(self, data): return save_config_pool(data)
    def pick_best(self): return pick_best()


_service = ProxyPoolServiceImpl()


def get_service() -> ProxyPoolServiceImpl:
    return _service


