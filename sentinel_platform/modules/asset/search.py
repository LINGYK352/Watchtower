"""asset/search —— 资产检索（8 侦察集合查询/去重/删除/导出/站点标签）。

domain/ip/site/url/cert/service/fileleak/wih 由 sentinel_engine 产出，本叶子只读查询 +
少量管理（删除/站点打标签）。净室重写 routes/{domain,ip,site,url,cert,service,fileleak,wih}.py
的查询/分页/去重/导出/标签逻辑，不 import app。

无 ROLE（对核心路由暴露能力，registry 字符串键 `asset_search_service`，照 api_keys 先例）。
只依赖 core（get_repo + core.query.one_clause 复用 REST→Mongo 运算符，保持与其它列表口径一致），
无第三方库（无需 vendor）。endpoints/asset.py 挂 /api/{集合}/*。

**数据 API 规范**：列表统一返回 {page,size,total,items}（对齐全平台分页信封）。
**禁止硬限制参数（铁律）**：size 按调用方请求取值，**不设上限、不砍**（历史踩坑：limit 硬上限
漏渗/漏查）；默认 size=10 仅为无参时缺省，非上限。order 默认 `-_id`（倒序）。
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.core.query import one_clause
from sentinel_platform.contracts import Collections

logger = get_logger()

# 可检索集合白名单（防 namespace 注入：只允许这些集合名）。
COLLECTIONS = {
    "domain": Collections.DOMAIN, "ip": Collections.IP, "site": Collections.SITE,
    "url": Collections.URL, "cert": Collections.CERT, "service": Collections.SERVICE,
    "fileleak": Collections.FILELEAK, "wih": Collections.WIH,
}
# 站点类集合（支持 dedup + 标签）：site 及资产组镜像 asset_site。
SITE_LIKE = {"site", "asset_site"}
_ASSET_SITE = "asset_site"

# 导出：每集合导出的代表字段（一值一行，去重）。ip 特殊（拼 ip:port）。
_EXPORT_FIELD = {
    "domain": "domain", "ip": "ip", "site": "site", "url": "url",
    "cert": "ip", "service": "service_name", "fileleak": "url", "wih": "content",
}
_SKIP_KEYS = {"page", "size", "order"}


def _to_oid(i: Any) -> Any:
    """字符串 id → bson.ObjectId（惰性、可选）。无 bson（Windows/离线单测）或非法 → 原值返回。
    对齐 core/db.py 惰性 pymongo 与 vuln_center 的 _oid：真实 Linux 部署 ObjectId 生效。"""
    try:
        from bson import ObjectId
        return ObjectId(i)
    except Exception:
        return i


def _coll_name(namespace: str) -> str:
    """namespace → 真实集合名（白名单校验）。非法返回空串（调用方拒绝）。"""
    if namespace in COLLECTIONS:
        return COLLECTIONS[namespace]
    if namespace == _ASSET_SITE:
        return _ASSET_SITE
    return ""


def _build_query(filters: Dict[str, Any]) -> Dict[str, Any]:
    """把请求过滤参数转 Mongo 查询。复用 core.query.one_clause 保持运算符口径一致
    （__dgt/__dlt/__neq/__not/__gt/__lt/正则/等值），_id 转 ObjectId，跳过分页字段。"""
    q: Dict[str, Any] = {}
    for key, val in (filters or {}).items():
        if key in _SKIP_KEYS or val is None or val == "":
            continue
        if key == "_id":
            q["_id"] = _to_oid(val)
            continue
        q.update(one_clause(key, val))
    return q


def _page_size_order(args: Dict[str, Any]) -> Tuple[int, int, str]:
    """解析分页/排序。size 无上限（禁止硬限制）；page/size 下限保护防非法值。"""
    try:
        page = max(1, int(args.get("page") or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        size = max(1, int(args.get("size") or 10))   # 无参默认 10；不设上限，按需取
    except (TypeError, ValueError):
        size = 10
    order = str(args.get("order") or "-_id")
    return page, size, order


def _stringify(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """_id/save_date/update_date 序列化为字符串（对齐 core.query.serialize_items）。"""
    special = ("_id", "save_date", "update_date")
    for d in docs:
        for k in special:
            if k in d:
                d[k] = str(d[k])
    return docs


def _annotate_shot_policy(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """给**无截图**的站点行标注其所属任务是否开了截图策略（options.site_capture）。

    治"资产检索无截图反复被误判为截图坏了"（真相多是策略默认未勾"站点截图"→截图阶段被门控跳过）：
    `_shot_off=True` → 该行任务**策略未开截图**，前端显"策略未截图"，与"截图失败/空白"区分开。
    只处理无 screenshot 的行；distinct task_id 一次 $in 批量查，避免逐行查库。任务查不到→不标注
    （保守退化为通用"无截图"）。"""
    pending = {str(it.get("task_id")) for it in items
               if not it.get("screenshot") and it.get("task_id")}
    if not pending:
        return items
    cap: Dict[str, bool] = {}
    try:
        oids = [_to_oid(t) for t in pending]
        for doc in get_repo().collection(Collections.TASK).find(
                {"_id": {"$in": oids}}, {"options.site_capture": 1}):
            cap[str(doc.get("_id"))] = bool((doc.get("options") or {}).get("site_capture"))
    except Exception as exc:
        logger.debug("annotate shot policy failed: %s", exc)
        return items
    for it in items:
        if it.get("screenshot"):
            continue
        if cap.get(str(it.get("task_id") or "")) is False:
            it["_shot_off"] = True   # 任务策略未开截图（非截图失败）
    return items


def list_records(namespace: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """集合分页查询。返回 {page,size,total,items}；非法集合返回 error。size 不设上限。"""
    coll_name = _coll_name(namespace)
    if not coll_name:
        return {"error": "unknown collection: {}".format(namespace),
                "page": 1, "size": 0, "total": 0, "items": []}
    page, size, order = _page_size_order(args)
    query = _build_query(args)
    try:
        coll = get_repo().collection(coll_name)
        total = coll.count_documents(query)
        direction = 1 if order.startswith("+") else -1
        field = order.lstrip("+-") or "_id"
        cur = coll.find(query).sort(field, direction).skip((page - 1) * size).limit(size)
        items = _stringify(list(cur))
        if namespace in SITE_LIKE:
            items = _annotate_shot_policy(items)   # 无截图行标注"策略未截图" vs 截图失败
        return {"page": page, "size": size, "total": total, "items": items}
    except Exception as exc:
        logger.debug("asset list %s failed: %s", namespace, exc)
        return {"page": page, "size": size, "total": 0, "items": []}


def _site_group_key(site_url: str) -> str:
    """站点归一 key：按 域名+端口（忽略 scheme/path）。默认端口 80/443 归到域名，
    非默认端口带端口。使 http/https、根路径/带 path、跨任务的同一站点归一组。"""
    s = (site_url or "").strip().lower()
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlsplit(s)
        host, port = p.hostname or "", p.port
    except Exception:
        return s
    if not host:
        return s
    return "{}:{}".format(host, port) if port and port not in (80, 443) else host


def list_dedup(namespace: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """站点按 域名+端口 去重展示。同站点多条折叠成一条（优先有 title、其次 http），
    代表行带 `_group_ids`（整组删用）+ `_group_count`。仅站点类集合有效。"""
    coll_name = _coll_name(namespace)
    if not coll_name or namespace not in SITE_LIKE:
        # 非站点集合无去重语义，退化为普通列表（不报错，前端通用组件安全）
        return list_records(namespace, args)
    page, size, _ = _page_size_order(args)
    query = _build_query(args)
    try:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for d in get_repo().collection(coll_name).find(query):
            d["_id"] = str(d["_id"])
            groups.setdefault(_site_group_key(d.get("site", "")), []).append(d)
    except Exception as exc:
        logger.debug("asset dedup %s failed: %s", namespace, exc)
        return {"page": page, "size": size, "total": 0, "items": []}

    def _pick(docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        titled = [x for x in docs if (x.get("title") or "").strip()]
        pool = titled or docs
        http_first = [x for x in pool if str(x.get("site", "")).lower().startswith("http://")]
        rep = dict((http_first or pool)[0])
        rep["_group_ids"] = [x["_id"] for x in docs]
        rep["_group_count"] = len(docs)
        return rep

    reps = [_pick(v) for v in groups.values()]
    reps.sort(key=lambda x: x.get("_id", ""), reverse=True)
    total = len(reps)
    items = _annotate_shot_policy(_stringify(reps[(page - 1) * size: page * size]))
    return {"page": page, "size": size, "total": total, "items": items}


def delete_by_ids(namespace: str, ids: List[str]) -> Dict[str, Any]:
    """按 _id 批量删除。返回 {deleted:N}；非法集合/空 ids 返回 error。"""
    coll_name = _coll_name(namespace)
    if not coll_name:
        return {"error": "unknown collection", "deleted": 0}
    if not isinstance(ids, list) or not ids:
        return {"error": "_id 必填(非空数组)", "deleted": 0}
    try:
        oids = [_to_oid(i) for i in ids]
        res = get_repo().collection(coll_name).delete_many({"_id": {"$in": oids}})
        return {"deleted": getattr(res, "deleted_count", 0)}
    except Exception as exc:
        logger.debug("asset delete %s failed: %s", namespace, exc)
        return {"error": str(exc)[:120], "deleted": 0}


def _update_tag(namespace: str, _id: str, tag: str, add: bool) -> Dict[str, Any]:
    coll_name = _coll_name(namespace)
    if not coll_name or namespace not in SITE_LIKE:
        return {"error": "标签仅站点类集合支持"}
    tag = (tag or "").strip()
    if not _id or not tag:
        return {"error": "_id 与 tag 必填"}
    try:
        oid = _to_oid(_id)
        coll = get_repo().collection(coll_name)
        doc = coll.find_one({"_id": oid})
        if not doc:
            return {"error": "站点不存在"}
        old = doc.get("tag")
        tags = ([old] if isinstance(old, str) else list(old)) if old else []
        if add:
            if tag in tags:
                return {"error": "标签已存在", "tag": tag}
            tags.append(tag)
        else:
            if tag not in tags:
                return {"error": "标签不存在", "tag": tag}
            tags.remove(tag)
        coll.update_one({"_id": oid}, {"$set": {"tag": tags}})
        return {"ok": True, "tag": tag, "tags": tags}
    except Exception as exc:
        logger.debug("asset tag %s failed: %s", namespace, exc)
        return {"error": str(exc)[:120]}


def add_tag(namespace: str, _id: str, tag: str) -> Dict[str, Any]:
    """给站点加标签（site/asset_site）。返回 {ok,tag,tags} 或 {error}。"""
    return _update_tag(namespace, _id, tag, add=True)


def delete_tag(namespace: str, _id: str, tag: str) -> Dict[str, Any]:
    """删站点标签。返回 {ok,tag,tags} 或 {error}。"""
    return _update_tag(namespace, _id, tag, add=False)


def export_values(namespace: str, args: Dict[str, Any]) -> Tuple[str, str]:
    """导出集合代表字段（一值一行，去重）。返回 (文本, 建议文件名)。

    **不设条数上限**（禁止硬限制）：按当前过滤条件全量导出该集合代表字段。
    """
    import time
    coll_name = _coll_name(namespace)
    if not coll_name:
        return "", "invalid.txt"
    field = _EXPORT_FIELD.get(namespace, "")
    query = _build_query(args)
    values = set()
    try:
        cur = get_repo().collection(coll_name).find(query)   # 全量，不 limit
        for item in cur:
            if not field or field not in item:
                continue
            if namespace == "ip":
                ip = item.get("ip", "")
                ports = item.get("port_info", []) or []
                if ports:
                    for pi in ports:
                        values.add("{}:{}".format(ip, pi.get("port_id", "")))
                elif ip:
                    values.add(ip)
            else:
                v = item[field]
                if isinstance(v, list):
                    values.update(str(x) for x in v)
                elif v:
                    values.add(str(v))
    except Exception as exc:
        logger.debug("asset export %s failed: %s", namespace, exc)
    text = "\r\n".join(sorted(values))
    filename = "{}_{}_{}.txt".format(namespace, len(values), int(time.time()))
    return text, filename


# —— 门面（供 endpoints 经 registry 调，不 import 叶子内部）——
class AssetSearchServiceImpl:
    """asset_search_service 门面。方法与模块函数一一对应。"""
    list_records = staticmethod(list_records)
    list_dedup = staticmethod(list_dedup)
    delete_by_ids = staticmethod(delete_by_ids)
    add_tag = staticmethod(add_tag)
    delete_tag = staticmethod(delete_tag)
    export_values = staticmethod(export_values)


_service = AssetSearchServiceImpl()


def get_service() -> AssetSearchServiceImpl:
    return _service
