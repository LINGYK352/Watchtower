"""asset/groups —— 资产分组（资产组 scope + 组内 domain/ip/site/wih + 任务结果同步）。

资产组 = 一个持续监控的资产范围（asset_scope），组内沉淀 asset_domain/asset_ip/asset_site/asset_wih。
对应前端 pages/assets/AssetGroupList.vue + AssetGroupDetail.vue（独立可跑，不孤岛）。

对外（供 router endpoints/asset_groups.py + 未来 task_list 经 registry 取）：
  资产组：list_scopes / add_scope_group / delete_scope_groups(级联) / add_scope_range / delete_scope_range
  组内资产：list_assets / delete_assets / add_asset / export_assets（domain/ip/site/wih）
  站点标签：add_site_tag / delete_site_tag
  同步：sync_task_to_scope(task_id, scope_id)（任务结果 → 资产库；供 task_list 的 /api/task/sync 调）

注册：字符串键 `"asset_group_service"`（照 api_keys 先例，不进冻结 ROLE）。端点 endpoints/asset_groups.py。
迁移来源：routes/assetScope + assetDomain/IP/Site/Wih + syncAsset。**净室**：域名/IP 校验用 stdlib re+ipaddress
自实现（不 import ARL utils）。依赖：仅 stdlib（re/ipaddress）+ bson(guard 兜底)。**无新增 vendor，默认本地库**。
不放 HTTP 路由。**禁硬限制参数**：list size 透传不砍上限、export 全量不 limit。
"""
from __future__ import annotations

import re
import ipaddress
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

# 组内资产集合（asset_ 前缀，区别于 search 叶子的原始侦察集合）+ 各自展示字段。
_ASSET_COLLS = {
    "asset_domain": Collections.ASSET_DOMAIN,
    "asset_ip": Collections.ASSET_IP,
    "asset_site": Collections.ASSET_SITE,
    "asset_wih": Collections.ASSET_WIH,
}
# 级联删除：删资产组时连带清这些集合里 scope_id 匹配的资产。
_CASCADE_COLLS = ("asset_domain", "asset_ip", "asset_site", "asset_wih", "scheduler")

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+\.?$")

def _oid(_id: str):
    """字符串 _id → ObjectId（生产）；bson 缺失/非法（测试/普通键）原样返回，兼容两态。"""
    try:
        from bson import ObjectId
        return ObjectId(_id)
    except Exception:
        return _id


def is_valid_domain(s: str) -> bool:
    """轻量域名校验（净室，不 import ARL）。"""
    return bool(_DOMAIN_RE.match((s or "").strip()))


def normalize_ip_scope(s: str) -> Optional[str]:
    """规整 IP 范围：单 IP / CIDR / a-b 段 → 标准串；非法返回 None（净室，用 stdlib ipaddress）。"""
    s = (s or "").strip()
    if not s:
        return None
    try:
        if "/" in s:
            return str(ipaddress.ip_network(s, strict=False))
        if "-" in s:  # a.b.c.d-e 或 a.b.c.d-a.b.c.e
            left, right = s.split("-", 1)
            ipaddress.ip_address(left.strip())
            r = right.strip()
            ipaddress.ip_address(r if "." in r else left.rsplit(".", 1)[0] + "." + r)
            return s
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _split(raw: str) -> List[str]:
    return [x for x in re.split(r"[,\s]+", raw or "") if x]


# ========== 资产组（asset_scope）==========

def _scope_coll():
    return get_repo().collection(Collections.ASSET_SCOPE)


def list_scopes(page: int = 1, size: int = 10, **filters: Any) -> Dict[str, Any]:
    """资产组列表（分页）。**禁硬限制**：size<=0 返全量，无 min 硬顶。"""
    q: Dict[str, Any] = {}
    if filters.get("name"):
        q["name"] = {"$regex": re.escape(filters["name"]), "$options": "i"}
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 10
    try:
        coll = _scope_coll()
        total = coll.count_documents(q)
        cur = coll.find(q).sort("_id", -1)
        if size and size > 0:
            cur = cur.skip((page - 1) * size).limit(size)
        items = []
        for d in cur:
            d["_id"] = str(d.get("_id", ""))
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        logger.debug("list_scopes degraded: %s", exc)
        return {"items": [], "total": 0, "page": page, "size": size}


def add_scope_group(data: Dict[str, Any]) -> Dict[str, Any]:
    """新建资产组。scope_type ip/domain（默认 domain），逐条校验范围。返回 {scope_id,...} 或 {error}。"""
    data = data or {}
    name = (data.get("name") or "").strip()
    scope_type = (data.get("scope_type") or "domain").strip().lower()
    if scope_type not in ("ip", "domain"):
        scope_type = "domain"
    new_scope: List[str] = []
    for x in _split(data.get("scope", "")):
        if scope_type == "domain":
            if not is_valid_domain(x):
                return {"error": "非法域名: {}".format(x)}
            new_scope.append(x)
        else:
            n = normalize_ip_scope(x)
            if n is None:
                return {"error": "非法 IP 范围: {}".format(x)}
            new_scope.append(n)
    if not new_scope:
        return {"error": "scope 不能为空或全部非法"}
    doc = {
        "name": name, "scope_type": scope_type,
        "scope": ",".join(new_scope), "scope_array": new_scope,
        "black_scope": data.get("black_scope", "") or "",
        "black_scope_array": _split(data.get("black_scope", "")),
    }
    try:
        res = _scope_coll().insert_one(doc)
        return {"scope_id": str(res.inserted_id), "name": name, "scope": doc["scope"]}
    except Exception as exc:
        return {"error": "保存失败: {}".format(exc)}


def delete_scope_groups(scope_ids: List[str]) -> Dict[str, Any]:
    """删除资产组 + 级联清组内资产（asset_domain/ip/site/wih + scheduler）。"""
    deleted = 0
    try:
        repo = get_repo()
        for sid in (scope_ids or []):
            repo.collection(Collections.ASSET_SCOPE).delete_one({"_id": _oid(sid)})
            deleted += 1
            for name in _CASCADE_COLLS:
                try:
                    repo.collection(name).delete_many({"scope_id": sid})
                except Exception:
                    continue
    except Exception as exc:
        return {"error": str(exc), "deleted": deleted}
    return {"deleted": deleted, "scope_id": scope_ids}


def add_scope_range(scope_id: str, scope: str) -> Dict[str, Any]:
    """向资产组追加范围段（按组 scope_type 校验，去重）。"""
    try:
        doc = _scope_coll().find_one({"_id": _oid(scope_id)})
    except Exception as exc:
        return {"error": str(exc)}
    if not doc:
        return {"error": "资产组不存在: {}".format(scope_id)}
    scope_type = doc.get("scope_type", "domain")
    arr = doc.get("scope_array", []) or []
    for x in _split(scope):
        val = x
        if scope_type == "domain":
            if not is_valid_domain(x):
                return {"error": "非法域名: {}".format(x)}
        else:
            val = normalize_ip_scope(x)
            if val is None:
                return {"error": "非法 IP 范围: {}".format(x)}
        if val not in arr:
            arr.append(val)
    try:
        _scope_coll().update_one({"_id": _oid(scope_id)},
                                 {"$set": {"scope_array": arr, "scope": ",".join(arr)}})
    except Exception as exc:
        return {"error": str(exc)}
    return {"scope_id": scope_id, "scope": ",".join(arr)}


def delete_scope_range(scope_id: str, scope: str) -> Dict[str, Any]:
    """从资产组删除单条范围段。"""
    try:
        doc = _scope_coll().find_one({"_id": _oid(scope_id)})
    except Exception as exc:
        return {"error": str(exc)}
    if not doc:
        return {"error": "资产组不存在: {}".format(scope_id)}
    arr = doc.get("scope_array", []) or []
    s = (scope or "").strip()
    if s not in arr:
        return {"error": "范围不存在: {}".format(s)}
    arr.remove(s)
    try:
        _scope_coll().update_one({"_id": _oid(scope_id)},
                                 {"$set": {"scope_array": arr, "scope": ",".join(arr)}})
    except Exception as exc:
        return {"error": str(exc)}
    return {"scope_id": scope_id, "scope": s}


# ========== 组内资产（asset_domain/ip/site/wih）==========

def _asset_coll_name(collection: str) -> Optional[str]:
    """校验并返回合法的组内资产集合名（防注入任意集合）。"""
    return _ASSET_COLLS.get(collection)


def list_assets(collection: str, page: int = 1, size: int = 10, **filters: Any) -> Dict[str, Any]:
    """组内资产列表（分页 + scope_id/关键字过滤）。**禁硬限制**：size<=0 返全量。"""
    name = _asset_coll_name(collection)
    if not name:
        return {"items": [], "total": 0, "page": 1, "size": size, "error": "未知集合"}
    q: Dict[str, Any] = {}
    if filters.get("scope_id"):
        q["scope_id"] = filters["scope_id"]
    for f in ("domain", "ip", "site"):
        if filters.get(f):
            q[f] = {"$regex": re.escape(filters[f]), "$options": "i"}
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 10
    try:
        coll = get_repo().collection(name)
        total = coll.count_documents(q)
        cur = coll.find(q).sort("_id", -1)
        if size and size > 0:
            cur = cur.skip((page - 1) * size).limit(size)
        items = []
        for d in cur:
            d["_id"] = str(d.get("_id", ""))
            items.append(d)
        return {"items": items, "total": total, "page": page, "size": size}
    except Exception as exc:
        logger.debug("list_assets degraded: %s", exc)
        return {"items": [], "total": 0, "page": page, "size": size}


def delete_assets(collection: str, ids: List[str]) -> Dict[str, Any]:
    """按 _id 删组内资产。"""
    name = _asset_coll_name(collection)
    if not name:
        return {"error": "未知集合", "deleted": 0}
    n = 0
    try:
        coll = get_repo().collection(name)
        for _id in (ids or []):
            try:
                n += coll.delete_one({"_id": _oid(_id)}).deleted_count
            except Exception:
                continue
    except Exception as exc:
        return {"error": str(exc), "deleted": n}
    return {"deleted": n}


def add_asset(collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """手动加一条组内资产（asset_domain/asset_site）。需 scope_id + 主字段。"""
    name = _asset_coll_name(collection)
    if not name:
        return {"error": "未知集合"}
    data = data or {}
    scope_id = (data.get("scope_id") or "").strip()
    if not scope_id:
        return {"error": "scope_id 必填"}
    key = "domain" if collection == "asset_domain" else ("site" if collection == "asset_site" else None)
    if not key or not (data.get(key) or "").strip():
        return {"error": "{} 必填".format(key or "主字段")}
    doc = {"scope_id": scope_id, key: data[key].strip()}
    if data.get("policy_id"):
        doc["policy_id"] = str(data["policy_id"]).strip()
    try:
        res = get_repo().collection(name).insert_one(doc)
        return {"_id": str(res.inserted_id)}
    except Exception as exc:
        return {"error": "保存失败: {}".format(exc)}


def export_assets(collection: str, **filters: Any) -> List[Dict[str, Any]]:
    """导出组内资产（全量，**禁硬限制不 limit**）。返回全部匹配行。"""
    r = list_assets(collection, page=1, size=0, **filters)   # size=0 → 全量
    return r.get("items", [])


def _site_tag(collection: str, _id: str, tag: str, add: bool) -> Dict[str, Any]:
    name = _asset_coll_name(collection) if collection.startswith("asset_") else (
        Collections.SITE if collection == "site" else None)
    if not name:
        return {"error": "未知集合"}
    tag = (tag or "").strip()
    if not tag:
        return {"error": "tag 必填"}
    op = {"$addToSet": {"tag": tag}} if add else {"$pull": {"tag": tag}}
    try:
        get_repo().collection(name).update_one({"_id": _oid(_id)}, op)
        return {"_id": _id, "tag": tag}
    except Exception as exc:
        return {"error": str(exc)}


def add_site_tag(collection: str, _id: str, tag: str) -> Dict[str, Any]:
    return _site_tag(collection, _id, tag, add=True)


def delete_site_tag(collection: str, _id: str, tag: str) -> Dict[str, Any]:
    return _site_tag(collection, _id, tag, add=False)


# ========== 任务结果同步进资产库（供 task_list 的 /api/task/sync 调）==========

def sync_task_to_scope(task_id: str, scope_id: str) -> Dict[str, Any]:
    """把某任务的 domain/ip/site 侦察结果同步进资产库（打 scope_id 标）。幂等：按主键 upsert。
    供 task_list 的 sync 端点调（本能力属 groups，路由归 task_list）。任务/资产集合缺失降级计数 0。"""
    if not task_id or not scope_id:
        return {"error": "task_id / scope_id 必填"}
    mapping = [(Collections.DOMAIN, Collections.ASSET_DOMAIN, "domain"),
               (Collections.IP, Collections.ASSET_IP, "ip"),
               (Collections.SITE, Collections.ASSET_SITE, "site")]
    synced = {"domain": 0, "ip": 0, "site": 0}
    try:
        repo = get_repo()
        for src, dst, key in mapping:
            for d in repo.collection(src).find({"task_id": task_id}):
                val = d.get(key)
                if not val:
                    continue
                doc = dict(d)
                doc.pop("_id", None)
                doc["scope_id"] = scope_id
                repo.collection(dst).update_one(
                    {"scope_id": scope_id, key: val}, {"$set": doc}, upsert=True)
                synced[key] += 1
    except Exception as exc:
        logger.debug("sync_task_to_scope degraded: %s", exc)
        return {"error": str(exc), "synced": synced}
    return {"ok": True, "synced": synced, "scope_id": scope_id}


class AssetGroupServiceImpl:
    """资产分组服务。注册字符串键 "asset_group_service"。"""
    def list_scopes(self, **kw): return list_scopes(**kw)
    def add_scope_group(self, data): return add_scope_group(data)
    def delete_scope_groups(self, scope_ids): return delete_scope_groups(scope_ids)
    def add_scope_range(self, scope_id, scope): return add_scope_range(scope_id, scope)
    def delete_scope_range(self, scope_id, scope): return delete_scope_range(scope_id, scope)
    def list_assets(self, collection, **kw): return list_assets(collection, **kw)
    def delete_assets(self, collection, ids): return delete_assets(collection, ids)
    def add_asset(self, collection, data): return add_asset(collection, data)
    def export_assets(self, collection, **kw): return export_assets(collection, **kw)
    def add_site_tag(self, collection, _id, tag): return add_site_tag(collection, _id, tag)
    def delete_site_tag(self, collection, _id, tag): return delete_site_tag(collection, _id, tag)
    def sync_task_to_scope(self, task_id, scope_id): return sync_task_to_scope(task_id, scope_id)


_service = AssetGroupServiceImpl()


def get_service() -> AssetGroupServiceImpl:
    return _service


