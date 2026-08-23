"""risk_intel/scan_result —— 扫描结果集合查询/删除（vuln / nuclei_result / npoc_service）。

引擎（sentinel_engine）产出的三类扫描结果集合，本叶子只做通用列表查询 + 按 _id 删除：
  - vuln          : 灯塔 PoC 插件扫描命中的漏洞
  - nuclei_result : nuclei 模板扫描命中
  - npoc_service  : 非 Web 服务（python NPoC）识别结果
补齐前端 `api/poc.ts` 的 vulnApi/nucleiResultApi/npocServiceApi（原有页无后端=孤岛；
`pages/risk/VulnCenter.vue` 三来源混排里对 poc/nuclei 单源删除走 /api/vuln/delete/、
/api/nuclei_result/delete/，此前未挂→按钮坏，本叶子修复）。

净室重写 routes/{vuln,nuclei_result,npoc_service}.py 的查询/删除，不 import app。
无 ROLE（核心路由暴露，registry 字符串键 `scan_result_service`，照 asset_search_service 先例）。
只依赖 core（get_repo + core.query.one_clause 复用列表口径），无第三方库。
**数据 API 规范**：list 返回 {page,size,total,items}。**禁止硬限制参数**：size 透传不设上限。
注：vuln_center(FINDING) 只读混排这些集合、不 owns 其 CRUD（其状态块明示），故本叶子不冲突。
"""
from __future__ import annotations

from typing import Any, Dict, List

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.core.query import one_clause
from sentinel_platform.contracts import Collections

logger = get_logger()

# 可查/可删的扫描结果集合白名单（防 namespace 注入）。npoc_service 仅列表（前端无删除入口）。
COLLECTIONS = {
    "vuln": Collections.VULN,
    "nuclei_result": Collections.NUCLEI_RESULT,
    "npoc_service": Collections.NPOC_SERVICE,
}
_SKIP_KEYS = {"page", "size", "order"}


def _to_oid(i: Any) -> Any:
    """字符串 id → bson.ObjectId（惰性、可选）。无 bson/非法 → 原值（对齐 asset/search）。"""
    try:
        from bson import ObjectId
        return ObjectId(i)
    except Exception:
        return i


def _coll_name(namespace: str) -> str:
    """namespace → 真实集合名（白名单校验）。非法返回空串（调用方拒绝）。"""
    return COLLECTIONS.get(namespace, "")


def _build_query(filters: Dict[str, Any]) -> Dict[str, Any]:
    """请求过滤参数转 Mongo 查询（复用 core.query.one_clause 保持列表口径一致）。"""
    q: Dict[str, Any] = {}
    for key, val in (filters or {}).items():
        if key in _SKIP_KEYS or val is None or val == "":
            continue
        if key == "_id":
            q["_id"] = _to_oid(val)
            continue
        q.update(one_clause(key, val))
    return q


def _page_size_order(args: Dict[str, Any]):
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
    special = ("_id", "save_date", "update_date")
    for d in docs:
        for k in special:
            if k in d:
                d[k] = str(d[k])
    return docs


def list_records(namespace: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """扫描结果集合分页查询。返回 {page,size,total,items}；非法集合返回 error。size 不设上限。"""
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
        return {"page": page, "size": size, "total": total, "items": _stringify(list(cur))}
    except Exception as exc:
        logger.debug("scan_result list %s failed: %s", namespace, exc)
        return {"page": page, "size": size, "total": 0, "items": []}


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
        logger.debug("scan_result delete %s failed: %s", namespace, exc)
        return {"error": str(exc)[:120], "deleted": 0}


# —— 门面（供 endpoints 经 registry 调，不 import 叶子内部）——
class ScanResultServiceImpl:
    """scan_result_service 门面。方法与模块函数一一对应。"""
    list_records = staticmethod(list_records)
    delete_by_ids = staticmethod(delete_by_ids)


_service = ScanResultServiceImpl()


def get_service() -> ScanResultServiceImpl:
    return _service
