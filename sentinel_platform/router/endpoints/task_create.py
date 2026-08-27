"""task_create 端点 —— 新建任务下发对外 REST（挂 /api/task/policy/ + /api/task_fofa/*）。

**独立成文件的原因**：`endpoints/task_plan.py`(policy)、`endpoints/task_list.py`(list/生命周期) 已被占。
为零撞车，下发端点单独成文件。两 Namespace：
  - `task_create`（path `/task`）→ `/api/task/policy/`（与 task_list 的 `/task` 同 path 不同路由，无冲突）
  - `task_fofa`（path `/task_fofa`）→ `/api/task_fofa/{test,submit,submit_by_unit}`
对齐前端 `frontend/src/api/task.ts` taskApi.policy + taskFofaApi.test/submit/submitByUnit + `pages/tasks/TaskCreate.vue`。

范式：经 `get_registry().get("task_create_service")` 调叶子门面（不 import 叶子内部）。
**FOFA 查询 / 单位反查在端点层经 kernel/ext_source**（router→leaf 允许，同 unit_view/resolve_icp 先例；
ext_source 无 ROLE、纯模块函数）：submit 把 FOFA query 解析成具体 targets 再交叶子建任务（**同步可用不依赖
orchestration**）；submit_by_unit 的单位→资产反查是 orchestration worker 职责，叶子落 WAITING unit 任务。

权限（RBAC）：全部写操作 = `task:write`（rbac.PERM_RULES 已含 `/api/task` + `/api/task_fofa`）。
数据 API 规范：返回统一信封；**禁止硬限制参数**——目标数 / FOFA size 透传不砍（叶子层已守）。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("task_create", path="/task", description="新建任务：按策略下发")
ns_fofa = Namespace("task_fofa", path="/task_fofa", description="新建任务：FOFA 导入 / 单位名")
register_envelope_models(ns)
register_envelope_models(ns_fofa)


def _svc():
    """取 task_create 服务（字符串键，无 ROLE）。未注册降级 500。"""
    return get_registry().get("task_create_service")


def _source_from(body: dict) -> dict:
    """从 body 抽 source.* 扁平字段（前端传 source.platform 等）。"""
    return {k: (body.get("source." + k) or "") for k in ("platform", "category", "unit", "src_id")}


def _ext():
    """取 ext_source 门面（模块级函数集合，无 ROLE）。未注册返 None。"""
    return get_registry().get("ext_source_service")


# 测绘源清单（源查询多源架构；新增源=加一项 + ext_source 加对应 xxx_query/xxx_count）。
_SOURCE_DEFS = [
    {"id": "fofa", "name": "FOFA", "key_id": "fofa",
     "placeholder": 'FOFA 语法，如 domain="example.com" && port="443"（domain= 是精确主域匹配）'},
    {"id": "hunter", "name": "鹰图 Hunter", "key_id": "hunter",
     "placeholder": '鹰图语法，如 domain="gov.cn"（domain= 是模糊匹配，命中全部 *.gov.cn）'},
]


def _source_available(ext, key_id: str) -> bool:
    """某源是否已配 key 可用（用 ext_source._apikey，与查询侧同源判断）。"""
    if not ext:
        return False
    try:
        from sentinel_platform.modules.kernel.ext_source import _apikey
        return bool(_apikey(key_id))
    except Exception:
        return False


def _fofa_targets(query: str):
    """经 kernel/ext_source.fofa_query 把 FOFA 语句解析成 target 列表（host 优先，回退 ip）。
    经 registry 取 ext_source_service 门面（不 import 叶子内部）；未注册/未配 key/失败返 []。"""
    ext_source = get_registry().get("ext_source_service")
    if not ext_source:
        return []
    rows = ext_source.fofa_query(query, fields="host,ip,port") or []
    targets = set()
    for r in rows:
        if isinstance(r, (list, tuple)) and r:
            host = str(r[0] or "").strip()
            ip = str(r[1]).strip() if len(r) > 1 and r[1] else ""
            targets.add(host or ip)
        elif isinstance(r, str) and r.strip():
            targets.add(r.strip())
    return sorted(t for t in targets if t)


def _validate_fofa(query: str):
    """校验 FOFA 语句字段名拼写。返回错误字符串或 None。"""
    ext_source = get_registry().get("ext_source_service")
    if ext_source and hasattr(ext_source, "validate_fofa_query"):
        return ext_source.validate_fofa_query(query)
    # 回退：直接调模块函数
    try:
        from sentinel_platform.modules.kernel.ext_source import validate_fofa_query
        return validate_fofa_query(query)
    except Exception:
        return None


# ---------------- /api/task/policy/ ----------------

_policy_req = ns.model("TaskPolicyReq", {})    # body {name,task_tag,policy_id,target,priority,...}


@ns.route("/policy/")
class TaskByPolicy(Resource):
    @ns.doc(security="token", description="需权限 task:write")
    @ns.expect(_policy_req)
    def post(self):
        """按策略下发任务（目标入口：域名/IP/IP段，经 policy 展开 options）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务下发服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.create_by_policy(
            name=body.get("name", ""), policy_id=body.get("policy_id", ""),
            target=body.get("target", ""), task_tag=body.get("task_tag", "task"),
            priority=body.get("priority", 2), source=_source_from(body),
            pentest_whitelist=body.get("pentest_whitelist", ""),
            mission_intel=body.get("mission_intel", ""),
            pentest_provider_id=body.get("pentest_provider_id", ""),
            pentest_egress_mode=body.get("pentest_egress_mode", ""))
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "下发失败"))
        return ok({"items": r["items"], "created": r["created"], "invalid": r.get("invalid", [])})


# ---------------- /api/task_fofa/* ----------------

_fofa_test_req = ns_fofa.model("FofaTestReq", {})
_fofa_submit_req = ns_fofa.model("FofaSubmitReq", {})
_fofa_unit_req = ns_fofa.model("FofaUnitReq", {})


@ns_fofa.route("/sources")
class Sources(Resource):
    @ns_fofa.doc(security="token", description="可用测绘源列表（源查询用，前端渲染绿√+输入框）")
    def get(self):
        """返回测绘源清单 + 各源是否已配 key 可用。"""
        ext = _ext()
        items = [{"id": s["id"], "name": s["name"], "placeholder": s["placeholder"],
                  "available": _source_available(ext, s["key_id"])} for s in _SOURCE_DEFS]
        return ok({"sources": items})


@ns_fofa.route("/test")
class FofaTest(Resource):
    @ns_fofa.doc(security="token", description="需权限 task:write：源查询预估命中数（多源/单源兼容）")
    @ns_fofa.expect(_fofa_test_req)
    def post(self):
        """源查询预估：body 支持 {queries:{fofa,hunter}} 多源 或 {query} 单源(兼容)。
        各源分别预估命中数（count 只查首页读官方 total，省配额，不浪费）。"""
        if not _svc():
            return err(CODE_ERROR, "任务下发服务未就绪")
        ext = _ext()
        body = request.get_json(silent=True) or {}
        queries = body.get("queries") if isinstance(body.get("queries"), dict) else None
        if not queries:
            q = (body.get("query") or "").strip()      # 兼容旧单 query（走 fofa）
            if not q:
                return err(CODE_BAD_REQUEST, "query 或 queries 必填")
            queries = {"fofa": q}
        per = {}
        for sid, q in queries.items():
            q = (q or "").strip()
            if not q:
                continue
            if sid == "fofa":
                verr = _validate_fofa(q)
                if verr:
                    per["fofa"] = {"size": 0, "ok": False, "error": True, "errmsg": verr}
                    continue
                r = ext.fofa_count(q) if (ext and hasattr(ext, "fofa_count")) else {"ok": False, "errmsg": "源未就绪"}
            elif sid == "hunter":
                r = ext.hunter_count(q) if (ext and hasattr(ext, "hunter_count")) else {"ok": False, "errmsg": "源未就绪"}
            else:
                continue
            per[sid] = {"size": int(r.get("size") or 0), "ok": bool(r.get("ok")),
                        "error": bool(r.get("error")), "errmsg": r.get("errmsg", "")}
        # 兼容旧前端（单 fofa）：平铺 size/ok/error/errmsg
        flat = per.get("fofa", {}) if list(queries.keys()) == ["fofa"] else {}
        return ok({"per_source": per, "size": flat.get("size", 0),
                   "ok": flat.get("ok", True), "error": flat.get("error", False),
                   "errmsg": flat.get("errmsg", "")})


@ns_fofa.route("/submit")
class FofaSubmit(Resource):
    @ns_fofa.doc(security="token", description="需权限 task:write")
    @ns_fofa.expect(_fofa_submit_req)
    def post(self):
        """FOFA 导入建任务（端点解析 query→targets，按策略落 ip/domain 任务，同步可用）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务下发服务未就绪")
        body = request.get_json(silent=True) or {}
        name = body.get("name", "")
        if not name:
            return err(CODE_BAD_REQUEST, "name 必填")
        ext = _ext()
        queries = body.get("queries") if isinstance(body.get("queries"), dict) else None
        # 归一 queries：兼容旧单 query（走 fofa）
        if not queries:
            q = (body.get("query") or "").strip()
            if not q:
                return err(CODE_BAD_REQUEST, "query 或 queries 必填")
            queries = {"fofa": q}
        queries = {k: (v or "").strip() for k, v in queries.items() if (v or "").strip()}
        if not queries:
            return err(CODE_BAD_REQUEST, "至少填写一个源的查询语句")
        # FOFA 语句字段名校验（有 fofa 源时）
        if queries.get("fofa"):
            verr = _validate_fofa(queries["fofa"])
            if verr:
                return err(CODE_BAD_REQUEST, verr)
        # 多源查询 + 去重合并（域名 hostname / 纯IP ip+port）
        if ext and hasattr(ext, "multi_source_targets"):
            try:
                mr = ext.multi_source_targets(queries)
            except Exception as exc:
                logger.debug("multi_source resolve failed: %s", exc)
                return err(CODE_ERROR, "源查询失败（检查 key/网络）")
            targets = mr.get("targets") or []
            per_source = mr.get("per_source") or {}
            errors = mr.get("errors") or {}
        else:
            # 降级：无 multi_source_targets 时走旧 fofa 单源
            targets = _fofa_targets(queries.get("fofa", ""))
            per_source, errors = {"fofa": len(targets)}, {}
        if not targets:
            emsg = "；".join("{}:{}".format(k, v) for k, v in errors.items()) if errors else ""
            return err(CODE_BAD_REQUEST, "未解析到目标（0 命中或 key 未配）{}".format(("：" + emsg) if emsg else ""))
        src = _source_from(body)
        src["platform"] = src.get("platform") or "multi_source"
        src["sources"] = list(queries.keys())
        r = svc.create_from_targets(name=name, targets=targets, policy_id=body.get("policy_id", ""),
                                    priority=body.get("priority", 2), source=src,
                                    pentest_whitelist=body.get("pentest_whitelist", ""),
                                    mission_intel=body.get("mission_intel", ""),
                                    pentest_provider_id=body.get("pentest_provider_id", ""),
                                    pentest_egress_mode=body.get("pentest_egress_mode", ""))
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "下发失败"))
        return ok({"created": r["created"], "items": r["items"],
                   "fofa_size": len(targets), "merged": len(targets),
                   "per_source": per_source, "errors": errors})


@ns_fofa.route("/submit_by_unit")
class FofaSubmitByUnit(Resource):
    @ns_fofa.doc(security="token", description="需权限 task:write")
    @ns_fofa.expect(_fofa_unit_req)
    def post(self):
        """单位名建任务（一任务装多单位，单位→资产反查交 orchestration 异步，先落 WAITING）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "任务下发服务未就绪")
        body = request.get_json(silent=True) or {}
        import re as _re
        units = [u for u in _re.split(r"[\r\n,;]+", str(body.get("units", ""))) if u.strip()]
        if not body.get("name") or not units:
            return err(CODE_BAD_REQUEST, "name 与 units（多行单位名）必填")
        r = svc.create_unit_task(name=body.get("name", ""), units=units,
                                 policy_id=body.get("policy_id", ""), priority=body.get("priority", 2),
                                 source=_source_from(body), pentest_whitelist=body.get("pentest_whitelist", ""),
                                 mission_intel=body.get("mission_intel", ""),
                                 pentest_provider_id=body.get("pentest_provider_id", ""),
                                 pentest_egress_mode=body.get("pentest_egress_mode", ""))
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "下发失败"))
        return ok({"task_id": r["task_id"], "name": r["name"], "unit_count": r["unit_count"]})
