"""单位视图 unit_view —— 按单位聚合资产/漏洞/报告/攻击链（risk_intel 叶子，核心路由暴露）。

单位视图：每个渗透过的单位一张卡（unit_overview），点进看明细（unit_detail），可级联删除
（delete_unit）。ICP 域名→单位反查由核心路由 endpoint 复用 kernel/ext_source（跨模块经暴露层）。

净室重写 intel_center.unit_overview/unit_detail + routes/intel unit 级联删除：按 unit 字段聚合
intel_asset/intel_finding/intel_report/intel_attack_chain（读集合=数据契约，允许）。无 ROLE。
只依赖 core + stdlib，无第三方库。分页不设硬上限（禁硬限制参数）。
"""
from __future__ import annotations

from typing import Any, Dict, List

from sentinel_platform.core import get_logger, get_repo

logger = get_logger()

C_ASSET = "intel_asset"
C_FINDING = "intel_finding"
C_REPORT = "intel_report"
C_CHAIN = "intel_attack_chain"
C_SESSION = "intel_pentest_session"
C_CLUE = "intel_exploit_clue"
C_SYSTEM = "intel_system"
_UNKNOWN = "未知单位"


def unit_overview() -> List[Dict[str, Any]]:
    """单位卡片列表：每单位聚合关键指标，按最近渗透时间倒序。
    返回 [{unit, asset_count, subdomain_count, system_count, vuln_count, lead_count,
           report_count, chain_count, last_pentest}]。"""
    units: Dict[str, Dict[str, Any]] = {}

    def _u(name: str) -> Dict[str, Any]:
        name = name or _UNKNOWN
        return units.setdefault(name, {
            "unit": name, "asset_count": 0, "vuln_count": 0, "lead_count": 0,
            "_subs": set(), "_systems": set(), "report_count": 0,
            "chain_count": 0, "last_pentest": ""})

    try:
        repo = get_repo()
        for a in repo.collection(C_ASSET).find({}, {"unit": 1, "subdomain": 1, "system_id": 1, "fld": 1}):
            u = _u(a.get("unit"))
            u["asset_count"] += 1
            sub = a.get("subdomain") or a.get("fld")
            if sub:
                u["_subs"].add(sub)
            if a.get("system_id"):
                u["_systems"].add(a.get("system_id"))
        for f in repo.collection(C_FINDING).find({"source": "ai"}, {"unit": 1, "verified": 1}):
            u = _u(f.get("unit"))
            if f.get("verified"):
                u["vuln_count"] += 1
            else:
                u["lead_count"] += 1
        for r in repo.collection(C_REPORT).find({}, {"unit": 1, "save_date": 1}):
            u = _u(r.get("unit"))
            u["report_count"] += 1
            sd = r.get("save_date") or ""
            if sd > u["last_pentest"]:
                u["last_pentest"] = sd
        for ch in repo.collection(C_CHAIN).find({}, {"unit": 1}):
            _u(ch.get("unit"))["chain_count"] += 1
    except Exception as e:
        logger.warning("unit_overview error: %s", e)

    out = []
    for u in units.values():
        u["subdomain_count"] = len(u.pop("_subs"))
        u["system_count"] = len(u.pop("_systems"))
        out.append(u)
    out.sort(key=lambda x: x.get("last_pentest", ""), reverse=True)
    return out


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0, "": 0}


def _unit_filter(unit: str) -> Dict[str, Any]:
    """单位查询过滤器（BUG-011）：列表把空 unit 分桶为哨兵值「未知单位」，详情按此值查询时
    必须反解为「unit 为空/缺失」的记录，否则字面查「未知单位」匹配不到空串记录 → 详情恒 0。
    列表分桶键（_u: name or _UNKNOWN）与详情查询键在此对齐。"""
    if unit == _UNKNOWN:
        return {"$or": [{"unit": ""}, {"unit": {"$exists": False}}, {"unit": None}]}
    return {"unit": unit}


def unit_detail(unit: str) -> Dict[str, Any]:
    """单位详情：该单位漏洞/线索/子域名/系统/报告/攻击链明细。unit 空返 {error}。
    「未知单位」哨兵值经 _unit_filter 反解为空 unit 查询（与列表分桶对齐，BUG-011）。"""
    unit = (unit or "").strip()
    if not unit:
        return {"error": "unit 必填"}
    uf = _unit_filter(unit)

    def _q(*extra: Dict[str, Any]) -> Dict[str, Any]:
        """把单位过滤器与其他条件合并（未知单位用 $or，普通单位用等值）。"""
        q = dict(uf)
        for e in extra:
            q.update(e)
        return q
    vulns: List[Dict[str, Any]] = []
    leads: List[Dict[str, Any]] = []
    subs: Dict[str, int] = {}
    systems: Dict[str, str] = {}
    reports: List[Dict[str, Any]] = []
    chains: List[Dict[str, Any]] = []
    try:
        repo = get_repo()
        for f in repo.collection(C_FINDING).find(_q({"source": "ai"})):
            sv = (f.get("severity") or "unknown").lower()
            cs = (f.get("chain_severity") or "").lower()
            eff = cs if _SEV_RANK.get(cs, 0) > _SEV_RANK.get(sv, 0) else sv
            row = {"_id": str(f.get("_id")), "vuln_type": f.get("vuln_type", ""),
                   "target": f.get("target", ""), "severity": eff,
                   "cvss_score": f.get("cvss_score"), "save_date": f.get("save_date", ""),
                   "report_session": f.get("session_id", "")}
            (vulns if f.get("verified") else leads).append(row)
        for a in repo.collection(C_ASSET).find(_q()):
            sub = a.get("subdomain") or a.get("fld") or a.get("key") or ""
            if sub:
                subs[sub] = subs.get(sub, 0) + 1
            sid = a.get("system_id")
            if sid:
                systems[sid] = a.get("system_name") or sid
        for r in repo.collection(C_REPORT).find(_q()).sort("_id", -1):
            reports.append({"report_id": str(r.get("_id")), "title": r.get("title", ""),
                            "system_name": r.get("system_name", ""), "max_severity": r.get("max_severity", ""),
                            "save_date": r.get("save_date", ""),
                            "vuln_count": len(r.get("vuln_index", []) or [])})
        for ch in repo.collection(C_CHAIN).find(_q()):
            chains.append({"chain_id": str(ch.get("_id")), "title": ch.get("title", ""),
                           "max_severity": ch.get("max_severity", ""),
                           "step_count": ch.get("step_count", 0)})
    except Exception as e:
        logger.warning("unit_detail error: %s", e)
    return {
        "unit": unit, "vuln_count": len(vulns), "lead_count": len(leads),
        "subdomain_count": len(subs), "system_count": len(systems),
        "report_count": len(reports), "chain_count": len(chains),
        "vulns": vulns, "leads": leads,
        "subdomains": [{"subdomain": k, "asset_count": v} for k, v in subs.items()],
        "systems": [{"system_id": k, "system_name": v} for k, v in systems.items()],
        "reports": reports, "chains": chains,
    }


def delete_unit(unit: str) -> Dict[str, Any]:
    """级联删除单位数据（高危：清该单位 asset/finding/report/session/clue/chain，
    并从 intel_system.units 移除）。unit 必填，绝不空→全删。返回 {unit, deleted:{...}}。"""
    unit = (unit or "").strip()
    if not unit:
        return {"error": "unit 必填（禁止空单位级联删除）"}
    deleted: Dict[str, int] = {}
    try:
        repo = get_repo()
        # session 修 P2-a：原只查 source.unit，但资产 source dict 未必含 unit 键 → 漏删会话孤儿。
        # 会话顶层 unit 字段可靠(session.py 写入必设)，故 $or 兼顾顶层 unit 与 source.unit。
        for coll, q in ((C_ASSET, {"unit": unit}), (C_FINDING, {"unit": unit}),
                        (C_REPORT, {"unit": unit}),
                        (C_SESSION, {"$or": [{"unit": unit}, {"source.unit": unit}]}),
                        (C_CLUE, {"unit": unit}), (C_CHAIN, {"unit": unit})):
            r = repo.collection(coll).delete_many(q)
            deleted[coll] = getattr(r, "deleted_count", 0)
        # intel_system.units 移除该单位（系统可能被多单位共享，不删系统本身）
        repo.collection(C_SYSTEM).update_many({"units": unit}, {"$pull": {"units": unit}})
        logger.info("unit cascade delete: %s -> %s", unit, deleted)
        return {"unit": unit, "deleted": deleted}
    except Exception as e:
        logger.warning("delete_unit error: %s", e)
        return {"error": "删除失败: {}".format(e)}
