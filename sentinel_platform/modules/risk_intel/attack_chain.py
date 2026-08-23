"""risk_intel/attack_chain —— 攻击链情报（集合 intel_attack_chain）。

记录单位内「一条利用链怎么一环扣一环打通」——区别于 intel_finding（孤立漏洞）、
exploit_clue（孤立钥匙）。攻击链是渗透价值最高的产出：单个低危信息泄露不值钱，但
「JS 泄露内网域名 → SSRF 打内网 → 拿凭证 → 登录后台 → 越权读全量」串成链，危害拉满。

key = 单位(unit) + 链标题(title)：支持**跨会话延续**——A 站会话打出的环节，B 站会话
接着往同一条链追加。环节(steps)有序，每环 seq/action/result/target/vuln_type/severity/
finding_ref/clue_ref/session_id/source_site/at。

**无 ROLE**（纯业务叶子）：经 registry 字符串键 `"attack_chain_service"` 注册（照
guard_log/dashboard 先例）。router `endpoints/attack_chain.py` + 未来 ai_pentest 闸刀取用。
`record_step` 供闸刀经 registry 调写环节（接口先立，非孤岛）。不放 HTTP 路由。

迁移来源：app/services/attack_chain.py。**净室解耦（关键）**：旧代码 `from app.services.finding import`
（跨模块耦合）+ 直写 `intel_finding`（链危害回传 #4，越权写别的叶子集合）。本叶子：
① 归一化辅助（_host_of/_norm_target/_norm_vuln_type）**自带**（不 import vuln_center，同 system_tags
先例保留自有子集）；② 链危害回传改 **registry best-effort**——FINDING 服务若暴露
`apply_chain_severity` 则调，无则跳过（不硬耦合、不越权写；vuln_center 后续加该门面即接通）。
bson.ObjectId 惰性 import（对齐 core/db 惰性 pymongo），无 bson 回退原值让单测可跑。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import get_registry, ROLE, Collections

logger = get_logger()

COLL = Collections.INTEL_ATTACK_CHAIN
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0, "": 0}


def _coll():
    return get_repo().collection(COLL)


def _oid(v: Any):
    """字符串 → bson.ObjectId（惰性）；无 bson 回退原值（测试/离线），空返 None。"""
    if v in (None, ""):
        return None
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v
    except Exception:
        return v          # 非法 ObjectId 回退原值（对齐平台约定；生产真 ObjectId 库对字符串查不到，效果一致）


# —— 归一化辅助（自带，不 import vuln_center；用于 P6 证据宽松匹配）——
def _host_of(url_or_target: str) -> str:
    s = (url_or_target or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    return s.split("/")[0].split("@")[-1].split(":")[0]


def _norm_target(target: str) -> str:
    s = (target or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("#")[0].split("?")[0]
    host_seg = s.split("/", 1)[0]
    if host_seg.startswith("www.") and host_seg.split(":")[0].count(".") >= 2:
        s = s[4:]
    return s.rstrip("/")


def _max_sev(steps: List[Dict[str, Any]]) -> str:
    best, best_rank = "", -1
    for s in steps or []:
        r = SEVERITY_RANK.get((s.get("severity", "") or "").lower(), -1)
        if r > best_rank:
            best_rank, best = r, (s.get("severity", "") or "")
    return best


def _target_has_evidence(target: str, tool_log: Optional[List[Dict[str, Any]]]) -> bool:
    """P6 证据约束：tool_log 里是否有工具**实际打过**该 target（host 相等 + path 沾边）。
    宽松匹配（不像 finding 那么精确），只证明 AI 真在此目标操作过，非凭空编。归一不可用降级放行。"""
    if not target or not tool_log:
        return False
    fhost = _host_of(target)
    if not fhost:
        return False
    fnorm = _norm_target(target)
    import json as _json
    for t in tool_log:
        args = t.get("arguments") or t.get("input") or {}
        if isinstance(args, str):
            try:
                args = _json.loads(args)
            except Exception:
                args = {}
        cand = args.get("url") or args.get("target") or ""
        if not cand or _host_of(cand) != fhost:
            continue
        cnorm = _norm_target(cand)
        if cnorm == fnorm or cnorm.startswith(fnorm) or fnorm.startswith(cnorm):
            return True
    return False


def _propagate_chain_severity(chain_doc: Dict[str, Any]) -> int:
    """链危害回传(#4)：整链 max_severity 提升链上关联 finding 的实际危害。
    **registry best-effort**：FINDING 服务暴露 apply_chain_severity 才调，无则跳过（解耦，不越权写 intel_finding）。
    返回提级条数（无服务/无方法返 0）。"""
    try:
        svc = get_registry().get(ROLE.FINDING)
        if not (svc and hasattr(svc, "apply_chain_severity")):
            return 0    # vuln_center 未暴露该门面 → 跳过（后续加即接通，接口先立）
        chain_sev = (chain_doc.get("max_severity", "") or "").lower()
        if SEVERITY_RANK.get(chain_sev, -1) <= 0:
            return 0
        return int(svc.apply_chain_severity(
            title=chain_doc.get("title", ""), chain_severity=chain_sev,
            steps=chain_doc.get("steps", []) or []) or 0)
    except Exception as exc:
        logger.debug("attack_chain: propagate severity skipped: %s", exc)
        return 0


class AttackChainServiceImpl:
    """攻击链情报能力（无 ROLE，字符串键 attack_chain_service 注册）。"""

    def record_step(self, unit: str, title: str, action: str, result: str = "", target: str = "",
                    vuln_type: str = "", severity: str = "", finding_ref: str = "", clue_ref: str = "",
                    session_id: str = "", source_site: str = "", tool_log: Optional[List] = None) -> Dict[str, Any]:
        """记一条攻击链环节。同 unit+title 已存在则追加环节（跨会话延续），否则新建链。
        P6 证据约束：声明了 target 的环节，tool_log 里须有对该 target 的实打记录，否则拒（治"猜的链"）。
        幂等：同链内 (action,target) 相同不重复追加。返回 {chain_id,title,step_count,action} 或 {error}。"""
        unit = (unit or "").strip()
        title = (title or "").strip()
        action = (action or "").strip()
        if not unit or not title or not action:
            return {"error": "unit / title / action 必填"}
        target = (target or "").strip()
        if target and tool_log and not _target_has_evidence(target, tool_log):
            return {"error": ("该环节 target={} 在本会话工具调用记录中无实打证据。攻击链每一环必须是"
                              "**你实际操作验证过的**（http_request/collect_js/run_nuclei 等真打过该目标），"
                              "不能凭情报库/CVE/推测记链。").format(target[:80])}
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        now_epoch = int(time.time())
        new_step = {
            "action": action[:500], "result": (result or "")[:500], "target": target[:300],
            "vuln_type": (vuln_type or "")[:60], "severity": (severity or "").lower(),
            "finding_ref": finding_ref or "", "clue_ref": clue_ref or "",
            "session_id": session_id or "", "source_site": source_site or "", "at": now,
        }
        try:
            coll = _coll()
            existed = coll.find_one({"unit": unit, "title": title})
            if existed:
                steps = existed.get("steps", []) or []
                for s in steps:
                    if s.get("action") == new_step["action"] and s.get("target") == new_step["target"]:
                        return {"chain_id": str(existed["_id"]), "title": title,
                                "step_count": len(steps), "action": "skipped(dup)"}
                new_step["seq"] = len(steps) + 1
                steps.append(new_step)
                sessions = set(existed.get("sessions", []) or [])
                if session_id:
                    sessions.add(session_id)
                new_max = _max_sev(steps)
                coll.update_one({"_id": existed["_id"]}, {"$set": {
                    "steps": steps, "max_severity": new_max, "step_count": len(steps),
                    "sessions": sorted(sessions), "cross_session": len(sessions) > 1,
                    "update_date": now, "update_epoch": now_epoch,
                }})
                existed.update(steps=steps, max_severity=new_max, title=title)
                _propagate_chain_severity(existed)
                return {"chain_id": str(existed["_id"]), "title": title,
                        "step_count": len(steps), "action": "appended"}
            new_step["seq"] = 1
            doc = {
                "unit": unit, "title": title, "steps": [new_step],
                "max_severity": new_step["severity"], "step_count": 1, "status": "building",
                "sessions": [session_id] if session_id else [], "cross_session": False,
                "save_date": now, "update_date": now, "update_epoch": now_epoch,
            }
            res = coll.insert_one(dict(doc))
            doc["_id"] = getattr(res, "inserted_id", "")
            _propagate_chain_severity(doc)
            return {"chain_id": str(doc["_id"]), "title": title, "step_count": 1, "action": "created"}
        except Exception as exc:
            logger.debug("attack_chain: record_step failed: %s", exc)
            return {"error": str(exc)}

    def read_chains(self, unit: str, limit: int = 20) -> Dict[str, Any]:
        """读本单位已有攻击链（开局接力：看有没有半成品链能接着串）。返回简表。limit 缺省 20 仅默认不砍。"""
        unit = (unit or "").strip()
        if not unit:
            return {"unit": "", "chains": [], "count": 0}
        try:
            limit = max(1, int(limit or 20))
        except (TypeError, ValueError):
            limit = 20
        out = []
        try:
            for d in _coll().find({"unit": unit}).sort("update_epoch", -1).limit(limit):
                steps = d.get("steps", []) or []
                out.append({
                    "chain_id": str(d["_id"]), "title": d.get("title", ""),
                    "step_count": len(steps), "max_severity": d.get("max_severity", ""),
                    "status": d.get("status", "building"), "cross_session": d.get("cross_session", False),
                    "outline": " → ".join((s.get("action", "") or "")[:40] for s in steps),
                })
        except Exception as exc:
            logger.debug("attack_chain: read_chains failed: %s", exc)
        return {"unit": unit, "chains": out, "count": len(out)}

    def list_chains(self, unit: str = "", status: str = "", page: int = 1, size: int = 20) -> Dict[str, Any]:
        """攻击链列表（前端用，过滤 + 分页）。size 缺省 20 仅默认，客户端传多大都透传不砍（禁硬限制）。"""
        try:
            page = max(1, int(page or 1))
            size = max(1, int(size or 20))
        except (TypeError, ValueError):
            page, size = 1, 20
        q: Dict[str, Any] = {}
        if unit:
            q["unit"] = unit
        if status:
            q["status"] = status
        try:
            coll = _coll()
            total = coll.count_documents(q)
            items = []
            for d in coll.find(q).sort("update_epoch", -1).skip((page - 1) * size).limit(size):
                d["_id"] = str(d["_id"])
                items.append(d)
            return {"items": items, "total": total, "page": page, "size": size}
        except Exception as exc:
            logger.debug("attack_chain: list failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "size": size}

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """按 id 拉单条攻击链完整记录（详情抽屉）。"""
        oid = _oid(chain_id)
        if oid is None:
            return None
        try:
            d = _coll().find_one({"_id": oid})
        except Exception:
            return None
        if not d:
            return None
        d["_id"] = str(d["_id"])
        return d

    def delete_chains(self, ids: List[str]) -> Dict[str, Any]:
        """批量删除攻击链。返回 {ok, deleted}。"""
        if not ids or not isinstance(ids, list):
            return {"ok": False, "error": "_id(非空数组) 必填", "deleted": 0}
        oids = [o for o in (_oid(i) for i in ids) if o is not None]
        if not oids:
            return {"ok": True, "deleted": 0}
        try:
            n = _coll().delete_many({"_id": {"$in": oids}}).deleted_count
            return {"ok": True, "deleted": n}
        except Exception as exc:
            logger.debug("attack_chain: delete failed: %s", exc)
            return {"ok": False, "error": str(exc), "deleted": 0}

    def stat(self, unit: str = "") -> Dict[str, Any]:
        """概览：链总数 / 跨会话链数 / 各危害等级链数。"""
        q = {"unit": unit} if unit else {}
        try:
            coll = _coll()
            total = coll.count_documents(q)
            cross = coll.count_documents(dict(q, cross_session=True))
            by_sev = {sev: coll.count_documents(dict(q, max_severity=sev))
                      for sev in ("critical", "high", "medium", "low", "info")}
            return {"total": total, "cross_session": cross, "by_severity": by_sev}
        except Exception as exc:
            logger.debug("attack_chain: stat failed: %s", exc)
            return {"total": 0, "cross_session": 0, "by_severity": {}}


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = AttackChainServiceImpl()


def get_service() -> AttackChainServiceImpl:
    return _service

