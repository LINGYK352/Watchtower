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

# 严重度归一：AI 上报的 severity 因模型不同可能是中文(高/中/低/严重)或英文各种写法，
# 统一归一为标准英文(critical/high/medium/low/info)——否则中文"高"不在 SEVERITY_RANK、
# 前端 sevColor 也匹配不到 → 标签无色/无标识(固定灰)。空/未知归 "unknown"。
_SEV_ALIAS = {
    "严重": "critical", "危急": "critical", "critical": "critical", "crit": "critical",
    "高危": "high", "高": "high", "high": "high", "severe": "high",
    "中危": "medium", "中": "medium", "medium": "medium", "med": "medium", "moderate": "medium",
    "低危": "low", "低": "low", "low": "low",
    "信息": "info", "info": "info", "informational": "info", "none": "info", "无": "info",
}


def _norm_sev(s: str) -> str:
    """severity 归一为标准英文（中英文别名 → critical/high/medium/low/info）；未知/空 → unknown。"""
    k = (s or "").strip().lower()
    if not k:
        return "unknown"
    return _SEV_ALIAS.get(k, k if k in SEVERITY_RANK else "unknown")


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
    """整链最高危害（归一英文）。step.severity 已在 record_step 归一，这里再归一一次兼容存量/直调。"""
    best, best_rank = "unknown", -1
    for s in steps or []:
        sev = _norm_sev(s.get("severity", ""))
        r = SEVERITY_RANK.get(sev, -1)
        if r > best_rank:
            best_rank, best = r, sev
    return best


# —— 链式组合升级（A4，接 vuln_playbook 的 chains_with 元数据）——
# 数据源=dicts/vuln_playbook 各 md 的 frontmatter chains_with（读文件，不跨模块 import，守解耦）。
# 进程级缓存，缺失/异常降级为空（不升级，保守）。
_CHAINS_WITH_CACHE: Optional[Dict[str, set]] = None
_SEV_UP = {"info": "low", "low": "medium", "medium": "high", "high": "critical", "critical": "critical"}


def _load_chains_with() -> Dict[str, set]:
    """加载 {playbook_name: set(chains_with)}。进程级缓存。找不到目录/解析失败 → {}（不升级）。"""
    global _CHAINS_WITH_CACHE
    if _CHAINS_WITH_CACHE is not None:
        return _CHAINS_WITH_CACHE
    result: Dict[str, set] = {}
    try:
        import os, glob
        from sentinel_platform.core import project_root
        for base in (os.path.join(project_root(), "dicts", "vuln_playbook"),
                     os.path.join(project_root(), "sentinel_platform", "dicts", "vuln_playbook")):
            if not os.path.isdir(base):
                continue
            for fp in glob.glob(os.path.join(base, "*.md")):
                name = os.path.splitext(os.path.basename(fp))[0]
                try:
                    txt = open(fp, "r", encoding="utf-8").read()
                except Exception:
                    continue
                # 极简 frontmatter 提取 chains_with: [a, b]（不引 yaml）
                m = re.search(r"^chains_with:\s*\[([^\]]*)\]", txt, re.M)
                if m:
                    result[name] = {x.strip().strip('"\'').lower() for x in m.group(1).split(",") if x.strip()}
                else:
                    result.setdefault(name, set())
            break
    except Exception as exc:
        logger.debug("attack_chain: load chains_with skipped: %s", exc)
    _CHAINS_WITH_CACHE = result
    return result


def _combo_upgrade(steps: List[Dict[str, Any]], base_sev: str) -> tuple:
    """链里出现「互为 chains_with 的两个不同漏洞类型」→ 组合危害升一级（封顶 critical）。
    返回 (升级后 severity, 组合说明 or "")。保守：只在有明确可组合对时升，且只升一级；无 chains_with 数据不升。"""
    cw = _load_chains_with()
    if not cw:
        return base_sev, ""
    # 取链里各环节的漏洞类型（归一到 playbook name 口径：小写、空格转下划线）
    types = []
    for s in steps or []:
        vt = str(s.get("vuln_type", "") or "").strip().lower().replace(" ", "_").replace("-", "_")
        if vt and vt not in types:
            types.append(vt)
    if len(types) < 2:
        return base_sev, ""
    # 找一对互相/单向 chains_with 的类型
    for i, a in enumerate(types):
        for b in types[i + 1:]:
            if b in cw.get(a, set()) or a in cw.get(b, set()):
                up = _SEV_UP.get(base_sev, base_sev)
                if SEVERITY_RANK.get(up, -1) > SEVERITY_RANK.get(base_sev, -1):
                    return up, "组合升级：{}+{} 可串成更高危利用链".format(a, b)
                return base_sev, ""
    return base_sev, ""


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
            "vuln_type": (vuln_type or "")[:60], "severity": _norm_sev(severity),
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
                new_max, combo_note = _combo_upgrade(steps, new_max)   # A4：多类型可组合则升一级（封顶 critical）
                upd = {
                    "steps": steps, "max_severity": new_max, "step_count": len(steps),
                    "sessions": sorted(sessions), "cross_session": len(sessions) > 1,
                    "update_date": now, "update_epoch": now_epoch,
                }
                if combo_note:
                    upd["combo_note"] = combo_note
                coll.update_one({"_id": existed["_id"]}, {"$set": upd})
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

    def read_chains(self, unit: str, limit: int = 20, min_severity: str = "high") -> Dict[str, Any]:
        """读本单位已有攻击链（开局接力：看有没有半成品链能接着串）。返回简表。limit 缺省 20 仅默认不砍。
        危害门槛（问题15）：默认只返回整链 max_severity >= high 的链（低危链不污染 AI 接力/展示/统计，
        但仍持久化——一旦后续追加出高危环节自然显现，不丢"低危前置串成高危链"）。传 min_severity="" 关闭过滤。"""
        unit = (unit or "").strip()
        if not unit:
            return {"unit": "", "chains": [], "count": 0}
        try:
            limit = max(1, int(limit or 20))
        except (TypeError, ValueError):
            limit = 20
        _floor = SEVERITY_RANK.get((min_severity or "").strip().lower(), -1)
        out = []
        try:
            for d in _coll().find({"unit": unit}).sort("update_epoch", -1):
                if _floor >= 0 and SEVERITY_RANK.get((d.get("max_severity") or "").lower(), 0) < _floor:
                    continue
                if len(out) >= limit:
                    break
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

    def list_chains(self, unit: str = "", status: str = "", page: int = 1, size: int = 20,
                    min_severity: str = "high") -> Dict[str, Any]:
        """攻击链列表（前端用，过滤 + 分页）。size 缺省 20 仅默认，客户端传多大都透传不砍（禁硬限制）。
        危害门槛（问题15）：默认只列整链 max_severity >= high 的链（低危链不进列表/统计，仍持久化）。
        传 min_severity="" 显示全部（如需看低危链）。用 $in 具体等级集合过滤（DB 侧，兼容内存替身 _match）。"""
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
        _floor = SEVERITY_RANK.get((min_severity or "").strip().lower(), -1)
        try:
            coll = _coll()
            # 危害过滤在 Python 侧做（不用 $in 查询——内存测试替身 _match 只认 _id 的 $in；且真 Mongo
            # 效果一致）：先取全量按时间排序，过滤掉低危链，再本地分页。禁硬限制 size 语义不变。
            rows = list(coll.find(q).sort("update_epoch", -1))
            if _floor >= 0:
                rows = [d for d in rows
                        if SEVERITY_RANK.get((d.get("max_severity") or "").lower(), 0) >= _floor]
            total = len(rows)
            items = []
            for d in rows[(page - 1) * size: (page - 1) * size + size]:
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

    def stat(self, unit: str = "", min_severity: str = "high") -> Dict[str, Any]:
        """概览：链总数 / 跨会话链数 / 各危害等级链数。
        危害门槛（问题15）：默认只统计整链 max_severity >= high 的链（与列表口径一致，低危链不计入
        统计避免"一堆低危链"污染概览）。传 min_severity="" 统计全部。"""
        q = {"unit": unit} if unit else {}
        _floor = SEVERITY_RANK.get((min_severity or "").strip().lower(), -1)
        try:
            coll = _coll()
            rows = list(coll.find(q))
            if _floor >= 0:
                rows = [d for d in rows
                        if SEVERITY_RANK.get((d.get("max_severity") or "").lower(), 0) >= _floor]
            total = len(rows)
            cross = sum(1 for d in rows if d.get("cross_session"))
            by_sev = {sev: sum(1 for d in rows if (d.get("max_severity") or "") == sev)
                      for sev in ("critical", "high", "medium", "low", "info")}
            return {"total": total, "cross_session": cross, "by_severity": by_sev}
        except Exception as exc:
            logger.debug("attack_chain: stat failed: %s", exc)
            return {"total": 0, "cross_session": 0, "by_severity": {}}


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = AttackChainServiceImpl()


def get_service() -> AttackChainServiceImpl:
    return _service

