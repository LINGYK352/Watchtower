"""task_plan/task_create —— 新建任务（按策略下发，落 task 集合）。

三入口：① 目标（域名/IP/IP段，taskApi.policy）② FOFA 导入（taskFofaApi.submit，targets 由端点经
ext_source 预解析）③ 单位名（taskFofaApi.submitByUnit，units 由端点经 ext_source ICP 反查预解析）。
统一经 `policy_service.get_options_by_policy_id` 把策略展开成 task.options，按目标类型（ip/domain）
拆成 task 文档落库（status=WAITING）。实际扫描投递是 orchestration（celery）职责——**未建则留 WAITING**
（orchestration 建成读 WAITING 投递，best-effort 接通，不硬依赖）。

**无 ROLE**（纯下发叶子）：经 registry 字符串键 `"task_create_service"` 注册（照 policy/task_list 先例）。
router `endpoints/task_create.py` 取用。不放 HTTP 路由。**不 import ext_source**（跨类别禁止）——
FOFA 查询 / 单位反查在端点层经 ext_source 解析出 targets 后传入本叶子（router→leaf 允许，同 unit_view 先例）。

迁移来源：app/routes/task.py（policy 下发）+ taskFofa.py + helpers/task.py（build_task_data/submit_task）。
净室重写：target 分类/校验自带（不 import app.utils）；options 经 policy_service（registry）；
派发经 orchestration best-effort。**SSRF 黑名单守 §8.3 V-03**：拒私网/环回 IP 目标（net-room 基础守卫）。
**禁止硬限制参数**：目标数量、priority 透传不砍（priority 只归一到 T0/T1/T2 合法档）。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import get_registry, Collections
from sentinel_platform.core import models

logger = get_logger()

# —— 目标分类正则（net-room，不 import app.utils）——
_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d{1,2})?$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9\*](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_URL_RE = re.compile(r"^https?://", re.I)

# 私网/环回段标记（仅用于打标，不再拒绝）——本平台是授权内网渗透工具，内网即主战场，
# 不因私网/环回拒绝目标（原 SSRF 黑名单拒内网导致"无有效目标"，2026-08-11 放开）。
_PRIVATE_PREFIXES = ("10.", "192.168.", "169.254.", "127.", "100.64.", "0.")


def _split_targets(target: str) -> List[str]:
    """目标串按 , ; 换行 分割去重去空。URL 不转小写（保留路径大小写）。"""
    parts = re.split(r"[,;\n\r]+", (target or "").strip())
    seen = set()
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # URL 保留原始大小写；域名/IP 转小写
        key = p if _URL_RE.match(p) else p.lower()
        if key not in seen:
            seen.add(key)
            out.append(p if _URL_RE.match(p) else p.lower())
    return out


def _extract_host_from_url(url: str) -> str:
    """从 URL 提取 hostname（不含端口）。"""
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url).hostname or "").strip().lower()
    except Exception:
        return ""


def _is_private_ip(item: str) -> bool:
    ip = item.split("/")[0]
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):                      # 172.16.0.0–172.31.255.255
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def classify_targets(target: str) -> Tuple[List[str], List[str], List[str]]:
    """分类目标为 (ip_list, domain_list, invalid_list)。

    支持三种格式：
      - 纯 IP / CIDR
      - 纯域名
      - 完整 URL（https://host/path）→ 提取域名归入 domain_list，原始 URL 记录到 url_targets
    内网/私网目标允许（授权内网渗透工具，2026-08-11 放开），仅格式非法计入 invalid。
    """
    ip_list, domain_list, invalid = [], [], []
    for item in _split_targets(target):
        # URL 格式：提取域名
        if _URL_RE.match(item):
            host = _extract_host_from_url(item)
            if not host:
                invalid.append("{}(URL解析失败)".format(item[:60]))
                continue
            # host 可能是 IP 或域名（内网 IP 也接受）
            if _IP_RE.match(host):
                ip_list.append(host)
            elif _DOMAIN_RE.match(host):
                if host not in domain_list:
                    domain_list.append(host)
            else:
                invalid.append("{}(URL主机名无效)".format(item[:60]))
            continue
        # 纯 IP
        m = _IP_RE.match(item)
        if m:
            cidr_suffix = m.group(5)
            if cidr_suffix and not (0 <= int(cidr_suffix[1:]) <= 32):
                invalid.append("{}(CIDR前缀长度须0-32)".format(item))
                continue
            # 内网/私网 IP 也接受（授权内网渗透）；仅校验八位组范围合法
            if any(int(o) > 255 for o in m.group(1, 2, 3, 4)):
                invalid.append("{}(IP八位组超范围)".format(item))
            else:
                ip_list.append(item)
        # 纯域名
        elif _DOMAIN_RE.match(item):
            domain_list.append(item)
        else:
            invalid.append("{}(无效目标)".format(item))
    return ip_list, domain_list, invalid


def extract_url_targets(target: str) -> List[str]:
    """提取输入中的完整 URL 列表（供 task options.url_targets 存储，AI 渗透用）。"""
    return [item for item in _split_targets(target) if _URL_RE.match(item)]


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _norm_priority(v: Any) -> int:
    """priority 归一到合法档 T0/T1/T2（默认 T2）——这是取值合法化，非硬限制（档位是业务枚举）。"""
    try:
        return models.TaskPriority.normalize(v)
    except Exception:
        return getattr(models.TaskPriority, "DEFAULT", 2)


def _normalize_source(source: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """来源子文档归一（仅用于结果归档贯穿 unit，不污染扫描 options）。全空返 None。"""
    if not isinstance(source, dict):
        return None
    s = {k: (source.get(k) or "") for k in ("platform", "category", "unit", "src_id")}
    return s if any(s.values()) else None


def _build_task_doc(name: str, target: str, task_type: str, task_tag: str, options: Dict[str, Any],
                    source: Optional[Dict[str, Any]], priority: Any) -> Dict[str, Any]:
    """构造 task 文档（对齐旧 build_task_data schema）。IP 任务关域名相关选项。"""
    opts = dict(options or {})
    if task_type == models.TaskType.IP:
        opts.update({"domain_brute": False, "alt_dns": False,
                     "dns_query_plugin": False, "arl_search": False})
    doc = {
        "name": name, "target": target, "start_time": "-",
        "status": models.TaskStatus.WAITING, "type": task_type, "task_tag": task_tag,
        "options": opts, "priority": _norm_priority(priority),
        "end_time": "-", "service": [], "celery_id": "",
        "save_date": _now(), "update_date": _now(),
    }
    ns = _normalize_source(source)
    if ns:
        doc["source"] = ns
    return doc


def _try_dispatch(task_id: str, task_doc: Dict[str, Any]) -> str:
    """派发投递：orchestration（celery 编排）best-effort。未注册/无方法 → 留 WAITING（正确降级）。
    返回 "dispatched" / "waiting"（orchestration 建成后读 WAITING 投递即接通）。"""
    try:
        orch = get_registry().get("orchestration_service")
        if orch and hasattr(orch, "submit_task"):
            result = orch.submit_task(task_id, task_doc) or {}
            return "dispatched" if result.get("submitted") else "waiting"
    except Exception as exc:
        logger.debug("task_create: dispatch skipped: %s", exc)
    return "waiting"


class TaskCreateServiceImpl:
    """新建任务能力（无 ROLE，字符串键 task_create_service 注册）。"""

    def _resolve_options(self, policy_id: str, task_tag: str) -> Optional[Dict[str, Any]]:
        """经 policy_service（registry）把策略展开成 options。服务缺失/策略不存在返 None。"""
        svc = get_registry().get("policy_service")
        if not (svc and hasattr(svc, "get_options_by_policy_id")):
            return None
        try:
            opts = svc.get_options_by_policy_id(policy_id, task_tag)
            return opts or None
        except Exception as exc:
            logger.debug("task_create: resolve options failed: %s", exc)
            return None

    def _create_tasks(self, name: str, ip_list: List[str], domain_list: List[str],
                      options: Dict[str, Any], source: Optional[Dict[str, Any]],
                      priority: Any) -> List[Dict[str, Any]]:
        """按目标类型拆 task 文档落库（IP 一篇 + 每域名一篇，对齐旧 submit_task_task 粒度）。"""
        repo = get_repo()
        coll = repo.collection(Collections.TASK)
        created: List[Dict[str, Any]] = []
        jobs: List[Tuple[str, str]] = []
        if ip_list:
            jobs.append((",".join(ip_list), models.TaskType.IP))     # IP 目标合并一篇
        for d in domain_list:
            jobs.append((d, models.TaskType.DOMAIN))                  # 每域名一篇
        for tgt, ttype in jobs:
            doc = _build_task_doc(name, tgt, ttype, models.TaskTag.TASK, options, source, priority)
            res = coll.insert_one(doc)
            tid = str(getattr(res, "inserted_id", ""))
            doc["_id"] = tid
            doc["task_id"] = tid
            doc["dispatch"] = _try_dispatch(tid, doc)
            created.append({"task_id": tid, "target": tgt, "type": ttype,
                            "status": doc["status"], "dispatch": doc["dispatch"]})
        return created

    def create_by_policy(self, name: str, policy_id: str, target: str, task_tag: str = "task",
                         priority: Any = 2, source: Optional[Dict[str, Any]] = None,
                         pentest_whitelist: str = "", mission_intel: str = "",
                         pentest_provider_id: str = "", pentest_egress_mode: str = "") -> Dict[str, Any]:
        """按策略下发任务（主入口，taskApi.policy）。经 policy_service 展开 options，按目标拆 task 落库。
        返回 {ok, items:[...], created:N} 或 {ok:False, error}。
        pentest_provider_id=为本任务派发的 AI 渗透会话锁定 AI 模型（空=跟随全局默认）。
        pentest_egress_mode=本任务 AI 攻击出口（direct/global/smart，空=跟随策略默认）——出口选择从策略移到任务。"""
        name = (name or "").strip()
        policy_id = (policy_id or "").strip()
        if not name or not policy_id or not (target or "").strip():
            return {"ok": False, "error": "name / policy_id / target 必填"}
        task_tag = task_tag if task_tag in (models.TaskTag.TASK, models.TaskTag.RISK_CRUISING) else models.TaskTag.TASK
        options = self._resolve_options(policy_id, task_tag)
        if options is None:
            return {"ok": False, "error": "策略不存在或 policy 服务未就绪: {}".format(policy_id)}
        # 禁渗透白名单 + 临时情报随 options 贯穿（scope 不拆字段，当自由文本存）
        wl = [w for w in re.split(r"[,;\s]+", (pentest_whitelist or "").strip()) if w]
        if wl:
            options["pentest_whitelist"] = wl
        if mission_intel:
            options["mission_intel_raw"] = mission_intel   # 端点已可预清洗；此处原样贯穿供派发解析
        if (pentest_provider_id or "").strip():
            options["pentest_provider_id"] = pentest_provider_id.strip()   # 锁定 AI 模型，透传到派发会话
        # AI 攻击出口（从策略移到任务）：任务传了就覆盖 options 的 pentest_egress.mode，rule_id 沿用策略。
        _egm = (pentest_egress_mode or "").strip()
        if _egm in ("direct", "global", "smart"):
            _peg = dict(options.get("pentest_egress") or {})
            _peg["mode"] = _egm
            options["pentest_egress"] = _peg
        ip_list, domain_list, invalid = classify_targets(target)
        if not ip_list and not domain_list:
            return {"ok": False, "error": "无有效目标", "invalid": invalid}
        # URL 目标提取：完整 URL 存入 options 供 AI 渗透会话直接使用（侦察走提取的域名）
        url_targets = extract_url_targets(target)
        if url_targets:
            options["url_targets"] = url_targets
        try:
            items = self._create_tasks(name, ip_list, domain_list, options, source, priority)
        except Exception as exc:
            logger.debug("task_create: create_by_policy failed: %s", exc)
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "items": items, "created": len(items), "invalid": invalid}

    def create_from_targets(self, name: str, targets: List[str], policy_id: str,
                            priority: Any = 2, source: Optional[Dict[str, Any]] = None,
                            pentest_whitelist: str = "", mission_intel: str = "",
                            pentest_provider_id: str = "", pentest_egress_mode: str = "") -> Dict[str, Any]:
        """从**已解析的目标列表**下发（FOFA 导入用；targets 由端点经 ext_source.fofa_query 解析）。
        创建 **1 个聚合任务**（type=fofa），对齐旧代码行为——任务列表只显示 1 条而非 N 条。
        目标列表存 options.fofa_ip 供 orchestration 拆解扫描。**FOFA 路径同步可用**
        （不依赖 orchestration，端点已把 query 解析成具体 ip/domain）。"""
        name = (name or "").strip()
        if not name or not policy_id or not targets:
            return {"ok": False, "error": "name / policy_id / targets 必填"}
        options = self._resolve_options(policy_id, models.TaskTag.TASK)
        if options is None:
            return {"ok": False, "error": "策略不存在或 policy 服务未就绪: {}".format(policy_id)}
        wl = [w for w in re.split(r"[,;\s]+", (pentest_whitelist or "").strip()) if w]
        if wl:
            options["pentest_whitelist"] = wl
        if mission_intel:
            options["mission_intel_raw"] = mission_intel
        if (pentest_provider_id or "").strip():
            options["pentest_provider_id"] = pentest_provider_id.strip()
        _egm = (pentest_egress_mode or "").strip()
        if _egm in ("direct", "global", "smart"):
            _peg = dict(options.get("pentest_egress") or {}); _peg["mode"] = _egm
            options["pentest_egress"] = _peg
        # FOFA 聚合任务：1 个 task 文档包含所有 targets（对齐旧 taskFofa submit_fofa_task 行为）
        options["fofa_ip"] = targets   # orchestration 消费此字段拆解扫描
        display_target = "FOFA 目标 {}".format(len(targets))
        try:
            coll = get_repo().collection(Collections.TASK)
            doc = _build_task_doc(name, display_target, "fofa", models.TaskTag.TASK,
                                  options, source, priority)
            res = coll.insert_one(doc)
            tid = str(getattr(res, "inserted_id", ""))
            doc["_id"] = tid
            dispatch = _try_dispatch(tid, doc)
            return {"ok": True, "task_id": tid, "items": [{"task_id": tid, "target": display_target,
                    "type": "fofa", "status": doc["status"], "dispatch": dispatch}],
                    "created": 1}
        except Exception as exc:
            logger.debug("task_create: create_from_targets failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    def create_unit_task(self, name: str, units: List[str], policy_id: str, priority: Any = 2,
                         source: Optional[Dict[str, Any]] = None, pentest_whitelist: str = "",
                         mission_intel: str = "", pentest_provider_id: str = "",
                         pentest_egress_mode: str = "") -> Dict[str, Any]:
        """单位名建任务（一个任务装多单位）。**反查(单位→资产)是 orchestration worker 职责**（ext_source
        未暴露反查），本叶子落一篇 type=unit 的 WAITING 任务，unit_names 存 options；orchestration 建成后
        读它异步反查种子 + 转 ip/domain 子任务（对齐旧 v2.7.62）。返回 {ok, task_id, name, unit_count}。"""
        name = (name or "").strip()
        units = [u.strip() for u in (units or []) if u and u.strip()]
        if not name or not policy_id or not units:
            return {"ok": False, "error": "name / policy_id / units 必填"}
        options = self._resolve_options(policy_id, models.TaskTag.TASK)
        if options is None:
            return {"ok": False, "error": "策略不存在或 policy 服务未就绪: {}".format(policy_id)}
        options["unit_names"] = units                       # 供 orchestration 反查种子
        wl = [w for w in re.split(r"[,;\s]+", (pentest_whitelist or "").strip()) if w]
        if wl:
            options["pentest_whitelist"] = wl
        if mission_intel:
            options["mission_intel_raw"] = mission_intel
        if (pentest_provider_id or "").strip():
            options["pentest_provider_id"] = pentest_provider_id.strip()
        _egm = (pentest_egress_mode or "").strip()
        if _egm in ("direct", "global", "smart"):
            _peg = dict(options.get("pentest_egress") or {}); _peg["mode"] = _egm
            options["pentest_egress"] = _peg
        try:
            coll = get_repo().collection(Collections.TASK)
            # type="unit"：orchestration dispatch 表消费（未建则留 WAITING，正确降级）。target 展示用单位名。
            doc = _build_task_doc(name, "、".join(units), "unit", models.TaskTag.TASK,
                                  options, source, priority)
            doc["unit_names"] = units
            res = coll.insert_one(doc)
            tid = str(getattr(res, "inserted_id", ""))
            doc["_id"] = tid
            dispatch = _try_dispatch(tid, doc)
            return {"ok": True, "task_id": tid, "name": name, "unit_count": len(units), "dispatch": dispatch}
        except Exception as exc:
            logger.debug("task_create: create_unit_task failed: %s", exc)
            return {"ok": False, "error": str(exc)}


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = TaskCreateServiceImpl()


def get_service() -> TaskCreateServiceImpl:
    return _service

