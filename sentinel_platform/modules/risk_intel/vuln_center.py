"""risk_intel/vuln_center —— 漏洞中心（实现 FINDING / FindingService）。

三来源漏洞统一治理：AI 渗透（intel_finding）+ 瞭望塔 PoC（vuln）+ Nuclei（nuclei_result）混排。
核心能力：
  - 证据强制：verified 仅在工具实抓「请求 + 正向响应」（confirmed）时为真，否则降 lead（治假验证）。
  - CVSS 3.1 定级 + triage 校准（信息型/指纹型降级，向量硬闸防误降真漏洞）——见 `_cvss.py`。
  - 三来源混排查询/标记/统计（供漏洞中心前端页），四状态（已验证/线索/未处理/误报，默认藏误报）。
  - 出洞推送：verified 漏洞经 registry 调 NOTIFY（缺失降级，不硬 import notify 模块）。

迁移来源：app/services/finding.py + utils/cvss.py + finding_template.py（逻辑规格，净室重写）。
**签名对齐冻结契约**（INTERFACES §二 FINDING）：
  - `record_finding(finding: dict) -> dict{ok,id?,dup}`：单条登记（幂等 norm_target+norm_type）；
    finding 传 `md_text` 时切换为「批量解析报告 md 登记」（session 收尾用，返回聚合摘要）。
  - `is_identify_poc(plg_name, vul_name) -> bool`：纯判定，识别类 PoC（指纹）不入漏洞库。
查询/标记/统计（list_unified_findings/mark_unified/finding_stat 等）非 Protocol 方法，
作 Impl 扩展方法 + 模块级函数供 `router/endpoints/risk_intel.py` 调。不放 HTTP 路由。

bson.ObjectId 惰性 import（对齐 core/db.py 惰性 pymongo 范式）——单测走 fake repo + 字符串 _id
不触发；真实部署 Linux 有 pymongo（wheel 已入 vendor/wheels）。
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import get_registry, ROLE, Collections
from . import _cvss
from . import _hazard_table
from . import _finding_quality as _quality
from . import _finding_index

logger = get_logger()

# —— 对抗式复核（v1.21.157-34 新增）：治低效模型假阳性 + 虚高等级 ——

def _adversarial_review(finding: Dict[str, Any]) -> Dict[str, Any]:
    """对抗式复核已验证漏洞（治假阳性+虚高）：拿真实证据响应 body 质疑 AI 声称的漏洞类型和等级。

    只复核 verified=True 的 finding（lead 不复核省 token）；降级但不删除（fail-safe）。
    输入：finding 带 vuln_type/target/cvss_vector/impact/evidence（真实 tool 响应 body）。
    返回：{verdict: "confirmed"|"downgrade_to_lead"|"adjust_severity", reason, suggested_severity?}

    判定原则（治症状①②）：
      - 业务拒绝响应（"请登录"/"请绑定"/"未授权"但无实际数据）→ downgrade_to_lead
      - 访问控制类（认证绕过/未授权访问/越权）响应不含受保护数据 → downgrade_to_lead
      - 等级虚高（C:L 信息泄露给了 high）→ adjust_severity 建议降级
      - 真有受保护数据/实际利用成功 → confirmed
    """
    vt = finding.get("vuln_type", "")
    tgt = finding.get("target", "")
    vec = finding.get("cvss_vector", "")
    impact = finding.get("impact", "")
    ev = finding.get("evidence") or []

    # 拼证据响应 body（取前 3 条 evidence 的 body 前 300 字，供复核 AI 判断）
    bodies = []
    for e in ev[:3]:
        res = e.get("result")
        if isinstance(res, dict):
            b = (res.get("body") or "")[:300]
            if b:
                bodies.append(b)
        elif isinstance(res, str):
            bodies.append(res[:300])
    if not bodies:
        return {"verdict": "confirmed", "reason": "无证据响应 body，保守确认（可能是 nuclei/npoc）"}

    evidence_text = "\n---\n".join(bodies)

    # 复核提示词（轻量、直接）
    prompt = f"""你是漏洞复核专家。一个 AI 渗透会话上报了以下漏洞，但需要你复核真实性和等级。

**声称漏洞**
- 类型: {vt}
- 目标: {tgt}
- 等级/向量: {vec}
- 危害: {impact[:200]}

**真实证据响应（工具实抓的 HTTP body）**
```
{evidence_text}
```

**复核任务**
判定这个响应是否真能证明该漏洞：
1. 如果响应是**业务拒绝**（"请登录"/"请先绑定"/"无权限"/"未找到"但无实际敏感数据），说明漏洞未实际利用成功 → verdict=downgrade_to_lead
2. 如果声称"认证绕过/未授权访问/越权"但响应**不含受保护的真实数据**（只有空/错误提示/公开信息） → downgrade_to_lead
3. 如果响应含**真实受保护数据**（用户信息/密码哈希/内部记录/敏感配置）→ verdict=confirmed
4. 如果等级虚高（如 C:L 轻微信息泄露却定 high/critical，或配置缺陷/版本暴露定 medium 以上）→ verdict=adjust_severity，给出 suggested_severity

严格标准：访问控制类必须有实际数据才算confirmed；业务拒绝页一律降级。

**JSON输出（只输出JSON，不要解释）**
{{"verdict": "confirmed/downgrade_to_lead/adjust_severity", "reason": "一句话判定依据", "suggested_severity": "low/medium/high"}}"""

    # 调复核 AI（轻量 scene，复用 guard 的 provider 配置）
    try:
        from ..ai_pentest import _llm
        from ..ai_pentest.ai_config import resolve_provider_for_scene

        provider = resolve_provider_for_scene("guard")  # 复用闸刀 AI 配置
        if not provider:
            logger.debug("adversarial_review degraded: guard scene 无 provider，保守确认")
            return {"verdict": "confirmed", "reason": "复核 provider 未配置，降级确认"}

        resp = _llm.chat(messages=[{"role": "user", "content": prompt}], provider=provider,
                         timeout=60, scene="finding_review")

        if not resp.get("ok"):
            logger.debug("adversarial_review LLM failed: %s，保守确认", resp.get("error"))
            return {"verdict": "confirmed", "reason": "复核 LLM 调用失败，降级确认"}

        txt = (resp.get("content") or "").strip()
        # 提取 JSON（容错：可能包 ```json 或多余文本）
        if "```json" in txt:
            txt = txt.split("```json")[1].split("```")[0].strip()
        elif "```" in txt:
            txt = txt.split("```")[1].split("```")[0].strip()

        result = json.loads(txt)
        logger.info("adversarial_review: %s → %s (%s)", vt, result.get("verdict"), result.get("reason"))
        return result

    except Exception as exc:
        logger.debug("adversarial_review exception: %s，保守确认", exc)
        return {"verdict": "confirmed", "reason": f"复核异常({exc})，降级确认"}

COLL = Collections.INTEL_FINDING

# 证据强制：能证明漏洞真实存在的"验证类"工具（真发包/真跑 PoC，产出请求+响应）。
VERIFY_TOOLS = {"http_request", "run_nuclei", "run_npoc"}
# 三来源混排可选值（poc=PoC 插件命中，nuclei=nuclei 扫描，ai=AI 渗透已验证）
UNIFIED_SOURCES = ("ai", "poc", "nuclei")
# 漏洞处理状态合法值：""(未处理)/ submitted(已提交)/ false_positive(误报)
HANDLE_STATUSES = ("", "submitted", "false_positive")

def _host_of(url_or_target: str) -> str:
    """从 URL/target 提取 host（去 scheme/port/path），用于宽松匹配 finding 与工具调用。"""
    s = (url_or_target or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("@")[-1].split(":")[0]
    return s


def _norm_target_for_dedup(target: str) -> str:
    """漏洞 target 归一化（去重键用）：去 scheme（协议无关）、剥 www、去 query/fragment、去末尾斜杠；
    保留 path（不同路径是不同漏洞点）与端口（不同端口常是不同服务）。"""
    s = (target or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("#")[0].split("?")[0]
    host_seg = s.split("/", 1)[0]
    if host_seg.startswith("www.") and host_seg.split(":")[0].count(".") >= 2:
        s = s[4:]
    return s.rstrip("/")


def _norm_vuln_type(vuln_type: str) -> str:
    """漏洞类型归一化（去重键用）：吸收 AI 措辞微差（空白/标点/大小写/常见分类前缀）。"""
    s = (vuln_type or "").strip().lower()
    s = re.sub(r"^(信息泄露|敏感信息泄露|漏洞|风险|缺陷|配置缺陷)[\s\-:：]+", "", s)
    s = re.sub(r"[\s\-_:：、,，.。()（）\[\]【】]+", "", s)
    return s


# 信息泄露家族（v1.21.157-34）。**v1.21.157-47 收紧（治 item2 同端点多类型被吞）**：
# 只把「模糊伞形」泛称（信息泄露/敏感信息泄露/版本信息泄露）吸收进同端点已存在的更具体家族洞，
# 具体类型（硬编码凭证泄露/源码泄露/接口文档泄露/备份文件泄露/配置缺陷/内网IP/内部路径泄露）**各自独立成条不再互吞**——
# 它们是不同性质问题（如 dc.js 同端点的 AK-SK 泄露 vs sourcemap 源码泄露 vs 接口文档泄露），此前一律按等级合并只留一条=丢洞。
_INFO_LEAK_FAMILY = {
    "敏感信息泄露", "硬编码凭证泄露", "信息泄露", "版本信息泄露", "内网IP泄露", "内部路径泄露",
    "源码泄露", "SourceMap源码泄露", "接口文档泄露", "配置缺陷", "备份文件泄露",
}
# 模糊伞形泛称：语义上被任何更具体的家族类型覆盖，同端点存在具体洞时这些泛称应被吸收（避免"信息泄露"+"硬编码凭证泄露"重复）。
_GENERIC_LEAK = {"信息泄露", "敏感信息泄露", "版本信息泄露"}


def _check_same_endpoint_dup(coll, norm_target: str, vuln_type: str, new_severity: str) -> Optional[Dict[str, Any]]:
    """同端点信息泄露去重（v1.21.157-47 收紧）：**仅当新洞是模糊伞形泛称**（_GENERIC_LEAK）且同端点已有
    家族内任意其他洞时，才把新泛称洞吸收（skip，返回已存在 doc）。具体类型一律不参与此去重、各自独立成条。

    返回已存在 doc → 新洞 skip；None → 新洞入库。家族外类型（SQLi/XSS/越权等）从不参与。
    """
    if vuln_type not in _GENERIC_LEAK:
        return None  # 具体类型（或非家族）→ 不吞，独立成条（治 item2 丢洞）
    # 新洞是泛称：查同端点是否已有家族内**更具体**的洞（排除同为泛称的自身类型，norm_type 去重已处理同类型）
    candidates = list(coll.find({
        "norm_target": norm_target,
        "vuln_type": {"$in": list(_INFO_LEAK_FAMILY - _GENERIC_LEAK)},
        "source": "ai"
    }))
    return candidates[0] if candidates else None


def _resolve_asset_type(finding: Dict[str, Any], ctx: Dict[str, Any]) -> str:
    """finding 的资产类型(web/miniapp)：显式给了用给的；否则按 session_id 继承会话的 asset_type；
    都无 → 缺省 web（存量数据/普通 Web 渗透向后兼容）。"""
    at = str(finding.get("asset_type") or ctx.get("asset_type") or "").strip()
    if at:
        return at
    sid = str(finding.get("session_id") or ctx.get("session_id") or "")
    if sid:
        try:
            sess = get_repo().collection(Collections.PENTEST_SESSION).find_one(
                {"_id": _oid(sid)}, {"asset_type": 1})
            if sess and sess.get("asset_type"):
                return str(sess["asset_type"])
        except Exception:
            pass
    return "web"


# 快筛模式（探测/保守）：不深入验证/不发或少发注入探针，产出多为待验证性质 → 漏洞标「疑似」。
# 常规(src)/红队(redteam) 能自行深入验证，产出不标疑似。
_QUICK_SCAN_MODES = {"detect", "conservative"}
_MODE_LABEL = {"detect": "探测", "conservative": "保守", "src": "常规", "redteam": "红队"}


def _resolve_pentest_mode(finding: Dict[str, Any], ctx: Dict[str, Any]) -> str:
    """finding 的产出渗透模式(detect/conservative/src/redteam)：显式给 > 按 session_id 继承会话 mode > 空。
    供漏洞中心标「疑似」标签 + 来源显示「AI 渗透·<模式>」。"""
    m = str(finding.get("pentest_mode") or finding.get("mode") or ctx.get("mode") or "").strip()
    if m:
        return m
    sid = str(finding.get("session_id") or ctx.get("session_id") or "")
    if sid:
        try:
            sess = get_repo().collection(Collections.PENTEST_SESSION).find_one(
                {"_id": _oid(sid)}, {"mode": 1})
            if sess and sess.get("mode"):
                return str(sess["mode"])
        except Exception:
            pass
    return ""


def _result_obj(res: Any) -> Dict[str, Any]:
    """tool_log 里的 result 是 dispatch 返回的 JSON 字符串，解析回 dict；失败返回 {}。"""
    if isinstance(res, dict):
        return res
    if isinstance(res, str):
        try:
            return json.loads(res)
        except Exception:
            return {}
    return {}


def _positive_signal(tool_name: str, result: Any) -> str:
    """判一次验证工具调用响应是否「正向」：positive / negative / unknown。只做客观信号判断。"""
    r = _result_obj(result)
    if r.get("error"):
        return "negative"
    if tool_name == "http_request":
        if r.get("partial"):
            return "unknown"               # §1.1：读取超时/中断/部分响应一律保留 lead，不当证据
        sc = r.get("status_code")
        if sc is None or not isinstance(sc, int):
            return "unknown"
        if 400 <= sc <= 404 or sc == 429:
            return "negative"
        if sc >= 500:                      # 5xx=WAF/代理/后端崩，不能证明漏洞存在（旧坑：503 误判 verified）
            return "unknown"
        if 300 <= sc < 400:                # 3xx 重定向：跳转本身不证明任何漏洞（常是跳登录/错误提示页）
            # 客观项，非漏洞语义判断——同 5xx→unknown。治「.NET/aspx 无效参数 302 跳错误页被当正向证据
            # →误判 SQLi verified」（实测 Redir.aspx?id=1' 与 id=1 都 302 到同一"栏目不存在"页=无注入铁证）。
            return "unknown"
        if r.get("body_skipped"):
            return "unknown"               # 大文件/二进制未读 body：能访问 ≠ 拿到敏感内容
        body = r.get("body") or ""
        if len((body or "").strip()) < 50:
            return "unknown"               # 空响应/极短默认页不算证据
        return "positive"
    if tool_name in ("run_nuclei", "run_npoc"):
        try:
            return "positive" if int(r.get("count", 0)) > 0 else "negative"
        except (TypeError, ValueError):
            return "unknown"
    return "unknown"


def _sha256_of(obj: Any) -> str:
    """统一散列（证据可追溯锚，R-02）：str 直接编码，dict/list 用 json 归一(sort_keys 让 key 顺序无关)。
    编码错误 ignore 兜底。同内容每次散列一致。"""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()


def _evidence_anchor(name: str, args: Dict[str, Any], raw: Any) -> Dict[str, Any]:
    """为一条 evidence hit 派生可追溯锚（R-02·纯加法）：让证据能回答"哪个请求打出来的、
    响应是否完整、内容有没有被改、能否去重比对"。不改 evidence 结构语义，只补 key。

    散列的是**手里拿到的 result**（可能已被上游 _stream_window 窗口截断 / match_evidence 二次截 4000）——
    证明的是"这条入库证据文本"的完整性/可去重，不假装持有完整上游报文；完整性由 complete/partial/truncated 如实标注。
    method/status_code 仅 http_request 有意义；nuclei/npoc 等一次性工具降级（method 空串、status_code None、complete True）。
    """
    r = _result_obj(raw)
    is_http = (name == "http_request")
    method = str(args.get("method") or "GET").upper() if is_http else ""
    status_code = r.get("status_code") if isinstance(r, dict) else None
    partial = bool(r.get("partial")) if isinstance(r, dict) else False
    truncated = bool(r.get("truncated")) if isinstance(r, dict) else False
    url = args.get("url") or args.get("target") or ""
    resp_hash = _sha256_of(raw)
    return {
        "method": method,
        "status_code": status_code,
        "partial": partial,
        "truncated": truncated,
        "complete": (not partial and not truncated),
        "resp_hash": resp_hash,
        "req_hash": _sha256_of({"method": method, "url": url, "body": args.get("body")}),
        "observation_id": _sha256_of("{}|{}|{}".format(name, _norm_target_for_dedup(url), resp_hash))[:16],
    }


def match_evidence(finding: Dict[str, Any], tool_log: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """为一条 finding 在 tool_log 里找支撑它的验证工具调用（证据强制核心）。

    匹配：VERIFY_TOOLS + 调用 url 归一化端点（host+path）**精确相等**命中 finding.target 端点
    （父路径不挂子路径，防 /api 误挂 /api/user/list）。
    返回 (evidence_level, evidence)：confirmed(有正向证据)/attempted(打过但否定)/none。
    """
    if not tool_log:
        return "none", []
    fhost = _host_of(finding.get("target", ""))
    if not fhost:
        return "none", []
    fnorm = _norm_target_for_dedup(finding.get("target", ""))

    def _endpoint_match(cand: str) -> bool:
        if _host_of(cand) != fhost:
            return False
        return fnorm == _norm_target_for_dedup(cand)

    hits: List[Dict[str, Any]] = []
    any_attempt = False
    for t in tool_log:
        name = t.get("name") or t.get("tool") or ""
        if name not in VERIFY_TOOLS:
            continue
        args = t.get("arguments") or t.get("input") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        cand = args.get("url") or args.get("target") or ""
        if not _endpoint_match(cand):
            continue
        if finding.get("method") and str(args.get("method") or "GET").upper() != finding["method"]:
            continue
        any_attempt = True
        raw = t.get("result") or t.get("output")
        signal = _positive_signal(name, raw)
        if signal == "positive":
            hits.append({
                "tool": name, "arguments": args,
                "result": raw[:4000] if isinstance(raw, str) else raw,
                "signal": signal,
                # R-02 可追溯锚（纯加法）：observation_id/req_hash/resp_hash/method/status_code/complete...
                **_evidence_anchor(name, args, raw[:4000] if isinstance(raw, str) else raw),
            })
    if hits:
        return "confirmed", hits[:5]
    if any_attempt:
        return "attempted", []
    return "none", []


# ---------------- 报告 md 解析（AI 会话收尾批量登记用） ----------------

# 标题解析改用宽容的 _parse_header（定位定级段而非固定「时间|等级|类型」位序），兼容不同模型格式。
_TARGET_RE = re.compile(r"^-\s*目标[:：]\s*(.+?)\s*$", re.M)
_IMPACT_RE = re.compile(r"^-\s*危害[:：]\s*(.+?)\s*$", re.M)
_VERIFY_RE = re.compile(r"^-\s*验证方式[:：]\s*(.+?)\s*$", re.M)
_KEYRESP_RE = re.compile(r"^-\s*关键响应[:：]\s*(.+?)\s*$", re.M)

_SEVERITY_MAP = {
    "critical": "critical", "严重": "critical", "高危": "high", "high": "high",
    "中危": "medium", "medium": "medium", "低危": "low", "low": "low",
    "信息": "info", "info": "info", "informational": "info",
}


def _norm_severity(s: str) -> str:
    return _SEVERITY_MAP.get((s or "").strip().lower(), (s or "").strip() or "unknown")


def _looks_like_time(s: str) -> bool:
    """标题某段是否像「时间/时间占位」：纯日期时间数字符号，或空/占位符（-、未知、N/A）。
    用于宽容解析里把「时间段」与「类型段」区分开（deepseek 等模型不写时间段）。"""
    s = (s or "").strip()
    if s in ("", "-", "—", "未知", "N/A", "NA", "na"):
        return True
    residue = re.sub(r"[\d\s\-/:年月日时分秒\.]", "", s)
    return residue == "" and any(ch.isdigit() for ch in s)


def _parse_header(h3_line: str):
    """宽容解析漏洞 `###` 标题 → (time, grade_field, vuln_type)；识别不出定级段返 None。

    兼容不同模型的标题格式（治「低效模型不遵守三段式约定 → 末尾补遗解析 0 条，漏洞进不了库/面板」）：
      - 标准三段 `### 时间 | 等级 | 类型`（时间首、定级中、类型末）——原严格格式，行为不变；
      - 两段 `### 序号.类型 | CVSS向量`（deepseek 实测格式：类型首、CVSS 末、无时间段）；
      - 其它 `|` 分段：自动定位「定级段」（CVSS 3.1 向量 或 等级词），其余段按是否像时间归位，
        剩下的做类型（去掉前缀序号 `1. `/`1、`/`1)`）。
    定级段是可靠锚点（CVSS 向量/等级词有明确特征），不是靠语义猜，故安全。"""
    body = h3_line.lstrip("#").strip()
    segs = [s.strip() for s in body.split("|") if s.strip()]
    if not segs:
        return None
    grade_idx = -1
    for i, s in enumerate(segs):
        if _cvss.is_valid_vector(s) or s.strip().lower() in _SEVERITY_MAP:
            grade_idx = i
            break
    if grade_idx < 0:
        return None                                  # 无可识别定级段 → 非规范漏洞标题
    grade = segs[grade_idx]
    rest = [s for i, s in enumerate(segs) if i != grade_idx]
    time_s = ""
    type_parts: List[str] = []
    for s in rest:
        if not time_s and _looks_like_time(s):
            time_s = s
        else:
            type_parts.append(s)
    vuln_type = re.sub(r"^\s*\d+\s*[\.、\)]\s*", "", " ".join(type_parts).strip())
    if not vuln_type:
        return None                                  # 只有定级没类型 → 无法登记
    return time_s, grade, vuln_type


def _grade(mid_field: str, vuln_type: str = "", impact: str = "",
           target: str = "") -> Tuple[str, Optional[float], str, str, str]:
    """解析标题第二段 → (cvss_vector, cvss_score, cvss_severity, calibrated_severity, basis)。
    第二段是 CVSS 3.1 向量 → 代码算分（权威）；旧格式文字等级 → cvss 留空走文字归一化（标 legacy）。
    target 透传给 triage 校准（前端密钥专项：前端资源 .js/.html 里硬编码密钥即使 C:H high 也降 medium）。"""
    raw = (mid_field or "").strip()
    if _cvss.is_valid_vector(raw):
        score, sev = _cvss.score_from_vector(raw)
        vec = raw if raw.upper().startswith("CVSS:") else "CVSS:3.1/" + raw
        cal_sev, basis = _cvss.calibrate_severity(sev, score, vuln_type, impact, vector=vec, target=target)
        return vec, score, sev, cal_sev, basis
    sev = _norm_severity(raw)
    cal_sev, basis = _cvss.calibrate_severity(sev, None, vuln_type, impact, target=target)
    return "", None, sev, cal_sev, basis


def parse_findings_md(md_text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """从渗透报告 md 的 `## 漏洞` 板块解析漏洞条目。返回 (findings, errors)。
    解析容错铁律：抓不到的标 parse_error 不静默丢（格式漂移要看得见）。"""
    if not md_text:
        return [], []
    m = re.search(r"^##\s*漏洞\s*$(.*?)(?=^##\s|\Z)", md_text, re.M | re.S)
    section = m.group(1) if m else md_text

    findings: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    # 逐个 ### 标题定位（body = 本标题到下一个 ### 之间），用宽容解析 _parse_header 归位
    # 时间/定级/类型三要素（兼容不写时间段的模型，如 deepseek 的 `### 序号.类型 | CVSS`）。
    h3_iter = list(re.finditer(r"^###\s+.+$", section, re.M))
    if not h3_iter:
        return [], errors
    for i, h in enumerate(h3_iter):
        start = h.end()
        end = h3_iter[i + 1].start() if i + 1 < len(h3_iter) else len(section)
        body = section[start:end]
        parsed_h = _parse_header(h.group(0))
        if not parsed_h:
            errors.append({"block": h.group(0)[:120],
                           "reason": "### 标题无可识别定级段(CVSS向量/等级词)，解析跳过"})
            continue
        time_s, sev_s, type_s = parsed_h
        tgt = _TARGET_RE.search(body)
        codes = list(re.finditer(r"```(?:\w+)?\n(.*?)```", body, re.S))
        executable = [code.group(1).strip() for code in codes if _quality.looks_like_poc(code.group(1))]
        poc_s = executable[0] if executable else (codes[0].group(1).strip() if codes else "")
        if tgt:
            target_s = tgt.group(1).strip()
        else:
            url_m = re.search(r"https?://[^\s'\"`)]+", poc_s)
            if url_m:
                target_s = url_m.group(0)
                errors.append({"block": h.group(0)[:120],
                               "reason": "缺 - 目标: 行(已从 PoC 的 URL 兜底提取，该漏洞已保留)"})
            else:
                errors.append({"block": h.group(0)[:120],
                               "reason": "缺 - 目标: 行且 PoC 无 URL，无法定位目标，跳过"})
                continue
        imp = _IMPACT_RE.search(body)
        impact_s = imp.group(1).strip() if imp else ""
        vm = _VERIFY_RE.search(body)
        kr = _KEYRESP_RE.search(body)
        cvss_vec, cvss_score, severity, cal_severity, cal_basis = _grade(sev_s, type_s, impact_s, target_s)
        if not cvss_vec:
            errors.append({"block": h.group(0)[:120],
                           "reason": "定级第二段非 CVSS 3.1 向量(已按文字等级兜底，标 legacy)"})
        findings.append({
            "time": time_s.strip(), "cvss_vector": cvss_vec, "cvss_score": cvss_score,
            "severity": cal_severity,              # 最终 triage 等级（校准后，展示/统计用）
            "cvss_severity": severity,             # CVSS base 原始等级（留痕，可审计）
            "severity_basis": cal_basis, "grade_legacy": not bool(cvss_vec),
            "vuln_type": type_s.strip(), "target": target_s, "impact": impact_s,
            "verify_method": vm.group(1).strip() if vm else "",
            "key_response": kr.group(1).strip() if kr else "", "poc": poc_s,
        })
    return findings, errors


def is_identify_poc(plg_name: str = "", vul_name: str = "") -> bool:
    """判断一条瞭望塔 PoC 命中是否属于「纯识别类」（指纹/服务发现，非漏洞，不进漏洞中心）。
    判定：① plugin_name 以 _identify 结尾（大小写不敏感）；② 或 vul_name 以"发现"开头且不含"漏洞"。"""
    pn = (plg_name or "").strip()
    vn = (vul_name or "").strip()
    if pn.lower().endswith("_identify"):
        return True
    if vn.startswith("发现") and "漏洞" not in vn:
        return True
    return False


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0, "unknown": 0, "": 0}

# 规范等级集（用于 min_severity 阈值计算；不含 unknown/none/"" 等哨兵值）。
_CANON_SEV = ("critical", "high", "medium", "low", "info")


def _below_severities(min_sev: Optional[str]) -> List[str]:
    """求「低于阈值」的等级名列表（min_severity 过滤用，$nin 排除）。

    列规范集内低于阈值的等级（min='low' → ['info']；min='medium' → ['info','low']）
    **外加 CVSS 明确的 0 分最低档 'none'**（当它低于阈值时）：min='low' → ['info','none']。
    修 bug：`none` 是 CVSS 规范里比 info 还低的确定档（全零向量 C:N/I:N/A:N=0 分→none），
    筛「low 及以上」必须排除它——原实现只遍历不含 none 的 _CANON_SEV，致 severity='none'
    的 0 分漏洞漏进「low 及以上」视图（实测 www.dhyct.com 配置缺陷 none 漏出）。
    **仍不含 unknown/''/缺失字段**——那是「未定级」非「明确低档」，且 $nin 对字段缺失的文档
    天然保留（missing 被 $nin 匹配），故只加明确的 'none' 不会误杀 PoC/Nuclei 缺失字段
    （守「误藏真漏洞」比「多显 info」更危险的取舍）。
    min 非法/为空 → 返回 []（不过滤）。
    """
    m = (min_sev or "").strip().lower()
    if m not in _CANON_SEV:
        return []
    thr = _SEV_RANK[m]
    below = [s for s in _CANON_SEV if _SEV_RANK[s] < thr]
    if _SEV_RANK.get("none", 0) < thr:      # none(0 分)低于阈值也排除（min≥low 即排除）；min=info 时 0<0 不排除，全显
        below.append("none")
    return below


# 合法推送阈值档（注意：不能用 `in _SEV_RANK` 判——那含 ""/unknown/none 会让空配置被当有效阈值→阈值=0→全推）
_VALID_MIN_SEV = ("critical", "high", "medium", "low", "info")


def _min_severity() -> str:
    """出洞推送阈值（api_keys.feishu.min_severity），默认 medium。库不可用/未配降级 medium。"""
    try:
        doc = get_repo().collection(Collections.API_KEYS).find_one({"name": "default"}) or {}
        v = ((doc.get("feishu") or {}) or {}).get("min_severity", "")
        return v if v in _VALID_MIN_SEV else "medium"
    except Exception:
        return "medium"


def _notify_vuln(vuln_type: str, target: str, severity: str, cvss_score: Any = None, unit: str = "") -> None:
    """出洞推送：**只推已验证漏洞**（调用方保证），severity 达阈值才推。经 registry 调 NOTIFY，
    取不到（未注册）优雅降级——不硬 import notify 模块（守强解耦）。"""
    if _SEV_RANK.get((severity or "").lower(), 0) < _SEV_RANK.get(_min_severity(), 2):
        return
    svc = get_registry().get(ROLE.NOTIFY)
    if not svc:
        return                              # NOTIFY 未注册：降级静默
    lines = ["类型: {}".format(vuln_type), "目标: {}".format(target), "等级: {}".format(severity)]
    if cvss_score:
        lines.append("CVSS: {}".format(cvss_score))
    if unit:
        lines.append("单位: {}".format(unit))
    lines.append("时间: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")))
    try:
        svc.notify("\n".join(lines), title="漏洞告警 [{}]".format(str(severity).upper()),
                   level=severity, channel="feishu")
    except Exception as exc:
        logger.debug("vuln_center: notify failed: %s", exc)


def _try_upgrade_lead(coll, existed: Dict[str, Any], ev_level: str,
                      evidence: List[Dict[str, Any]], now: str) -> str:
    """同 key 已存记录时：旧 lead + 新 confirmed → 升级（不无脑 skip）。只升不降。
    返回 "upgraded"（需补推送）/ "kept"（无需动）。"""
    if ev_level != "confirmed":
        return "kept"
    if existed.get("verified") and existed.get("status") == "finding":
        return "kept"
    coll.update_one({"_id": existed["_id"]}, {"$set": {
        "verified": True, "evidence_level": "confirmed", "evidence": evidence,
        "status": "finding", "update_date": now, "upgraded_from_lead": True,
    }})
    return "upgraded"


def _persist_finding(coll, doc):
    """会话内幂等，跨会话保留历史；Mongo _id 唯一约束防多 worker 并发重复。"""
    from bson import ObjectId
    from pymongo.errors import DuplicateKeyError
    sid = doc.get("session_id", "")
    key = _quality.identity(sid or (doc.get("asset_key", "") + "|" + doc.get("unit", "")),
                            doc["target"], doc["vuln_type"], doc.get("parameter", ""), doc.get("request_method", ""))
    oid = ObjectId(key)
    existed = coll.find_one({"_id": oid})
    if not existed and sid:
        # 兼容热更前的随机 _id；只在本会话、同物理端点、同类别内寻找，不跨会话吞并。
        same_point = [row for row in coll.find({"session_id": sid, "duplicate_of": None})
                      if _quality.endpoint(row.get("target", "")) == _quality.endpoint(doc["target"])
                      and _quality.category(row.get("vuln_type", ""))[0] == doc["vuln_type"]
                      and str(row.get("parameter") or "") == str(doc.get("parameter") or "")]
        method = doc.get("request_method", "")
        candidates = [row for row in same_point if _quality.request_method(row) == method]
        if not candidates:
            # 旧记录缺方法时，仅在无歧义情况下补齐；GET 与 POST 两条已知记录不能互相吸收。
            candidates = [row for row in same_point if not _quality.request_method(row)]
        if not candidates and not method and len(same_point) == 1:
            candidates = same_point
        if candidates:
            existed = max(candidates, key=lambda row: (bool(row.get("verified")), row.get("save_date", ""), str(row["_id"])))
            if method and not _quality.request_method(existed):
                coll.update_one({"_id": existed["_id"], "request_method": {"$in": [None, ""]}},
                                {"$set": {"request_method": method}})
                claimed = coll.find_one({"_id": existed["_id"]})
                existed = claimed if claimed and _quality.request_method(claimed) == method else None
    if not existed:
        doc["_id"] = oid
        try:
            coll.insert_one(doc)
            return doc, False, False
        except DuplicateKeyError:
            existed = coll.find_one({"_id": oid})
            if not existed:
                raise
    # 旧 confirmed 不被后续 lead 降级；升级以数据库 CAS 判断，只有赢得升级的进程通知。
    upgraded = False
    if doc.get("verified") and not existed.get("verified"):
        fields = {k: v for k, v in doc.items() if k not in
                  ("_id", "save_date", "first_seen", "handle_status", "handle_note")}
        if existed.get("manual_severity"):
            fields["severity"] = existed["manual_severity"]
            fields["severity_basis"] = existed.get("severity_basis", "")
        res = coll.update_one({"_id": existed["_id"], "verified": {"$ne": True},
                               "manual_severity": existed.get("manual_severity")}, {"$set": fields})
        upgraded = bool(getattr(res, "modified_count", 0))
    coll.update_one({"_id": existed["_id"]}, {"$set": {"last_report_date": doc["update_date"]},
                   "$addToSet": {"reported_titles": doc.get("raw_vuln_type", doc["vuln_type"])}})
    saved = coll.find_one({"_id": existed["_id"]}) or existed
    return saved, True, upgraded


class FindingServiceImpl:
    """FINDING 实现。满足 contracts.FindingService（结构化子类型，无需继承）。"""

    def is_identify_poc(self, plg_name: str = "", vul_name: str = "") -> bool:
        return is_identify_poc(plg_name, vul_name)

    def parse_findings_md(self, md_text: str) -> List[Dict[str, Any]]:
        """解析报告 md 的漏洞列表(供引擎 _report_quality_score 按漏洞数×等级选 best_content)。
        只返 findings 列表(丢弃 errors)。解析失败返空。"""
        try:
            findings, _errors = parse_findings_md(md_text)
            return findings or []
        except Exception:
            return []

    def record_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """登记一条 AI 渗透漏洞（幂等 norm_target+norm_type）。证据强制：无实抓正向证据 → status=lead 降级。

        finding 关键字段：target(必填)/vuln_type(必填)/cvss_vector/impact/poc/verify_method/key_response/
                          tool_log(证据核对用)/session_id/asset_key/subdomain/unit。
        **批量模式**：finding 含 `md_text` 时，解析报告 md 逐条登记（AI 会话收尾用），返回聚合摘要
                     `{ok, ingested, leads, skipped, errors}`；tool_log/session_id/asset_key/subdomain/unit
                     作为公共上下文透传给每条。
        单条返回：`{ok, id?, dup, verified, evidence_level, severity}`。内部捕获异常不抛。
        """
        if not isinstance(finding, dict):
            return {"ok": False, "dup": False, "error": "finding 必须是 dict"}
        if "md_text" in finding:
            return self._ingest_md(finding)
        return self._record_one(finding)

    def _record_one(self, finding: Dict[str, Any], tool_log: Optional[List] = None,
                    ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = ctx or {}
        raw_vuln_type = str(finding.get("vuln_type") or "").strip()
        target = str(finding.get("target") or "").strip()
        if not raw_vuln_type or not target:
            return {"ok": False, "dup": False, "error": "vuln_type 与 target 必填"}
        # 漏洞名规范化（落库归一，零 AI token）：别名映射标准表(sqli→SQL注入)、垃圾名识别(表头/纯符号)、
        # CVE 优先保留原名。归一后的名参与去重键与展示，治"换模型产出 sqli/表头当漏洞名"。
        vuln_type, _name_matched, _name_garbage = _quality.category(raw_vuln_type)
        tool_log = tool_log if tool_log is not None else (finding.get("tool_log") or [])
        impact = finding.get("impact", "")
        cvss_vec_in = finding.get("cvss_vector", "")
        cvss_vec, cvss_score, severity, cal_severity, cal_basis = _grade(cvss_vec_in, vuln_type, impact, target)
        reproduction = _quality.reproduction(finding, tool_log)
        request_method = _quality.request_method({**finding, "poc": reproduction["poc"]})
        ev_level, evidence = match_evidence({"target": target, "method": request_method}, tool_log)
        verified = (ev_level == "confirmed")
        # 不确定性通过 verified/evidence_level 表达，不再通过篡改风险等级表达。
        severity_capped = False
        # 影响等级与证据置信度独立：未实证标 lead，不把 high/critical 改写成 info。
        norm_target = _norm_target_for_dedup(target)
        norm_type = _norm_vuln_type(vuln_type)
        unit = finding.get("unit", "") or ctx.get("unit", "")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            coll = get_repo().collection(COLL)

            # 首次发现仍跨会话追踪；同会话重复报送由 _persist_finding 幂等处理。
            key = {"norm_target": norm_target, "norm_type": norm_type}
            is_first_seen = None  # 首次发现由持久漏洞点锚确定，禁止先查后写和缺字段默认 True。
            doc = {
                "time": finding.get("time", now), "cvss_vector": cvss_vec, "cvss_score": cvss_score,
                "observed_at_ns": time.time_ns(),
                "severity": cal_severity, "cvss_severity": severity, "severity_basis": cal_basis,
                "grade_legacy": not bool(cvss_vec), "vuln_type": vuln_type, "target": target,
                # 命名规范化留痕：raw_vuln_type=AI 原始上报名；name_quality=命名质量
                # (standard=命中标准表 / garbage=表头/纯符号等异常名 / custom=未匹配但保留,如CVE/新型)。
                # 前端可据 garbage 提示"命名异常"；不因归一丢失 AI 原意。
                "raw_vuln_type": raw_vuln_type,
                "name_quality": "standard" if _name_matched else ("garbage" if _name_garbage else "custom"),
                "impact": impact, **reproduction,
                "parameter": str(finding.get("parameter") or ""),
                "request_method": request_method,
                "quality_version": _quality.QUALITY_VERSION,
                "supporting_evidence": _quality.script_support(target, tool_log),
                "verify_method": finding.get("verify_method", ""), "key_response": finding.get("key_response", ""),
                "source": "ai", "session_id": str(finding.get("session_id") or ctx.get("session_id") or ""),
                "norm_target": norm_target, "norm_type": norm_type,
                "asset_key": finding.get("asset_key", "") or ctx.get("asset_key", ""),
                "subdomain": finding.get("subdomain", "") or ctx.get("subdomain", ""),
                "asset_type": _resolve_asset_type(finding, ctx),   # web/miniapp 类型标识(会话继承+缺省web)
                "pentest_mode": _resolve_pentest_mode(finding, ctx),  # 产出模式(探测/保守=疑似;常规/红队=自证)
                "unit": unit, "verified": verified, "evidence_level": ev_level, "evidence": evidence,
                "severity_capped_by_evidence": severity_capped,   # 无实证被封顶 info（前端可标"待复核"）
                # first_seen：该资产该接口该类型是否首次发现（方案B，同 norm_target+norm_type 未命中=True）。
                # 首次=绿标「首次发现」，重复=黄标「重复发现」；重复条目默认列表隐藏，"全部漏洞"模式才显。
                "first_seen": is_first_seen,
                "status": "finding" if verified else "lead", "save_date": now, "update_date": now,
            }

            # 【v1.21.157-34】对抗式复核：verified=True 的 finding 入库前过复核 AI，治假阳性+虚高
            if verified:
                review_input = {
                    "vuln_type": vuln_type, "target": target, "cvss_vector": cvss_vec,
                    "impact": impact, "evidence": evidence
                }
                review_result = _adversarial_review(review_input)
                verdict = review_result.get("verdict", "confirmed")
                reason = review_result.get("reason", "")

                if verdict == "downgrade_to_lead":
                    # 降级为线索（假阳性：业务拒绝/无实际数据）
                    doc["verified"] = False
                    doc["evidence_level"] = "attempted"
                    doc["status"] = "lead"
                    doc["review_downgraded"] = True
                    doc["review_reason"] = reason
                    logger.info("finding downgraded by review: %s @ %s (%s)", vuln_type, target, reason)
                    verified = False  # 后续不推送、不记 verified
                elif verdict == "adjust_severity":
                    # 调整等级（虚高）
                    sugg_sev = review_result.get("suggested_severity", "").lower()
                    if sugg_sev in ("critical", "high", "medium", "low", "info"):
                        doc["severity"] = sugg_sev
                        doc["review_adjusted"] = True
                        doc["review_reason"] = reason
                        logger.info("finding severity adjusted by review: %s @ %s %s→%s (%s)",
                                    vuln_type, target, cal_severity, sugg_sev, reason)
                        cal_severity = sugg_sev  # 更新后续推送等级
                # confirmed: 保持原样

            saved, duplicate, upgraded = _persist_finding(coll, doc)
            try:
                _finding_index.index_one(get_repo(), saved)
                _finding_index.annotate(get_repo(), [saved])
            except Exception as exc:
                saved = {**saved, "first_seen": None}
                logger.warning("finding identity pending id=%s: %s", saved["_id"], type(exc).__name__)
            if saved.get("verified") and (not duplicate or upgraded):
                _notify_vuln(vuln_type, target, saved["severity"], saved.get("cvss_score"), unit)
            return {"ok": True, "id": str(saved["_id"]), "dup": duplicate, "upgraded": upgraded,
                    "verified": bool(saved.get("verified")), "evidence_level": saved.get("evidence_level", "none"),
                    "severity": saved["severity"], "poc_quality": saved.get("poc_quality", "needs_review"),
                    "first_seen": saved.get("first_seen")}
        except Exception as exc:
            logger.debug("vuln_center: record_finding failed: %s", exc)
            return {"ok": False, "dup": False, "error": str(exc)}

    def _ingest_md(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """批量：解析报告 md 逐条登记（幂等）。公共上下文（tool_log/session_id/unit 等）透传每条。"""
        md_text = finding.get("md_text") or ""
        tool_log = finding.get("tool_log") or []
        ctx = {k: finding.get(k, "") for k in ("session_id", "asset_key", "subdomain", "unit")}
        parsed, errors = parse_findings_md(md_text)
        ingested = leads = skipped = 0
        for f in parsed:
            r = self._record_one(f, tool_log=tool_log, ctx=ctx)
            if not r.get("ok"):
                continue
            if r.get("dup"):
                skipped += 1
            elif r.get("verified") or r.get("upgraded"):
                ingested += 1
            else:
                leads += 1
        if errors:
            logger.warning("vuln_center ingest md 有 %d 个漏洞块解析失败(格式漂移): %s",
                           len(errors), errors[:3])
        return {"ok": True, "ingested": ingested, "leads": leads, "skipped": skipped,
                "errors": errors, "findings": parsed}

def _oid(v: Any):
    """字符串 → bson.ObjectId（惰性 import，对齐 core/db.py 惰性 pymongo）。

    无 bson（如无 pymongo 的开发/测试机）时回退返回原值——真实部署 Linux 有 pymongo，
    ObjectId 生效；测试用 fake repo 存字符串 _id，回退原值即可匹配。仅在 v 为空时返 None。
    """
    if v in (None, ""):
        return None
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v                       # 无 bson：回退原值（测试/无 pymongo 环境）
    except Exception:
        return v                       # 非法 ObjectId 回退原值（对齐平台约定；生产真库对字符串查不到，效果一致）


def _norm_unified(doc: Dict[str, Any], source: str) -> Dict[str, Any]:
    """把一条原始漏洞文档归一成混排列表行（只取公共字段，详情另拉）。"""
    base = {
        "_id": str(doc.get("_id", "")), "source": source,
        "save_date": doc.get("save_date", ""), "task_id": doc.get("task_id", ""),
        "task_name": "",
        "session_id": str(doc.get("session_id", "")) if source == "ai" else "",
        "handle_status": doc.get("handle_status", "") or "",
        "handle_by": doc.get("handle_by", "") or "", "handle_at": doc.get("handle_at", "") or "",
    }
    if source == "ai":
        _sev = (doc.get("severity") or "unknown").lower()
        _chain = (doc.get("chain_severity") or "").lower()
        _eff = _chain if _SEV_RANK.get(_chain, 0) > _SEV_RANK.get(_sev, 0) else _sev
        _mode = (doc.get("pentest_mode") or "").strip()
        base.update({
            "name": doc.get("vuln_type", "") or "未分类", "target": doc.get("target", ""),
            "severity": _eff, "base_severity": _sev, "chain_severity": _chain,
            "chain_title": doc.get("chain_title", ""), "verified": bool(doc.get("verified")),
            "unit": doc.get("unit", ""), "cvss_score": doc.get("cvss_score"),
            "cvss_severity": doc.get("cvss_severity", ""), "severity_basis": doc.get("severity_basis", ""),
            # 产出模式：来源显示「AI 渗透·<模式>」；探测/保守=快筛未深验→标「疑似」
            "pentest_mode": _mode, "mode_label": _MODE_LABEL.get(_mode, ""),
            "suspect": _mode in _QUICK_SCAN_MODES,
            # 首次/重复发现（方案B）：存量无字段默认 True（不误标黄）。前端漏洞名列末尾标绿/黄 tag。
            "first_seen": doc.get("first_seen"),
            "first_seen_at": doc.get("first_seen_at", ""), "first_finding_id": doc.get("first_finding_id", ""),
            "point_key": doc.get("point_key", ""), "occurrence_count": doc.get("occurrence_count", 1),
            # norm_target/norm_type：漏洞点去重键（同资产+同接口+同类型），供 list_unified_findings 去重用。
            "norm_target": doc.get("norm_target", ""), "norm_type": doc.get("norm_type", ""),
            "request_method": doc.get("request_method", ""), "parameter": doc.get("parameter", ""),
            "dedup_target": _quality.endpoint(doc.get("target", "")),
        })
    elif source == "nuclei":
        base.update({
            "name": doc.get("vuln_name", "") or doc.get("template_id", "") or "nuclei",
            "target": doc.get("vuln_url", "") or doc.get("target", ""),
            "severity": (doc.get("vuln_severity") or "unknown").lower(),
            "verified": True, "unit": "", "cvss_score": None,
        })
    else:  # poc（vuln 集合，NPoC 插件命中，无 severity 字段）
        base.update({
            "name": doc.get("vul_name", "") or doc.get("plg_name", "") or "PoC",
            "target": doc.get("target", ""),
            "severity": (doc.get("vuln_severity") or doc.get("severity") or "unknown").lower(),
            "verified": True, "unit": "", "cvss_score": None,
        })
    return base


def _attach_task_names(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """为当前页漏洞行批量回填 task_name（四级目录第一级）。poc/nuclei 经 task_id；ai 经 session→source_task_id 两跳。"""
    if not rows:
        return rows
    repo = get_repo()
    sess_ids = {r["session_id"] for r in rows if r.get("source") == "ai" and r.get("session_id")}
    sess2task: Dict[str, str] = {}
    if sess_ids:
        oids = [o for o in (_oid(s) for s in sess_ids) if o is not None]
        if oids:
            for s in repo.collection(Collections.PENTEST_SESSION).find(
                    {"_id": {"$in": oids}}, {"source_task_id": 1}):
                sess2task[str(s["_id"])] = s.get("source_task_id", "") or ""
    task_ids = set()
    for r in rows:
        tid = sess2task.get(r.get("session_id", ""), "") if r.get("source") == "ai" else (r.get("task_id", "") or "")
        if tid:
            task_ids.add(tid)
    task2name: Dict[str, str] = {}
    if task_ids:
        oids = [o for o in (_oid(t) for t in task_ids) if o is not None]
        if oids:
            for t in repo.collection(Collections.TASK).find({"_id": {"$in": oids}}, {"name": 1}):
                task2name[str(t["_id"])] = t.get("name", "") or ""
    for r in rows:
        tid = sess2task.get(r.get("session_id", ""), "") if r.get("source") == "ai" else (r.get("task_id", "") or "")
        r["task_name"] = task2name.get(tid, "")
    return rows


_POC_EXCLUDE_IDENTIFY = {"$nor": [{"plg_name": {"$regex": "_identify$", "$options": "i"}},
                                  {"vul_name": {"$regex": "^发现(?!.*漏洞)"}}]}


def _apply_handle_date(q: Dict[str, Any], handle_status: Optional[str],
                       date_from: Optional[str], date_to: Optional[str]) -> Dict[str, Any]:
    """处理状态 + 时间范围过滤注入（列表/计数同口径）。未指定 handle_status 时默认藏误报。"""
    if not handle_status:
        q["handle_status"] = {"$ne": "false_positive"}
    elif handle_status == "unhandled":
        q["handle_status"] = {"$in": [None, ""]}
    else:
        q["handle_status"] = handle_status
    if date_from or date_to:
        rng: Dict[str, Any] = {}
        if date_from:
            rng["$gte"] = str(date_from)
        if date_to:
            dt = str(date_to)
            rng["$lte"] = dt + " 23:59:59" if len(dt) <= 10 else dt
        q["save_date"] = rng
    return q


def list_unified_findings(unit=None, severity=None, source=None, keyword=None, verified=None,
                          page=1, size=20, include_leads=False, handle_status=None,
                          date_from=None, date_to=None, min_severity=None, dedup=True) -> Dict[str, Any]:
    """三来源混排列表（vuln + nuclei_result + intel_finding），按 save_date 倒序 + 分页。
    **v1.21.157-47（治 item2 漏洞被吞）**：不再默认锁 verified=True 隐藏线索——未证实的 finding 已被
    证据封顶闸降到 info（见 _record_one），默认按 min_severity(low) 过滤即自然隐藏 info 噪声；
    用户把 min_severity 调到 info/全部即可看到全部线索（含 attempted/none）。既不丢洞、又不刷屏。
    显式传 verified=1 仍只看已验证；include_leads 保留兼容。返回 {items, total}。

    severity=精确等级过滤（单选）；min_severity=最低等级阈值（默认前端传 low，隐藏 info 噪声）。
    两者可叠加；severity 精确命中时 min_severity 自然被 severity 收窄，无冲突。"""
    page = max(1, int(page or 1))
    size = max(1, int(size or 20))
    # verified=None → 不加 verified 过滤（已验证漏洞 + 线索都进候选，靠 min_severity 控噪）。
    # 仅当调用方显式传 verified 才按其过滤（如 stat 卡"已验证漏洞"计数走 verified=True）。
    sources = [source] if source in UNIFIED_SOURCES else list(UNIFIED_SOURCES)
    if unit and source not in ("poc", "nuclei"):
        sources = [s for s in sources if s == "ai"]
    kw = (keyword or "").strip()
    below = _below_severities(min_severity)
    fetch_n = page * size
    repo = get_repo()
    source_totals = {}
    if "ai" in sources:
        _finding_index.ensure_legacy_index(repo)

    def _collect(coll_name: str, src: str, extra_q: Dict[str, Any]) -> List[Dict[str, Any]]:
        q = dict(extra_q)
        field = {"ai": "severity", "nuclei": "vuln_severity"}.get(src, "vuln_severity")
        if severity:
            q[field] = severity.lower()
        elif below:                            # min_severity：排除低于阈值的规范等级（$nin 不误杀缺失字段）
            q[field] = {"$nin": below}
        _apply_kw_clause(q, src, kw)           # AUD-10：keyword 下推到 DB 查询（截取前过滤，不漏旧记录）
        _apply_handle_date(q, handle_status, date_from, date_to)
        if src == "ai":
            raw, count = _finding_index.select_rows(repo.collection(coll_name), q, fetch_n, dedup)
            source_totals[src] = count
            _finding_index.annotate(repo, raw)
            return [_norm_unified(row, src) for row in raw]
        source_totals[src] = repo.collection(coll_name).count_documents(q)
        return [_norm_unified(d, src) for d in repo.collection(coll_name).find(q).sort([("save_date", -1), ("_id", -1)]).limit(fetch_n)]

    merged: List[Dict[str, Any]] = []
    for src in sources:
        if src == "ai":
            aq: Dict[str, Any] = {"source": "ai", "duplicate_of": None}
            if unit:
                aq["unit"] = {"$regex": re.escape(unit.strip()), "$options": "i"}
            if verified is not None:
                aq["verified"] = bool(verified)
            merged += _collect(COLL, "ai", aq)
        elif src == "nuclei":
            merged += _collect(Collections.NUCLEI_RESULT, "nuclei", {})
        elif src == "poc":
            merged += _collect(Collections.VULN, "poc", dict(_POC_EXCLUDE_IDENTIFY))

    # AUD-10：keyword 已下推到各来源 DB 查询（见 _collect 的 _apply_kw_clause），此处不再 Python 后过滤。
    # 修复前是「每源先 limit(page*size) 截取 → 再 Python 内 keyword 过滤 → total 取截取后长度」，
    # 导致命中项若在截取窗口外则漏、total 偏小（UI 显示不存在、翻页也找不回）。
    merged.sort(key=lambda r: r.get("save_date") or "", reverse=True)
    # AI 已在数据库分页前分组，此处只合并各来源的窗口。
    page_rows = merged[(page - 1) * size: page * size]
    _attach_task_names(page_rows)
    # 总数在分组后、分页前计算，不受页码影响。
    total = sum(source_totals.values())
    return {"items": page_rows, "total": total}


def _kw_terms(kw: str) -> List[str]:
    """拆关键词为词项（空白分隔，去空）。"""
    return [t for t in (kw or "").strip().lower().split() if t]


# 各来源可搜字段（对齐 _norm_unified 的 name/target/unit 取值来源），keyword 在这些字段上做 OR 正则。
_KW_FIELDS = {
    "ai": ("vuln_type", "target", "unit"),
    "nuclei": ("vuln_name", "template_id", "vuln_url", "target"),
    "poc": ("vul_name", "plg_name", "target"),
}


def _apply_kw_clause(q: Dict[str, Any], src: str, kw: str) -> None:
    """把 keyword 下推为 DB 查询条件（AUD-10）：每个词项在该来源可搜字段上 OR 正则命中，
    多词项之间 AND（全部命中）。空 keyword 不加条件。就地改 q。"""
    terms = _kw_terms(kw)
    if not terms:
        return
    fields = _KW_FIELDS.get(src, ("target",))
    ands = []
    for t in terms:
        rx = {"$regex": re.escape(t), "$options": "i"}
        ands.append({"$or": [{f: rx} for f in fields]})
    # 与已有条件合并：统一并入 $and，避免覆盖调用方可能已放的 $or/$and
    existing = q.pop("$and", [])
    q["$and"] = list(existing) + ands


def _unified_count(sources, unit, severity, source, verified, handle_status=None,
                   date_from=None, date_to=None, min_severity=None, kw="") -> int:
    repo = get_repo()
    below = _below_severities(min_severity)

    def _sev_clause(field: str, q: Dict[str, Any]) -> None:
        if severity:
            q[field] = severity.lower()
        elif below:
            q[field] = {"$nin": below}

    total = 0
    for src in sources:
        if src == "ai":
            q: Dict[str, Any] = {"source": "ai", "duplicate_of": None}
            if unit:
                q["unit"] = {"$regex": re.escape(unit.strip()), "$options": "i"}
            if verified is not None:
                q["verified"] = bool(verified)
            _sev_clause("severity", q)
            _apply_kw_clause(q, "ai", kw)      # AUD-10：count 与 items 用完全相同的 keyword 过滤
            total += repo.collection(COLL).count_documents(
                _apply_handle_date(q, handle_status, date_from, date_to))
        elif src == "nuclei":
            q = {}
            _sev_clause("vuln_severity", q)
            _apply_kw_clause(q, "nuclei", kw)
            total += repo.collection(Collections.NUCLEI_RESULT).count_documents(
                _apply_handle_date(q, handle_status, date_from, date_to))
        elif src == "poc":
            q = dict(_POC_EXCLUDE_IDENTIFY)
            _sev_clause("vuln_severity", q)
            _apply_kw_clause(q, "poc", kw)
            total += repo.collection(Collections.VULN).count_documents(
                _apply_handle_date(q, handle_status, date_from, date_to))
    return total


_SRC_COLL = {"ai": COLL, "poc": Collections.VULN, "nuclei": Collections.NUCLEI_RESULT}


def unified_detail(source: str, _id: str) -> Optional[Dict[str, Any]]:
    """按来源拉单条漏洞完整记录（详情取全字段：AI 的 CVSS/证据、PoC/nuclei 原字段）。"""
    coll_name = _SRC_COLL.get(source)
    if not coll_name:
        return None
    oid = _oid(_id)
    if oid is None:
        return None
    try:
        doc = get_repo().collection(coll_name).find_one({"_id": oid})
    except Exception:
        return None
    if not doc:
        return None
    if source == "ai" and doc.get("session_id") and doc.get("quality_version") != _quality.QUALITY_VERSION:
        reconcile_session_findings(doc["session_id"])
        doc = get_repo().collection(coll_name).find_one({"_id": oid}) or doc
    visited = set()
    while source == "ai" and doc.get("duplicate_of"):
        if str(doc["_id"]) in visited:
            return None
        visited.add(str(doc["_id"]))
        replacement = get_repo().collection(coll_name).find_one({"_id": _oid(doc["duplicate_of"])})
        if not replacement:
            break
        doc = replacement
    doc = dict(doc)  # 不把数据库/测试替身中的原 _id 就地改成字符串。
    if source == "ai":
        _finding_index.ensure_legacy_index(get_repo())
        _finding_index.index_one(get_repo(), doc)
        _finding_index.annotate(get_repo(), [doc])
    doc["_id"] = str(doc["_id"])
    doc["source"] = source
    return doc


def delete_unified(source: str, ids: List[str]) -> int:
    """漏洞中心批量删除：按来源删对应集合的多条记录。返回删除条数。"""
    coll_name = _SRC_COLL.get(source)
    if not coll_name or not ids:
        return 0
    oids = [o for o in (_oid(i) for i in ids) if o is not None]
    if not oids:
        return 0
    try:
        return get_repo().collection(coll_name).delete_many({"_id": {"$in": oids}}).deleted_count
    except Exception as exc:
        logger.debug("vuln_center: delete_unified failed: %s", exc)
        return 0


def mark_unified(source: str, ids: List[str], handle_status: str, handle_by: str = "") -> int:
    """漏洞中心批量标记处理状态（""重置/submitted/false_positive）。记 handle_by/handle_at 审计。返回更新条数。"""
    coll_name = _SRC_COLL.get(source)
    if not coll_name or not ids:
        return 0
    if handle_status not in HANDLE_STATUSES:
        raise ValueError("非法 handle_status: {}".format(handle_status))
    oids = [o for o in (_oid(i) for i in ids) if o is not None]
    if not oids:
        return 0
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    set_fields = {"handle_status": handle_status, "update_date": now}
    set_fields["handle_by"] = handle_by or "" if handle_status else ""
    set_fields["handle_at"] = now if handle_status else ""
    try:
        return get_repo().collection(coll_name).update_many(
            {"_id": {"$in": oids}}, {"$set": set_fields}).modified_count
    except Exception as exc:
        logger.debug("vuln_center: mark_unified failed: %s", exc)
        return 0


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0, "": 0}


def downgrade_severity(source: str, ids: List[str], target_severity: str, handle_by: str = "") -> Dict[str, Any]:
    """人工降低漏洞危害等级（item5，v1.21.157-47）。**只降不升**：目标等级必须严格低于当前等级，
    否则该条跳过。仅 AI 来源(intel_finding)支持（poc/nuclei 是外部工具产出，不改其定级）。
    记 manual_severity/downgraded_by/downgraded_from 审计。返回 {updated, skipped}。"""
    if source != "ai":
        return {"error": "仅 AI 漏洞支持人工降级", "updated": 0}
    tgt = _norm_severity(target_severity)
    if tgt not in _SEV_RANK:
        return {"error": "非法目标等级: {}".format(target_severity), "updated": 0}
    tgt_rank = _SEV_RANK[tgt]
    oids = [o for o in (_oid(i) for i in (ids or [])) if o is not None]
    if not oids:
        return {"error": "ids 必填", "updated": 0}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    coll = get_repo().collection(COLL)
    updated, skipped = 0, 0
    for o in oids:
        d = coll.find_one({"_id": o})
        if not d:
            skipped += 1; continue
        cur = (d.get("severity") or "").lower()
        if _SEV_RANK.get(cur, 0) <= tgt_rank:   # 只降不升：当前≤目标 → 跳过
            skipped += 1; continue
        coll.update_one({"_id": o}, {"$set": {
            "severity": tgt, "manual_severity": tgt, "downgraded_from": cur,
            "downgraded_by": handle_by or "", "downgraded_at": now, "update_date": now,
            "severity_basis": (d.get("severity_basis", "") + " | " if d.get("severity_basis") else "")
                              + "人工降级 {}→{}".format(cur, tgt)}})
        updated += 1
    return {"ok": True, "updated": updated, "skipped": skipped}


def reconcile_session_findings(session_id: str, dry_run: bool = False) -> Dict[str, Any]:
    """热更后的存量会话惰性修复；只更新派生质量字段，保留原文、证据与重复条目原始记录。"""
    repo = get_repo()
    sess = repo.collection(Collections.PENTEST_SESSION).find_one({"_id": _oid(session_id)})
    if not sess:
        return {"ok": False, "error": "session not found"}
    logs = sess.get("tool_log") or []
    coll = repo.collection(COLL)
    rows = list(coll.find({"session_id": str(session_id), "duplicate_of": None}))
    groups = {}
    updates = []
    for row in rows:
        canon, matched, _ = _quality.category(row.get("raw_vuln_type") or row.get("vuln_type", ""))
        original_poc = row.get("poc_original", row.get("poc", ""))
        reproduction = _quality.reproduction({**row, "poc": original_poc}, logs)
        method = _quality.request_method({**row, "poc": reproduction["poc"]})
        key = _quality.identity(session_id, row.get("target", ""), canon, row.get("parameter", ""), method)
        groups.setdefault(key, []).append(row)
        if row.get("quality_version") == _quality.QUALITY_VERSION:
            continue
        _, _, _, severity, basis = _grade(row.get("cvss_vector", ""), canon, row.get("impact", ""), row.get("target", ""))
        # 已有人工/对抗复核评级不以无证据理由覆盖；保留明确复核结论及说明。
        if row.get("review_adjusted"):
            severity, basis = row.get("severity", severity), row.get("review_reason", basis)
        if row.get("manual_severity"):
            severity, basis = row["manual_severity"], row.get("severity_basis", "")
        fields = {"vuln_type": canon, "norm_type": _norm_vuln_type(canon), "severity": severity,
                  "point_index_version": 0,
                  "severity_basis": basis, "severity_capped_by_evidence": False,
                  "quality_version": _quality.QUALITY_VERSION,
                  "request_method": method,
                  "supporting_evidence": _quality.script_support(row.get("target", ""), logs),
                  "poc_original": original_poc, **reproduction}
        updates.append({"id": str(row["_id"]), "severity_before": row.get("severity"), "severity_after": severity,
                        "poc_quality": fields["poc_quality"], "script_references": len(fields["supporting_evidence"])})
        if not dry_run:
            coll.update_one({"_id": row["_id"], "quality_version": row.get("quality_version"),
                             "cvss_vector": row.get("cvss_vector"), "poc": row.get("poc"),
                             "manual_severity": row.get("manual_severity")}, {"$set": fields})
    duplicates = []
    for group in groups.values():
        if len(group) < 2:
            continue
        canonical = max(group, key=lambda row: (bool(row.get("verified")), bool(row.get("manual_severity")), row.get("save_date", ""), str(row["_id"])))
        for row in group:
            if row["_id"] == canonical["_id"]:
                continue
            duplicates.append({"id": str(row["_id"]), "duplicate_of": str(canonical["_id"])})
            if not dry_run:
                coll.update_one({"_id": row["_id"], "duplicate_of": None}, {"$set": {
                    "duplicate_of": str(canonical["_id"]), "duplicate_reason": "同会话、端点、规范类别与参数重复",
                    "quality_version": _quality.QUALITY_VERSION}})
    return {"ok": True, "updates": updates, "duplicates": duplicates, "dry_run": dry_run}


def query_hazard_template(vuln_type: str) -> Dict[str, Any]:
    """按类型名查《漏洞危害等级表》单条基准（供 ai_tools.query_finding_template）。整表不返，只回单条。"""
    return _hazard_table.query_template(vuln_type)


def finding_stat(unit=None) -> Dict[str, Any]:
    """漏洞统计：AI 渗透（intel_finding）已验证 vs 线索分开计 + 瞭望塔扫描（vuln/nuclei）合计。"""
    repo = get_repo()
    # 与去重列表(list_unified_findings 的 AI 分支)完全同口径:同 source/duplicate_of 过滤 + unit 用相同 regex。
    fq: Dict[str, Any] = {"source": "ai", "duplicate_of": None}
    if unit:
        fq["unit"] = {"$regex": re.escape(unit.strip()), "$options": "i"}
    try:
        fcoll = repo.collection(COLL)
        # 卡片与去重列表口径一致(v1.21.163-16 收尾):列表走 _finding_index.select_rows 按 point_key 跨会话去重,
        # 卡片此前用未去重 count_documents(仅 duplicate_of 同会话去重)→ 卡片数≥列表数。改用现成但此前未接线的
        # _finding_index.statistics()(同 point_key 分组口径);先 ensure_legacy_index 回填 point_key(同列表)。
        _finding_index.ensure_legacy_index(repo)
        ai_verified, ai_leads, by_sev, by_type = _finding_index.statistics(fcoll, fq)
        # poc/nuclei 是系统扫描来源，无 unit 维度（unit 是情报归集层才有）。
        # 修 bug：原 `if not unit` 使按单位筛选时 poc/nuclei 统计恒 0，而列表(list_unified_findings)
        # 对 poc/nuclei 忽略 unit 全量显示 → 统计与列表口径不一致，用户见"系统扫描=0/合计对不上"。
        # 现统一口径：poc/nuclei 恒全量计（与列表一致）；unit_scoped 标记告知前端该口径，避免误解。
        poc_total = (repo.collection(Collections.VULN).count_documents(dict(_POC_EXCLUDE_IDENTIFY))
                     + repo.collection(Collections.NUCLEI_RESULT).count_documents({}))
        return {
            "ai": {"total": ai_verified, "verified": ai_verified, "leads": ai_leads,
                   "by_severity": by_sev, "by_type": by_type},
            "poc": {"total": poc_total, "unit_scoped": False},
            "combined_total": ai_verified + poc_total, "unit": unit or "",
        }
    except Exception as exc:
        logger.debug("vuln_center: finding_stat failed: %s", exc)
        return {"ai": {"total": 0, "verified": 0, "leads": 0, "by_severity": {}, "by_type": {}},
                "poc": {"total": 0}, "combined_total": 0, "unit": unit or ""}


# —— Impl 扩展方法（供 router 经 registry 调查询/标记/统计；Protocol 只含 record_finding/is_identify_poc）——
FindingServiceImpl.list_unified_findings = staticmethod(list_unified_findings)
FindingServiceImpl.reconcile_session_findings = staticmethod(reconcile_session_findings)
FindingServiceImpl.unified_detail = staticmethod(unified_detail)
FindingServiceImpl.delete_unified = staticmethod(delete_unified)
FindingServiceImpl.mark_unified = staticmethod(mark_unified)
FindingServiceImpl.downgrade_severity = staticmethod(downgrade_severity)
FindingServiceImpl.finding_stat = staticmethod(finding_stat)
FindingServiceImpl.query_hazard_template = staticmethod(query_hazard_template)


# —— 进程级单例 + registry 接入 ——
_service = FindingServiceImpl()


def get_service() -> FindingServiceImpl:
    return _service








