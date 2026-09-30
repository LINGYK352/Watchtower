"""CVSS 3.1 Base Score 计算 + triage 等级校准（vuln_center 私有辅助，净室重写）。

严格按 CVSS v3.1 官方规范实现 Base Score；分数由代码算（不由 AI/人拍脑袋）。
另含 triage 校准层：CVSS base score 衡量「内在技术影响」不衡量「信息利用价值」，
信息型/指纹型泄露 base 天然偏高（≥5.3 medium），按语义 + 向量硬闸做确定性降级（只降不升）。

用法：
    score, severity = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")  # (7.5,"high")
    cal_sev, basis = calibrate_severity(severity, score, vuln_type, impact, vector=vec)

迁移来源：app/utils/cvss.py（公式/权重属客观规范，非抄源码）。本文件是 vuln_center 叶子的
同类别 `_` 私有辅助（叶子=文件的合规拆分），不对外暴露、不被别的叶子 import。
"""
from __future__ import annotations

import math
import re
from typing import Dict, Optional, Tuple

CVSS_VERSION = "3.1"

# 各指标取值权重（CVSS 3.1 规范）
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}        # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                              # Attack Complexity
_UI = {"N": 0.85, "R": 0.62}                              # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}                  # C/I/A 影响
# Privileges Required 依赖 Scope（变更时 L/H 取值不同）
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}

_METRIC_RE = re.compile(r"\b(AV|AC|PR|UI|S|C|I|A):([A-Z])\b")


def parse_vector(vector: str) -> Dict[str, str]:
    """解析 CVSS 向量字符串为 {指标: 值} dict。非法返回 {}。
    容错：大小写、有无 CVSS:3.x 前缀、空格都能吃。"""
    if not vector or not isinstance(vector, str):
        return {}
    metrics = dict(_METRIC_RE.findall(vector.upper()))
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]   # 8 个 Base 指标必须齐全
    if not all(k in metrics for k in required):
        return {}
    return metrics


def _roundup(x: float) -> float:
    """CVSS 3.1 规定的 roundup（向上取到 0.1，带精度修正）。"""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> Optional[float]:
    """按 CVSS 3.1 公式算 Base Score（0.0~10.0）。向量非法返回 None。"""
    m = parse_vector(vector)
    if not m:
        return None
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, TypeError, ValueError):
        return None


def severity_of(score: Optional[float]) -> str:
    """CVSS 3.1 定性等级映射（分数 → none/low/medium/high/critical）。"""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score_from_vector(vector: str) -> Tuple[Optional[float], str]:
    """便捷入口：向量 → (score, severity)。非法 → (None, "unknown")。"""
    s = base_score(vector)
    return s, severity_of(s)


def is_valid_vector(vector: str) -> bool:
    return bool(parse_vector(vector))


# ---------------- triage 等级校准词表（信息型/指纹型泄露 base 偏高的修正） ----------------
# 强信号：纯技术指纹/版本暴露 → info（几乎无直接危害，只是给攻击者情报）
_FINGERPRINT_HINTS = (
    "版本", "version", "banner", "serverinfo", "server info", "指纹", "fingerprint",
    "server header", "server 头", "x-powered-by", "构建号", "build", "技术栈",
    "中间件版本", "组件版本", "插件版本", "框架识别", "cms 识别", "cms识别", "中间件识别",
    "组件识别", "技术栈识别", "操作系统指纹", "os 指纹", "os指纹", "web 容器", "容器指纹",
    "waf 指纹", "cdn 指纹", "语言识别", "whatweb", "header 泄露版本", "响应头版本",
    "版本号暴露", "版本信息暴露", "app.config.js", ".config.js", "前端配置文件", "前端配置",
    "前端构建配置", "构建配置文件", "webpack", "manifest.json", "前端配置暴露", "构建产物",
    "静态资源配置",
    # 纯配置弱/未被利用（安全响应头缺失、TLS/证书配置类）→ info（几乎无直接危害，只是配置不佳，问题6）。
    # 与「已验证点击劫持」区分：点击劫持是实际可利用结论(→low，留在 _INFO_LEAK_HINTS)，头缺失只是配置问题。
    "安全头缺失", "响应头缺失", "安全响应头", "x-frame-options", "csp 缺失", "csp缺失", "hsts",
    "httponly", "secure 标志", "secure标志", "samesite", "autocomplete", "自动补全",
    "加密套件", "密码套件", "cipher", "弱 tls", "弱tls", "弱 ssl", "弱ssl", "ssl 配置", "ssl配置",
    "tls 配置", "tls配置", "自签名证书", "证书问题", "证书过期",
    # 通用配置缺陷/默认配置（纯配置弱、未展示实际危害）→ info（问题6 延伸，用户 2026-09-12 定调：
    # 「配置缺陷」类最多 info）。真危害配置（未授权访问/.git 泄露/actuator 等）留在 _INFO_LEAK_HINTS→low。
    "配置缺陷", "配置缺失", "运维配置", "misconfig", "默认配置",
)
# 前端可见密钥/凭证：硬编码在前端资源(.js/.html/前端路由)里的 key/私钥/secret。
# 关键认知：**凡是前端 JS 能拿到并用来加解密的"私钥/密钥"，攻击者打开浏览器同样能拿到并解密——
# 它对数据的真实机密性没有额外击穿(数据本就在客户端可解)**，破坏的只是"前端传输混淆强度"，
# 与"服务端配置泄露 DB 密码/云 AK/SK(能横向脱库)"的 C:H 有本质区别。故 AI 常给的 C:H high 偏高，
# 前端密钥专项校准把它降到 medium(仍非无害：加密混淆被破、可能配套后端逻辑，不降到 low/info)。
# 服务端真凭证(target 是配置文件/API 响应/服务端路径)不命中本闸，保留原级。
_FRONTEND_RES_HINTS = (".js", ".html", ".htm", ".vue", ".jsx", ".ts", ".css", ".map",
                       "/js/", "/static/", "/assets/", "/dist/", "/public/", "javascript")
_CRED_HINTS = ("私钥", "privatekey", "private key", "密钥", "secret", "appsecret", "app secret",
               "硬编码", "hardcode", "hard-code", "凭证", "credential", "秘钥", "加密密钥",
               "sm2", "sm4", "aes key", "rsa 私钥", "签名密钥", "signing key")
# 但这些"密钥"名如果指向真·服务端凭证泄露，target 会落在配置/服务端而非前端资源——不命中前端闸。


# 弱信号：泛信息泄露 / 未授权只读 / 运维配置缺陷 → low
_INFO_LEAK_HINTS = (
    "信息泄露", "敏感信息", "泄露", "泄漏", "暴露", "exposure", "disclosure", "info leak",
    "枚举", "enumerat", "未授权访问", "未授权读", "匿名访问", "目录列表", "directory listing",
    "503", "重定向失效", ".git", ".svn", ".ds_store",
    ".bak", "源码泄露", "源代码泄露", "备份文件", "备份泄露", "目录遍历", "路径遍历", "目录穿越",
    "swagger", "api 文档", "接口文档", "api docs", "openapi", "调试接口", "debug 接口",
    "actuator", "调试模式", "debug mode", "调试信息", "堆栈泄露", "报错泄露", "错误信息泄露",
    "异常堆栈", "stack trace", "报错回显", "报错信息", "内网 ip", "内部 ip", "内网地址",
    "内部域名", "内部地址", "注释泄露", "源码注释", "html 注释", "用户名枚举", "邮箱枚举",
    "账号枚举", "手机号枚举", "user enumeration", "robots", "sitemap", "默认页面",
    "示例页面", "测试页面", "phpinfo",
    # 已验证「点击劫持」= 实际可利用结论，属 low（不是 info）。安全响应头缺失类（x-frame-options/csp/hsts/
    # httponly/samesite/tls·证书配置等）已移到 _FINGERPRINT_HINTS→info（纯配置弱，问题6）——此处只留可利用项。
    "clickjacking", "点击劫持",
)


def _vector_is_low_impact(metrics: Dict[str, str], allow_avail_low: bool = False) -> bool:
    """向量是否「低影响」：无完整性影响、保密 ≤ Low、可用性按需 ≤ Low。降级硬闸，杜绝误伤真漏洞。"""
    if not metrics:
        return False
    if metrics.get("I", "N") != "N":          # 有任何完整性影响 → 不降级
        return False
    if metrics.get("C", "N") == "H":          # 高保密泄露（脱库）→ 保留原级
        return False
    a = metrics.get("A", "N")
    if a == "H":                               # 高可用影响（可打挂）→ 不降级
        return False
    if a == "L" and not allow_avail_low:
        return False
    return True


def _vector_is_info_only(metrics: Dict[str, str]) -> bool:
    """向量是否「纯信息/配置型、无实质危害」= 治本判据（不靠关键词猜名字，问题6 根治）。

    判据只看 CVSS 影响三维（AI 声明的结构化影响，比 vuln_type 自由文本可靠）：
      • I == N   无完整性影响（不能篡改数据）
      • A != H   无高可用破坏（打不挂）
      • C in (N,L) 至多轻微信息暴露（不能脱库）
    三者同时成立 → 本质就是「配置缺陷/响应头缺失/TLS 弱配置」这类无实际危害项，
    CVSS 公式却因 AV:N+C:L 结构性顶到 medium(5.3)。降到 info。

    关键：**只看影响维度，不看是否验证**——探测/保守快筛模式的 SQLi 即便没实证，
    AI 给的向量也是 C:H（SQLi 本质能读/改数据），不命中本闸，保留高危（配「疑似」标签独立于定级）。
    真危害（C:H 脱库 / I 任意非N 篡改 / A:H 打挂）任一成立即不命中，绝不误伤。"""
    if not metrics:
        return False
    if metrics.get("I", "N") != "N":          # 有任何完整性影响(能篡改) → 不是纯信息型
        return False
    if metrics.get("A", "N") != "N":          # 有任何可用性影响(哪怕 A:L 的轻微 DoS) → 不是纯信息型
        return False
    return metrics.get("C", "N") in ("N", "L")   # 至多轻微信息暴露(不能脱库 C:H)


def _is_frontend_key_leak(vuln_type: str, impact: str, target: str) -> bool:
    """前端可见密钥专项判定：**必须同时满足** ①target 是前端资源(.js/.html/前端路径) ②语义是密钥/凭证类。
    命中即"前端硬编码密钥"——前端能解密的密钥攻击者也能解密，不构成真 C:H 击穿(见词表说明)。
    双条件缺一不可，避免误伤：服务端配置泄露的真凭证 target 不在前端资源里，不会命中。"""
    tgt = (target or "").lower()
    if not any(h in tgt for h in _FRONTEND_RES_HINTS):
        return False
    text = "{} {}".format(vuln_type or "", impact or "").lower()
    return any(h in text for h in _CRED_HINTS)


def calibrate_severity(cvss_severity: str, cvss_score: Optional[float], vuln_type: str = "",
                       impact: str = "", vector: str = "", target: str = "") -> Tuple[str, str]:
    """triage 等级校准：对低影响信息型 finding 把展示等级降到 low/info（CVSS 分数保留不动）。

    入参：cvss_severity/cvss_score 为按向量算出的原始定级；vuln_type/impact 提供语义信号；
         vector 可选，提供则做「向量硬闸」；target 可选，用于前端密钥专项校准（判是否前端资源）。
    返回 (calibrated_severity, basis)：calibrated 只可能 == 或低于原级；basis 校准依据（未触发为 ""）。
    """
    sev = (cvss_severity or "").lower()
    rank = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    # 【前端密钥专项闸】优先于"high 一律不校准"：前端 JS/HTML 硬编码的私钥/密钥即使 AI 给 C:H high，
    # 也降到 medium——前端可见密钥不构成真机密性击穿(客户端本就能解密)。**仅同时命中前端资源+凭证语义**
    # 才破例校准 high，服务端真凭证(DB/AK/SK，target 非前端资源)不命中，保留原 high。只降不升。
    # 只对 medium/low/none 考虑校准；high/critical 一律不动（真杀伤，语义判断交 AI 挑战机制）。
    if sev in ("high", "critical") or (cvss_score is not None and cvss_score >= 7.0):
        return cvss_severity, ""
    # 不用 impact 中顺带提到的 version/config/令牌等词给其他漏洞降级。
    text = (vuln_type or "").lower()
    metrics = parse_vector(vector) if vector else {}

    def _lower_to(level: str, basis: str) -> Tuple[str, str]:
        if rank.get(level, 9) < rank.get(sev, 2):       # 只降不升
            return level, basis
        return cvss_severity, ""

    # 判定顺序（不可随意调换，顺序即语义优先级）：
    #   ① 指纹/配置语义 → info（含「安全头缺失」，最先——否则"防点击劫持头缺失"会被 ② 的"点击劫持"子串误伤成 low）
    #   ② 点击劫持特例 → low（已验证可利用的 UI 欺骗，危害有限；向量常带 I:L，向量闸③收不干净故用特例兜）
    #   ③ 向量治本闸 → info（不靠关键词，纯 I:N/A:N/C≤L 即无实质危害；覆盖没进词表的新说法）
    #   ④ 向量硬闸 → 非低影响不降（防混合命名误伤真漏洞）
    #   ⑤ info_leak 词表兜底 → low（信息泄露/未授权只读/枚举/运维缺陷）
    # ① 指纹/配置语义（→info）：放最前，先把"配置/头缺失"这类无害项收走，不被 ② 点击劫持子串抢
    if any(h in text for h in _FINGERPRINT_HINTS) and (not metrics or _vector_is_low_impact(metrics)):
        return _lower_to("info", "纯技术指纹/版本暴露/配置弱项，triage 降级 info(base={})".format(cvss_score))
    # ② 点击劫持特例（→low）：其向量常带 I:L(诱导用户操作=轻微完整性)，向量闸③不认 I:L 会保留 medium，
    # 但用户定调「已验证点击劫持最多 low」。向量收不干净，用极小特例兜（问题6）。
    if any(h in text for h in ("clickjacking", "点击劫持")):
        return _lower_to("low", "点击劫持(需用户交互的 UI 欺骗，危害有限)，triage 封顶 low(base={})".format(cvss_score))
    # ③ 向量治本闸（→info）：不靠关键词猜名字，向量客观为「纯信息/配置型」(I:N 且 A:N 且 C≤L) → info。
    # 覆盖配置缺陷/安全响应头缺失/TLS·证书弱配置等一切「AV:N+C:L 被 CVSS 结构性顶到 medium」的项——
    # 哪怕 vuln_type 没进任何词表也照降（治本，杜绝黑名单追词）。
    # 真危害(C:H 脱库/I 非N 篡改/A 非N 破坏)不命中，保留原级；探测模式疑似 SQLi 给 C:H 也不命中(见 _vector_is_info_only)。
    if vector:
        _m = parse_vector(vector)
        # C:L 是有限机密性损失，不等于无危害。有效向量不得仅因只读/未验证被降为 info。
        if _m:
            return cvss_severity, ""
        # ④ 向量硬闸：有向量但非低影响 → 词表也不降（防混合命名误伤真漏洞）
        if _m and not _vector_is_low_impact(_m, allow_avail_low=True):
            return cvss_severity, ""
    # ⑤ info_leak 词表兜底（→low）：信息泄露/未授权只读/枚举/运维缺陷（无向量/legacy 或向量为低影响时生效）
    if any(h in text for h in _INFO_LEAK_HINTS):
        # 只有 C:H（真敏感数据脱库/完整源码）才保留原级不降；C:L 是信息泄露天然属性 → 降 low。
        if vector:
            m = parse_vector(vector)
            if m and m.get("C", "N") == "H":
                return cvss_severity, "信息泄露类但向量 C:H(真实敏感数据脱库)，尊重原级不降"
        return _lower_to("low", "信息泄露/未授权只读/枚举/运维缺陷(C≤L)，triage 降级 low(base={})".format(cvss_score))
    return cvss_severity, ""


