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
)
# 弱信号：泛信息泄露 / 未授权只读 / 运维配置缺陷 → low
_INFO_LEAK_HINTS = (
    "信息泄露", "敏感信息", "泄露", "泄漏", "暴露", "exposure", "disclosure", "info leak",
    "枚举", "enumerat", "未授权访问", "未授权读", "匿名访问", "目录列表", "directory listing",
    "配置缺陷", "运维配置", "misconfig", "503", "重定向失效", ".git", ".svn", ".ds_store",
    ".bak", "源码泄露", "源代码泄露", "备份文件", "备份泄露", "目录遍历", "路径遍历", "目录穿越",
    "swagger", "api 文档", "接口文档", "api docs", "openapi", "调试接口", "debug 接口",
    "actuator", "调试模式", "debug mode", "调试信息", "堆栈泄露", "报错泄露", "错误信息泄露",
    "异常堆栈", "stack trace", "报错回显", "报错信息", "内网 ip", "内部 ip", "内网地址",
    "内部域名", "内部地址", "注释泄露", "源码注释", "html 注释", "用户名枚举", "邮箱枚举",
    "账号枚举", "手机号枚举", "user enumeration", "robots", "sitemap", "默认页面", "默认配置",
    "示例页面", "测试页面", "phpinfo", "安全头缺失", "响应头缺失", "安全响应头", "x-frame-options",
    "csp 缺失", "hsts", "clickjacking", "点击劫持", "httponly", "secure 标志", "samesite",
    "autocomplete", "自动补全", "加密套件", "密码套件", "cipher", "弱 tls", "弱 ssl", "ssl 配置",
    "tls 配置", "自签名证书", "证书问题", "证书过期",
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


def calibrate_severity(cvss_severity: str, cvss_score: Optional[float], vuln_type: str = "",
                       impact: str = "", vector: str = "") -> Tuple[str, str]:
    """triage 等级校准：对低影响信息型 finding 把展示等级降到 low/info（CVSS 分数保留不动）。

    入参：cvss_severity/cvss_score 为按向量算出的原始定级；vuln_type/impact 提供语义信号；
         vector 可选，提供则做「向量硬闸」——只有向量客观证实低影响才允许降级。
    返回 (calibrated_severity, basis)：calibrated 只可能 == 或低于原级；basis 校准依据（未触发为 ""）。
    """
    sev = (cvss_severity or "").lower()
    # 只对 medium/low/none 考虑校准；high/critical 一律不动（真杀伤，语义判断交 AI 挑战机制）。
    if sev in ("high", "critical") or (cvss_score is not None and cvss_score >= 7.0):
        return cvss_severity, ""
    # 向量硬闸：提供向量就必须客观确认低影响，否则不降（防混合命名误伤）
    if vector:
        metrics = parse_vector(vector)
        if metrics and not _vector_is_low_impact(metrics, allow_avail_low=True):
            return cvss_severity, ""
    text = "{} {}".format(vuln_type or "", impact or "").lower()
    rank = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def _lower_to(target: str, basis: str) -> Tuple[str, str]:
        if rank.get(target, 9) < rank.get(sev, 2):      # 只降不升
            return target, basis
        return cvss_severity, ""

    if any(h in text for h in _FINGERPRINT_HINTS):
        return _lower_to("info", "纯技术指纹/版本暴露，triage 降级 info(base={})".format(cvss_score))
    if any(h in text for h in _INFO_LEAK_HINTS):
        # 向量硬闸：只有 C:H（真敏感数据脱库/完整源码）才保留原级不降；C:L 是信息泄露天然属性 → 降 low。
        if vector:
            m = parse_vector(vector)
            if m and m.get("C", "N") == "H":
                return cvss_severity, "信息泄露类但向量 C:H(真实敏感数据脱库)，尊重原级不降"
        return _lower_to("low", "信息泄露/未授权只读/枚举/运维缺陷(C≤L)，triage 降级 low(base={})".format(cvss_score))
    return cvss_severity, ""


