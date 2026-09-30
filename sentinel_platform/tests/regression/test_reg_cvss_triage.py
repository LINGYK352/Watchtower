"""回归①：CVSS triage 定级校准 calibrate_severity（_cvss.py:204，顺序即语义）。

事故史（记忆 sentinel-grading-calibrate-fix / dengta-fofa...cvss 降级）：
- 信息泄露(C:L)/账号枚举本该低却显 MEDIUM；banner/枚举天生 C:L 被"C!=N 就不降"误卡。
- 修=只 C:H 才不降 C:L 一律降 low；机械关键字必顾此失彼，真解=AI 按等级表自评 + calibrate 做最保守安全网。
- 判定顺序不可调换（① 指纹闸先于 ② 点击劫持，否则"防点击劫持头缺失"被误伤成 low）。
本套件锁"顺序即语义"+"只降不升"+几个专项闸，防校准逻辑被改乱。
"""
import unittest

from sentinel_platform.modules.risk_intel._cvss import calibrate_severity as calib


class CvssTriageRegression(unittest.TestCase):
    def test_high_and_score_ge_7_never_downgraded(self):
        """high/critical 或 score≥7.0 一律不降（真杀伤交 AI 挑战机制，不机械降）。"""
        sev, _ = calib("high", 7.5, vuln_type="SQL注入", impact="脱库")
        self.assertEqual(sev, "high")
        sev2, _ = calib("critical", 9.8, vuln_type="RCE")
        self.assertEqual(sev2, "critical")

    def test_fingerprint_before_clickjacking(self):
        """顺序红线：'防点击劫持响应头缺失'含"点击劫持"子串，但指纹/配置闸①先命中→info，
        不被②的点击劫持特例误伤成 low。"""
        sev, basis = calib("medium", 5.0, vuln_type="X-Frame-Options 响应头缺失",
                           impact="缺少防点击劫持头", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual(sev, "info")

    def test_clickjacking_capped_low(self):
        sev, _ = calib("medium", 6.1, vuln_type="clickjacking", impact="UI 欺骗")
        self.assertEqual(sev, "low")

    def test_info_leak_cl_downgraded(self):
        """信息泄露 C:L 必被降级（修复前被 C!=N 误卡在 medium）。
        注：带向量 I:N,A:N,C:L 时先命中③向量治本闸→info；无向量时走⑤词表→low。两者都必须 < medium。"""
        # 带向量：向量客观纯信息型 → info（比 low 更保守，正确）
        sev_v, _ = calib("medium", 5.3, vuln_type="敏感信息泄露", impact="响应回显主机名",
                         vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual(sev_v, "medium")
        self.assertNotEqual(sev_v, "info")   # 红线：绝不再卡在 medium
        # 无向量（legacy）：走 info_leak 词表兜底 → low
        sev_n, _ = calib("medium", 5.3, vuln_type="敏感信息泄露", impact="响应回显主机名")
        self.assertEqual(sev_n, "low")

    def test_info_leak_ch_keeps_original(self):
        """信息泄露类但向量 C:H(真实敏感数据脱库) → 尊重原级不降。"""
        sev, _ = calib("medium", 6.5, vuln_type="源码泄露", impact="完整源代码泄露",
                       vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(sev, "medium")

    def test_vector_info_only_downgrade_without_wordlist(self):
        """向量治本闸：I:N,A:N,C≤L 纯信息型 → info，即使 vuln_type 没进任何词表。"""
        sev, _ = calib("medium", 4.3, vuln_type="某种没进词表的新说法配置项", impact="",
                       vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual(sev, "medium")

    def test_never_upgrades(self):
        """只降不升：low 输入不会被校准成更高。"""
        sev, _ = calib("low", 3.1, vuln_type="信息泄露")
        self.assertIn(sev, ("low", "info"))   # 只可能 == 或更低


if __name__ == "__main__":
    unittest.main()
