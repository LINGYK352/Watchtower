"""回归⑧：AI 工具 dispatch 执行层门控（_tools.dispatch，ai_pentest/_tools.py:1791）。

对应研究 R-14（低能力模型约束由执行层保证，非提示词）/ R-15（执行合规评级）。
把"模型能提议危险动作、但执行层拦住真实副作用"固化成红线——这些门控都引发过真实事故。

**只测拦截方向（负优化红线=防欠拦截）**：项目历次事故都是"该拦没拦"（主动扫描封 IP、
低权限模式进内网）。over-block（该放行却拦）是功能问题非安全事故，不属本 harness 范围。
且被拦路径都在 dispatch 顶部、资源池 acquire 之前**早返回** → 纯函数式、零副作用；
**绝不测放行路径**（放行会触达真实执行器→触库/触网/起浏览器，违反回归层"不联网不碰库"）。

覆盖四道门控（_tools.dispatch:1797-1822）：
- 主动扫描全局禁（_ACTIVE_SCAN_TOOLS）：run_nuclei/npoc/爆破/fuzz——触发目标 WAF/封 IP 的事故元凶
  （记忆 sentinel-mode-gate-and-delete-halt / 项目说明 §15.7）。红线：**所有模式**（含 redteam、
  含 console_manual 人工接管）无条件 blocked——弱模型改 mode 或声称人工都绕不过。
- 内网立足工具（_REDTEAM_ONLY_TOOLS）：src/detect/conservative 模式拦（防低权限模式擅自进内网）。
- 持久浏览器工具（_PERSISTENT_BROWSER_TOOLS）：v1.21.157-57 起对 AI 渗透会话通用（不再门控）——
  按设计持久型重浏览器是给 AI 的主力（登录/懒加载 JS），自动+会话台都可用，内存由 L3 池管控。
- 情报沉淀开关（_INTEL_WRITE_TOOLS + intel_enabled=False）：不往共享情报库沉淀（skip，非安全 block）。
"""
import unittest

from sentinel_platform.modules.ai_pentest._tools import (
    dispatch, gate_tool, _ACTIVE_SCAN_TOOLS, _REDTEAM_ONLY_TOOLS,
    _PERSISTENT_BROWSER_TOOLS, _INTEL_WRITE_TOOLS,
)


class ActiveScanGateRegression(unittest.TestCase):
    """主动扫描工具：所有模式无条件禁（弱模型改 mode/声称人工都绕不过）。IP 封禁事故红线。"""

    def test_blocked_in_every_mode_including_redteam_and_manual(self):
        tool = "run_nuclei"
        self.assertIn(tool, _ACTIVE_SCAN_TOOLS)
        for ctx in ({"mode": "src"}, {"mode": "detect"}, {"mode": "conservative"},
                    {"mode": "redteam"}, {"mode": "redteam", "console_manual": True},
                    {"console_manual": True}):
            r = dispatch(tool, {"targets": ["http://t.com"]}, ctx)
            self.assertTrue(r.get("blocked"),
                            "主动扫描工具在 ctx={} 未被拦（IP 封禁事故红线）".format(ctx))

    def test_all_active_scan_tools_blocked_even_in_redteam(self):
        """整个 _ACTIVE_SCAN_TOOLS 集合在 redteam（最宽松档）都被拦（防将来漏进白名单）。
        全局禁在 redteam-only/浏览器门控之前，故此调用对每个工具都早返回，无副作用。"""
        for tool in _ACTIVE_SCAN_TOOLS:
            r = dispatch(tool, {}, {"mode": "redteam", "console_manual": True})
            self.assertTrue(r.get("blocked"), "{} 未被全局禁".format(tool))


class RedteamOnlyGateRegression(unittest.TestCase):
    """内网立足工具：src/detect/conservative 模式拦（防低权限模式擅自后渗透）。"""

    def _pick(self):
        # 取一个不在 active-scan（否则被更前的全局禁拦、测不到本门控）的 redteam-only 工具
        for t in sorted(_REDTEAM_ONLY_TOOLS):
            if t not in _ACTIVE_SCAN_TOOLS:
                return t
        self.skipTest("无纯 redteam-only 工具")

    def test_blocked_in_low_privilege_modes(self):
        tool = self._pick()
        for mode in ("src", "detect", "conservative"):
            r = dispatch(tool, {}, {"mode": mode})
            self.assertTrue(r.get("blocked"), "{} 在 {} 模式应被拦".format(tool, mode))
            self.assertIn("红队", str(r.get("reason", "")),
                          "{} 拦截理由应指明仅红队/人工可用".format(tool))

    def test_known_internal_tool_gated(self):
        """硬编码锚点（防"从集合悄悄移除工具"的欠拦截回归——遍历式断言抓不到被移除项）。
        internal_recon 是明确的内网后渗透工具，src 模式必须拦。"""
        self.assertIn("internal_recon", _REDTEAM_ONLY_TOOLS,
                      "internal_recon 应在 redteam-only 门控集合内")
        r = dispatch("internal_recon", {}, {"mode": "src"})
        self.assertTrue(r.get("blocked"), "internal_recon 在 src 模式必须被拦")


class PersistentBrowserGateRegression(unittest.TestCase):
    """持久浏览器工具（v1.21.157-57 放开）：对 AI 渗透会话通用——不再被 gate_tool 门控。
    按设计持久型重浏览器是给 AI 的主力（登录/懒加载 JS），自动+会话台都可用；内存由 L3 池 + MAX_GLOBAL 管控。
    **只测 gate_tool 判定（不 dispatch，放行会真起浏览器违反回归层不联网铁律）**——门控层返回 None=放行。"""

    def test_not_gated_in_auto_session(self):
        """自动会话（无 console_manual）：持久浏览器工具不再被门控拦（gate_tool 返 None）。"""
        for tool in sorted(_PERSISTENT_BROWSER_TOOLS):
            self.assertIsNone(gate_tool(tool, {"mode": "src"}),
                              "{} 自动会话不应再被门控（已放开给 AI）".format(tool))

    def test_not_gated_in_console_manual(self):
        """会话台人工接管：同样放行。"""
        for tool in sorted(_PERSISTENT_BROWSER_TOOLS):
            self.assertIsNone(gate_tool(tool, {"console_manual": True, "mode": "src"}),
                              "{} 会话台应放行".format(tool))

    def test_known_browser_tool_ungated(self):
        """硬编码锚点：browser_open 是持久浏览器主力工具，AI 渗透会话必须能用（不门控）。"""
        self.assertIn("browser_open", _PERSISTENT_BROWSER_TOOLS)
        self.assertIsNone(gate_tool("browser_open", {"mode": "src"}),
                          "browser_open 应对 AI 渗透会话放开")


class IntelWriteGateRegression(unittest.TestCase):
    """情报沉淀开关：intel_enabled=False → 情报写工具 skip（是策略选择，非安全 block）。
    红线：关闭情报体系时不往共享库沉淀，且用 skip 语义（不是 blocked，不是 error）。"""

    def test_skipped_when_intel_disabled(self):
        for tool in sorted(_INTEL_WRITE_TOOLS):
            r = dispatch(tool, {}, {"mode": "src", "intel_enabled": False})
            self.assertFalse(r.get("ok"), "{} 情报关闭时不应 ok".format(tool))
            self.assertIn("skipped", r, "{} 应带 skipped 说明".format(tool))
            self.assertFalse(r.get("blocked"), "{} 情报开关是 skip 非安全 blocked".format(tool))


if __name__ == "__main__":
    unittest.main()
