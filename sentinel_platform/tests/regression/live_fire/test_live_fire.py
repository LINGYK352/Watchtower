"""实弹效果评测占位（R-01 第二层）。

现状：scenarios/ 为空 → 整类 skip（不误报绿）。用户放入授权场景 JSON 后，此文件按 scenarios 动态生成用例。
**不在** `python -m sentinel_platform.tests.regression` 的 test_reg_*.py pattern 内，故默认门禁不跑实弹。
需真实授权靶标 + 活 LLM + 网络才有意义，assertions 执行逻辑待接活 LLM 适配（见 TODO）。
"""
import os
import glob
import json
import unittest

_SCEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios")


def _load_scenarios():
    out = []
    for p in sorted(glob.glob(os.path.join(_SCEN_DIR, "*.json"))):
        try:
            with open(p, "r", encoding="utf-8") as f:
                out.append((os.path.basename(p), json.load(f)))
        except Exception:
            pass   # 坏 JSON 不误报绿，跳过（真跑时会因场景为空而 skip）
    return out


_SCENARIOS = _load_scenarios()


@unittest.skipUnless(_SCENARIOS, "无实弹场景（scenarios/*.json 为空）——需真实授权靶标，见 live_fire/README.md")
class LiveFireEvaluation(unittest.TestCase):
    """按 scenarios/*.json 逐个跑真实渗透会话并核验发现/复现/报告。

    每个场景契约（README.md 定义）：
      {target, authorization_ref, input_context, expected_outcome, assertions:[...]}
    """
    def test_scenarios_present(self):
        # 有场景才跑到这里：先断言场景结构合法（真评测逻辑接活 LLM 后补）
        for name, sc in _SCENARIOS:
            self.assertIn("target", sc, "场景 {} 缺 target".format(name))
            self.assertIn("authorization_ref", sc, "场景 {} 缺 authorization_ref（仅限书面授权靶标）".format(name))
            # TODO(活 LLM 适配)：起真实渗透会话打 sc["target"]，按 sc["assertions"] 核验
            #   precision/复现率/每发现成本；expected_outcome 对照。需网络+活 LLM key，不进默认门禁。


if __name__ == "__main__":
    unittest.main()
