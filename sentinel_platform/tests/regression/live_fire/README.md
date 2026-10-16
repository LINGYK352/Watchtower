# 实弹效果评测（R-01 第二层，待填）

评"真实发现率 / 复现率 / 报告可用性 / 每有效发现成本"——这是 R-01 完整版意图，需**真实书面授权靶标 + 活 LLM + 网络**，非确定性、默认不进门禁。

## 现状

`scenarios/` 为空 → `test_live_fire.py` 整类 `@unittest.skip`（**不填假数据、不误报绿**）。
`python -m sentinel_platform.tests.regression` 用 `test_reg_*.py` pattern，**不含**本层，故门禁默认不跑实弹。

## 场景格式（scenarios/*.json）

```json
{
  "target": "https://授权靶标",
  "authorization_ref": "书面授权编号/文件引用（仅限依法拥有或已获授权的目标）",
  "input_context": { "mode": "src", "mission_intel": "可选人工交代" },
  "expected_outcome": { "min_findings": 1, "must_find_types": ["越权访问"] },
  "assertions": [
    { "kind": "precision_gte", "value": 0.8 },
    { "kind": "reproducible", "value": true },
    { "kind": "cost_per_finding_lte", "unit": "token", "value": 200000 }
  ]
}
```

## 铁律

- **仅限书面授权目标**（依法拥有或已取得授权），authorization_ref 必填。
- 真跑逻辑（起会话打靶标、按 assertions 核验）待接活 LLM 适配（`test_live_fire.py` 的 TODO）。
- 已知描述复现 与 未知漏洞发现 **分榜**，不混算（对齐 CyberGym 方法）。
- 每次固定模型/提示词/工具/策略版本，多次运行报方差，防记忆泄漏虚高。
- 绝不把这里的结果当"全自动渗透可靠性"的综合结论——分阶段核验发现/复现/报告链。
