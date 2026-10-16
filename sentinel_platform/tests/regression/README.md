# 负优化回归 harness（R-01 评测地基）

把项目反复踩坑的负优化点固化成**场景回归红线**：给定输入 → 断言预期 → 可重复跑。
改动踩回同一个坑时立刻 FAIL，不再靠"用户当场拦下"。

## 跑法

```bash
# 统一入口（推荐）：只跑确定性回归层，退出码 0=全绿/非0=有失败（供门禁）
python -m sentinel_platform.tests.regression

# 子集 discover
python -m unittest discover -s sentinel_platform/tests/regression -p "test_reg_*.py"

# 全量（回归会被自动带上，不改现状）
python -m unittest discover -s sentinel_platform
```

## 覆盖的负优化点（每条对应真实事故）

| 文件 | 被测 | 事故 / 红线 |
|---|---|---|
| test_reg_resource_score.py | `dashboard._resource_score` | 资源评分改坏 3 次（恒22→踢磁盘拿93→才修对）。红线：磁盘剩 5.9GB 不得拿「充裕」；以水位为骨架；磁盘绝对余量只向下拉档 |
| test_reg_engine_progress.py | `_engine` 空转三函数+阈值常量 | 空转防护 5 阶段反复被绕。红线：`EMPTY_STREAK_LIMIT==2`（2→3 已否决）；404 空壳不算进展但 4xx 带实质 body 算（防误杀越权 403→200） |
| test_reg_cvss_triage.py | `_cvss.calibrate_severity` | 定级过度提级。红线：顺序即语义（指纹闸先于点击劫持）；C:L 信息泄露降 low、C:H 不降；只降不升 |
| test_reg_scope_match.py | `session._target_scope_match` | AUD-03 情报越界。红线：DNS 标签边界，绝不子串匹配（example.com 不命中 evil-example.com） |
| test_reg_dedup_key.py | `session._dedup_key` | v2.7.34 去重灾难。红线：键用物理标识（hostname/ip:port），绝不含 system_id/指纹；不同 hostname 壳页不合并 |
| test_reg_evidence_match.py | `vuln_center.match_evidence` | 假阳性。红线：端点精确匹配，父路径不挂子路径；打过否定=attempted 非 confirmed。含 R-02 可追溯锚（observation_id/req_hash/resp_hash/method/status_code/complete，散列稳定、nuclei 降级不炸） |
| test_reg_resource_pool_cas.py | `resource_pool.acquire` | AUD-06 超额。红线：CAS 原子准入，陈旧 rev 登记必失败、不超额 |
| test_reg_dispatch_gate.py | `_tools.dispatch` 执行层门控 | R-14/15。红线：主动扫描工具（run_nuclei/npoc/爆破/fuzz）**所有模式**（含 redteam/人工接管）无条件禁（IP 封禁事故）；内网工具仅 redteam/console_manual；持久浏览器仅 console_manual；intel_enabled=False 情报写工具 skip。**只测拦截方向**（放行路径会触达真实执行器有副作用，禁调） |

## mock 范式（易踩，务必照做）

被测函数多用**函数内 import**（`from sentinel_platform.contracts import get_registry`）。
patch 必须打**源模块**而非调用方属性，否则 mock 不生效：
- `_resource_score`：patch `sentinel_platform.contracts.get_registry`（**不是** dashboard 模块属性）+ `os.getloadavg`（`create=True`，非 Linux 无此属性）。
- 资源池：`set_repo(_FakeRepo())` 注入回归层自有 fake（`_fakes.py`，支持 $inc/$setOnInsert/matched_count）+ mock `_available_mb`/`learned_peak_mb`。
- 纯函数（scope/dedup/calibrate/engine 信号/match_evidence）：直接 import 调用，零依赖。
- **dispatch 门控：只测拦截方向**（被拦路径在资源池 acquire 之前早返回，纯函数式无副作用）。
  **绝不测放行路径**——放行会走到真实执行器（触库/触网/起 Playwright），实测会 hang 死回归层
  （踩过：intel_write 默认 enabled 调 mark_playbook_useful 连 Mongo 超时挂住）。放行方向若要测，
  复刻判据是重言式（抓不到生产回归），应交 live_fire 或模块单测（可 mock repo）。

## 边界

- 确定性层：不联网、不调 LLM、不碰生产库，本地/VM 可重复跑。
- 实弹效果评测在 `live_fire/`（真实授权靶标+活 LLM），默认不在门禁 pattern，空场景全 skip。
- 新增被测锚点时：先查对应记忆/CHANGELOG 事故，锁"防再犯"断言，不重写已有模块单测的逻辑。
- **不动 `risk_intel/tests/_fakedb.py`**（13 文件依赖，升级它=典型负优化）。回归层用自带 `_fakes.py`。
