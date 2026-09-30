# 瞭望塔 Watchtower 更新日志

## 2026-09-28 更新（镜像瘦身：删除 `docker/Dockerfile` 两处冗余 chmod，`sentinel:base` 3.46G→2.64G，省 ~820M；不递增版本号——构建优化非应用迭代）

- **【镜像瘦身】删除 external 冗余 `chmod -R +x`**（`docker/Dockerfile`）：
  - **现象**：`sentinel:base` 达 3.46GB。`docker history` 实测两层异常肥——`RUN chmod -R +x external`(524M) + 软链 RUN 内 `chmod -R +x external/bin`(219M)，凭空各复制一份 external。
  - **根因**：external 内所有原生二进制（`bin/*` 全套 + nuclei/phantomjs/mihomo/killwxapkg/ncrack/wih，SSH 实测均 `-rwxr-xr-x` 755）源文件本已带执行位，`COPY` 原样保留 Unix 权限位 → 两处 `chmod -R +x` 对 755 源是**空操作**；但 `chmod -R` 会 touch 每个文件 inode，触发 overlayfs 把整个 external(501M) **copy-up 复制成新层**，白占 ~740M。
  - **修复**：删 `RUN chmod -R +x external` 整行 + 软链 RUN 内的 `chmod -R +x external/bin`（保留 `ln -sf` 建软链）。软链目标已带 755，PATH 调用不受影响；external 不入 git（`.gitignore` 排除）、经文件系统分发保权限，VM 构建源恒 755。
  - **验证（VM 实测目标态，非静态检查）**：VM `docker build` 出 `sentinel:slimtest` = **2.64GB**（vs base 3.46GB，省 **820M / -23.7%**）；容器内 `ls -la` 确认 subfinder/nuclei/phantomjs 仍 755，`subfinder -version`(v2.14.0)/`nuclei -version`(v3.3.9) 正常执行，`which` 解析 PATH 软链 OK；build 47.6s（前置 apt/pip/playwright 重层缓存命中）。
  - **不递增版本号**：Dockerfile 构建优化不改应用逻辑，守"递增只限应用迭代"铁律。
  - **待办/风险**：替换生产及 VM 正式镜像需**人工批准**（铁律 12.6，AI 不擅自更新正式镜像）；⚠️ 在丢失 Unix 权限的环境（如 Windows 裸 checkout）直接 build 需先对 external 内二进制恢复 +x（Dockerfile 注释已标）。构建仍走 legacy builder（VM 无 buildx），故未用 BuildKit 专属的 `COPY --chmod`。

## 2026-09-28 更新（v1.21.165 正式版：漏洞情报中心化分发——云端 Watchtower 统一采集，实例改从云端拉取，系统不再本地爬外部源）

- **【漏洞情报中心化】按 `云端/docs/漏洞情报中心化分发设计.md` 落地**：`vuln_intel`（CVE/组件漏洞库）从「每实例各自翻墙爬 10 源」改为「分发系统 watchtowers.info 中心爬外部源、各实例拉取入本地库」，治各实例重复劳动 + 海外源（NVD/CISA KEV）拉不到（VM 实测 cisa_kev 曾 fetch failed）+ 库版本参差。
  - **分发端（`云端/distribution/`，已部署 watchtowers.info）**：新增 `intel_feed.py`（8 个外部源 fetcher **逐字移植自 `_feed.py`**，仅 I/O 层换 stdlib urllib shim + 入库改 `intel_store`，零逻辑漂移；seebug 证书链不全用 verify=False 兜底）；新增 `intel_store.py`（sqlite，dedup_key 去重合并 + `updated_at` 增量 + **pull 字段白名单硬编码**，绝不含 unit/finding/report 任何字段）；`update_source.py` do_GET 加 `/intel/version`+`/intel/pull?since=`（鉴权闸后 X-Update-Key 授权 + gzip），serve 起 6h 后台爬取线程（空库或超 6h 才真爬）；`_update_common.py` 的 `intel_store` 加进 `CLEAN_EXCLUDE_NAMES`（情报库绝不进代码 manifest）。实测中心爬 2932 条 CVE 入库。
  - **实例拉取端（`sentinel_platform/`）**：新增 `modules/risk_intel/intel_pull.py`（仿 `_extension_store._get` 授权，拉增量 → 经**现有 `upsert_vuln`（不改）**入本地 Mongo `vuln_intel`）；`scheduler._tick_vuln_feed` 改为——`UPDATE.INTEL_PULL`(默认开)时从云端拉外部 CVE 情报 + 本地跑 `arl_npoc`/`nuclei`。
  - **【本系统不再携带外部源抓取代码】**（用户明令）：`_feed.py` 瘦身 646→269 行，**删除全部 8 个外部源 fetcher + HTTP 抓取层**（cisa_kev/nvd/qianxin/... 已在分发系统 `intel_feed.py`），只保留本地可执行源 `arl_npoc`(读本地 poc 集合)/`nuclei`(读本地模板)——产 `executable=True` 情报、天然 per-instance。**中心不可达时外部情报本轮暂缺、下轮重试，不再本地爬外部**（放弃离线自爬兜底，外部情报唯一来源=云端）。`run_feed()` 只跑本地源。
  - **漏洞情报 UI 改版**（`frontend/src/pages/intel/VulnIntel.vue`）：情报来源区改为**云端主来源 hero**——突出「Watchtower 云端情报库」（云图标+霓虹青渐变+在野/严重指标），本地可执行源作次级 chips；页描述/按钮（「立即同步」）与"从云端统一采集分发"口径对齐；`feed_status` 返回 `mode=cloud` + central 主来源。
  - **消费方零改动**：`query_vuln_intel`/漏洞情报页读的还是本地 `vuln_intel` 集合，仅数据来源变了。
  - **存量情报回灌云端**：把 VM 实例历史积累的 vuln_intel 经 `intel_store.import_docs` 合并入云端库——云端 **2932 → 36825 条**（新增 33893），实例后续拉取即得全量库。
  - **验证**：分发端 `/intel/version` 带 key 返 count/无 key 403、`/intel/pull` gzip 返 2932 条真实 CVE、外网经 Caddy HTTPS 正常、字段白名单实测无泄密字段；VM 端 `intel_pull.pull_and_upsert` 拉 2932 条入库(new1065/merged1867)、二次拉「up to date」增量生效。配置加 `UPDATE.INTEL_PULL`(默认 true)。
  - **待办**：venustech 源 HTML 抓取返 0（`_feed.py` 原有的 HTML 脆弱性，非本次引入，7/8 源有数据不阻塞）；正式发布(clean v1.21.165 随分发触达存量实例)需人工批准（12.6）。

## 2026-09-28 更新（v1.21.164 正式版，汇总 -1~-16 测试迭代：截图UX + 移除无进展硬收尾 + dispatching 自愈 + 分发源迁移 watchtowers.info）

- **【分发源迁移】旧分发服务器 124.222.145.172 失效，迁至新机 `83.229.121.83` = 域名 `watchtowers.info`（HTTPS）**：
  - 新机部署 `云端/distribution/` 分发系统（systemd `sentinel-cloud-update.service`，`serve --root /opt/sentinel-cloud/snapshot --host 127.0.0.1 --port 5080`），前置 **Caddy** 反代做自动 Let's Encrypt HTTPS（`watchtowers.info`+`www`）。5080 仅本机、对外只 443。
  - 客户端 `UPDATE.SOURCE_URL` 及全部代码硬编码默认（`activation.py`/`update_check.py`/`_updater.py`/`router/endpoints/{meta,about}.py`/`_extension_store.py`）、前端 `SetupWizard.vue`、`docker/install.sh`/`README`/`landing` 一并由 `http://124.222.145.172:5080` 改为 `https://watchtowers.info`。prod 推送脚本（`_sftp_push_prod.py`/`_push_prod_fast.py`）SSH 目标同步改新机。
  - **注册库全新起**（旧 124 的 `update_registry.db` 不可恢复）：新库空 → 鉴权强制生效，旧 key 失效，客户端需重新签发/激活。
  - **热更触达**：SOURCE_URL 属代码/前端改动随分发生效；但存量指向旧 124 的实例拿不到本更新（旧源已死），需人工把其 config 的 SOURCE_URL 改指 watchtowers.info + 配新 key。

- **【会话 dispatching 停滞回收】`scheduler._tick_sessions` + `orchestration._claim_session` + `session.run_session`**：

- **【会话 dispatching 停滞回收】`scheduler._tick_sessions` + `orchestration._claim_session` + `session.run_session`**：
  - **现象（用户报）**：AI 渗透会话卡在 `dispatching` 不动，不会复活。实测 VM 上有 2 个会话卡 `dispatching`（其一 round=135 的长会话），触发时机是 rabbitmq 容器被 `--force-recreate` 重建（无持久卷，重建即丢消息），派发中的会话 celery 消息丢失。
  - **根因**：`dispatching` 是 `queued→(scheduler 原子认领)→dispatching→(worker 起转)→running` 的过渡态。周期 watchdog `_tick_sessions` **只回收 `running` 心跳超时的（15min），完全不回收 `dispatching`**，还把它算进占用槽位；`dispatching` 的唯一回收路径是 `_reclaim_on_startup`——**仅 scheduler 进程重启时跑一次**。故只要 scheduler 不重启，真卡死的 `dispatching` 就一直占槽不动、无法自愈。且 `_claim_session` 进 dispatching 时**不刷 update_date 心跳**（保留上次 running 的旧心跳），无法区分「刚派发在途」与「派发后卡死」。
  - **修复（三处配合，缺一会抖动）**：
    ① `_claim_session` 进 dispatching 时盖 `update_date` 心跳，给 dispatch 窗口可测起点；
    ② `_tick_sessions` 加 dispatching 停滞回收：心跳超 `DISPATCH_STALL_SECONDS`（默认 `max(3×tick,90s)`，远长于正常亚秒级 dispatch）且非 `stop_requested` → 回 `queued` 重新派发（`dispatch_reclaim_count`++）；连续回收超 `MAX_DISPATCH_RECLAIM`（默认 3）次仍起不来（如 provider 失效/run_agent 起转即崩）→ 降级 `paused_manual`（由既有 ②.5 隔 `MANUAL_RETRY_SECONDS` 延迟自愈），不无限 `queued↔dispatching` 抖动占槽；
    ③ `run_session` 成功进 `running` 时重置 `dispatch_reclaim_count=0`，避免偶发停滞累加把长期健康会话误降级。
  - **守铁律**：修 bug 完善逻辑非加死参数（回收/降级阈值均可配、默认非硬上限）；客观事实（心跳超时）机械触发，不猜语义；排除 `stop_requested`（用户显式停的不复活，与 `_claim_session`/`_reclaim_on_startup` 同口径）。
  - **验证**：新增 3 个单测（停滞回收+计数、超限降级 paused_manual、新鲜 dispatching 不误回收防抖动）；VM worker 容器内 scheduler 全测 + 真实端到端观察卡死会话自愈。
  - **热更触达**：`scheduler.py` 走 scheduler 容器重启；`orchestration.py`/`session.py` 走 worker 重启 + web reload。

## 2026-09-23 更新（v1.21.163-16，红队收尾两项：统计卡片与去重列表口径统一 + 清理红队默认模板旧流程）

- **【漏洞统计卡片口径统一】`vuln_center.finding_stat`**（`sentinel_platform/modules/risk_intel/vuln_center.py`）：
  - **现象**：漏洞中心顶部统计卡片（AI 已验证/严重·高危/合计）的数字比下方"去重列表"的条数大，对不上。
  - **根因**：卡片用 `count_documents` + `duplicate_of:None`（仅**同会话**去重），而去重列表走 `_finding_index.select_rows(dedup=True)` 按 **`point_key` 跨会话**去重；同一漏洞点被多个会话发现时，卡片按会话各计一次 → 卡片数 ≥ 列表数。
  - **修复**：`finding_stat` 改用**早已写好却未接线**的 `_finding_index.statistics(fcoll, fq)`（与列表同 `point_key` 分组口径），并像列表一样先 `ensure_legacy_index` 回填 `point_key`、unit 过滤用与列表相同的 regex。卡片 verified/leads/by_severity/by_type 全部与去重列表一致。去掉旧卡片按 `chain_severity` 上调有效等级的逻辑（列表按原始 `severity` 展示/过滤，去掉正是对齐口径）。
  - **验证**：新增 `test_finding_stat_dedup_matches_list`（跨会话同漏洞点 2 条未去重记录 → 卡片 verified==去重列表 total==1）；risk_intel 220 + vuln_center 35 测试全绿。
  - **热更触达**：后端 `.py` 走 worker 重启 + web reload。
- **【清理红队默认模板旧流程】`_scene_prompts.py` 红队 scene**（`sentinel_platform/modules/ai_pentest/_scene_prompts.py`）：
  - v1.21.163-15 红队闸刀已改为 advisory（永不拦截、红队分支不消费 `exploit_verify`），且真正播种的 `ai_config._PROMPT_REDTEAM` 已是新口径无 `exploit_verify`；唯独 `_scene_prompts.py` 的红队基线/默认模板仍残留"必须用 exploit_verify 自证验证性写操作"等旧话术，与新机制矛盾。
  - **修复**：清掉红队基线与默认模板里的 `exploit_verify` 自证要求，改为对齐 advisory 新口径——"红队闸刀不拦写操作、仅对可能影响业务可用性的写/破坏操作给一句话提醒"，保留非破坏铁律（不删库/勒索/DoS/关服务/持久后门、写操作优先可逆可控留痕）。`exploit_verify` 仍保留在 src/conservative（会拦截的模式）及工具参数中，不受影响。
  - **热更触达**：后端 `.py` 走 worker 重启 + web reload。

## 2026-09-23 更新（v1.21.163-15，一项：红队模式接入监管闸刀——advisory 业务影响提醒，永不拦截）

- **【红队闸刀提示词 + 监管接入】**（`ai_pentest/_guard.py`，用户 2026-09-23 定调）：
  - 此前红队模式（redteam）在 `guard_request` 是**纯放行仅记录**，不接监管 AI。现接入监管，但**定位是提醒而非拦截**：红队授权内允许删除/修改/清空/**重置管理员密码**/提权等高危操作，**不做强制拦截**；监管 AI 只对可能**影响目标业务可用性**的写/破坏性操作出**一句话提醒**（确认删改不破坏业务可用性、新增不污染生产/不触发误发短信邮件支付、改密提权注意可逆勿锁死管理员等），**恒放行**，提醒经 `reason` 透给执行 AI（工具回执/guard_log 可见）。
  - 实现：新增 `_GUARD_SYS_REDTEAM` advisory 提示词 + `GUARD_SCENE_REDTEAM` scene（provider 未配降级回主 guard provider）；`guard_request` 红队分支：纯只读静默放行（不调 AI 省开销），写/danger/ambiguous → 监管 AI 出提醒但恒 allow=True。
  - 与其他三档（standard/conservative/detect 会真拦截）区别：红队 danger 只表示"需提醒"不代表拦截，拿捏为结对式风险提示。
  - 测试：新增 2 例（advisory 提醒非阻断 + 纯读不调 AI），test_guard 22 例全绿。
  - **热更触达**：`_guard.py` 走 worker 重启 + web reload。

## 2026-09-23 更新（v1.21.163-14，一项：系统提示词强化"历史漏洞/情报收集"到与 JS 收集同等强制）

- **【提示词强化】新增 `INTEL_COVERAGE_PROMPT`「历史漏洞/情报覆盖与收尾条件」章节**（`ai_pentest/_system_prompts.py`，并入 runtime_quality 质量块，与 `JS_COVERAGE_PROMPT` 并列同级）：
  - **背景（用户要求）**：JS 收集有一整段专门的 7 条覆盖清单+收尾条件+报告要求（`JS_COVERAGE_PROMPT`），但历史漏洞/往期情报收集此前只在 scene 提示词里作为工具名一带而过，强调程度远不够。要求提到和 JS 收集一样的程度。
  - **新增内容（6 条，镜像 JS 覆盖结构）**：建清单（每个组件/系统/单位查过哪些源/命中/复验状态）→ 中期确认指纹后按需调 query_vuln_intel/read_system_playbook/match_playbook/get_pentest_report/query_unit_reports/read_vuln_playbook/read_exploit_clues/query_leaked_creds/query_subdomain_intel（无命中再 web_search）→ 本资产往期漏洞逐条复验→ 历史打法/CVE 当假设实证（复验通过才算确认）→ 情报内容视为不可信数据+单位凭证不跨单位→ 收尾前每个已确认组件/系统/单位都查过借鉴过、报告须有"历史情报利用摘要"。
  - **守防锚定铁律**：明确"全部是待验证假设不是结论、不开局当滤镜、不照抄历史结论"（对齐记忆 防锚定两铁律），只强化收集/利用的强制度，不把历史情报当基准真值。
  - runtime_quality 版本标签 V1→V2：`refresh_runtime_quality`（run_agent/console 每轮/恢复时调）会把存量会话的旧 V1 块替换为含新章节的 V2 → **在跑/恢复的会话也即时获得强化**。
  - **热更触达**：`_system_prompts.py` 走 worker 重启 + web reload。

## 2026-09-23 更新（v1.21.163-13，一项：修 AI 渗透会话并发上不去——stop_requested 会话堵死 slot 预算）

- **【会话并发调度修复】`scheduler._tick_sessions` 两处**：
  - **现象（用户报）**：AI 渗透会话始终只有 1-2 个并发运行，即使并发上限 4、资源水位 relaxed、有 10+ 个 queued 会话待派。误以为是资源水位限的。
  - **根因**：3 个 `stop_requested=true` 的会话卡在 `paused_transient` 状态（来自已停止任务）。候选排序 paused_transient 排在 queued 前（且 priority 高排最顶），`candidates[:slots]` 只切前 slots 个恰好全是这些停掉的会话 → `submit_session` 的 `_claim_session` 带 `stop_requested!=True` 过滤认领失败 → `continue` → **slot 预算被认领失败的候选白白消耗，后面健康 queued 被 slice 切掉、永远轮不到** → 每 tick 重复 → 并发卡死。**不是资源水位。**
  - **修复**：① 候选查询（paused_transient + queued）加 `stop_requested: {$ne: True}`，停掉的不进候选（与 `_claim_session` 同口径）；② 派发循环从"切前 slots 个尝试"改为"填满 slots 个**成功派发**"——认领失败不计入、不占 slot 预算，继续尝试下一个健康候选。守"修 bug 完善逻辑不加死参数"。
  - 同步修一个陈旧测试（`test_tick_sessions_queued_and_paused` 的 pmax retry_count=5 假设降级，但 MAX_TRANSIENT_RETRY 早已 5→12，改为 12）+ 假 repo 补 `$ne` 支持。
  - **热更触达**：`scheduler.py` 走 scheduler 容器重启。

## 2026-09-23 更新（v1.21.163-12，一项：unit 任务反查改生产者-消费者流式，逐目标边反查边侦察派发）

- **【unit 任务流式派发·producer-consumer 重写】**（`kernel/orchestration.py` `_unit_handler` + `ext_source.py`/`recon_bridge.py`）：
  - 反查（生产者，主线程）每反查出一个单位的域名/IP 即经 `on_unit` 回调入有界队列（`maxsize=scan_parallelism` 背压）；**单个后台消费者线程**逐目标 `run_recon(use_checkpoint=False)`——边反查边侦察落库派发，不等全部 488 单位反查完（守流式铁律）。单消费者避免同进程扫描代理 env 并发串线。
  - `reverse_lookup_units(units, on_unit=, cancel_check=)`：加逐单位回调 + 协作式取消；签名自适应（旧签名回退按单位逐个调用，仍不攒全部）。`run_recon(use_checkpoint=)` 流式块不复用/不写 checkpoint（避免同 task 多次调用被阶段跳过）。
  - 修一个旧批量语义测试（`test_reverse_then_recon`：逐目标流式后假 recon 只留最后一次调用，改累积记录并断言每个目标都被扫）。kernel 144 测试全绿。
  - **热更触达**：后端 `.py` 走 worker 重启 + web reload。

## 2026-09-22 更新（v1.21.163-11，一项：任务列表目标列真正截断——自定义插槽显式省略号容器）

- **【任务列表目标截断修复】**（`frontend/src/pages/tasks/TaskList.vue`）：v1.21.163-9 给「目标」列加了 `width:240 + ellipsis:true`，但该列是 `<CopyText>` **自定义插槽**渲染——Ant Design 的 `ellipsis:true` **只对纯 dataIndex 文本自动截断，对自定义插槽单元格不生效**，所以 unit 任务的数千字符 target 实际仍未截断。本次在插槽内显式包单行省略号容器（`max-width:228px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis`），真正夹住；点击 CopyText 复制全量。

## 2026-09-22 更新（v1.21.163-10，一项：unit 任务反查改流式分块派发 + 详情页目标截断）

- **【unit 任务流式派发】反查按单位流式喂 recon，不再等全部单位反查完**（`kernel/ext_source.py`/`recon_bridge.py`/`orchestration.py` + `frontend/tasks/TaskDetail.vue`）：
  - **现象（用户报）**：488 单位的 unit 任务跑 ~40 分钟一个资产都没派发。
  - **根因**：`_unit_handler` 调 `reverse_lookup_units(units)` 把全部单位**串行反查完**（每个 auth+滑块验证码+queryByCondition ≈5s）才 `run_recon` 一次——反查期间已查到的种子全卡在内存，recon 不启动→站点不产出→不归集不派发，违反「站点形成即归集派发」铁律。（ICP 查询本身正常：live 实测北京大学/阿坝师范/西昌学院均 status=ok。）
  - **修复**：① `reverse_lookup_units(units, on_unit=)` 加逐单位回调，每单位反查完即外抛 domains/ips/fld片段；② `_unit_handler` 用回调分块累积（累计域名≥15 或 每20单位，非硬上限）→ 边反查边 `run_recon(use_checkpoint=False)` 喂一块，每块 fresh pipeline 流式落库+派发，flush 前增量写 `task.unit_map` 保归属正确；③ `run_recon` 加 `use_checkpoint` 开关（默认 True 存量不变；unit 流式块传 False，避免同 task 多次调用被 checkpoint 跳过阶段）。资产现在边反查边陆续产出/派发。
  - **详情页目标截断**：`TaskDetail.vue` 目标改定高滚动容器（96px+overflow），unit 任务几千字符单位名清单不再撑长页面，点击 CopyText 复制全量。
  - **边界**：只改 unit 路径；ICP 查询与每单位固有耗时不变（流式只让结果尽早陆续出）；checkpoint 绕开仅限 unit 流式块，domain 等任务断点续扫不变。
  - **热更触达**：后端 `.py` 走 worker 重启 + web reload；前端走 `docker/frontend` 产物。

## 2026-09-22 更新（v1.21.163-9，一项：任务列表「目标/任务名」列定宽截断，修 unit 任务超长 target 撑爆表格）

- **【任务列表布局修复】给「任务名」「目标」列加固定 width + ellipsis 截断**（`frontend/src/pages/tasks/TaskList.vue`）：
  - **现象（用户报）**：任务列表第一个任务（unit 类型）内容太长，表格被撑长/横向爆开。
  - **根因**：表格 `:scroll="{ x: 'max-content' }"`，而「任务名」「目标」两列只有 `ellipsis:true` **没设 width**——ellipsis 需列有固定宽度才真正截断；无 width 时列被最宽单元格撑开。unit 任务的 `target` 是单位反查出的一大串域名（实测达 5567 字符），把「目标」列撑到超宽 → 整表横向爆开。
  - **修复**：「任务名」width=180、「目标」width=240，保留 `ellipsis:true` → 定宽夹住、超出显省略号；目标全量靠单元格内 `CopyText` 点击复制。
  - **热更触达**：前端走 `docker/frontend` 产物，rebuild 后随热更/nginx 直读挂载卷到达。

## 2026-09-22 更新（v1.21.163-6，一项：会话台思考气泡改流式，看得见 token 分块流动）

- **【会话台气泡流式】LLM 生成中的 partial 文本实时流进气泡（分块式，推理+回复都流）**（`_claude_stream.py`/`_llm.py`/`_engine.py`/`_console.py`/`session.py` + `pentest.ts`/`PentestConsole.vue`）：
  - **动机（用户报）**：会话卡住时思考气泡只显静态「AI 执行中（后台）…」一片沉默，分不清「AI 在慢慢生成（活着）」还是「卡死在死中转站里」（本轮中转站 api.lt4net.org 半死、300s 超时+重试期间气泡零反馈）。
  - **根因**：`_chat_claude` 内部已 SSE 流式读（`_claude_stream.read_message` 逐帧累加 text/thinking），但攒完整段才返回，中间 token 不外抛；执行体 `run_console_agent` 在 worker、前端靠 observe 轮询 Mongo（2s）看增量 → 生成期间不落库 → 气泡沉默。
  - **实现（贴合现后台执行架构，不引入新通道、不动执行模型）**：`read_message`/`read_response` 加 `on_delta(phase, 累计文本)` 回调（text/thinking 增量各触发，回调异常吞掉不破坏解析）→ 逐层透传 `_llm.chat`/`_engine._call_resilient` → `run_console_agent` 节流（`STREAM_FLUSH_SEC=0.6s`）写 `stream_buffer`/`stream_phase`；`_persist_turn` 落真实消息时恒清空 `stream_buffer`（预览切回真实气泡不重复）。observe 流 `_console_event_stream` 降到 `_CONSOLE_POLL_SEC=1.0s` 轮询 + meta 带 `stream`/`stream_phase`。前端气泡有 partial 文本时显「推理中/回复中」标签 + 流式文本 + 闪烁光标，否则回退静态文案。
  - **边界/不回归**：`on_delta=None` 时零行为变化；只做会话台(console)路径，自动/live 会话共用底层管道可后续跟进（本次不接，不回归）；openai/deepseek 非流式协议无 delta，气泡回退静态文案。
  - **热更触达**：后端 `.py` 走 `--reload`/worker 重启，前端走 `docker/frontend` 产物，热更即得。

## 2026-09-21 更新（v1.21.163-5，一项：会话卡片副行显目标站点/IP 而非组件指纹 nginx）

- **【会话列表卡片显示修复】副行从组件指纹改显目标 site**（`PentestConsole.vue` 会话卡片）：
  - **现象（用户报）**：系统派发的渗透会话卡片，标题一律「政府-保守」（task_name，同批全一样），副行显 `nginx`/`php`（system_name 组件指纹）——229 个卡片主标题、副行都近乎雷同，**看不出是哪个目标**。用户指出那个 nginx 位置应是目标链接/IP。
  - **根因**：副行逻辑 `v-if="s.system_name && s.task_name"` 命中即显 `system_name`（指纹），把本该显目标 URL 的位置占了。系统派发会话 `task_name` 与 `system_name` 都有值 → 恒显指纹。而组件指纹（nginx/php/301 Moved Permanently/jquery...）对区分不同目标无价值，真正区分靠 `site`（完整目标 URL，如 `https://zw.jingzhou.gov.cn`）。
  - **修复**：副行优先显 `s.site`（目标站点/IP）——`v-if="s.site && (s.task_name || s.system_name)"`；仅无 site 的会话（如白板）才回退系统指纹避免副行空；标题回退到 site 时不重复显示。主标题（task_name）不动。
  - **热更触达**：前端改动走 `docker/frontend` 产物，rebuild 后随热更/nginx 直读挂载卷到达。

## 2026-09-21 更新（v1.21.163-4，一项：删除会话台步数上限 MAX_TURN_STEPS，改用上下文 token 预算做唯一硬边界）

- **【会话台中断顽疾根治】删除 `MAX_TURN_STEPS=12` 步数上限**（`_console.py`：`run_console_agent` 活路径 + `chat_turn`/`stream_turn` 两条已死同步端点，三处全删常量）：
  - **现象（VM 排查）**：会话台一条指令让 AI 连调 12 个工具后，「AI 执行中」思考气泡突然消失、无任何回复、无报错——像莫名其妙中断。实测 `acb.bzjksypark.com` 会话落库坐实：最后一次结束是 AI 连续调满 12 个工具轮撞 `MAX_TURN_STEPS`，`run_console_agent` 的 `if steps >= MAX_TURN_STEPS: break` **静默退出**，`console_running` 落 false → 前端气泡消失，末条停在 `tool_result`（`last_error` 为空，非报错、非用户停止）。
  - **根因**：会话台后台执行体循环里**从没真正执行 token 预算检查**（`budget` 只算出来传给前端限位卡片显示），`MAX_TURN_STEPS` 是唯一的"防无限工具轮"闸，撞上限即静默 break。与自动会话 `run_agent` 设计不一致——`run_agent` 无步数上限，唯一硬边界是上下文窗口占用（`window_tokens >= budget`），符合"禁硬限制参数"铁律。
  - **修复**：三处循环 `while steps < MAX_TURN_STEPS` → `while True`，**补上真实的 `window_tokens >= budget` 硬边界**（复用已有 `_console_budget()` = max_context×0.9，与 `_engine.run_agent` 同口径）。逼近窗口上限时本轮不给工具（`tools=None`）逼 AI 出纯文字收束本回合，并给「上下文窗口已近上限，本回合暂停，可继续发指令」明确提示——消除"静默 break 无提示"观感。`run_console_agent` 保持原语义：不改 status（恒 paused_manual）、不 finalize、不释放持久浏览器资源。
  - **热更触达**：改动在 `sentinel_platform/modules/ai_pentest/_console.py`（分发代码），worker 跑 `run_console_agent`，热更后重启 worker 即得。

## 2026-09-18 更新（v1.21.157-84，一项真根治：AI 工具调用被中转站截断——Claude 请求补 interleaved-thinking beta 头）

- **【AI 调用工具失败根治】Claude 协议默认注入 `anthropic-beta: interleaved-thinking-2025-05-14`**（`_llm.py:_chat_claude`）：
  - **现象（用户报）**：会话台一让 AI「抓 js」就反复失败——`AI 调用失败：上游返回空响应（HTTP 200，content 块为空，stop_reason=tool_use）`，重试 3 次仍失败；但同一中转站接 Claude Code 却能正常调工具（MCP）。
  - **根因（VM 逐层对照实验坐实）**：平台用的中转站（`sub.vankit.top`/`api.lt4net.org` 等）都是 **Kiro/CodeWhisperer 逆向池**（响应含 `kiro_credits`/`kiro_actual_input_tokens` 字段），后端**强制开 extended thinking**。请求**不带 `interleaved-thinking` beta 头**时，中转站在多轮工具续接场景（messages 已含 tool_use/tool_result 历史，如"打开浏览器后抓 js"）输出 thinking 块后**截断 tool_use**（`output_tokens=1`，content 只有 thinking 无 tool_use）→ 平台收到空工具调用。**Claude Code 天生带此 beta 头**故不受影响——这不是平台代码 bug 也不是中转站质量差，是缺了这个 beta 头。
  - **决定性对照（同中转站同请求）**：带 `interleaved-thinking-2025-05-14` → thinking+tool_use 完整（out_tok=15）✅；带 `fine-grained-tool-streaming` → 截断（out_tok=1）❌；无 beta → 截断 ❌。唯此头有效。
  - **修复**：`_chat_claude` headers 默认加 `anthropic-beta: interleaved-thinking-2025-05-14`（provider 可经 `extra_headers` 覆盖/清空，官方 Anthropic API 用此头无害）。VM 真实 worker E2E：`run_console_agent` 从"空响应失败"变为连续调 13 次工具、成功抓到 app.js 完整 API 映射。
  - **排查中走过的弯路（如实留档）**：曾误判为「thinking 参数导致（reasoning_effort 本就空，无关）」「工具表太大截断（20KB 实测 OK）」「非流式是根因（实测非流式带 beta 头正常）」「中转站质量差（Claude Code 用同站也行，推翻）」——最终经变量隔离对照锁定唯一变量=beta 头。
  - **热更触达**：改动在 `_llm.py`（`sentinel_platform` 分发），`--reload` 自动重载，存量用户热更即得。

## 2026-09-18 更新（v1.21.157-83/82/81，同一问题的排查中间版：thinking 参数试改 + 空响应详情日志）

- **① 空响应详情日志（-81）**（`_llm.py`）：`_chat_claude` 遇 content+tool_calls 全空时，`logger.warning` 记录中转站返回的完整响应 JSON（前 500 字符）供排查——正是靠此日志坐实中转站只返回 `type=thinking` 块、无 `tool_use` 块、`output_tokens=1`。保留（诊断价值）。
- **② thinking 参数试改（-82/-83，已被 -84 取代）**：曾尝试「有工具时禁用 thinking」（-82）、「完全禁用 thinking」（-83）——均基于「平台主动开了 thinking」的错误假设（实际 provider `reasoning_effort` 为空、平台从不发 thinking 参数），故无效。-84 回退这些改动，改为补 beta 头的正解。

## 2026-09-18 更新（v1.21.157-80/79/78，三项前端交互修复：命令重复显示 + 人工指令前缀对齐 + 会话页自动滚底 + discover 白屏）

- **① 会话台命令重复显示根治（-78/-79/-80）**（`PentestConsole.vue`）：
  - **现象（用户报）**：会话台发一次命令，对话区出现两条相同记录；切菜单返回后也重复；各种重复场景都出现过。
  - **根因（逐步定位）**：会话台后台执行模型下，用户发消息=本地回显 + `consoleSubmit` 入队，后台执行后观察流（observe）又推同一条消息。去重逻辑失效有两层：① 旧逻辑只比对**最后一条**（`dialogue[last]`），中间有 AI 回复时失效（-78 改为 `dialogue.value.some()` 全量扫描去重）；② **更深层**——后端 `_engine._merge_user_injection` 给每条人工消息加 `【人工指令】` 前缀，而前端本地回显用原始文本，去重严格 `===` 比对不上（-80 根治：本地回显也加 `【人工指令】` 前缀，与后端 `console_messages` 落库格式严格一致）。
  - **修复**：去重扫全量历史 + 比对前 trim 双方（-79）+ 本地回显加 `【人工指令】` 前缀对齐后端（-80）。彻底消除 user 消息重复、AI 回复重复、整轮重复、切菜单重复四类场景。
- **② 会话页用户输入自动滚到底部（-84 前端部分）**（`PentestConsole.vue`）：
  - **现象（用户报）**：输入命令后对话没自动到底部，用户消息被「AI 执行中」思考气泡顶上去看不到。
  - **根因**：`send()` 里 push 用户消息后调 `scrollChat()`，但此时 `consoleRunning` 还是 false、思考气泡未渲染；等 `consoleSubmit` 成功置 `consoleRunning=true` 气泡渲染后对话区增高，却没再滚。
  - **修复**：加两个 `watch`——监听 `consoleRunning`/`liveMode`（气泡出现/消失时重滚到底）+ 监听 `dialogue.length`（任何增消息路径兜底滚底）。
- **③ 持久浏览器 discover 遍历路由 SPA 白屏对齐（-78）**（`_browser_session.py`）：`browser_discover` 深度遍历同源路由时 `goto` 的 `wait_until` 从 `commit` 改 `domcontentloaded`，与主导航（-75 已改）对齐，治遍历时截图/抓取仍白屏。
- **热更触达**：前端走 `docker/frontend` 产物、后端 `_browser_session.py` 走 `--reload`，存量用户热更即得。

## 2026-09-16 更新（v1.21.157-76，一项：人工作战会话也过闸刀，程度由渗透模式决定，仅自定义无校验）

- **【人工作战会话纳入闸刀校验】**（`_tools.py` + `_console.py` + `NewSessionModal.vue` + `pentest.ts`，用户 2026-09-16 定调）：
  - **旧行为**：会话台人工接管/新建作战会话（`console_manual`）**无条件跳过智能闸刀**（写请求不审查）。
  - **新行为**：人工作战会话**也走闸刀**，校验程度由**渗透模式**决定（探测最严 → 保守 → 常规 → 红队放行仅记录，与自动会话同一 `guard_request` 口径）；**唯独「自定义」档（mode=custom）跳过闸刀**——自定义由人工全权负责合规。scope 范围 + 全工具开放**保持不变**（本次只收敛闸刀，不动范围/工具）。
  - **实现**：新增单一事实源 `_tools._guard_bypassed(ctx)`（`mode=='custom'` 才 True，大小写无关；缺 mode/空/其余模式一律过闸刀）。`_t_http_request` + `_t_foothold_exec` 两个写口的旧 `if not console_manual` 判据统一改用它。前端 `NewSessionModal` 提交 mode 时**不再把 custom 塌成 src**（`mode: mode.value`），后端 `console_create_session` 本就存 `mode` → `_build_ctx` 透出 `ctx["mode"]` → 闸刀按模式生效；custom 的 scene 仍归一到常规提示词（`scene_for_mode`），prompt 用用户填写。
  - **文案更新**：新建作战会话提示语从「无闸刀/范围限制」改为「**写请求经智能闸刀校验，程度由渗透模式决定；选自定义则无闸刀校验（人工全权负责合规）。漏洞/情报默认入库**」；模式选择区自定义档标红「不过闸刀校验」；`_console.py`/`pentest.ts` 相关 3 处 stale 注释同步纠正。
- **验证**：新增 `ConsoleGuardByModeTest`（`_guard_bypassed` 只对 custom 放行 + console 危险写在 src 下被闸刀拦、custom 下闸刀不被调用），2 例通过；`test_guard`(20)/`test_engine_loop`(34) 回归全绿。
- **热更触达**：后端 `sentinel_platform/modules/ai_pentest/` 走 `--reload`；前端走 `docker/frontend` 产物，存量用户热更即得。

## 2026-09-16 更新（v1.21.157-75，两项真根治：AI 调用失败真原因 + SPA 白屏（-74 未治本，本版 VM 逐层实证定位））

- **① AI 调用失败「未知错误(无详情)」真根治**（`_llm.py`）：-74 只修了**异常路径**（`_describe_exc`），但 VM 逐层实证发现真实失败是**另一条路径**——中转站 `api.lt4net.org` 对**带 tools 的请求**返回 `HTTP 200 + stop_reason=tool_use + content=[]（空数组）`：模型想调工具但中转站把 tool_use 块整个丢了。`_chat_claude` 算出 `content=""`、`tool_calls=[]`、`ok=False`，但该 return dict **根本没有 error 字段** → UI 落到兜底串「未知错误(无详情)」。**修复**：claude 空响应路径改为**必带非空可读 error**（`上游返回空响应（HTTP 200，content 块为空，stop_reason=tool_use）——疑似中转站不兼容/截断`）+ 归 `ERR_TRANSIENT` 重试 + 透出 `stop_reason`；新增 `_salvage_inline_tool_calls` 抢救中转站把工具调用当 `<tool_use>{json}` 文本返回的情况（openai 侧同补）。**真实成因诚实交代**：该中转站对 tool-use **系统性损坏**（实测每次都空，换 [1m]/beta/thinking 都一样；纯文本对话正常）——本版让它**报清原因 + 自动重试**，但根治需用户换可用中转站/模型。
- **② SPA 浏览器白屏真根治**（`_browser_session.py`）：-74 加的「等 #app 渲染」软等**也没治本**——VM 实证 `goto(wait_until="commit")` 下 `#app` **10s 恒 null**（截图 5320 字节纯色白屏）；**根因**=`commit` 在服务器刚响应导航、HTML `<head>` 脚本尚未解析时就返回，JS 从没运行 → Vue 永不挂载。**修复**：open/goto 的 `wait_until` **从 `commit` 改 `domcontentloaded`**（等 HTML 解析完 + defer 脚本就绪 = SPA 挂载起点；仍不等长轮询资源，长轮询站照常返回）；domcontentloaded 超时才退回 commit 兜底。**VM 实证**：改后 1s 内 `#app`=2826 字符、`elements`=4（用户名/密码/验证码/登录）、截图 477KB 真渲染岳阳楼登录页（对比修前 5KB 白屏）。
- **验证**：`_salvage_inline_tool_calls` 单测通过；VM 真 E2E 打开 `app.yueyang.gov.cn` 截图非白屏（477KB，登录页完整渲染）+ 抓到 4 元素；空响应现返非空 error。测试数据（截图目录/僵尸 holder）已清理。
- **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`，`--reload` 自动重载，无需 rebuild 镜像。

## 2026-09-16 更新（v1.21.157-74，两项：AI 调用失败空原因根治 + SPA 浏览器白屏根治）

- **① AI 调用失败「原因为空」根治**（`_llm.py` + `_console.py` + `_engine.py`）：**现象**：会话台反复「（AI 调用失败：。可继续发指令重试。）」——冒号后**空白**，用户不知为何失败；VM 日志同样 `LLM transient err, retry 1/3 ... : `（冒号后空）。**根因**：requests 的 `ConnectTimeout/ReadTimeout/ConnectionError/ProxyError` 等异常 `str(exc)` **是空串**，`_chat_openai/_chat_claude` 的 `except` 落成 `error=str(exc)=""` → 层层透传到 UI 就是空原因。**修复**：新增 `_llm._describe_exc(exc, url)`——按异常类型给**非空中文成因**（请求超时/连接失败/入口代理连接失败/TLS 错误 + 目标 host），普通异常空 str 回退类型名，**绝不返回空串**；两个协议 handler 的 except 都改用它。消费侧 `_console`（3 处）/`_engine`（1 处）把 `.get("error","默认")` 改为「空也回退默认」（原 default 对空串不生效）+ 重试日志同样兜底。
- **② SPA 浏览器白屏根治**（`_browser_session.py`）：**现象**：持久浏览器打开 `app.yueyang.gov.cn`（Vue SPA）白屏。**根因**：`goto(wait_until="commit")` + `_settle`(domcontentloaded/networkidle) 在 **Vue/React 挂载前**就返回，此刻 `#app` 仍空 → 截图/取状态得白屏。**修复**：`_settle` 末尾加「等根容器真渲染」——`wait_for_function` 轮询 `#app`/`#root`/`body` 出现非空子树 + 可见文本，软等上限 `_SPA_RENDER_WAIT_MS=6000ms`，等不到不阻塞（静态站/异常照常继续）。实测该站 settle 后 `#app` 有 2826 字符、标题「岳办岳好管理平台」、登录框可见。
- **验证**：`_describe_exc` 对 6 类 bare 异常均返非空可读原因 + 空 str 回退类型名（`test_llm_error_class` 新增用例，5 例全绿）；`test_engine_loop`(34)/`test_guard`(20) 回归通过；`py_compile` 全过。（注：`test_console`/`test_browser` 需真 Mongo/Playwright 环境，本地无库跳过，属既有依赖。）
- **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`，`--reload` 自动重载，无需 rebuild 镜像。

## 2026-09-16 更新（v1.21.157-73，三项：公共扩展 both 类型 + 默认夜间主题 + 内核工具扩展去分隔）

- **① 公共扩展（ext_type=both）**（`_extension_manifest.py` + `ai_extension.py` + 前端）：扩展 manifest 的 `ext_type` 新增 **`both`**（原 ai/feature → ai/feature/both）——公共扩展**两个 Tab 都注册**（AI 工具扩展 + 内核工具扩展都列出）**且进 AI 工具表**（AI 侧可调用）。`list_extensions` 的 ai/feature 过滤都含 both；`list_enabled_tools`（喂 AI）含 ai+both（纯 feature 仍绝不进 AI 工具表防幻觉）。前端 ExtCard/详情/商店卡加「公共扩展」紫标，上传确认文案补 both 说明。**为「AI/内核工具表与两个扩展页一一对应」奠基**：同一工具要两边都有，用 both 注册一次即两边可见。
- **② 默认夜间主题**（`useTheme.ts` + `index.html`）：全站默认主题从日间(light)改为**夜间(dark)**——未存过 theme / 非 light 一律 dark，仅用户显式切到 light 才浅色（`read()` 与 index.html 防闪脚本口径一致）。切换按钮保留，用户选择仍持久化。
- **③ 内核工具扩展去分隔**（`SystemExtension.vue`）：删掉「内核内置工具（N）」「已装内核工具扩展（N）」两段 `a-divider` 分隔，合并为一个连续列表（内置只读卡 + 已装扩展卡并列，顶部一行统计「共 N 个内核工具（内置 X · 已装扩展 Y）」）——与 AI 工具扩展 Tab 去分隔口径一致。
- **验证**：manifest `both` 接受 + both 两边可见并进 AI 工具表单测通过（ManifestTest+ExtTypeFilterTest 12 例全绿）；`npm run build` 通过；VM 部署 + UI 点击（默认进站夜间 + 内核工具扩展单列表）。（注：`test_dynamic_extension_dispatch` 因 L3 资源池需真 Mongo 而在无库环境失败，属既有环境依赖，非本次引入。）
- **热更触达**：后端走 `sentinel_platform` 分发 `--reload`；前端走 `docker/frontend` 产物，存量用户热更即得。

## 2026-09-16 更新（v1.21.157-72，一项：AI 禁用的主动扫描工具移入「内核工具扩展」只读展示）

- **【AI 禁用工具归位内核】**（`ai_tools.py` + `router/endpoints/ai_extension.py` + `SystemExtension.vue` + `api/aiExtension.ts`）：
  - **背景**：`run_nuclei`/`run_npoc` 原在 AI `TOOL_CATALOG` 里显示「可调用·内置」，但它们（连同 `weak_brute`/`run_wih`）是内核扫描 pipeline 的主动 PoC/弱口令/JS 挖掘工具，**全局禁用于 AI**（易触发 WAF/封 IP，见 -69/-28 铁律）——在 AI 工具扩展里冒充「可调用」是误导。
  - **修复**：新增 `KERNEL_TOOL_CATALOG`（run_nuclei/run_npoc/weak_brute/run_wih 四个内核扫描工具）+ `list_kernel_builtin()` + `GET /api/pentest/extensions/builtin_kernel`。这 4 个从 AI `TOOL_CATALOG` 移除（run_nuclei/run_npoc 之前在，weak_brute/run_wih 本就不在），改在「系统扩展→工具扩展→**内核工具扩展**」子页以**只读卡片**展示（在已装内核扩展上方），标「AI 禁用」红标 + 「内核已接入/未接入」状态。执行器保留在 `_tools._EXECUTORS` 供内核 pipeline 复用；`gate_tool` 的 `_ACTIVE_SCAN_TOOLS`/`_KERNEL_ONLY_TOOLS` 仍兜底拦 AI 幻觉调用。
  - **`fuzz_params` 不移**：它是 AI 参数模糊器（非内核扫描工具），仍留在 AI 工具表（虽当前全局禁用），语义准确。
  - **顺带修**：`test_ai_tools.py` 三处 stale 断言（工作区早已把 `collect_js` 移出 catalog、`http_request` 归类改「漏洞验证」，但测试没跟上，与本次改动无关的历史遗留）——一并对齐现状。
- **验证**：后端 `list_kernel_builtin` 返 4 工具（3 已接入 + weak_brute 未接入）、AI 工具表已排除这 4 个、fuzz_params 仍在；`test_ai_tools`/`test_tool_schema_gate`/`test_engine_loop` 全绿（7+10+34）；`npm run build` 通过；VM 部署 + UI 点击验证。
- **热更触达**：后端 `ai_tools.py`/端点走 `sentinel_platform` 分发 `--reload` 自动重载；前端走 `docker/frontend` 产物，存量用户热更即得。

## 2026-09-16 更新（v1.21.157-71，一项：扩展页层级修正——「系统扩展」保留，内部「工具扩展」子页含 AI工具扩展/内核工具扩展 两级 Tab）

- **【扩展页层级修正】改为两级 Tab**（`SystemExtension.vue` + `router/index.ts`，纯前端）：上一版（-70）误把菜单/页面整体改成「工具扩展」并拍平成 AI扩展/内核扩展/运行日志三个平级 Tab；本版按需求修正为**两级**结构：
  - **菜单叶子 + 页面标题改回「系统扩展」**（-70 误改，本版回退 router menu title + route meta.title + PageContainer title/kicker）。
  - **顶层 Tab = 工具扩展 / 运行日志**（原「AI 扩展」子页改名为「工具扩展」）。
  - **「工具扩展」内再分两个子 Tab**：`AI 工具扩展`（AI 可调用工具，据此生成 AI 工具表 = 内置 61 + 已装 AI 扩展，按 7 类功能分类）/ `内核工具扩展`（原「功能扩展」，`ext_type=feature`，内核扫描用、不进 AI 工具表）。
  - 后端 `ext_type`（ai/feature）数据模型零改动，仅前端展示层级与命名调整。脚本层：顶层 `tab`（tools/logs）+ 子 `subTab`（ai/feature），`onTab`/`onSubTab`/`refreshCurrent` 按层级分流载数据。
- **验证**：`npm run build`（vue-tsc）通过、产物含 `-71`；VM 部署 + Playwright 真实点击（登录→系统扩展→工具扩展 Tab→两子 Tab 切换）。
- **热更触达**：纯前端走 `docker/frontend` 产物，存量用户热更即得。

## 2026-09-16 更新（v1.21.157-70，一项：扩展页规范化——「系统扩展」→「工具扩展」，拆 AI 扩展/内核扩展 + 去内置/已装分隔）

- **【扩展信息架构规范化】「系统扩展」改「工具扩展」，Tab 语义清晰化**（`SystemExtension.vue` + `router/index.ts` + `api/aiExtension.ts`，纯前端）：
  - **① 菜单 + 页面标题**：「系统扩展」→「工具扩展」（router 菜单项 title + route meta.title + `PageContainer` title/kicker/description 全改）。
  - **② Tab 语义拆分**：`AI 扩展`（AI 渗透可主动调用的工具，平台据此生成 AI 工具表）/ `内核扩展`（原「功能扩展」，内核扫描时使用的工具，不进 AI 工具表）/ `运行日志`。**「内核扩展」= 重命名现有「功能扩展」（`ext_type=feature`），后端数据模型零改动**——`feature` 取值不变，仅前端展示名 功能扩展→内核扩展（`ExtCard` tag / 详情类型 / 上传确认文案 / API 注释同步）。
  - **③ 去「内置能力(N)/已装 AI 工具扩展(N)」两段分隔**：AI 扩展 Tab 原用两个 `a-divider` 把内置工具与已装扩展割裂显示（空扩展时显 `已装 AI 工具扩展（0）` 空态很突兀）；现合并为**统一按功能分类**（`aiGroups` computed：内置工具 + 已装 AI 扩展按 7 类功能维度合并，每类含 builtin 只读卡 + exts 可管卡），内置卡保留「内置」标签只读、已装卡保留启停/删除，杜绝「61 / 0」割裂观感。
- **验证**：`npm run build`（vue-tsc 类型检查）通过、产物含 `-70` 与「工具扩展」；全前端 grep 无「系统扩展」残留（Changelog 历史条目按惯例保留原文）。
- **热更触达**：纯前端走 `docker/frontend` 产物，存量用户热更即得，无需 rebuild 镜像。

## 2026-09-16 更新（v1.21.157-69，两项：run_wih 移出 AI 工具表 + 「只说不做」nudge 判据修正）

- **① run_wih 移出 AI 工具表**（`ai_tools.py` + `_tools.py`）：**现象**：AI 抓 JS 时调用了 `run_wih`（内核 WebInfoHunter 扫描）——它是侦察内核 pipeline 用的主动扫描能力，AI 该自己用浏览器抓。**根因**：run_wih 在 `TOOL_CATALOG` 里且有执行器、**不在任何门控清单** → 对 AI 完全开放。**修复**：从 TOOL_CATALOG 移除（AI 看不到就不调，schema 预过滤自动生效）；`gate_tool` 加 `_KERNEL_ONLY_TOOLS` 门控兜底（全场景含 console 拦，防旧会话残留/幻觉调用），blocked reason 引导「用 browser_open→discover→resources 自己抓」。执行器 `_t_run_wih` 保留供内核内部复用。
- **② 「只说不做」nudge 判据修正**（`_console.py`）：**现象**：AI 说"现在截图查看JS"后又卡住（-67 的 nudge 没生效）。**根因**：-67 的 nudge 判据是 `_has_action=len(tool_log)>0`（要求本回合有过工具动作史），**首轮就"承诺动作却没调"时 tool_log 为空 → 不 nudge → 卡住**。**修复**：判据从"有动作史"改为"文字含**下一步动作意图**"（`_looks_like_action_intent`：现在/让我/我来/截图/抓/查看/下载/访问/点击/登录/遍历… 等短语）——首轮就只说不做也能被推着真调工具；纯收束答复（不含动作意图）仍正常结束等人。上限仍 CONSOLE_MAX_NUDGES=2。
- **验证**：`run_wih` 不在 catalog + gate 全场景拦（含 console）；意图检测精准（"现在截图"True / "已完成"False）；`test_console` 新增「首轮只说不做也 nudge」用例 + 原 nudge 用例，RunConsoleAgentTest 5 例全绿。
- **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`，`--reload` 自动重载，无需 rebuild 镜像。

## 2026-09-16 更新（v1.21.157-68，一项：持久浏览器补深度遍历 browser_discover 抓懒加载 JS）

- **【SPA 懒加载 JS 抓不全】持久浏览器补 browser_discover**（`_browser_session.py` + `_tools.py` + `ai_tools.py`）：
  - **现象（用户报）**：AI 用持久浏览器抓 JS 不全（岳办岳好平台 app.js 里 `n.e("chunk-xxx")` 引用 7 个 chunk，只抓到登录页加载的部分，`queryBindingList` 所在业务 chunk 没抓到）。
  - **根因（VM 逐层实测坐实）**：`browser_resources` 只捕获**当前路由已加载**的 JS（登录页=app+elementUI+libs+3个路由懒加载 chunk=6个，已比 run_wih 的3个强）；**其余业务 chunk 是登录后经菜单路由才懒加载**的，当前无路由遍历不会触发。（另：contenthash 表不在 app.js 里，无法靠静态解析拼完整 URL——排除了"解析 manifest 枚举"这条路。）
  - **修复**：持久浏览器加 `discover` op + `browser_discover` 工具——自动滚动 + 遍历同源 SPA 路由（只读 goto 不点提交），触发其他路由的懒加载 chunk/XHR，由 `_on_request` 捕获。复用 `_browser` 的 `_auto_scroll`/`_extract_same_origin_routes`/`_route_pattern` 纯遍历辅助（同 worker 线程调用无 greenlet 问题），收敛守「不设死上限」（同模式路由去重+连续无新增停）。工具描述点明**正确顺序 browser_open→browser_login→browser_discover**（业务 chunk 多在登录态菜单路由才懒加载）。
  - **VM E2E**：持久浏览器开目标站 → `browser_resources` 6 个 JS（已比 run_wih 全）；`browser_discover` 遍历路由（登录页无导航链接故新增 0，符合预期——登录后遍历菜单才触发业务 chunk）。
  - **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`，`--reload` 自动重载，无需 rebuild 镜像。

## 2026-09-16 更新（v1.21.157-67，一项：会话台「只说不做」有限 nudge）

- **【AI 说要截图却停住】会话台后台回合有限 nudge**（`_console.py`）：
  - **现象（用户报）**：AI 说"现在截图并查看JS"后就不动了，像卡死。
  - **根因（VM 实测坐实非卡死）**：后端 `run_console_agent` 其实正常 succeeded 收尾了——AI 那一轮**出了文字但没调工具**（只说要截图/看JS，没真调 browser_screenshot/browser_resources），循环判定「已出 assistant 文字回复 → 结束回合等人」，于是 AI 的下一步意图没被执行、前端 console_running 变 false 显示停住。（对比自动渗透 run_agent 遇「只说不做」会 nudge 推它继续。）
  - **修复（有限 nudge，人在场故上限低）**：`run_console_agent` 循环——AI 出**非空文字但无工具调用**、且本回合**有过工具动作史**（在执行流程中、非纯问答）→ 追加一句系统 nudge 推它「说了就调工具执行」，最多 `CONSOLE_MAX_NUDGES=2` 次；超限或纯问答（空文字/无动作史）则正常结束回合等人（不无限空转、不抢人节奏）。新人工指令进来重置 nudge 计数。
  - **验证**：`test_console` 新增 nudge 用例（有动作史后只说不做 → 被推着真调 browser_resources）+ 原 3 例回归全绿；纯问答答复仍正常结束（text_reply 用例）。
  - **热更触达**：改动全在 `_console.py`，`--reload` 自动重载，无需 rebuild 镜像。

## 2026-09-16 更新（v1.21.157-66，一项：会话台发消息后自动滚到底部）

- **【AI 回复被藏在下方】会话台对话滚动加固**（`PentestConsole.vue`）：
  - **现象（用户报）**：用户输入后对话没自动到底部，AI 回复被隐藏在下面看不到。
  - **根因**：`scrollChat` 用单次 `nextTick + scrollTop=scrollHeight`，但对话高度在 tick 之后才增长（流式追加/「AI 执行中」思考气泡换行/**观察流异步推来的 AI 回复**），滚动定位在高度增长前就算完 → 滚不到底。
  - **修复**：`scrollChat` 改 `nextTick + 双 requestAnimationFrame`（等真实布局/绘制完成后再定位）+ 兜底再滚一次，确保新气泡（含异步推来的 AI 回复）进入视口。纯前端热更。

## 2026-09-16 更新（v1.21.157-65，一项：持久浏览器补网络捕获——AI 自己抓加载的 JS+接口）

- **【AI 抓不到加载的 JS 缺口】持久浏览器补 browser_resources**（`_browser_session.py` + `_tools.py` + `ai_tools.py`）：
  - **现象（用户报）**：AI 用持久浏览器打开 SPA 页面后，「列不出加载的 JS 文件列表」，只能退回内核 `run_wih` 扫描（而 run_wih 是内核扫描用的，AI 该自己抓）。
  - **根因**：无状态 `browser_navigate`（`_browser.py`）本就 `page.on("request")` 拦截同源 XHR/fetch，但**持久浏览器 worker 完全没装网络监听** → AI 打开页面拿不到加载的 JS/接口。
  - **修复**：持久浏览器 worker 加 `page.on("request", _on_request)` 网络捕获——累积**加载的 JS 脚本**（script 类型 .js，去重保序）+ **同源 XHR/fetch 接口**（复用 `_browser._is_api_request` 判定口径）；新增 `resources` op + `browser_resources` 工具（AI 调它拿 `{scripts:[{url}], apis:[{method,url}]}`）；`browser_open` 描述引导「打开后调 browser_resources 自己抓，不必退回 run_wih」。
  - **VM E2E**：持久浏览器开百度 → `browser_resources` 捕获 38 个 JS 脚本 + 1 个 XHR 接口（真实 URL）。AI 现在能自己抓 JS，拿到 url 可再 http_request 下载 / fetch_sourcemap 还原。
  - **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`，`--reload` 自动重载，无需 rebuild 镜像（纯后端；brand.ts/version.txt 随例递增+前端 rebuild）。

## 2026-09-16 更新（v1.21.157-64，一项：持久浏览器填充/点击超时根治——选择器暴露 + JS 赋值兜底）

- **【浏览器 fill/click 超时根治】**（`_browser_session.py` + `ai_tools.py`）：
  - **现象（用户报）**：AI 控制台命令打开百度并在搜索框输入"你好"，`browser_fill`/`browser_click` 反复超时（换选择器、点击激活都超时）。
  - **根因（VM 实测坐实，两层）**：① **AI 拿不到真实选择器**——`_state()` 返回的 elements 只有 `{tag,text,type}`、**无 id/name/selector**，工具描述却让 AI「用 elements 精确定位」，AI 只能猜（如 #kw）；② **更深层**：无头 chromium 里百度搜索框 `#kw` 虽存在且 CSS visible，但 **offsetW/H=0（未真正布局）**，Playwright `fill`/`click` 的 actionability 检查（元素须可见有尺寸）永远等不到 → 必超时。
  - **修复（三层）**：① `_state()` 的元素 JS 为每个可交互元素生成**可直接用的 CSS 选择器 `sel`**（#id > [name] > tag[type] > tag.class > nth-of-type），工具描述改为「用 elements[].sel」，AI 不再猜；② fill/click 前 `scroll_into_view_if_needed`；③ **兜底链**：fill 超时→click+逐字 type→仍超时→**JS 直接 `el.value=` + 派发 input/change 事件**（绕过 0 尺寸 actionability，实测百度 #kw 成功）；click 超时→**JS `el.click()`** 兜底。
  - **VM E2E**：持久浏览器开百度 → `fill #kw:ok`（走 JS 赋值兜底）+ `click #su:ok`，不再超时。
  - **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`，`--reload` 自动重载，无需 rebuild 镜像（纯后端；brand.ts/version.txt 随例递增+前端 rebuild）。

## 2026-09-16 更新（v1.21.157-63，一项：AI 控制台指令回车下发）

- **AI 控制台指令输入改回车下发**（`PentestConsole.vue`）：指令输入框从 `Ctrl+Enter` 发送改为**回车发送 · Shift+回车换行**（对齐聊天输入通用直觉）。`@keydown.ctrl.enter` → `@keydown.enter.exact.prevent="send"`（纯回车发送，Shift/Ctrl+回车不触发、留作换行）；占位符 + 提示文案同步更新（`↵ 发送 · ⇧↵ 换行`）。纯前端热更。

## 2026-09-16 更新（v1.21.157-62，会话台执行模型重构：后台执行 + SSE 只观察 + inject 队列）

- **【会话台切菜单中断根治】执行与 SSE 请求解耦，向系统派发会话看齐**（`_console.py`/`session.py`/`orchestration.py`/`_celery_adapter.py`/`scheduler.py`/`endpoints/session.py` + 前端 `PentestConsole.vue`/`pentest.ts`）：
  - **现象（用户报 + VM 坐实）**：新建作战会话命令 AI 打开浏览器操作时，**LLM 调用期间切菜单再返回 → 命令中断、无法控制浏览器**。根因=会话台把「执行」绑死在 SSE 请求上——`stream_turn` 生成器在 HTTP 请求内同步跑 LLM+工具循环，切菜单 `onUnmounted` abort SSE → Flask 抛 GeneratorExit → 生成器中途终止，剩余工具调用（含 browser_open/goto）不执行。对比系统派发会话（后台跑+SSE只观察+inject队列）天生不中断。
  - **重构（执行放 celery worker，与自动会话一致）**：
    - **后台执行体** `_console.run_console_agent(session_id)`：worker 跑，无 SSE 依赖；消息来自 pending_user_msgs 队列每轮消费；每轮 `_persist_turn` 落 console_messages/tool_log/token + console_running 心跳；协作式停（console_stop_requested）；**跑完不改 status（恒 paused_manual）、不 finalize/不存报告/不标资产、绝不释放工具资源（持久浏览器跨回合存活——本 bug 根治点）**。抽 `_prepare_console_ctx` 与 stream_turn 共用组装。
    - **worker 认领**：`orchestration.submit_console_turn`（`console_running` CAS 锁防重复投）+ `_celery_adapter` 注册 `sentinel.run_console_session` task + `session.console_submit`（入队+触发）。paused_manual 绝不进 scheduler 自动认领（与 auto 零交叉）。
    - **只读观察流** `/session/console/<key>/observe`（读 console_messages 对话+tool_log+meta，用 console_running 判活，非 status）+ 发送端点 `/submit`。
    - **crash 兜底** `scheduler._tick_console_sessions`：心跳超时清 console_running 死锁 + 按 pending 重投（不续跑半截回合）；`_reclaim_on_startup` 清 stale。
    - **前端**：console 会话 send() 改「本地回显 + consoleSubmit 入队」+ 开只读观察流；**onUnmounted 只关观察流不中断执行**（根治点）；停止走协作式 consoleStop；运行中可继续入队。
  - **验证**：后端 py_compile 全过；`test_console` 新增 RunConsoleAgentTest 3 例（console_messages 落库/status 恒 paused_manual/console_running true→false/pending 消费/未释放资源/submit 入队触发）+ 修 2 个 stale 测试；`test_engine_loop`+gate 52 例回归绿；前端 build 零错。**VM E2E 待做**（核心：切菜单不中断）。
  - **附**：FakeRepo 补 `$push`/`$unset` 支持（测试替身对齐 Mongo）。

## 2026-09-15 更新（v1.21.157-61，三项：新建作战会话加上下文额度拉选 + 备用 AI + 会话 token 计量修复）

- **① 新建作战会话加上下文额度拉选**（`NewSessionModal.vue` + `session.console_create_session`）：会话台「新建作战会话」（入口A/白板）对齐新建任务页，加同款滑块（0~1000K 拉动 + k 精确输入框 + 拉满原生上限勾选）。后端 `console_create_session` 加 `max_context_tokens` 参（`_norm_ctx_tokens` 归一 0/-1/正数）落会话 doc。
- **② 新建作战会话加备用 AI**（同上）：加「备用 AI」下拉，仅列与首要模型**同协议**的 enabled provider（跨协议历史不兼容）、排除首要自身、首要改协议时自动清空非法备用；留空=不指定。后端加 `backup_provider_id` 参（`_resolve_backup_provider` 校验同协议）落 doc，首要失败时切它（复用引擎 backup 逻辑）。
- **③ 用户创建的会话 token 未计量根治**（`_console.py`）：**根因**——会话台 `chat_turn`/`stream_turn` 的 `_persist_turn` 此前**只落 console_messages/tool_log，从不累加 token** → 用户创建的会话 `total_tokens` 恒 0、限位卡片"占用"恒空。**修复**：两个交互内核与 `run_agent` 同口径累加——`window_tokens=max(字符估算, API 真实 prompt_tokens)`、`total_tokens` 单调增长（中转站 total 缺失时用窗口+回复估算兜底）、`token_budget` 落库；`_persist_turn` 加 token 形参落库。前端限位卡片"占用/上限"从此有数。
- **改动面**：后端 `ai_pentest/session.py`（console_create_session 加两参）+ `_console.py`（token 计量）+ `router/endpoints/session.py`（console_new 端点透传）；前端 `NewSessionModal.vue`（滑块+备用AI）+ `api/pentest.ts`（consoleCreate 类型）。
- **验证**：前端 `npm run build`（含 vue-tsc）零错；后端 py_compile 通过。**VM E2E 验证。** 纯后端 + 前端热更，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-60，一项：浏览器"打不开"根因修复——出口解析源头不再把死代理递给浏览器）

- **【浏览器打不开根因】AI 工具出口解析调错函数 + 默认值错**（`ai_pentest/_tools.py`）：
  - **现象（用户追问"为什么打不开"）**：AI 打开浏览器访问百度连接被关闭。-59 加了"打不开后降级直连"是补救，但用户对——根子是**为什么会去连不可达的代理**。
  - **根因（VM 实测坐实，两 bug 叠加）**：会话实际**没配代理**（`egress_proxy=None`/`direct`，VM 实测最近会话皆如此），但 `_egress_proxy_url`：① `ctx.get("egress_proxy", "smart")` 默认抬成 **smart**；② 调 `resolve_egress`（**只返 URL 不探可达性**）而非 `resolve_egress_url`（smart 探可达性、不可达回退直连）。→ 解析出挂掉的 `mihomo:17890` 递给 chromium → ERR_CONNECTION_CLOSED。VM 对比铁证：`resolve_egress('smart')`→`('http://mihomo:17890',True)`（返死代理）、`resolve_egress_url('smart')`→`''`（正确探测降级为直连）。
  - **修复**：`_egress_proxy_url` 改用带可达性探测+降级的 `resolve_egress_url`；默认值 smart→**direct**（会话没显式配代理就直连，不擅自 smart）。从源头杜绝把不可达代理递给浏览器/HTTP 工具，**一处修复惠及所有经它取出口的 AI 工具**（browser_navigate/browser_open/fetch_large_file 等）。与 -59（持久浏览器打不开后降级兜底）叠加：源头不递死代理 + 万一递了也能降级。
  - **VM E2E**：三种出口配置 browser_open 百度全成功——未配代理(None)→egress=''直连 7.1s、显式 direct→''  5.8s、smart(节点全挂)→探测不可达降级''  10.4s，均 `ok=True title=百度一下,你就知道`；不再把死代理递给 chromium。
  - **热更触达**：改动在 `_tools.py`（TRACK_DIRS 覆盖），`--reload` 自动重载，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-59，一项：持久浏览器代理不可达自动降级直连——对齐 smart 出口语义）

- **【持久浏览器连接被关闭根治】代理不可达时降级直连**（`ai_pentest/_browser_session.py`）：
  - **现象（用户报）**：AI 打开浏览器访问百度，"连接被关闭了"，最终降级 requests 模式访问。即 -57 放开门控让 AI 用持久浏览器后，持久浏览器在真实会话里启动失败。
  - **根因（VM 复现坐实）**：真实会话出口经 `resolve_egress("smart")` 解析成 `http://mihomo:17890`，持久浏览器带这个 proxy 启动 chromium → 首次导航 `net::ERR_CONNECTION_CLOSED`（VM 上 mihomo 节点全挂）。**smart 模式语义本应"代理不可达自动降级直连"**（`http_req`/`browser_navigate` 经 requests 降级都有兜底），唯独持久浏览器 `open_session` 拿到 proxy 硬用、失败不降级 → 两套浏览器容错不对等。
  - **修复**：`open_session` 首次导航若因代理连接类错误失败（`_is_proxy_conn_error`：ERR_CONNECTION_CLOSED/PROXY_CONNECTION_FAILED/TUNNEL/REFUSED/TIMED_OUT 等）且当前带了 proxy → **同步拆掉带代理的 worker（投关闭命令 + join 线程真退出 + 腾名额，不异步 close+递归防名额/内存占用卡超时）→ 无代理重开（直连）**。只降级一次（重开传 proxy_server=""，不再命中降级分支，不递归）。`_forget`/`_release_mem` 加 hid 清空幂等防重复释放。
  - **VM E2E**：smart 出口（mihomo 不可达）下 `browser_open` 百度 → 日志"proxy unreachable, degrade to direct" → 直连重开 `ok=True title=百度一下，你就知道`（17.9s，含失败探测+降级+渲染）；存活 worker=1 名额无泄漏。之前"连接被关闭→降级 requests"变为"持久浏览器代理不可达→降级直连成功"（拿到真实渲染的持久浏览器，面板可见，不再掉 requests）。
  - **热更触达**：改动全在 `_browser_session.py`（TRACK_DIRS 覆盖），gunicorn `--reload` 自动重载，存量用户走热更即得，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-58，两项：报告模板列表 500 根治 + 错误上报弹窗夜间 UI）

- **【报告模板列表 500 根治】INTEL 门面 list_templates 漏传 scope**（`risk_intel/asset_intel.py`）：
  - **现象（用户报）**：`GET /api/intel/report_template/` 返 500。VM 抓 traceback：`TypeError: list_templates() got an unexpected keyword argument 'scope'`。
  - **根因**：v1.21.157-48 给 `report_template.list_templates` 加了 scope 过滤 + 端点 `asset_intel.py:427` 传了 `scope=`，但端点走的是 **INTEL 门面** `IntelServiceImpl.list_templates`（asset_intel.py:1820），**这个门面方法没加 scope 形参**——端点调 `svc.list_templates(scope=...)` 命中旧签名 → TypeError。典型「一处改了、转发门面没对齐」。
  - **修复**：`IntelServiceImpl.list_templates` 加 `scope` 形参并透传给 `report_template.list_templates`。
- **【错误上报弹窗夜间 UI】ErrorReportModal 暗色适配**（`components/ErrorReportModal.vue` + `styles/theme-dark.css`）：
  - **现象（用户报）**：夜间模式下错误详细信息弹窗无暗色 UI，白盒黑字看不清。
  - **根因**：`.er-box` 用**从未在 theme-dark.css 定义的** `--dt-panel`/`--dt-line` 变量 → 恒 fallback 浅色（`#f6f8fa` 白底）；且 a-modal 内容 teleport 到 body。同 -48 网络横幅坑。
  - **修复**：① 组件改用已定义的 `--dt-card`/`--dt-border`/`--dt-muted`/`--dt-text`（日间 fallback 保持浅色）；② theme-dark.css 加全局 `.er-box`/`.er-k`/`.er-v`/`.er-msg`/`.er-hint` 暗色规则（teleport 保险，同网络横幅先例）。错误红改 `#ff6b6b`（暗底可读）。
  - **验证**：前端 `npm run build`（含 vue-tsc）零错。**VM E2E 验证。** 纯后端 + 前端热更，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-57，一项：AI 浏览器功能页失效根治——持久浏览器给 AI 用 + 跨进程可见 + 提示词脱耦）

- **【浏览器功能页面失效根治】三层断裂修复**（`_tools.py` + `_browser_session.py` + `_system_prompts.py` + `_scene_prompts.py`）：
  - **现象（用户报）**：创建渗透会话让 AI 启动浏览器，按设计应能在「浏览器功能页面」看到网站内容并交互，实际失效（面板恒"未开启"）。
  - **根因（逐层 VM 实测坐实）**：系统有两套浏览器——轻量无状态 `browser_navigate`（`_browser.py`，扫描/快速渲染，用完即关）+ 持久型 `browser_open`系列（`_browser_session.py`，能登录/抓懒加载 JS/多步复用，**面板 `console_browser_state` 只显示它**）。三层断裂：① 持久浏览器工具被门控成**仅 console_manual 可用**，自动渗透 AI 调不到；② 所有 scene 提示词只教 `browser_navigate`，AI 从不开持久浏览器 → 面板恒空；③ 持久浏览器 `_workers` 是**进程内字典**，自动渗透在 worker 进程起浏览器、面板走 HTTP 在 web 进程读 → **跨进程查不到**。
  - **修复（按设计：持久型给 AI 主力用）**：
    - **① 门控放开**（`_tools.py`）：持久浏览器工具（browser_open/goto/click/fill/screenshot/close）从"仅 console_manual"改为**AI 渗透会话通用**（自动+会话台都可用）；内存由 L3 池 + MAX_GLOBAL 上限管控（不再靠门控挡）。`_tool_schemas` 预过滤随之把它们纳入 AI 工具表。
    - **② 跨进程可见**（`_browser_session.py`）：worker 进程持久浏览器每步操作后把 `{active,url,title,elements,shot}` 落**会话文档 browser_state**；面板 `session_state` 本进程有 worker→实时截图，无 worker→回退读会话文档（截图本落磁盘、image 端点公开可取）。
    - **③ 提示词脱耦**（用户要求不碰 scene 内置逻辑、引导放系统层）：scene 提示词删掉硬编码的 `browser_navigate`（6 处改中性"浏览器工具，见系统协议"）；系统层新增 `BROWSER_USAGE_PROMPT`（`build_system_prompt` 拼入，用户不可覆盖）统一讲清"默认优先持久浏览器（登录/懒加载/多步），轻量 navigate 仅快速只读渲染"——消除"两套都在用"的冲突。
  - **VM 实测地基**：worker 进程内两套浏览器都能起（navigate rendered:True / open_session ok:True 有截图）。
  - **验证**：`test_reg_dispatch_gate` + `test_tool_schema_gate` + `test_engine_loop` 共 52 例全绿（门控放开断言、schema 纳入持久浏览器、系统提示词含持久浏览器优先引导）。**VM E2E 验证。**
  - **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`（TRACK_DIRS 覆盖），gunicorn `--reload` 自动重载，存量用户走热更即得，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-56，一项：模型串号根治——删自动 failover，兜底只走显式备用模型）

- **【模型隔离泄露彻底根治】删除自动全局同协议 failover，兜底只认用户显式备用模型**（`_engine.py`）：
  - **现象（用户报 + VM 实证）**：会话锁/跟随的是有钱的 `Claude (Anthropic)`，却报没钱的 `Claude (Anthropic) - 1` 的额度错误中断。VM 查实：两个中断会话 `provider_id=''`（跟随全局默认），`last_error` = `HTTP 403 new_api_error 用户额度不足 剩余额度 ¥0.002632`（claude-1 真没钱），状态 `paused_manual`。系统里确有 `Claude (Anthropic)` 与 `Claude (Anthropic) - 1` 两个**同协议同模型** provider。
  - **根因**：v1.21.157-49 的 `locked` 修复只堵了「锁定会话」，**未锁定会话（provider_id 空=跟随全局默认，含大量存量/自动会话）仍全量展开 `list_failover_candidates`** → 首要模型一抖动/永久错，系统就**自作主张** failover 到同协议同名但没钱的 claude-1 → 串号中断。**真正的病灶是「系统自动 failover」本身**——它与「备用模型」这个**用户显式配置的兜底功能**职责重叠且不可控。
  - **修复（删自动 failover）**：`_call_resilient` 候选**恒为 `[首要模型] + [用户显式 backup_prov]`**，**彻底删除** `list_failover_candidates` 的自动展开——系统绝不自己拉第三个 provider 进候选。锁定/未锁定行为一致（`locked` 形参保留仅为签名兼容，已无行为差异）。兜底路径唯一：用户在新建任务/会话里主动选的备用模型（已限同协议）。
  - **效果**：不管会话锁没锁模型，系统都不会再自动串到没钱的同协议 provider；要兜底就用「备用模型」显式指定。全局默认 provider 现指向有钱的 `Claude (Anthropic)`，两个卡住会话恢复即用它、不再串号。
  - **验证**：`test_engine_loop` 43 例全绿（新增 `test_no_auto_failover_even_unlocked`=未锁定也不自动串 claude-1→paused_manual、`test_explicit_backup_still_works`=显式备用仍生效；`test_locked_skips_global_failover` 保留）；`test_backup_provider` 全过。`ai_config.list_failover_candidates` 函数保留（引擎不再调用）。
  - **热更触达**：改动在 `sentinel_platform/modules/ai_pentest/_engine.py`（TRACK_DIRS 覆盖），gunicorn `--reload` 自动重载，存量用户走热更即得，无需 rebuild 镜像。**VM E2E 验证。**

## 2026-09-15 更新（v1.21.157-55，一项：GET 请求网络瞬断自愈——不再因 reload 抖动误报"网络异常"）

- **【误报"网络异常"根治】前端幂等请求网络失败静默重试**（`api/request.ts`）：
  - **现象（用户上报）**：`GET /api/console/resource_alert` 报「网络请求失败：Failed to fetch」。VM 核查端点健康（直连/经 nginx 均 401 秒回 6ms、web 容器 Up 3h、日志无 traceback）——**端点没挂**。真因 = gunicorn `--reload`（热更后端 .py 时）重启 worker 的几百毫秒窗口，前端 30s 轮询的 GET 恰好吃一次网络失败，被 v1.21.155 的全局错误上报机制如实弹窗，属**瞬断误报**。
  - **根因**：`request.ts` 对 `fetch` 网络层失败零容忍——一失败立刻 `captureError` 弹窗，违反铁律「间歇失败优先重试自愈，别把单次波动当确定性失败」。
  - **修复**：网络层失败时，**幂等请求（GET/HEAD）先静默重试最多 3 次 + 退避（400/800ms，等 reload 恢复）再上报**；写请求（POST/PUT/DELETE/PATCH）不盲重试（防重复提交），保持快速失败。重试仍失败才判真故障、捕获上报。
  - **效果**：reload 抖动/偶发网络波动下轮询 GET 自愈，不再弹"网络异常"打扰用户；真的服务端故障（重试耗尽）仍如实上报。
  - **验证**：前端 `npm run build`（含 vue-tsc）零错。纯前端热更，无需 rebuild 镜像。**VM 部署验证。**

## 2026-09-15 更新（v1.21.157-54，一项：上下文上限滑块量程扩到 0~1000K）

- **【滑块量程】上下文上限可拉动长条 0~512K 扩到 0~1000K**（`TaskCreate.vue` + `PentestConsole.vue`）：
  - 用户要求常用大值直接拖到，滑块 `CTX_MAX_POS` 64→125（125×8K=1000K）。新建任务节点标记 默认/250K/500K/750K/1000K；会话台接管窗节点 保持/放大/+1000K。
  - k 精确输入框保留，供 >1000K 的极端值直接输入。后端契约（0/-1/正数）不动。
  - **验证**：前端 `npm run build`（含 vue-tsc）零错。**VM UI 点击验证待做**。纯前端热更。

## 2026-09-15 更新（v1.21.157-53，一项：上下文上限滑块加精确输入框——突破滑块 512K 封顶）

- **【滑块拉不到大值】上下文上限滑块 + 精确 k 输入框 + 拉满勾选**（`TaskCreate.vue` + `PentestConsole.vue`）：
  - **现象（用户报）**：-52 的滑块封顶 512K，拉不到 900k 等更大值。
  - **修复**：重构为「权威值 + 三视图」——权威值就是后端要的 token 数（新建任务 `form.ctx_tokens` / 会话台 `takeoverWant`，口径 0=默认/-1=拉满/正数=token）；滑块、**精确 k 输入框（默认单位 k）**、拉满勾选是它的三个可写视图，互不打架。滑块负责 0~512K 快速拖动，**滑块够不到的大值（如 900k）在右侧「精确值」框直接输入**，突破滑块上限；勾「拉满（原生上限）」= -1（勾上时输入框置灰）。
  - **两处一致**：新建任务页（默认 0=跟随全局默认）+ 会话台接管窗（默认 0=保持当前，k 框输入低于当前 floor 的值自动回落为"不放大"，守只增不减）。
  - **后端零改**：`pentest_max_context_tokens`/`set_session_context` 契约（0/-1/正数）完全不动，仅前端表现层。
  - **验证**：前端 `npm run build`（含 vue-tsc）零错。**VM UI 点击验证待做**。纯前端热更，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-52，一项：单会话上下文上限控件改回滑块——按钮组还原为可拉动长条）

- **【上下文上限控件设计错误还原】三态按钮组 → 可拉动长条滑块**（`TaskCreate.vue` + `PentestConsole.vue`）：
  - **现象（用户报）**：原设计单会话上下文上限应是「一根可拉动长条，右侧靠近顶端一个节点，拉过节点=模型原生上限」；实际全系统设置上下文长度的地方都变成了按钮组（跟随全局默认/拉满/自定义三个 radio-button）。
  - **修复**：两处控件（新建任务页 + 会话台接管窗）从 `a-radio-group` 按钮组改为 `a-slider` 长条滑块。位置分段映射（后端契约 `pentest_max_context_tokens` 0/-1/正数**完全不动**，只改前端表现层）：
    - **新建任务**：`pos 0`=最左「默认」（跟随全局默认，值 0）→ `pos 1..64`=中段自定义 token（8K~512K，8K 步进）→ `pos 65`=最右端过节点「拉满」（模型原生上限，值 -1）。节点标记 默认/128K/256K/384K/拉满，滑块下方实时显示当前档文字。
    - **会话台接管窗**（只放大不缩小语义保留）：`pos 0`=最左「保持当前」（约当前 floor，want 0）→ 中段=在当前上限基础上放大（floor + pos×8K，天然 ≥ floor 只增不减）→ 最右端过节点=拉满原生上限（want -1）。节点标记 保持/放大/拉满。
  - **改动范围**：仅这两处渲染上下文上限控件的地方（全局 AiConfig `max_context_tokens=200000` 是全局默认兜底值，页面无编辑控件，不涉及）。删 `ctx_mode`/`ctx_custom`/`takeoverCtxMode`/`takeoverCtxCustom`，改用滑块位置 `ctx_pos`/`takeoverCtxPos` + 位置↔token 映射函数。payload/提交逻辑（`ctxTokensPayload`/`confirmTakeover`）改读滑块位置，后端接口零改。
  - **验证**：前端 `npm run build`（含 vue-tsc 类型检查）零错，TaskCreate/PentestConsole 产物重建。**VM UI 点击验证待做**。纯前端改动，走 `docker/frontend` 产物热更触达，无需 rebuild 镜像。

## 2026-09-15 更新（v1.21.157-51，一项：禁用工具不再暴露给 AI——工具表按会话上下文预过滤）

- **【禁用工具 AI 仍在调用根治】AI 工具表按会话 ctx 预过滤**（`ai_pentest/_engine.py` + `_tools.py` + `_console.py`）：
  - **现象（用户报）**：已禁用的工具，AI 渗透会话仍在调用。按设计（核心链路 §四 / 记忆 10.2「只向 LLM 暴露当前可执行工具」）AI 拿到的工具表里就不该有这些工具。
  - **根因**：`_engine._tool_schemas()`（喂给 LLM 的工具表）用 `ai_tools.list_effective_tools()` —— **全局静态表，只过滤 implemented/available/扩展enabled，完全不接收会话 ctx**；而 `_tools.dispatch()` 有 4 类**会话级/模式级运行时门控**（① 主动扫描 run_nuclei/run_npoc/weak_brute/fuzz_params 全局禁；② 内网立足工具仅 redteam/console；③ 持久浏览器仅 console_manual；④ 情报沉淀 intel_enabled=False 时禁）。结果：这些工具在 schema 里可见 → AI 反复调 → 每次 dispatch 返 blocked → 白烧 token/轮次 + 可能误判"工具坏了放弃攻击面"。
  - **修复（门控单一事实源 + schema 预过滤）**：`_tools.py` 抽出纯判定 `gate_tool(name, ctx)` —— dispatch（执行拦截）与 `_tool_schemas`（暴露给 LLM 前预过滤）**共用同一判定，杜绝两处规则漂移**。`_tool_schemas(ctx)` 组装工具表时用 `gate_tool` 预过滤：当前会话会被门控的工具**直接不进表**，AI 看不到就不会调。dispatch 保留 gate_tool 兜底（旧会话历史残留调用/扩展动态变更/人工构造时运行时语义仍与 schema 一致）。两处调用点（自动渗透 `_engine.run_agent` / 会话台 `_console._prepare_turn`）均改为传 ctx。`ctx=None`（纯展示）不做会话级过滤，向后兼容。
  - **效果**：src 自动会话工具表不含主动扫描/内网工具/持久浏览器；redteam 会话放行内网工具；会话台（console_manual）放行持久浏览器；主动扫描任何模式（含人工接管）都不进表；intel 关时情报沉淀工具不进表。
  - **测试**：新增 `test_tool_schema_gate.py` 10 例（gate_tool 与 dispatch 判定一致 ×5 + schema 按 ctx 过滤 ×5：src 隐藏扫描/内网/浏览器、intel 关隐藏沉淀、redteam 放行内网、console 放行浏览器、ctx=None 向后兼容）；`test_engine_loop` 33 例回归全绿（含 locked failover 等，证明未打破引擎循环）；`test_internal_tools` dispatch 门控行为不变。
  - **热更触达**：改动全在 `sentinel_platform/modules/ai_pentest/`（TRACK_DIRS 覆盖），存量用户走热更即得，gunicorn `--reload` 自动重载，无需 rebuild 镜像。纯后端逻辑，前端无改（brand.ts/version.txt 随例递增 + rebuild）。**VM E2E 待做**。

## 2026-09-15 更新（v1.21.157-50，一项：设备状态资源可靠性评分重构——磁盘偏紧不再被无视 + 分数实时动态）

- **【资源分数严重失真根治】设备状态「资源运行可靠性」评分重构**（`workspace/dashboard.py:_resource_score`）：
  - **现象（用户报 + VM 实证）**：VM 磁盘 78%/仅剩 5.7GB、系统自己算出磁盘维=58 且 `disk_note` 明写"偏紧"，总分却恒 **99「资源充裕」**——headline 与自己的明细自相矛盾；且 CPU/内存怎么变分数都钉在 99 不动（"不是实时动态"）。
  - **根因（两个真 bug，同一病根）**：旧「水位档定 `[lo,hi]` 区间 + `cap_short=min(cpu,mem)` 线性落位」两层模型自我打架——① relaxed 档地板 85 把量程压成 `[85,100]`，分数死区 99~100，CPU/内存变化跨不过水位档就不动；② 磁盘被**结构性踢出总分**（v1.21.157-46「治恒76」时为躲开磁盘钉死分数而矫枉过正），磁盘偏紧对总分零影响。两个极端（恒76 ↔ 恒99）都是这套模型的通病。
  - **重构（三维加权 + 最弱维拖低 + 物理见底硬闸）**：总分 = `0.6×(0.35·cpu+0.35·mem+0.30·disk) + 0.4×min(三维)`（连续 0-100，任一维变化实时体现，弱项拖低不被均值稀释）；再叠加物理"见底硬闸"守告急红线——磁盘绝对见底(<1.5GB/≥95%)→告急封顶、偏紧(<3GB/≥90%)→偏紧封顶、内存 0 slots/综合 critical→告急封顶（加权表达不了写失败/停投这类硬风险，必须封顶，守禁删信号维铁律，不重演恒22/恒76）。水位档退为仅供 critical 硬闸 + 展示，不再定分数区间。
  - **效果（VM 实测同机对比）**：磁盘 78%/剩5.7G 场景 **99「充裕」→ 74「运行良好」**（磁盘维 58 真实拉低总分）；CPU 空闲/满载分数差 >8 分（死区消除，实时动态）。
  - **红线守护**：磁盘真见底(<3G偏紧/<1.5G告急)仍拉低、内存 0 slots/水位 critical 仍告急+"收缩并发保命"、全空仍充裕≥85、slots 驱动内存维分档——回归测试 `test_reg_resource_score` 9 例全绿（翻转 1 条被推翻的旧断言"5.8G算充裕" + 新增 2 条锁死修复：磁盘偏紧拉低总分 / 分数随 CPU 实时动）。
  - **前端**：消费键 `score/level/level_text/verdict/disk_note/task_slots/dims` 全保留，`rv-` 样式类档位（excellent/good/tight/critical）不变——纯后端算法改动，前端零改。
  - **热更触达**：改动全在 `sentinel_platform/modules/workspace/dashboard.py`（TRACK_DIRS 覆盖），存量用户走热更即得，靠 gunicorn `--reload` 自动重载，无需 rebuild 镜像。**VM E2E 已实测**（-50 测试迭代，待人工批准去测试号正式分发）。

## 2026-09-15 更新（v1.21.157-49，十一项：控制台卡片名/新建会话跳转/上下文上限移任务/封禁出口默认直连/急救恢复合并/批量恢复/新建会话去接管加选模型/模型隔离泄露/攻击链穿框/系统知识中危门槛/单位视图并入资产视图）

本批 11 项（用户 2026-09-15 反馈，横跨前端交互、AI 渗透引擎、任务/会话链路 + 一处模型隔离根因修复）：

- **① AI 控制台卡片名显任务名**（`PentestConsole.vue` + `session.py` + `api/pentest.ts`）：原卡片标题绑 `system_name`（组件指纹如 "express (nginx)"），应显任务名。会话 doc 无任务名字段 → `create_session`/`batch_create_from_assets` 新增 `task_name`（用 `source_task_id` 反查一次 task.name 冗余落库），卡片标题改 `task_name > system_name > site > 白板`，副行显 system_name。白板/会话台会话无 task_name 自然回退。

- **② 渗透会话「新建」改为跳转 AI 控制台**（`PentestList.vue`）：删本页内建新建弹窗 + `openCreate`/`create`/`form`，按钮改 `router.push('/pentest/console?new=1')`；控制台 `onMounted` 读 `?new=1` 自动弹「新建作战会话」窗。统一新建入口。

- **③ 单会话上下文上限从策略移到新建任务**（`task_create.py` 三入口 + 端点 + `TaskCreate.vue` + `PolicyEdit.vue`）：原在策略 `auto_pentest` 块配（-46），改到新建任务、**仅所选策略绑定 AI 渗透（auto_pentest=True）时可配**。加 `pentest_max_context_tokens` body 参 → `_apply_ctx_tokens` 门控写 `options.max_context_tokens`（照 `pentest_egress_mode` 从策略移任务的先例）→ 已有透传链落会话。滑条三态：跟随全局默认(0)/**拉满=模型原生上限(-1)**/自定义(正数)，不设上界（守禁硬限制铁律）。策略页移除该 UI，后端 `policy.max_context_tokens` 保留作兜底（任务不传时用）。

- **④ 新建任务「AI 封禁备用出口」默认改直连**（`TaskCreate.vue`）：默认值 `smart`→`direct`（直连选项本就存在，只是默认错成智能代理），对齐《代理出口规范》「默认直连」原则。

- **⑤ 会话「急救」与「恢复」合并为「恢复」**（`PentestList.vue`）：删独立「急救」入口，「恢复」点击弹窗——默认沿用原发起模型直接恢复，也可换**同协议**模型（额度不足时）后恢复，**跨协议模型置灰不可选**（协议过滤逻辑复用，弹窗标题/文案改「恢复会话」）。

- **⑥ 渗透会话加批量恢复**（`PentestList.vue`）：批量操作栏加「批量恢复」，仿 `batchStop` 过滤选中项里 `canResume` 的会话逐个 resume，**默认沿用各会话原发起模型**（不传 provider）。

- **⑦ AI 控制台新建作战会话去接管提示 + 去上下文限制 + 加模型选择**（`NewSessionModal.vue` + `PentestConsole.vue` + `_console.py` + `session.py`）：按设计 §10 区分两类入口——**入口A 新建白板会话**（`console_created`）人工从零开始、无接管对象 → 不弹接管窗、不设上下文限制、**加 AI 模型选择器**（锁定会话所用模型）；**入口B 恢复已结束自动会话**保留接管语义。`console_create_session` 加 `provider_id`（复用 `_resolve_lock_provider`）；`_console._prepare_turn` 的 provider 解析改「会话锁定优先」（对齐 `_engine._resolve_session_provider`）；`console_load` meta 透出 `console_created` 供前端分流。

- **⑧【模型隔离泄露根因修复】**（`_engine.py`）：用户报「claude-1 没钱但 claude 有钱，会话却因额度不足中断」。真因 = `_call_resilient` 无差别把 `list_failover_candidates`（所有同协议 enabled provider）拉进候选，架空会话锁定——funded `claude` 一瞬时抖动就 failover 到没钱的 `claude-1`，其额度 403 又被判 transient（-47），把整条会话拖成 `paused_transient`。修：`_call_resilient` 加 `locked` 参，**会话锁定 provider_id 时不展开全局同协议 failover**，候选仅 `[首要 + 用户显式 backup]`（都受会话控制、已限同协议）；未锁定会话保持全量 failover 向后兼容。`run_agent`/`_console` 两处调用按 `sess.provider_id` 非空传 `locked=True`。

- **⑨ 攻击链模型箭头横穿方块**（`AttackChain.vue`）：真因 = `graphEdges` 同行水平连线写死 `a.x+70→b.x-70`（假设 a 在 b 左侧），但蛇形布局奇数行是反向的（右→左），此时 a 在 b 右侧 → 从 a 右缘一路向左穿过 a 自己和 b 的方块。修：按 a、b 相对位置取正确出入边（正向 a右缘→b左缘 / 反向 a左缘→b右缘）。

- **⑩ 无中危以上漏洞的会话不写入系统知识**（`_engine.py`）：`_writeback_system_playbook` 危害门槛从 `{critical,high}` 对齐到设计（§3.4 回写闭环 + 重设计留档「只沉淀中高危及以上」）的 `{critical,high,medium}`——原代码注释写「中高危」但 `$in` 漏了 medium，与设计漂移。此 query 即会话级门控：会话无 verified 的中危+漏洞→返回空→一条打法都不写（天然实现「无漏洞/无中危以上漏洞不写入系统知识」）。只门控收尾打法库，运行中主动写的攻击链/单位情报池不动（用户拍板）。

- **⑪ 单位视图并入资产视图**（`IntelCenter.vue` + `UnitView.vue` + `router/index.ts`）：「资产情报」改名「资产视图」；单位视图作为一个 Tab 内嵌（`UnitView` 加 `embedded` prop，嵌入时不渲染外层 PageContainer 避免双标题，Tab 首次打开懒挂载）；删除独立「单位视图」菜单项（路由保留作书签兼容）。

- **⑫ 文档 + 版本**：本 CHANGELOG + changelog.json + 版本 -48→-49（version.txt + brand.ts）+ 云端 MODULES/INTERFACES/代理出口规范相应处。

- 验证：`py_compile` 6 后端文件全过；前端 `npm run build` 零错含 -49（产物已重建 `docker/frontend`）；`test_task_create`(22，含新增 #3 门控) / `test_task_create_endpoints`(53，顺带修 -48 遗漏未更的多目标合一/归属过滤陈旧断言) / `test_policy` / `test_llm_error_class`(4) 全绿；新增 3 例回归（#8 locked 隔离×2 / #10 medium 门槛）+ #7 console 锁定 provider 隔离脚本验证通过。**纯后端 + 前端热更，无新依赖，不需 rebuild 镜像**（前端已 `npm run build` 重建 `docker/frontend`；brand.ts 版本变已随之重建）。**VM E2E 待做**（本批为 VM 测试迭代 -49，按 SOP 先 VM 实测再经人工批准去测试号正式分发）。注：本地 `SessionE2E` 6 例报 402 是无激活 config.yaml 致整类统一门控（含未改的 stat/detail 用例），非本批引起，VM 有激活配置不受影响。

## 2026-09-15 更新（v1.21.157-48，九项：网络卡夜间UI / 攻击链重叠 / 单位视图碎片 / 多URL合一任务 / 漏洞中心弹模板 / 报告排FP / 会话急救 / 中断计数+详情漏洞数）

- **① 网络质量「网络环境总评」卡无夜间 UI**（`NetworkCheck.vue` + `theme-dark.css`）：真因 = `.q-overall`/`.q-sec` 用未定义的 `--dt-line`(恒 fallback #eee) + `.ov-*` 各级硬编码浅色 pastel 背景，无暗色覆盖 → 夜间白板压亮字。修：theme-dark.css 加 `html[data-theme=dark]` 覆盖（横幅底改按级半透明彩色、border 走 --dt-border），仿 v46 `.res-verdict` 范式。

- **② 攻击链模型互相重叠**（`attack_chain.py`）：真因 = `record_step` 合并键=精确 `{unit,title}`，title 全 AI 控；同目标近义 title→平行链共享步骤，前端各渲一图=视觉重叠（前端 SVG 几何本身无碰撞）。修：`record_step` 找已存在链时，除精确 `{unit,title}` 外，**加"同 unit + 同 session 已有链则并入"**（一个会话本就一条链），不做模糊字符串匹配（避免误并）。

- **③ 单位视图碎片化（负优化）**（`asset_intel.py`）：真因 = `_fallback_unit(task_name, host)` 返 `任务名_目标名(host)`，每 host 一桶 → 单位视图碎成一堆单资产"单位"（VM 实证 `政府-探测_3g_zzxm_hnzwfw_gov_cn` 等）。优先级本身对（user source.unit > ICP unit_map > fallback），碎片元凶是 fallback 拼 host。修：`_fallback_unit` 去 host 维度——回退**任务名**（缺则主域 fld），同任务/同主域资产落同一单位桶。不碰 user/ICP 优先级。

- **④ 多 URL 建任务被拆成多个任务**（`task_create.py` + `orchestration.py`）：真因 = `_create_tasks` 每域名 insert 一篇。修：**多目标（多域名 或 IP+域名混合）合并成一篇聚合任务**，全量目标按 ip/domain 分类存 `options.multi_targets`，`_recon_handler` 分批侦察（域名批保留子域枚举，区别于 FOFA 关爆破）。单目标行为不变。VM 实证：4 目标→created=1。

- **⑤ 漏洞中心报告生成直接生成没弹模板选择**（`VulnCenter.vue` + `report_template.list_templates` 加 scope 过滤）：真因 = VulnCenter `genReport` 直调 `intelApi.generatePentestReport`(LLM/markdown 无模板)。修：改为**弹模板选择**→`reportTemplateApi.generate`；会话报告选 scope=session 模板、任务报告选 scope=task 模板。`list_templates` 加 `scope` 参（含 `$or scope 缺失` 兼容学习模板）。TaskList 的模板弹窗也补 scope=task 过滤（只列任务级）。

- **⑥ 报告排除误报 + 按降级后等级写**（`report_template._collect_findings` + `asset_intel` 三处采集器）：真因 = 采集器不过滤 `handle_status==false_positive`。修：三处（模板采集/task markdown 汇总/session 报告）加 FP 过滤。降级部分无需改（都读 `severity`，降级已写 severity=降后值，自动生效）。VM 实证：标 1 条 FP → 报告采集 8→7。

- **⑦ 渗透会话「设置」改「急救」+ 加长中断重试轮次**（`PentestList.vue` + `scheduler.py`）：会话列表「设置」改名「急救」——中断会话**一键急救**（可换锁定 AI 模型如原模型额度不足 + 自动恢复运行）。`scheduler.MAX_TRANSIENT_RETRY` 默认 5→12，中断会话更耐心自愈。

- **⑧ 任务列表中断数显示(标橙) + 任务详情漏洞/url 恒 0**：
  - **8a 中断计数**（`session.progress_by_tasks` + `TaskList.vue` + `pentest.ts`）：`progress_by_tasks` 加 `interrupted`=count(paused_manual/paused_transient/fatal/error)，且**从 active 剔除**（此前 paused_* 算 active 显"渗透中"、fatal 谁都不算漏计 → "1/1 渗透中"假象）。前端加橙色「AI 已中断 N/total」标。
  - **8b 详情拿错任务**（`task_list.list_tasks` + endpoint）：`TaskDetail` 传 `_id` 但 `list_tasks` 忽略 → 详情恒拿"最新任务"。修：`list_tasks` 认 `_id` 精确过滤（复用 policy `_id` 修复范式）。
  - **8c 漏洞数恒 0**（`task_list._compute_statistic`）：AI 漏洞在 `intel_finding` 只带 session_id 无 task_id，旧算法只数 vuln+nuclei_result by task_id → 纯 AI 渗透任务漏洞恒 0。修：加两跳（该任务会话→intel_finding，数 status=finding）。VM 实证：某任务 vuln_cnt 0→3。

- **⑨ 文档**：本 CHANGELOG + INTERFACES/MODULES 相应处 + 版本 -47→-48。

- 验证：新增/更新单测 131 例全绿（task_create 多目标合一 + 200 目标不砍 / vuln_center / report_template FP 排除 / asset_intel `_fallback_unit`+unit 优先级 / task_list `_id`+两跳 vuln_cnt / session interrupted 计数）+ orchestration 14 例。前端 `npm run build` 零错含 -48。**VM E2E**：④多目标合一 / ⑥报告排 FP / ⑧中断计数+详情漏洞数+_id 过滤 均实证。**纯后端+前端热更，无新依赖，不需 rebuild 镜像**。①⑤⑦为前端交互，随 -48 部署。

## 2026-09-15 更新（v1.21.157-47，五项：绑定AI冻结 / 漏洞不被吞 / 猜想封顶info / 额度403可重试 / 漏洞降级）

- **① 冻结「AI 任务环节·绑定 AI」选择器**：现在模型都在「新建任务」按任务选（`pentest_provider_id`/`observer_provider_id` 等，会话锁定优先于 scene 绑定），scene 级绑定已基本废弃。前端 `AiConfig.vue` 表格内联 select 改**只读 tag 展示**、弹窗 select `disabled`、删 `bindScene`、更新提示文案。**后端 `resolve_provider_for_scene` 一字不动**（guard*/observer/template_learn/finding-review 仍依赖它兜底全局默认），存量绑定值保留可解析——纯 UI 冻结，只停新绑定。

- **② 漏洞被吞修复（VM 实测 57 findings：31 条是被隐藏的 lead）**：真因 = 漏洞中心默认视图 `verified=True` 硬过滤把所有未证实(attempted/none)的 finding 藏了（24 attempted + 7 none）。修复 `list_unified_findings` **不再默认锁 verified=True**——未证实 finding 已被证据封顶闸降到 info（见③），默认按 `min_severity`(low) 过滤即自然隐藏 info 噪声；用户把 min_severity 调到 info/全部就能看到全部线索。次因 = 信息泄露家族同端点去重跨不同类型合并（dc.js 同端点的硬编码凭证/源码/接口文档泄露被并成一条）→ **收紧 `_check_same_endpoint_dup`：只把模糊伞形泛称（信息泄露/敏感信息泄露/版本信息泄露）吸收进同端点具体洞，具体类型各自独立成条不再互吞**。

- **③ 猜想被当高危修复（VM 实测该 finding：evidence_level=confirmed 但 5 条证据全是 HTTP 200 差异化报错，AI 凭推理自评 HIGH 7.4）**：真因 = 严重度与证据完全解耦（`calibrate_severity` 对 ≥7.0/high 直接短路不动，且无"无实证⇒封顶"规则）。修复 = `_record_one` 加**证据封顶闸**：`evidence_level != confirmed`（attempted/none）→ `severity` 一律封顶 `info`（记 `severity_capped_by_evidence` + basis，原始 `cvss_severity` 留档）。既不隐藏(仍入库可复核)、也不冒充高危。确定性规则、零 token；nuclei/npoc 一次性工具本就 confirmed 不受误伤。**此闸同时服务②**（lead 降 info 后默认视图放开也不刷屏）。

- **④ 额度 403 误判 permanent 修复（VM 实测 session 跑 246 轮后 403「剩余额度 $0.002632」立即 paused_manual）**：真因 = `_llm` 纯按状态码分类，403→permanent 零重试，从不看 body。new-api 聚合代理余额同步抖动会瞬时误报「额度不足」($0.002632 正是同步竞争产生的极小正值)。修复 = `_classify_status`→`_classify_error(status, body)`，402/403 **命中额度标记**（额度不足/余额/insufficient/quota/balance/new_api_error/欠费）→ `ERR_TRANSIENT`，走 3 次退避重试（`RETRY_BACKOFF=[1,2,4]`）给代理余额重算时间；真权限 403（无额度标记）仍 permanent。同 provider 重试比 failover 更能救瞬时余额抖动。

- **⑤ 漏洞中心「降级」操作 + 负面标记喂 AI 效益比讨论**：
  - **降级操作（已落地）**：`vuln_center.downgrade_severity(source, ids, target, handle_by)` **只降不升**（目标须严格低于当前，否则跳过），记 `manual_severity`/`downgraded_from`/审计；端点 `POST /finding/unified/downgrade`（vuln:write）；前端 `VulnCenter.vue` 操作菜单加「降低危害等级」子菜单（中危/低危/信息，弹确认，仅 AI 漏洞）。
  - **负面标记喂 AI 杜绝③——结论：只做轻量方案，不做历史 RAG（效益比不划算）**。详见下方分析：③的确定性封顶闸已治本（零 token），把历史误报/降级做成 RAG 让 AI 每次报 finding 前检索类似历史，边际收益低（③已解决根因）、成本高（每会话数百~数千 token + 易过拟合具体目标，违背禁硬编码目标铁律）。轻量替代 = 后续在"报 finding"工具描述里强化"无实抓证据只能报 info/线索"（一次性静态、零增量 token）。

- 验证：`test_vuln_center` 新增 5 例（无实证封顶 info / confirmed 保留定级 / 同端点具体泄露类型不互吞 / 泛称被具体洞吸收 / 降级只降不升）+ 更新 1 例（lead 不再被吞、靠 min_severity 控噪）；新增 `test_llm_error_class` 4 例（额度 403/402 转 transient、真权限 403 仍 permanent）全绿（33+4 例）。前端 `npm run build` 零错含 -47。**VM E2E**：③无实证 finding 落 info 不再 HIGH ✓；⑤ confirmed critical 降级→low ✓；④额度分类器 ✓；下游 downgrade 端点注册 ✓。**纯后端+前端热更，无新依赖，不需 rebuild 镜像**。

### 附：item⑤「负面标记喂 AI」效益比分析（供决策留档）
- **方案甲（重，不采用）**：历史误报/降级 finding 做成情报，AI 报 finding 前 RAG 检索"类似历史是否被降级"。成本：每会话多次检索 + 上下文注入（数百~数千 token/会话），易过拟合具体目标（碰禁硬编码目标铁律）。收益：③根因（无实证却自评 confirmed）已被确定性封顶闸解决，RAG 仅锦上添花。
- **方案乙（轻，采用）**：不喂历史。靠 ① ③的证据封顶闸（确定性、零 token、已覆盖③）+ ② 提示词层强化"无实抓证据只能报 info"（一次性静态、零增量 token）。
- **结论**：③封顶闸治本且零成本；负面标记喂 AI 边际收益低、token/过拟合成本高 → 只做方案乙，方案甲留档不落地。

## 2026-09-15 更新（v1.21.157-46，八项批量：任务级报告入口 / 上下文上限移策略 / 会话台接管交互 / 评分卡修恒76+夜间UI）

本批 8 项（横跨前端 UI、AI 渗透会话台、策略配置、仪表盘评分 + 一次运行时系统核查）：

- **① 任务列表「导出」改「报告」**：原「导出」是死链 `/api/export/<id>`（当前后端无此路由，ARL 遗留）。改为「报告」按钮 → 弹窗选就绪模板（默认选中内置任务级 `builtin_task_v1`）→ 调 `reportTemplateApi.generate({type:'task'})` 聚合整个任务漏洞生成 docx → 跳「报告编辑」。删 `exportUrl`。文件 `frontend/src/pages/tasks/TaskList.vue`。

- **② 单会话上下文上限从 AI 配置中心移到策略「AI渗透」内**：
  - 旧设计：上限只在 AI 配置中心全局设一个值（`ai_config.max_context_tokens`），所有会话一刀切。作废原因：不同策略/目标该用不同上下文预算，且用户要「拉满=模型原生上限」。
  - 新：策略 `auto_pentest` 块内加「单会话上下文上限」（跟随全局默认 / 原生上限 / 自定义三态）。落 `policy.max_context_tokens`（0=跟随全局默认，-1=原生上限哨兵，正数=固定 token；`_norm_ctx_tokens` 归一，**不设死上界**守禁硬限制铁律）。经 `task.options`→`batch_create_from_assets`→`create_session` 落会话 doc。
  - 引擎 `_engine._run_agent_impl` 上限解析改为 **会话值 > 全局配置 > DEFAULT**；哨兵 -1 → `_llm.native_max_context(prov)` 按模型名 `[Nm]` 后缀解析原生最大上下文（如 `claude-opus-4-6[1m]`→1M），无后缀按协议查保守默认表。`budget=max_context×0.9` 不变。
  - AI 配置中心移除该滑块 UI（字段保留作全局兜底，会话台/未配策略仍用）。修正旧文案「达 95%」→实际「达 90%」。

- **③ 会话台「插话」改「对话」+ 首次对话弹接管窗**：文案「插话」→「对话」（`PentestConsole.vue`）。首次对话前 `send()` 弹「接管 AI」确认窗，内含上下文上限选择器（保持当前/原生上限/自定义，**只放大不缩小**）；确认后 `takenOver=true` 才发送。放大经新端点 `POST /session/<id>/context`→`session.set_session_context`（校验只增不减）。接管语义=人工介入，AI 继续自主跑，对话即 inject 入队（保持 liveMode 行为）。

- **④ 删除「留痕入库」选项，接管后默认入库**：删 `traceEnabled` 复选框+ref（`PentestConsole.vue`）。后端 `_console._prepare_turn` 恒 `ctx["trace_enabled"]=True`，使 `_tools.dispatch` 写回门控永不拦截 → 漏洞/情报恒入库。`intel_enabled`（跨会话共享情报池）另一维度不动。

- **⑤ 夜间模式态势总览数值/背景对比过低**：`.metric-value` 硬编码暗色字 `#1f2937` 压在暗卡底 `#0d1424` 看不清 → 改用 `var(--dt-text)`（亮暗两态自适应）。文件 `Dashboard.vue`。

- **⑥ 设备状态评分卡：修恒 76 + 补夜间 UI**：
  - **恒 76 真因（VM 实测）**：磁盘把分数钉死两次——① 磁盘绝对余量 5.8GB<`DISK_FREE_GOOD_GB=8` 把水位档从 relaxed 拉到 normal[65,84]；② `cap_short=min(cpu,mem,disk)=disk_s=59` 又当短板 → `65+19×0.59≈76`。VM 磁盘常年 ~78%/5.8GB 不动 → CPU/内存怎么变都是 76。
  - **修复（`dashboard._resource_score`，不删磁盘维守铁律）**：磁盘绝对档只在**真见底**（<3GB tight / <1.5GB critical）才向下拉档，"够但不宽裕"(5.8GB)不再拉档（与真实调度 relaxed 不收缩并发对齐）；档内落位磁盘非临界时不当短板，用 CPU/内存短板（随负载动态），磁盘见底才主导。磁盘 disk_note 单列提示保留（信号不丢）。回归测试 `test_reg_resource_score` 更新（分数随 CPU 动、5.8GB 不再钉 76、真见底仍告急）。
  - **夜间 UI**：`.res-verdict` 用未定义的 `--dt-hover` 恒 fallback 近白 → 夜间白板。改用 `--dt-fill` + `theme-dark.css` 加 `.res-verdict` 暗色覆盖（略亮填充+描边）。

- **⑦ 运行时资源/工具调用/水位系统核查（只读，无改动）**：VM 实测三系统**均正常**——资源分配(`get_resource_level/budget` 动态重算)、工具调用分配(`TOOL_RESOURCES` Mongo 账本+CAS，多 worker 安全)、水位系统(orchestration 派发闸 + scheduler L2 每 30s 采样)。运行中会话 window_tokens 92k→159k 逼近 budget 180000 限位正常。**待观察（低优先级本次不改）**：`resource_history` 采样只写 ts/cpu/memory/disk 未写 level 字段（趋势读回 None）。

- **⑧ 文档**：本 CHANGELOG + 版本 -45→-46（version.txt + brand.ts）。

验证：`test_reg_resource_score`(8)/`test_policy`(22)/`test_session.ContextLimitTest`(4)/`test_report_template`(20) 全绿；前端 `npm run build` 零错、产物含 v1.21.157-46。**纯后端+前端热更，无新依赖，不需 rebuild 镜像**（前端已 `npm run build` 重建 `docker/frontend`）。**VM E2E 待做**。（注：`test_console` 有 2 例失败源于另一 AI 未完成的 `_guard.py`/`_tools.py` 改动，与本批无关，已实证隔离。）

## 2026-09-15 更新（v1.21.157-45，内置默认报告模板：会话级/任务级，携带 POC + 修 POC 特殊字符被吞 bug）

- 需求：报告模板不必每次上传真实报告让 AI 学，开箱即用一套内置默认模板；会话级（单系统）、任务级（多系统，比会话级多一级「分系统」目录）各一个，且报告要**携带 POC**（payload/请求/关键响应/证据）。
- **新增 `report_template_builtin.py`**（内置模板，不走 LLM 学习）：直接用 python-docx 构造带 docxtpl 标签的 `template.docx`（`{{}}` 标量 / `{%tr%}` 表格行循环 / `{%p%}` 段落块循环）——这就是学习流程最终产出的等价物，省掉一次性 LLM 学习。同时用样本数据渲染出 `origin.docx` 供复核抽屉左右对比。schema 手工冻结（scalars=report.* + images=严重度饼图位；stat.*/findings/systems 循环由生成器直接注入 ctx）。
  - **会话级模板**（`builtin_session_v1`）：概述 → 漏洞统计+饼图位 → 漏洞清单表 → 逐条详情（目标/等级/危害/验证/**POC(payload+请求+关键响应)**/证据/截图位/加固）→ 总体加固建议。
  - **任务级模板**（`builtin_task_v1`）：与会话级同款，唯一区别 = 多一级「分系统」目录——漏洞部分 `{%p for sys in systems%}` 外层按系统分组（每组各自漏洞清单表+详情+分系统统计），会话级则直接一个清单。
- **生成器增强**（`report_template.py:_collect_findings/generate_from_template`，向后兼容）：任务级从会话报告 `system_name` 继承每条 finding 所属系统 → 新增 `_group_findings_by_system` 按系统分桶（组内 seq 重排 + 分系统 stat）→ ctx 追加 `systems`/`stat`。会话级=单组，内置会话级模板不用 `systems`，多给不碍事。
- **【修真 bug】POC 特殊字符被 docxtpl 吞掉**：VM/本地实证 `tpl.render(ctx)` **未开 autoescape**，POC/证据里的 `< > &`（XSS/SQLi payload、HTML 响应体）被当 XML 标签**整段吞掉**（`<script>...` 凭空消失、`&size=2` 截断）——直接违背「携带 POC」。修复：`generate_from_template` 与 `_self_check_render` 的 `tpl.render` 统一加 `autoescape=True`。**此 bug 影响所有模板（含用户自学模板）的生成**，不止内置。
- **POC 字段对齐真实数据模型**（守禁臆想设计铁律）：生成时 finding 只有单一自由文本 `poc`（AI 把 payload/请求/关键响应写进去，见 `_tools.py` report_finding）+ `evidence`（工具原始响应），**无独立 request/response 字段**。故内置模板 POC 块绑定 `{{ item.poc }}` + `{{ item.evidence }}`（等宽承载请求/响应），不臆造字段。
- **播种**：`seed_builtin_templates()` 由 `bootstrap.ensure_indexes` 幂等调用（同 `seed_prompts`）——按 `builtin_version` 增量覆盖、磁盘产物缺失自愈重建。内置模板 `delete_template` 拒绝删除（删了也会重播）。
- **前端**（`ReportEdit.vue`）：模板列表内置模板显「内置」金标、隐藏删除按钮、加「预览」按钮（打开只读左右对比，隐藏换模型重学/定稿）。
- 部署：**纯后端+前端热更**（python-docx/docxtpl 已在依赖，无新依赖）→ 走分发热更即到达存量实例，**不需 rebuild 镜像**；前端改动需 `npm run build` 重建 `docker/frontend`。存量用户升级后 bootstrap 自动播种，无需手动操作。
- 验证：`test_report_template` 新增 6 例（播种幂等/磁盘缺失自愈/内置不可删/POC 特殊字符保留/任务级分系统分组/会话级单组）全绿（20 例）；in-process E2E：任务级 2 系统分组渲染 2 张表、`<script>`/`&` 保留，会话级正常生成。**VM E2E 待做**（启动播种→列表见 2 个内置→用任务级模板生成真实任务报告，确认分系统+POC 完整）。
- 桌面样本（供人工审阅，不入库）：`报告样本_会话级.docx` / `报告样本_任务级.docx` 已更新，去除真实单位名改用「示例单位」占位。

## 2026-09-14 更新（v1.21.157-44，修策略编辑变新建同名重复 bug）

- 现象：在现有策略上编辑修改保存，结果新建成两条完全同名策略，而非更新原策略（VM 实证 DB 有 2 条同名"政府-探测"）。
- 根因（VM 实证）：`list_policies` **完全忽略 `_id` 过滤参数**（签名只有 name/page/size）。编辑页 `PolicyEdit.loadOne` 用 `list({_id})` 加载目标策略，后端忽略 `_id` 返回列表倒序**最新那条**（非用户点击编辑的那条）→ 编辑页加载错策略数据，保存链错乱产生同名重复。
- 修复（纯后端）：① `list_policies` 加 `_id` 精确过滤（复用 `_oid`，非法/不存在返空，不传向后兼容返全部）+ 端点 `_list_parser` 加 `_id` query 参透传——编辑页加载正确目标策略。② `add_policy` insert 前查同名，已存在则拒绝并提示"策略名已存在，请换名或直接编辑现有策略"（纵深防御：即使前端分流出错走 add 也不再产生重复）。
- 存量清理：删除 VM 上旧的重复"政府-探测"策略（保留含最新编辑的那条）。
- 验证：`test_policy` 新增 3 例（list(_id) 精确返回 / add 拒绝重名不增文档 / edit 原地更新总数不变）全绿（22 例）。**VM E2E**：编辑现有策略改字段保存→原策略更新、总数不+1。纯后端热更，不需 rebuild 镜像。

## 2026-09-14 更新（v1.21.157-43，子域枚举：第三方收集源有效时跳过 subfinder 公共被动枚举，治多域名串行卡死）

- 卡死事故根因（VM 实证）：97 个 FOFA 已知 .gov.cn 域名的源查询任务派发后 task 卡 running 近 30 分钟。定位 = `_stage_subdomain` 跑 `subfinder.enumerate(roots)`（**公共被动枚举全部内置默认源**）——逐域名串行（实测单域名 23.6s、5 域名 82.7s 线性累积 → 97 域名≈26~37min），且 subfinder `-max-time 3` 对阻塞网络读(ep_poll)不生效、外层硬超时 1800s 太长。非爆破（domain_brute=false，massdns 未跑）。
- 修复（`recon/pipeline.py:_stage_subdomain`）：**第三方收集源有效时不启用 subfinder 公共被动枚举**。判据 `_has_third_party = _collection_source_credentials 非空(API 增强源如 Hunter) 或 _fofa_collector 可调用(FOFA)`。有第三方源→跳过公共全量枚举、只用第三方源（已把资产捞回，公共枚举既慢又重复=卡死元凶）+ 落 info 日志；无第三方源→退回公共枚举兜底（不丢子域发现能力，向后兼容）。
- 边界：**非硬禁 subfinder**——它的 API 增强源模式（Hunter 走此路，精准快）仍用，只是不跑"全部内置默认源"的公共枚举。不碰爆破门控（massdns 受 domain_brute 独立控）。
- 验证：`test_pipeline` 新增 3 例（API 源有效→公共 enumerate 不被调用+API 源仍跑 / FOFA collector 有效→同跳过 / 无第三方源→公共枚举兜底），本地 27 例全绿。**VM E2E 待做**（重跑同款 FOFA+Hunter 97 域名任务，确认不再卡、分钟级跑通、日志出现跳过提示）。**纯后端热更，不需 rebuild 镜像**。
- 留档（本次不修，优先级降低）：subfinder/massdns 外层超时不可配（硬编码 1800s）、recon 阶段心跳不刷新——是"无第三方源纯 subfinder 兜底"场景的加固，后续再做。

## 2026-09-14 更新（v1.21.157-42，源查询资产归属过滤：治测绘源仿冒/域名混淆越界派发）

- 事故（VM 实测）：Hunter 语句 `domain=".gov.cn"&&title="后台"||domain=".gov.cn"&&title="login"` 建源查询任务，派发出的会话混入 `www.gov.cn.ugome.top`、`gov.cn.emy.flicksfrenzy.com`、`ctdwhsdds-gov-cn.enjoylost.com`、`sdds-gov-cn.binguosoft.cn` 等**攻击者故意注册的钓鱼/域名混淆域**（把 gov.cn/gov-cn 塞进子域前缀或用连字符变体）——既越权打第三方无关域，又浪费预算。
- 根因：`ext_source.hunter_query`/`multi_source_targets` 把测绘源返回的每条 domain **原样收下、零归属校验**。Hunter `domain=` 是模糊包含匹配，返回一切字面含 root 的 host。单位反查侧有 `_belongs` 归属过滤、任意语句查却没有——缺口。
- 修复（`kernel/ext_source.py`）：新增 `_extract_domain_roots(query)`（正则解析查询里的 `domain="X"` 子句，多个取并集，归一去引号/前导点/小写）+ `_host_belongs_roots(host, roots)`（**DNS 标签边界**：`host==root or host.endswith("."+root)`，天然排除 `gov.cn.x.com`/`x-gov-cn.y.cn`，绝不子串匹配）+ `_filter_rows_by_domain_roots`（有 host 的行按归属过滤，纯 IP 行保留，落 warning 记过滤量）。接入 `hunter_query`（返回前过滤）+ `multi_source_targets` 的 fofa 分支（各源按各自查询根过滤）。
- 边界（用户拍板）：**DNS 后缀边界过滤**（真站全留、仿冒全滤，不误伤合法资产）；**查询无 domain 子句时不过滤**（纯 title/app 查无归属根可依，尊重用户意图，守禁臆想设计铁律）。纯 IP 行不受 domain 根过滤。复用 `core.domains.extract_fld`（零依赖 stdlib）。
- 顺带清理：删除上一批 fofa 任务派发的 108 个会话（99 stopped + 9 done，级联清 workspace）。
- 验证：`test_ext_source` 新增 4 例（根解析单/多/无 domain、DNS 边界归属判定、行过滤保留 IP 滤仿冒、hunter_query 端到端滤假域名）全绿；既有 multi_source/normalize/collection 测试回归全绿（`TestFofaQuery` 3 例失败是 VM 配了真 FOFA key 的环境原因，与本改动无关）。**VM 真 E2E**：跑用户原始 Hunter 查询，滤除 10 个仿冒域名（www.gov.cn.ugome.top/gov.cn.*.flicksfrenzy.com 等）、保留 90 个真 .gov.cn 站、漏网仿冒 0。**纯后端热更，不需 rebuild 镜像**。

## 2026-09-14 更新（v1.21.157-41，报告模板学习二轮：异步学习+进度 / 默认复核 / 在线左右对比 / 空 schema 兜底）

- 承接 -40，用户实测反馈 4 项优化：
- **① 异步学习 + 进度（不再阻塞）**：上传后端**秒回** `status=learning`，LLM 学习在后台 daemon 线程跑（学习只写 `template_dir/<tid>/`+mongo doc、不改 .py，不触发 gunicorn `--reload`，故 worker 内线程安全）。前端列表立即显示「学习中」+ **进度条 + 阶段文案**（读取结构 10%→AI 学习 30%→注入 75%→自检 90%→完成 100%，经 mongo `learn_phase`/`learn_progress`），**每 3s 轮询**刷新（全部离开 learning 即停）；学习期间可自由用其他功能。`learn_template` 加 `sync` 参（默认 False 异步；单测/兜底用 True）。
- **scheduler 兜底**：新增 `_tick_template_learn`（模仿 `_tick_github`，`_tpl_learn_running` 防堆积）扫心跳超时仍 learning 的模板（worker 崩线程死）重跑，经 `INTEL.run_pending_learn`（阈值 `REPORT_TEMPLATE.LEARN_STALE_SEC` 默认 600s 可配）。保证 worker 重启不留永久「学习中」僵尸。
- **② 默认需人工复核**（反转 -40）：上传 `need_review` 默认 **True**（前端勾选框默认勾上），学成一律先落 `review` 待确认；仅显式取消勾选才直接 ready。
- **③ 在线左右对比（替换下载预览）**：删后端 `preview_template`+`/preview`、前端下载预览按钮；新增 `GET /report_template/<id>/docx?which=origin|template`（realpath 防遍历，inline 返 docx 字节）。前端引入 **mammoth.js**（docx→HTML，动态 import 代码分割，随前端 build 走热更、**不需 rebuild 镜像**），复核抽屉改**左右并排**：左=origin.docx（真实报告排版）、右=template.docx（可变位显 `{{占位符}}`、漏洞表显 `{%tr%}` 循环标记）——即「去了原数据、打了标记的给 AI 用的模板」；下方折叠保留结构判定明细表 + 换模型 refine + 确认定稿。
- **④ 空 schema 兜底（修"效果不理想"真缺陷）**：VM 实证用户样本（安庆市住建局，64 段落 1.8MB）DeepSeek 学出 **schema 全空**却落 review = 空模板伪装待确认。修复：`_run_learn_cycle` 学完判 scalars+loops+images 全空 → **落 `failed`**（非 review）+ 提示「未学到可变结构/循环表，请换更强模型（如 Claude 高配）重学」。列表 failed 态显「重学」入口。
- 三角度自检：可用性——上传不再卡、进度可见、空 schema 明确失败可重学、左右对比一眼看出学漏；可靠性——异步线程 worker 崩由 scheduler 心跳兜底重跑、`sync` 参保证单测确定性、docx 端点 realpath 防遍历、mammoth 加载失败前端降级提示不白屏；逻辑完整性——learning(进度)→review⇄refine→ready 状态机 + 空 schema→failed 分支闭合。
- 验证：`test_report_template` 14 例全绿（新增 异步秒回+进度流转/空 schema→failed/get_template_docx origin+template/need_review 默认 True/循环变量名健壮）；前端 `npm run build`（含 mammoth）零错、产物含 v1.21.157-41 + ReportEdit 重建。**VM E2E 待做**（上传大样本→秒显学习中+进度→切页→学完 review/空 schema failed→左右对比→换模型重学→confirm）。

## 2026-09-14 更新（v1.21.157-40，报告模板学习：可选学习模型 + 强模型引导 + 人在回路迭代精修）

- 需求：报告模板学习（§15.12）现状是「上传→LLM 一次性学 schema→ready/failed」一次成型、无迭代，两个痛点：①学习质量强依赖模型能力，但学习模型写死走 `template_learn` scene，用户不能按模板难度选强模型，弱模型学错结构（固定文案当可变/循环表列判错/占位符跨 run 失败）只会 failed 或"能渲染但填错"，且失败重试白烧 token；②低能力模型初次学的模板可能有问题，用户希望能手动"再匹配学习"——拿初版和原样本比对、修正，反复直到认同定稿，而非删了重传。
- **特性 A：模板学习模型用户可选 + 强模型提示**。`learn_template`/`_learn_schema_via_llm` 加 `provider_id`（空=沿用 template_learn 场景→全局默认，向后兼容）；新增 `_resolve_learn_provider` 按 id 取（`ai_config.get_provider(require_enabled)`+`_provider_usable`，不可用降级场景默认并 warning）；落库记 `learn_provider_id/learn_provider_name`。前端上传区加"学习模型"下拉（`aiConfigApi.providerOptions()`，空=跟随全局默认，范式对齐 TaskCreate）+ 固定强模型提示文案（强调一次性复杂判断建议强模型、弱模型可能反复重试多花 token）。**不加任何硬闸/预检**（守禁硬限制铁律，模型能力由用户判断）。
- **特性 B：人在回路迭代精修**（用户说的"强化学习"=HITL 迭代，非 RL）。新增 `review` 态（介于 learning 和 ready，生成端点仍只认 ready）；上传"需人工复核"勾选才进 review（默认不勾=直接 ready，向后兼容不打断存量"上传即用"）。抽出 `_run_learn_cycle`（learn 首学 + refine 重学共用）。新增：`refine_template`（复用 origin.docx 重学，可换模型 + 带 feedback 纠正意见，仍落 review，refine_count++）、`confirm_template`（review→ready，非 review 态拒绝）、`template_diff`（在线并排：origin 每段原文 vs schema 判定 fixed/可变/循环/图表/未识别，纯 JSON 不渲染 docx）、`preview_template`（用 origin 真值回填模板渲染预览 docx 供下载，真实看渲染效果）。端点 `/report_template/<id>/{refine,confirm,diff,preview}`（RBAC 现有规则已覆盖：POST→pentest:write、GET→泛 intel:read）。前端复核抽屉：并排对比表 + 下载样本回填预览 + 换模型 + 纠正意见重学 + 确认定稿；状态标签加 review（橙"待确认"）+ 展示学习模型名。
- 三角度自检：可用性——弱模型学错可换强模型带纠正意见反复重学、预览 docx 直观看渲染效果；可靠性——review 态不可生成（只有认同的模板才产报告）、confirm 幂等保护、provider 不可用降级不炸、向后兼容（provider_id 空/不勾复核=旧行为，存量 ready 模板不受影响）；逻辑完整性——learning→(review⇄refine)→ready 状态机闭合 + 首学/重学共用 cycle。
- 验证：新增 `test_report_template` 5 例（need_review 落 review 非 ready+生成被拒 / 默认直接 ready / review→refine（refine_count++）→confirm→ready 状态机 / provider_id 记录+无效降级不炸 / diff 判定映射），本地 10 例全绿；前端 `npm run build` 零错、产物含 v1.21.157-40 + ReportEdit 重建。**无新依赖**（docxtpl/python-docx/matplotlib 已在）→ **纯热更不需 rebuild 镜像**。**VM E2E 待做**（选弱模型学出 review→下载预览发现学错→换强模型 refine→预览正确→confirm→ready→生成）。

## 2026-09-14 更新（v1.21.157-38/39，资源运行可靠性评分重构：需求导向 + 以水位系统为骨架）

- 现象：仪表盘「资源运行可靠性」恒定 22 分「资源告急，已收缩并发保命」纹丝不动。用户质疑"不该是动态的吗"。
- 病根链（分三步修，前两步走过弯路如实记录）：
  1. 旧算法 `min(100-cpu%,100-mem%,100-disk%)` 线性短板：磁盘常年 77.5% 满→磁盘维恒 22 把总分钉死、不随 CPU/内存波动；且套"已收缩并发保命/减负"文案——但真实并发调度(get_resource_level)对磁盘用阈值(≥85%)判定，77.5%<85% 根本没触发并发收缩，是纯误报。
  2. 第一版修复**矫枉过正**：为消除磁盘干扰直接把磁盘踢出评分→磁盘 77.5% 剩 5.9GB 还拿 93 分「充裕」，被用户当场质疑。教训：修 bug 别删有效信号维度=负优化（见记忆 [[feedback-fix-root-cause-not-remove-signal]]）。
  3. 第二版改需求导向 + 短板法，但档位是自设的、与水位档没对齐，仍有"仪表盘一套/调度一套"口径打架风险。
- 最终方案（v1.21.157-39，**需求导向 + 以水位系统为骨架**）：
  - **评"够不够跑平台实际工作负载"，不评"用了百分之几"**。三维各回答"够不够"：
    - 内存=真实并发闸：读 `get_resource_budget().task_slots`（可用内存/每任务预算×水位系数 算出的"当前还能起几个并发任务"），非用量%。
    - CPU=排队压力：`loadavg1/核数`（I/O 密集平台 CPU 少是瓶颈，瞬时% 抖动无意义），缺 loadavg 回退瞬时%。
    - 磁盘=写入底线：**绝对剩余 GB 为主**（平台一直写扫描产出/mongo/日志/镜像，一次大扫描 1~2GB，剩 5.9GB 是真风险；同样 77% 在 500GB 盘上没事），阈值可配 `DISK_FREE_*_GB`。
  - **以水位档为权威骨架**：headline 档位 = get_resource_level（relaxed→充裕[85-100]/normal→良好[65-84]/tight→偏紧[40-64]/critical→告急[0-39]），分数在档区间内用三维容量短板落位。水位说 critical(0 slots 停投)才显示"已收缩并发保命"，与真实调度字字对应，彻底消除口径打架。
  - **磁盘绝对余量只向下拉档不向上抬**：补水位%阈值看不到"绝对空间见底"的盲区（如水位 normal 但磁盘只剩 1GB→拉到告急+"否则写入失败"提示）。
  - verdict 按短板是谁给可操作建议：内存/CPU 短板→降并发/收缩保命；磁盘短板→清理磁盘。前端展示 task_slots + disk_note。
- VM 实测：cpu24%/mem21%/磁盘剩5.9GB → wl=normal、task_slots=4、**score=76「运行良好」（当前可起 4 个并发任务）**，磁盘维59拉短板；不再是钉死22也不是虚高93。边界验证：磁盘50G→99充裕/2.5G→48偏紧/1G→5告急、水位critical停投→7告急、水位normal但磁盘1G→被拉到告急。
- 改动：`dashboard._resource_score` 重写（纯后端热更）+ 前端 Dashboard.vue 展示 task_slots/disk_note（rebuild）+ config.yaml.example 新增 DISK_FREE_*_GB 可配项。

## 2026-09-13 更新（v1.21.157-37，代码审计缺陷批量修复：11 项已修 + 1 项暂缓）

按《瞭望塔 Watchtower 代码审计报告-2026-09-13》逐项排查修复。核查确认 AUD-02（会话跨用户归属闸）早前已修、AUD-05（复核签名）审计期已修；本轮修复以下 11 项，每项补针对性回归测试并通过：

- **AUD-03（中·情报 scope 越界）**：`_filter_mission_intel` 的 target 级匹配从子串 `m_target in host_l` 改为 DNS 标签边界（`_target_scope_match`：精确等于或 `.`+scope 结尾，剥端口/尾点/大小写归一）。修复前 `example.com` 会误命中 `notexample.com`、`example.com.attacker.invalid`，把凭证等临时情报注入无关目标。
- **AUD-04 + AUD-12（高·更新链）**：`_updater.run_update` 改为**事务化两阶段**——Phase1 全部下载到独立 staging 区并逐个校验（sha256 对 manifest 严格比对 + .py 编译），任一失败即中止、**不碰运行文件**；Phase2 全部通过才一次性提交（备份+os.replace），提交中失败自动回滚已替换文件。根治「哈希算了不校验、错版/篡改照样落地」（AUD-04）与「逐文件覆盖第 N 个失败留半新半旧」（AUD-12）。
- **AUD-06（中·资源池非原子）**：资源池账本加 `rev` 版本号，`acquire` 改 **CAS 原子准入**——预算判定基于某 rev，只在该 rev 未变时 `_register_cas` 登记（`$inc rev`），rev 已变（别的 worker 抢先）则冲突重采样重试（上限 5 次），登记失败绝不返回 holder id。根治多 worker 读同一空账本各自获批超预算。
- **AUD-07（高·云端存储型 XSS）**：`云端/distribution/update_source.py` 管理页新增 `esc()`（HTML 文本+属性上下文转义），报错列表/详情所有动态字段（version/ip/user_id/ts/description）全部过转义；入库侧对 version 做字符集白名单约束（纵深防御）。修复前 version 原样拼 innerHTML、description 只转义 `<` 未转义 `"`。
- **AUD-08（高·scheduler 误回收在跑任务）**：`_reclaim_on_startup` 从「无条件回收所有 running」改为「**只回收心跳（update_date）已过期的**」。独立容器拓扑下只 scheduler 重启、worker 仍在跑时，心跳新鲜的任务/会话保留不动，交给周期 watchdog 按 STALL 判；根治重复扫描/重复 LLM 调用/checkpoint 竞争覆盖。
- **AUD-09（中·登出不撤销 token）**：新增 `revoke_token(token)` 按请求 Token 头精确清除服务端 token（登出是 public 端点，凭 token 而非用户名定位）；登出端点改调它；`verify_token` 加 TTL（config `SENTINEL.TOKEN_TTL_HOURS` 默认 168h，缺 login_date 的老会话兼容不过期）。修复前 `update_user(token=None)` 是无操作，登出后旧 token 仍有效。
- **AUD-10（中·搜索先截取后过滤）**：`vuln_center.list_unified_findings` 把 keyword 过滤**下推到各来源 DB 查询**（每词项在该来源可搜字段上 OR 正则、多词 AND），count 与 items 用同一过滤。修复前先 `limit(page*size)` 截取再 Python 过滤、total 取截取后长度，命中项在窗口外则漏、total=0。
- **AUD-11（中·资源超时误判 completed_empty）**：新增非终态 `deferred_resource`（`terminal` 属性排除它，不进 done_steps）；nmap 资源门降级返 `{"__degraded__": True}` 而非空 `{}`，`_stage_service` 据此产出 deferred_resource。根治「资源不足未执行」被误当「执行了无发现」而续扫跳过。
- **AUD-14（中·SALT 不被读取）**：`_salt()` 优先读 `SENTINEL.SALT`（配置样例要求配的位置），兼容旧顶层 SALT/ARL.SALT。**含平滑迁移**：登录时新盐验不过再按历史盐验，命中即用新盐重哈希回写——改盐不锁死任何存量账户。
- **AUD-15（中·黑名单落库后才过滤）**：`_stage_site` 改为**每批 emit 前**先过滤黑名单（`filter_site_batch`），黑名单站点从不进 ctx.sites、不落库、不派发。修复前全部批次落库+派发后才过滤，已持久化/已派发的收不回。

- **AUD-13（高·明文 HTTP + 无发布签名）暂缓**：HTTPS 强制会中断现有指向 http://124 的更新通道、发布签名需云端签名基建配合，经用户决策留待后续连云端一起做。

测试：新增/改造回归测试覆盖各项（DNS 边界 scope、CAS 不超额、deferred_resource 不入 done_steps、keyword 跨页可查 total 正确、登出撤销、盐迁移、黑名单批前过滤）；risk_intel/kernel/system 相关测试套件全绿（vuln_center 28 / resource_pool 11 / recon pipeline+nmap+blacklist 82 / system 154 / user_manage 26）；全部改动 py_compile 通过；前端 `npm run build` 零错（版本同步 v1.21.157-37）。
- 说明：AUD-13 暂缓、`test_session.py` 的 `TestPentestDispatcher`（触发真实蜜罐探测网络调用）本地会挂属既有环境问题，与本次改动无关；本轮为本地代码修复，未部署生产。云端 XSS 修复在 `云端/distribution`（独立云端系统，非主平台镜像），随云端部署生效。

## 2026-09-13 更新（v1.21.157-36，报告模板学习：AI 学一次→确定性批量生成，省 token｜⚠️需 rebuild 镜像）

- 需求：报告编辑处现在生成报告靠 `build_task_report`/`regenerate_session_report` **每次都调 LLM 从零写整篇**（费 token + 格式不稳）。用户要的是：上传报告模板 docx → AI 一次性解析学成可复用模板 → 之后确定性填充批量生成，就像"AI 拆解数学题→变成可计算机校验的结构"。需解决截图/画图/举证 + WPS/Office 文档变形。
- 设计（两阶段，省 token 核心）：
  1. **学习（一次性 LLM）**：`report_template.py` 用 python-docx 读模板结构（段落/表格带锚点）→ LLM（新 scene `template_learn`，tool-use `emit_template_schema` 强约束结构化输出）判定每个元素是【固定文案/可变字段/循环表格/图表位】+ 映射语义字段 → 程序在**用户原始 docx** 里注入 docxtpl 占位符（`{{}}`/`{%tr%}`），保留全部样式/logo/排版/字体 XML。
  2. **生成（确定性，零 LLM）**：选模板 + 数据源(task/session) → 从 intel_finding 组装 context → matplotlib 画图表 PNG → docxtpl 只换文字/插图 → 输出 docx。同模板生成 N 篇增量 token=0。
- 防变形：以用户原模板为底，docxtpl 填充只替换占位符，排版零漂移。**WPS 变形**：只收 .docx，.wps/.doc 前端拦截提示「另存为 docx」（python-docx 读不了 WPS 私有二进制；libreoffice 转换镜像膨胀数百 MB 不值得）。
- 攻克的两个硬技术点（均有单测坐实）：
  1. **docxtpl 标签跨 run 限制**：Word 常把文字拆多 run，`{{`/`}}` 分落两 run 会渲染失败 → 注入前**合并 paragraph 所有 run**（文本归并进 runs[0]、保留其 rPr 样式）再替换，标签落单 run。
  2. **表格行循环**：docxtpl `{%tr%}` 是整行操作，for/endfor 必须**各占独立一行**（同行首尾放会报 "unknown tag endfor"）→ 用 lxml 在数据行前插 for 标记行、后插 endfor 标记行，渲染时删标记行只循环数据行。
- 举证三源：①会话已有证据（intel_finding.evidence 真实请求/响应 body，按 session_id/task_id 目录约定弱关联 image/ 截图）；②Playwright 按需补截图（预留）；③报告编辑人工上传截图补充图（`/manual_shot` 绑 finding_id）。
- 画图：matplotlib Agg headless（`matplotlib.use("Agg")` 在 pyplot 前）；严重度分布饼图 + 攻击链竖向流程框图（读 intel_attack_chain）；**CJK 字体防豆腐块**（镜像装 fonts-noto-cjk + rcParams 指定字体，缺失降级不崩）；每次新建 Figure + `plt.close()` 防泄漏/gthread 串扰。
- 与现有报告共存：模板生成的报告落 `pentest_report`，新增 `gen_mode="template"` + `docx_path`（二进制 docx 文件，不是 md content），导出端点检测 gen_mode 直接下发预生成 docx（realpath 防遍历）；md 报告仍走 md→docx 渲染。幂等键 `tpl:<source_id>:<template_id>`，与 task:/session: 不冲突。
- 端点（/api/intel/report_template/*）：upload（学习）/list/detail（含 schema 供人工校对）/delete（连带删磁盘目录）/generate/manual_shot。RBAC 加 `("/api/intel/report_template", POST/PUT/DELETE, "pentest:write")`（operator 可用，前缀最长匹配优先于泛 intel；GET 由泛 intel:read 覆盖）。新集合 `report_template` + `template/` 磁盘根（仿 image_dir，host 卷持久，多 worker 共享）。
- 前端：ReportEdit.vue 新增「模板学习」tab（上传走原生 fetch 带 Token 避 multipart 被 request.ts 污染、模板列表含学习状态、失败原因 tooltip、「用此模板生成」弹窗选 task/session）。
- **⚠️ 本次需 rebuild 镜像**（新依赖 + 字体，非纯热更）：requirements.txt 增 docxtpl/docxcompose/matplotlib/Pillow（附离线 cp38 manylinux wheel 的 pip download 命令，开发机 Windows 直接 download 会拉 win wheel 装不进镜像）；Dockerfile apt 增 fonts-noto-cjk/fonts-wqy-zenhei。vendor/wheels 需按注释补 cp38 wheel。
- 三角度自检：可用性（渗透视角）——学一次后批量生成零 LLM、格式 100% 稳定、排版不变形；可靠性（测试视角）——新增 test_report_template.py 5 例（结构读取/跨 run 注入/端到端学+生成/严重度统计+证据/空图不崩），学习末尾强制 mock 试渲染把带病模板挡在 status=failed；逻辑完整性（开发视角）——两阶段 + 两数据源 + 三举证源 + 与现有 md 报告共存四象限覆盖。
- 验证：本地 py_compile + `npm run build` 零错（产物含 v1.21.157-36 + report_template 路径）；单测 61 绿。待 VM **rebuild 镜像**后端到端：`docker exec` 验 import docxtpl/matplotlib/PIL + CJK 字体在镜像内；上传样例 docx→学习 ready→选 task 生成→下载 docx 断言含填充值 + 图表中文不乱码。

## 2026-09-13 更新（v1.21.157-35，报告物理隔离：人看成品报告 pentest_report 与 AI 情报报告 intel_report 分家）

- 现象：用户报「正常报告编辑处生成的报告是给人看的、独立于情报体系的报告，但现在一个会话结束就自动去生成一个报告」——把情报报告和给人看的报告搞混了，直接拿来用。
- 病根（坐实）：平台**从来只有一个 `intel_report` 集合**，「人看成品报告」和「AI 情报报告」共用它，靠 `report_type`(session/task) 字段区分（`asset_intel.py` 老注释「复用 intel_report 集合，report_type 区分」自认）。会话收尾 `_engine._finalize_findings` 调 `save_pentest_report` 把报告 md 打上 `report_type="session"` 写进 `intel_report`——**设计本意只是供三层情报联动第二层「往期报告借鉴」**（AI 靠 `query_unit_reports`/`get_pentest_report`/开局 briefing 读它）；但报告编辑处 `ReportEdit.vue` 的「会话级报告」tab 直接按 `report_type:{$ne:task}` 把这批自动写的情报文档当成品捞出来展示。二者物理无隔离 → 会话一结束就在编辑处冒出一份「给人看的报告」。
- 原设计为何作废：`intel_report` 单集合 + `report_type` 区分的「逻辑隔离」不成立——同一份文档既被 AI 当往期借鉴读、又被编辑处当成品读，职责耦合。改为**物理隔离到两个集合**。
- 改（新建独立集合 `pentest_report` 给人看的成品报告；AI 情报链路零改动）：
  1. **契约**：`collections.py` 新增 `PENTEST_REPORT="pentest_report"`。
  2. **会话收尾不变**：`save_pentest_report` 仍只写 `intel_report`（AI 情报，供往期借鉴）；`get_pentest_report`/`query_unit_reports`/`mark_report_useful`/`report_tree`/`_mark_asset_pentested` 全部不动。
  3. **人看报告只在人工点「生成」时产出**：`build_task_report`(任务级)/`regenerate_session_report`(会话级) 改为落 `pentest_report`（幂等键 `report_key=task:{tid}`/`session:{sid}`，`upsert` 消多 worker 双插竞态）；`regenerate` 只读 `intel_report` 取元数据 + 从 `intel_finding` 派生 vuln_index，**不再调 `_mark_asset_pentested`**（关键不变量：不污染 AI 开局借鉴指针 `intel_asset.report_id`）；`update_report` 改写 `pentest_report`；`get_report`/`export_report_docx` 加 `collection` 参数（默认 intel_report 保情报中心，报告编辑处传 pentest_report）。
  4. **端点**：新开 `/api/intel/pentest_report/*`（列表/详情/编辑/生成/导出）指向 pentest_report；删除复用 `/api/intel/delete/`（白名单 `_INTEL_COLLS` 加 pentest_report）；旧 `/report/*` PUT/generate 保留加 deprecated 注释（无调用方）。`/report/*` 列表/`/report_tree/` 原封不动继续给情报中心用。
  5. **RBAC**：新增 `("/api/intel/pentest_report", (POST/PUT/DELETE), "pentest:write")`（前缀最长匹配优先于泛 intel；operator 可生成/编辑报告，与删情报/攻击链同口径）；GET 由泛 `intel:read` 覆盖无读洞。
  6. **索引**：`bootstrap.INDEX_SPECS` 加 PENTEST_REPORT（report_key 唯一 sparse + source_task_id/source_session/unit/asset_key）。
  7. **前端**：`intel.ts` 新增 `pentestReports/pentestReportDetail/updatePentestReport/generatePentestReport/exportPentestDocx`（`exportReportDocx` 加路径段参数）；`ReportEdit.vue` 全部 API 切到 pentest_report*，文案改「人工按需生成、独立于情报报告」；`VulnCenter.vue` 的「生成报告」也切到 `generatePentestReport`（生成后引导去报告编辑页，本就是成品）；`IntelCenter.vue` **完全不动**（报告 tab 继续读 intel_report，情报归档视角）。
- 存量迁移：新增 `migrate_pentest_report.py`（`--check/--dry-run/--execute` 三档，幂等可重跑、只增不删）——把 `intel_report` 里 `report_type=task` 或 `edited=true` 的人工成品一次性 upsert 到 pentest_report（`report_key` 唯一 + `migrated_from` 溯源），普通自动会话报告不迁、原文档全留。
- 三角度自检：可用性（渗透视角）——会话结束不再在编辑处冒出未经人工确认的自动报告，编辑处只放人工成品，情报报告仍在情报中心供 AI 借鉴；可靠性（测试视角）——新增 `test_report_isolation.py` 7 例（save 只进 intel/build 只进 pentest/regenerate 不污染 report_id 指针/AI 借鉴仍读 intel/get_report 双集合/delete 白名单/迁移幂等），改 `test_report_edit.py` 断言到 pentest_report，risk_intel 全套 66+ 用例绿；逻辑完整性（开发视角）——两类目标（有/无 intel_report 元数据）、两条产出路径（自动收尾/人工生成）四象限覆盖。
- 多 worker 一致：pentest_report 写全走 report_key upsert（原子幂等），读走 Mongo fresh，无进程内状态。
- 热更新触达：纯 `sentinel_platform` 后端 + `frontend` 前端改动，走热更新即到达存量（后端 gunicorn --reload、前端 nginx 直读 docker/frontend）；迁移脚本随代码分发，运营方按需手动跑 `--execute`。
- 附带增强（报告编辑处批量操作）：任务级/会话级两 tab 均加**多选删除 + 批量导出**——`AppTable` 开 `selectable` + `v-model:selectedRowKeys`（复用情报中心报告 tab 范式），选中后批量删除走 `delete_records`（非空数组一次删），批量导出串行逐份触发 docx 下载（间隔 400ms 避免浏览器多下载拦截，后端未提供 zip 打包端点故按份下载并逐份反馈成败）；切页/切 tab 自动清空选中防跨页残留。
- 验证：本地 py_compile 全过 + `npm run build` 零错（产物含 v1.21.157-35 + pentest_report 路径 + 批量操作）；单测全绿。待 VM 带测试号 v1.21.157-35 端到端：发起会话跑完确认 pentest_report 无新增/intel_report 有情报报告；报告编辑处生成/编辑/导出/多选删除/批量导出走 pentest_report；情报中心报告 tab 功能不变。

## 2026-09-13 更新（v1.21.157-34，漏洞中心质量闸：对抗式复核治假阳性+虚高 + 同端点信息泄露家族去重一致性）

- 现象：用户报三症状——①「认证绕过根本不能算漏洞」②「敏感信息泄露 和 硬编码凭证泄露 同洞不同级别」③「怀疑也是低效模型出的问题」。
- VM 排查：拉 18 条 `INTEL_FINDING`（6 verified / 12 leads），逐条看模型归属、CVSS 向量、**每条 evidence 真实响应 body**。坐实：
  1. **症状①假阳性**：`认证绕过 @ /api/Phone/setPassword sev=medium verified=True`，证据响应 `200 {"code":0,"msg":"请到设置先绑定手机号","data":"13800138000"}`——这是**业务拒绝**（密码根本没被重置），模型从"被拒绝的请求"凭空编出"认证绕过"。跟猜的一样。
  2. **症状②同洞双级**：`/api/Phone/sendMessage` 同一个"错误响应回显 AccessKeyId"的洞，被两会话用两类型名上报（redteam 会话=`敏感信息泄露 low` / src 会话=`硬编码凭证泄露 high`），去重键 `(norm_target, norm_type)` 认成两条 → 一洞既 low 又 high。
  3. **症状③模型归因**：有问题的条目（假阳性认证绕过 + 敏感信息泄露重复）全来自 **`deepseek-v4-pro` 红队会话**，另一条硬编码凭证泄露来自 src 会话（可能已删）。用户「换模型才出问题」判断正确。
- 根因（系统侧可修）：**`证据强制`闸太浅**。`_positive_signal` 判 http_request 只看**状态码 2xx + body 长度≥50**，完全不看响应内容**是否支持所声称的漏洞类型**。业务拒绝页（200、够长）照样判 `positive` → `verified=True`。系统对模型上报的类型和等级**全盘照收**，只机械复核"这端点确实有过一次 2xx 响应"。Claude 上报克制看不出来，DeepSeek 上报激进浅闸就兜不住了。
- 约束（决定不能怎么修）：本单 6 条 verified 里有 **3 条真·越权/未授权访问**（getUserPhoneInfo / getInformation / getTearchTlogOne）返回**真实用户/请假记录数据**，其中 getUserPhoneInfo 成功响应恰恰是 `{"code":0,"msg":"no",data:{...}}`。用 `code` 判成败会误杀真洞；用"msg 像拒绝词"判也会误杀（真洞 msg 是 `"no"`）。**机械关键字/状态码语义判定必然误杀本单最值钱的 3 条越权洞**——这正是记忆反复强调：客观事实能机械判，"响应算不算成功利用"是语义判断，机械猜必误杀。
- 改（**对抗式复核 + 去重一致性**，两条腿）：
  1. **对抗式复核 AI**（治假阳性+虚高，覆盖所有模型）：`_record_one` 里 `verified=True` 的 finding 入库前过轻量复核 AI——拿 `{vuln_type, target, cvss_vector, impact, evidence响应body前300字}` 质疑"这响应真能证明该漏洞吗？是业务拒绝/登录页吗？等级虚高吗？"。判定：① 业务拒绝响应（"请登录"/"请绑定"但无实际数据）→ `downgrade_to_lead`；② 访问控制类响应不含受保护数据 → `downgrade_to_lead`；③ 等级虚高（C:L 信息泄露给 high）→ `adjust_severity`；④ 真有数据/实际利用成功 → `confirmed`。降级但不删除（fail-safe），打标 `review_downgraded/review_adjusted` + `review_reason` 留痕。复用 `guard` scene provider（轻量调用），`_ingest_md` 收尾解析自动走 `_record_one` 已覆盖（两条产出路径都过复核）。代价：每条已验证洞多一次小额 LLM 调用。
  2. **同端点信息泄露家族去重一致性**（治症状②，mechanical，零 token）：定义信息泄露家族（敏感信息泄露/硬编码凭证泄露/版本泄露/内网 IP 泄露/源码泄露/接口文档泄露/配置缺陷等），`_record_one` 入库前查同 `norm_target` 下是否已有家族内其他类型、且等级≥新洞 → skip（新洞 `dup=True`）。跨家族不合并（SQLi + 信息泄露可共存同端点）。守 v2.7.34 铁律：不按 target 盲目合并不同漏洞类型。
- 三角度自检：可用性（渗透视角）——假阳性被降 lead 不再污染已验证洞列表，同洞双级合并为一条高级别，省重复分析；可靠性（测试视角）——复核 prompt 严格要求访问控制类必须有实际数据才 confirmed、业务拒绝一律降级，复核失败保守确认（fail-safe）不误杀，家族去重只在信息泄露内不跨类；逻辑完整性（开发视角）——`_record_one` 单条上报 + `_ingest_md` 收尾解析双入口都过复核，家族去重在 existed 常规去重之前先查（两层去重）。
- 多 worker 一致：复核 AI 无状态函数，去重查询 Mongo fresh 读。
- 验证：待 VM 带测试号 v1.21.157-34 用现有 6 条 verified finding 端到端验证——假阳性"认证绕过"应被降 lead、sendMessage 两条应家族去重留 high 那条。

## 2026-09-13 更新（v1.21.157-33，AI 控制台攻击面板「已确认漏洞」不显示根治：无 INTEL_ASSET 也带出 known_findings + 末尾报告解析宽容化）

- 现象：某 AI 控制台会话目标明明挖到漏洞，攻击驾驶舱左侧「目标攻击面 › 已确认漏洞」却空白。用户观察：Claude 会话正常显示，DeepSeek 会话不显示，怀疑「不同模型间，低效模型不遵守规则」。
- VM 实测坐实（deepseek-v4-pro 打小程序 `wxc4d49fae72cdc656` 后端 `zl.scemi.com` 的会话）——**是两个独立 bug，主因与模型无关**：
  1. **主因（空面板真凶）：`build_pentest_context` 提前 return 吞掉漏洞。** 该会话 `INTEL_FINDING` 按 asset_key 已有 **10 条**漏洞，但 `asset_intel.build_pentest_context` 先查 `INTEL_ASSET.find_one({key})`，查不到就提前 `return` 一个**不含 `known_findings` 键**的档案。而小程序目标 `miniapp://...` 从不走资产 pipeline 建 `INTEL_ASSET` 文档 → 前端 `c.known_findings` 为 `undefined` → `vulns=[]` → 面板恒空。表象像「模型差异」，实际是「目标有没有 INTEL_ASSET 记录」的差异（普通站点走 pipeline 建了档才正常）。
  2. **次因（用户点的「模型不遵守规则」，确实存在）：末尾报告解析吃不下非标标题。** DeepSeek 大量把 tool_call 当纯文本吐（未走原生协议→未真正 dispatch），漏洞只写进最终报告文本；而末尾兜底 `parse_findings_md` 要求严格三段式 `### 时间 | 等级 | 类型`，DeepSeek 写的是 `### 1. 越权访问（…）| CVSS:3.1/…`（两段：序号.类型 | CVSS，无时间段）→ 实测**解析 0 条、8 条 error**，漏洞进不了库。realtime 上报是软性提示词约束（管不住低效模型），但末尾兜底解析可以做鲁棒。
- 改（纯后端，走热更新即到达存量）：
  1. `asset_intel.py`：抽出 `_known_findings(repo, asset_key, host)` 统一取法；无 `INTEL_ASSET` 分支也按 asset_key 查 `INTEL_FINDING` 带出 `known_findings`（不再提前 return 丢字段）；有 asset 分支复用同一函数消除重复。
  2. `vuln_center.py`：新增宽容标题解析 `_parse_header`——**定位「定级段」（CVSS 3.1 向量 / 等级词）作为可靠锚点**，其余段按是否像时间归位，剩下做类型（去前缀序号）。兼容标准三段式（行为不变）、DeepSeek 两段式、及其它 `|` 分段；无可识别定级段的标题（如「总结与建议」）仍标 error 跳过不误捞。定级段是结构特征不是语义猜测，安全。
- 三角度自检：可用性（渗透视角）——低效模型不 realtime 上报时，漏洞仍能经末尾解析落库+面板显示，不再因模型不守约定而丢成果；可靠性（测试视角）——VM 真实测试：DeepSeek 两段式 2/2 解析、标准三段式 1/1 回归通过、CVSS 三段式通过、垃圾标题 0 捞；`build_pentest_context('miniapp://…')` 从 `MISSING KEY` → 返回 10 条；逻辑完整性（开发视角）——两条产出路径（realtime report_finding / 末尾 md 解析）与两类目标（有/无 INTEL_ASSET）四象限均覆盖。
- 多 worker 一致：纯查询函数，数据源 Mongo fresh 读，无进程内状态。
- 说明：面板实时刷新由 `onMeta` 里 `tool_count` 增长触发 `loadSurface()`（已有机制），本次修的是它取数的后端源；前端 `PentestConsole.vue` 无需改动（bundle 仅因 version.txt 递增而重建，避免更新弹窗死循环）。
- 验证：本地 py_compile + VM 真实解析测试全过；`build_pentest_context` E2E 返回 10 条漏洞。待 VM 带测试号 v1.21.157-33 前端进控制台复看面板。

## 2026-09-13 更新（v1.21.157-32，假攻击告警根治：内网/保留地址豁免 + 弱信号进桶阈值收紧）

- 现象：攻击告警页「一直有假攻击告警」。VM 实测：全部 9 条告警均为 `Sustained Attack`（漏桶溢出），来源仅两个内网 IP——`172.19.0.1`（docker 网桥网关，50 次，`curl/7.68.0` 打**合法 2xx 接口** `/api/pentest/session`、`/api/miniapp/launch`、`/api/attack_alert/whitelist`）与 `192.168.128.1`（宿主/局域网网关，48 次，打 `/yum.log`）。全是平台自身/运维内网流量被误判成攻击，且 `172.19.0.1` 被**自动封禁**——正是之前 E2E 里 curl 登录被 403「IP 因攻击行为已被封禁」的根因。
- 病根（两处，均在自动监控 `_monitor_loop`）：
  1. **无内网/保留地址豁免**。`172.19.0.1`/`192.168.128.1` 是 RFC1918 私网 / docker 网关，只可能是平台基础设施与可信运维访问，绝非公网攻击者；却照常进检测/漏桶/自动封禁。封禁 docker 网关会锁死所有经反代的流量（自锁事故）。注：`_geo_lookup` 早已把私网标注「内网/保留地址」，检测侧却没对齐。
  2. **弱信号进桶阈值过低（代码偏离自身设计）**。`detect_scored` 文档明写「2xx + 无 payload 总分不进桶（治 curl 验证误报）」，但 `_monitor_loop` 对 `raw_score >= 2` 就滴 1 滴进桶——而 `curl/`、`python-requests`、`go-http-client`、`wget/` 全在 `SCANNER_UA_KEYWORDS`（各 +2），正常内部/客户端调用打 2xx 也累积成「持续攻击」溢出。
- 改（纯后端 `attack_alert.py`，无 requirements/Dockerfile 变更，走热更新即到达存量）：
  1. 新增 `is_internal_ip()`（`ipaddress.is_private/is_loopback/is_link_local`）；`_monitor_loop` 里与白名单一并跳过内网 IP（不检测/不进桶/不封禁）。
  2. 弱信号进桶阈值 `raw_score >= 2` → `>= 3`：单独一个扫描器 UA（+2）在正常 2xx 上不进桶；真扫描器必伴随敏感路径命中（+3）或大量 4xx（UA+4xx=3），仍进桶不漏抓；强 payload（SQLi/RCE/遍历/XSS=5）单独即溢出，一如既往。
  3. 兜底加固：`auto_ban_ip` 与 `is_banned` 均对内网 IP 直接放行——即便库里残留本次修复前误封的 docker 网关记录，网关侧 `before_request` 也不再拦截，彻底根治「基础设施被误封→经反代流量全 403」自锁。
- 三角度自检：可用性（渗透视角）——真外部攻击者经 nginx `X-Real-IP` 传公网 IP，检测/封禁照常，仅内网段豁免（宁可对内网漏报也不自锁基础设施；如前置私网反代需配 real_ip 拿真实客户端 IP）；可靠性（测试视角）——纯函数单测覆盖 curl-2xx 不进桶/yum.log 仍是探测信号/dirsearch+4xx 仍抓/SQLi-from-curl 仍抓/curl+4xx 进桶五个边界全过，`is_internal_ip` 对空/畸形 IP 兜底返 False；逻辑完整性（开发视角）——手动检测端点 `AttackDetect`（不进桶/不封禁）不受影响，仍可测任意输入。
- 多 worker 一致：监控靠 MongoDB 单例锁只一个 worker 真跑，判定为纯函数无进程内分裂；`is_banned` 内网豁免在每个 worker 的 `before_request` 都生效。
- 验证：本地 py_compile 通过 + 纯函数单测「ALL ASSERTIONS PASSED」；待 VM 带测试号 v1.21.157-32 清残留误封/误报后端到端复验告警不再自增。

## 2026-09-12 更新（v1.21.157-31，小程序渗透 AI 控制台看不到实时思考根治：queued 会话也开实时 SSE）

- 现象：小程序渗透「发起渗透」后跳进 AI 控制台，一直停在「AI 自动执行中（实时观察）…」转圈，看不到实时思考/工具流，不符合设计。
- 病根（VM 实测坐实，非引擎问题）：小程序会话在库里跑得很完整（实测某会话 146 轮、146 次工具调用、状态 done），引擎正常每轮 checkpoint 落库；问题在**前端路由判定**——`doLaunch` 发起后**立刻**跳 `/pentest/console?live=<id>`，而此刻会话是 `queued`（`auto_start` 先入队，scheduler 稍后才 promote 到 `running`）。控制台 `enterSession` 只在 `status==='running'` 时开实时 SSE（`enterLive`），`queued` 落到**静态** `loadConsole` 分支——永不开 SSE、也不再复查状态，于是画面停在静态空台，看不到后续实时增量。
- 改（纯前端 `PentestConsole.vue`）：把「是否走实时观察」的判定从「仅 running」放宽到**活跃非终态**集合 `_LIVE_STATUS = [queued, dispatching, running, paused_transient, paused_resource]`。这些会话进控制台即开 SSE；后端 SSE 生成器本就把非终态会话按 2s 轮询（上限 30min），会在引擎 promote 到 running 产 checkpoint 时自然推增量思考/工具，无需前端轮询状态再切。终态（done/stopped/fatal/paused_manual）仍走静态人工接管台。
- 兼容：列表「🔴实时」入口、`onMounted` 的 `?live=` 处理均复用 `enterSession`，一并受益；`enterLive` 内部的终态兜底（拿到 detail 若已终态则转静态）不变，双保险。
- 说明（次要）：本次实测会话是 OpenAI 协议、53 条 assistant 里仅 3 条带文本（大量纯 tool_use 轮无讲话），故中间对话栏本就稀疏——但右侧「工具调度流」146 条会在 SSE 打开后全程实时呈现；文本稀疏是模型行为非 bug。
- 验证：本地 `npm run build` 零错、产物含 -31；VM 带测试号 v1.21.157-31 实测发起小程序渗透后控制台实时刷出工具流。

## 2026-09-12 更新（v1.21.157-30，小程序解包「一直解不开」根治：两阶段解包+超时收紧+进程组清理）

- 病根（VM 实测坐实）：不是代码逻辑错，是外部二进制 KillWxapkg 对**个别包**在 `-restore`/`-pretty` 阶段**死循环空转**——实测某包 277% CPU 跑满 7 分钟、0 产物，一直转到代码里的 300s 超时才被杀，前端表现为「一直解不开」。另外 `subprocess.run` 的 timeout 只杀直接子进程，KillWxapkg 孤儿进程仍在烧 CPU（实测残留）。
- 改（纯后端 `_wxapkg.py`）：解包拆**两阶段**——① 基础解包（不带 `-restore`/`-pretty`，只解密+解出 JS 源码，最稳最快，`base_timeout=120s`）有产物即成功；② 美化还原（`-restore -pretty`，锦上添花）另起短超时（`restore_timeout=60s`）跑，**卡死/超时/失败都用阶段①的基础产物兜底**（AI 读源码不依赖工程目录还原与美化）。新增 `_run_killwxapkg`：`start_new_session=True` 建独立进程组，超时用 `os.killpg` **整组杀干净**防孤儿空转。
- 效果：能解的包照常解；遇到卡死包最多在 `base_timeout`+`restore_timeout` 内拿到基础源码或明确失败，不再「一直转」。失败/超时回传分阶段日志，前端可见卡在哪一阶段。
- 兼容：`unpack_dir` 新增两个带默认值的参数，调用方 `miniapp.py` 三参调用不受影响；`extract_intel`/`_valid_wxid`/`resolve_binary` 相关单测全过（`TestLaunchPentest` 两条失败是早先「一包一会话」重构遗留的过时测试，与本次无关）。
- 验证：本地 py_compile 通过；VM 拿卡死包 `wx751f9237f323337e` 端到端实测（带测试号 v1.21.157-30）。

## 2026-09-12 更新（v1.21.157-29，会话卡片超预算时顶破卡片修复）

- 病根：会话上下文用量超过限位（如 `184.6k/180.0k`）时，`限位` 胶囊文本变长；`.sc-meta` 是 `flex-wrap: nowrap`，三个定宽胶囊横向总宽超过窄卡片内容宽 → 溢出把卡片顶破（div 撑破）。顶行额度条文本（`.sq-txt`）同样 `flex-shrink: 0 + nowrap`，超预算时也会顶破顶行。
- 改（纯前端 CSS）：① `.sc-meta` 改 `flex-wrap: wrap`，放不下的胶囊换到下一行，`gap` 兼作行距；② 顶行 `.sc-quota` 去掉 `flex-shrink:0` 加 `min-width:0`、`.sq-txt` 加省略号截断（完整值在下方 `限位` 胶囊 + tooltip 仍可见），`.sq-bar` 保持 `flex-shrink:0` 不被压扁。
- 验证：`npm run build` 零错；VM SFTP 直推，超预算会话卡片实测不再顶破。

## 2026-09-12 更新（v1.21.157-28，AI 控制台四处 UI 修复 + 全局「未保存修改」守卫）

用户实测反馈四个问题，逐一修复（纯前端）：

### 1. 会话卡片额度条方向搞反
- 病根：额度条宽度直接用「已用百分比」——用得越多条子越长，颜色却又是「用得多→红」，观感成了「长条=红」，与燃料表直觉相反。
- 改：条子宽度改为**剩余额度百分比**（燃料表语义：剩得越多越长，剩得越少越短）；配色按剩余额度（剩 ≤15% 红 / ≤40% 黄 / 否则绿），方向与条子变短一致。

### 2. 工具集弹层仍是夜间黑底
- 病根：`ToolsModal.vue` 全是硬编码深色（`#0a1020/#00e5ff…`），没有日间覆盖，日间打开仍黑底，与全站割裂。
- 改：加 `[data-theme="light"]` 覆盖，映射到系统 `--dt-*` 令牌（白卡/系统蓝/系统描边/语义色徽标）；`.cc-modal` 外壳的日间覆盖也从 bespoke `#0091cc` 统一改用 `--dt-*` 令牌。

### 3. 卡片缺颜色、不协调
- 改：轮次/Token/限位三个指标胶囊加**语义色底**（`color-mix` 半透底 + 同色描边 + 同色数值）——轮次=系统主色蓝、Token=品红计量、限位=按剩余额度动态色（与额度条同色），卡片信息一眼分层。

### 4. 需要保存的地方切走无「未保存」提示（设置静默丢失）
- 病根：API 密钥等整页表单，改了没点保存直接切页/刷新，改动静默丢失（用户反馈勾了「不推送告警」退出没提示、设置未生效）。
- 改：新增可复用 `composables/useUnsavedGuard.ts`（脏比对 + `onBeforeRouteLeave` 弹确认框 + `beforeunload` 原生拦截 + 显式「● 有未保存修改」角标），接入整页内联编辑的配置页：**API 密钥、策略编辑、网络检测(自定义 DNS)**。数据载入/保存成功后重置基线，避免误报；模态框式新增/编辑（用户管理/GitHub 监控）是离散提交点不适用。

### 验证
- `npm run build` 零错；产物含 `v1.21.157-28`、`ToolsModal` 日间令牌、卡片语义色。
- VM SFTP 直推 `docker/frontend`（nginx 只读挂载直读免重启），逐项点击链路实测。

## 2026-09-12 更新（v1.21.157-27，AI 控制台日间改为「对齐系统整体日间风格」）

用户最终定调：不要控制台自造配色（-25 雾青灰 / -26 清新青绿都作废），日间控制台直接**复用系统全局主题令牌**（`styles/theme.css` 的 `--dt-*`），与仪表盘/任务/配置等全站页面同一套蓝色科技风。仍纯前端、仅日间，夜间赛博深色主题零改动。

### 1. 做法（映射而非自造）
- 控制台内部变量（`.cc-root` 的 `--bg/--panel/--line/--cyan/--txt/--dim…`）在 `[data-theme="light"]` 下全部指向系统令牌：
  - 画布 `--bg → var(--dt-bg)`(#f6f8fc)、面板 `--panel → var(--dt-card)`(#ffffff)、描边 `--line/--line2 → var(--dt-border-strong)/var(--dt-border)`。
  - **主色青 `--cyan → var(--dt-primary)`(#1677ff)**——控制台大量把 `--cyan` 当主色用（标题/按钮/chip/编号点），随之统一变系统蓝。
  - 文字 `--txt → var(--dt-text)`(#0f1f33)、弱标签 `--dim → var(--dt-muted)`(#64748b)；次/三级取 `#334155/#475569`。
  - 语义色（成功/危险/警示/品红）取与系统蓝协调的稳重值（`#16a34a/#dc2626/#d48806/#d6337a`）。
  - 字体栈换成**系统同款** `-apple-system, BlinkMacSystemFont, "Segoe UI", Arial, "Microsoft YaHei", sans-serif`（仅代码/URL/报文/数字保留等宽）。
- 保留 -24/-25 的结构性修复：去所有霓虹辉光/扫描线/流光动画、字符加粗醒目、teleport 弹层（浏览器面板 `.browser-modal` / 漏洞抽屉 `.vuln-drawer`）浅色化。

### 2. 覆盖面
- AI 控制台 `pentest/console` 全部日间呈现：遥测带、三栏面板、消息气泡、工具调度流卡片、列表卡片，及 teleport 弹层统一到系统蓝色科技风。

### 3. 验证
- `npm run build` 零错；产物 `PentestConsole-*.css` 含系统令牌引用 `var(--dt-bg)`/`var(--dt-primary)`/`var(--dt-card)`；`index` 含 `v1.21.157-27` 无旧配色 `#0a9bae`/`#e9f1f2` 残留。
- VM SFTP 直推 `docker/frontend`（nginx 只读挂载直读免重启），截图确认日间控制台与全站蓝色主题一致；纯展示层改动无写库无需清理。

## 2026-09-12 更新（v1.21.157-26，AI 控制台日间配色转「清新科技」调）

在 -25 人体工程学基础上按用户要求把色调调得更清新科技（仍纯前端、仅日间、夜间赛博主题零改动）：
- 画布 `#e7ecf2`(灰蓝) → `#e9f1f2`(清透冷调雾青)；面板 `#f7f9fc` → `#f8fcfc`(带一丝青绿的冷净近白)。
- 主色 `#0b7599`(沉稳深青) → `#0a9bae`(清新青绿 teal-cyan)，浅底上清透有科技感又不刺眼；辅色/描边/次级底同步转冷调青雾。
- 面板头、遥测格、chip、工具卡编号点、弹层/抽屉证据块全部统一到新青绿调；文字仍近黑蓝强对比、无衬线加粗（-25 的去眩光 + 字符醒目不变）。
- 验证：`npm run build` 零错，产物 CSS 含 `#0a9bae`/`#e9f1f2`/`#f8fcfc`；`index` 含 `v1.21.157-26`。VM SFTP 直推 `docker/frontend`（nginx 只读挂载直读免重启），截图确认清新青绿调生效、不刺眼、字符醒目。

## 2026-09-12 更新（v1.21.157-25，AI 控制台日间 UI 人体工程学重设计——去眩光 + 字符醒目）

-24 只去了辉光，但用户反馈**仍太刺眼伤眼、字符不醒目**。定位到两大人体工程学病根并重设计（仍纯前端、仅日间、夜间赛博主题零改动）：

### 1. 太刺眼（眩光）
- 病根：原纯白面板 `#ffffff` 坐在亮蓝白画布 `#f5f8fc` 上——两层高亮度蓝白几乎无明度层次，大片纯白灼眼。
- 改：画布降为柔雾灰蓝 `#e7ecf2`（非亮白），面板改雾白 `#f7f9fc`（非纯白），两级明度拉开、边界靠层次而非靠亮；主色由电光青 `#0091cc` 收为沉稳深青 `#0b7599`（浅底上不振动刺眼），辅色同步降饱和；网格背景透明度降到 .3 减噪。

### 2. 字符不醒目
- 病根：整个指挥视图继承**等宽字体**，中文渲染纤细发虚；标签用发灰色 + 英文式 `uppercase`/字间距，中文更显松散无力。
- 改：容器换**中文无衬线字体栈**（PingFang SC/微软雅黑…），中文端正醒目；仅真代码/URL/报文/数字保留等宽（技术值等宽更整齐）；文字色整体加深（主文近黑蓝 `#14202e`）；面板头/区块标题/遥测标签**加粗提字重、去 uppercase 与字间距**（中文不适配）；AI 气泡字号 13.5px、行高 1.75 提可读。

### 3. 覆盖面
- AI 控制台 `pentest/console` 全部日间呈现：遥测带、三栏面板、消息气泡、工具调度流卡片、列表卡片，及 teleport 弹层（浏览器面板 `.browser-modal`、漏洞抽屉 `.vuln-drawer`）统一到新柔和浅色调。

### 4. 验证
- `npm run build` 零错；产物 `PentestConsole-*.css` 含新画布 `#e7ecf2`、雾白面板 `#f7f9fc`、深青 `#0b7599`、`PingFang SC` 字体栈；`index` 含 `v1.21.157-25` 无 `-24` 残留。
- **VM 真实 E2E 已过**：SFTP 直推 `docker/frontend`（nginx 只读挂载直读，无需重启）→ 日间命令视图不再刺眼（画布/面板明度分层）、中文字符加粗醒目、标签深色清晰；纯展示层改动无写库无需清理。

## 2026-09-12 更新（v1.21.157-24，AI 控制台日间 UI 重构——夜间赛博风套浅色残留辉光根治）

纯前端视觉重构，只改 AI 控制台（`pentest/console`）**日间浅色**呈现，夜间赛博深色主题完全不动。

### 1. 问题（先核实现状）
- AI 控制台是**夜间赛博风优先**设计（深空黑+霓虹青/品红），日间是靠 `[data-theme="light"]` 覆盖 `--*` 变量的补丁式浅色。
- 病根：约 25 处**硬编码 `rgba(0,229,255,…)` 霓虹青 / `rgba(255,45,120,…)` 品红**，变量覆盖（`--cyan:#0091cc`）根本抓不到——日间仍残留品牌字 `text-shadow` 辉光、按钮 `box-shadow: 0 0 16px` 外发光、中区 `inset 0 0 60px` 青色内发光、动画流光输入边框 `.comp-glow`、顶部 `.core-scan` 扫描线。像「褪色的深色主题」而非专门的浅色 UI。
- 另有两处真实可读性 bug：① 用户气泡夜间用浅粉字 `#ffd9e6`，日间白底几乎不可见；② 浏览器面板弹层 / 漏洞详情抽屉（teleport 到 body）内部硬编码深底 `#0d1424`+浅字，在日间浅色弹窗里是「深块套浅字」割裂。

### 2. 方向（用户拍板：清爽科技风，保留作战室三栏骨架）
- 保留三栏驾驶舱（攻击面 / 指令台 / 工具流）+ 遥测带结构 + 青色主色调；日间**去掉所有霓虹辉光/扫描线/流光动画**，改**实心细描边 + 柔和投影**强化面板边界，青色只作点缀。

### 3. 改动（全部在 `[data-theme="light"] .cc-root` 覆盖块，夜间零改动）
- 遥测带：透明底青色渐变 → 实心白底 + 底部实描边 + 柔投影。
- 三栏 + 中区面板：实心描边 `#d4e0ec` + 柔投影 `rgba(15,40,70,.05)`，替掉夜间内发光。
- 关辉光：品牌字影、脉冲点/状态灯光晕、主按钮/发送/停止外发光、代理字影、返回键悬停光、状态标签脉冲动画全部 `box-shadow/text-shadow/animation: none`。
- 去 `.core-scan` 扫描线（`display:none`）、`.comp-glow` 流光动画 → 静态中性细边、`.tcard.enter::after` 扫光。
- 修可读性 bug：用户气泡日间改深红字 `#7a1740` + 浅红底；浏览器面板 `.browser-modal` / 漏洞抽屉 `.vuln-drawer` 证据报文块日间统一浅底深字（请求/响应左彩条保留）。

### 4. 验证
- 前端 `npm run build` 零错，产物 `PentestConsole-*.css` 含 56 条 `data-theme=light` 规则 + 新增覆盖（`core-scan`/`browser-modal`/`vuln-drawer`/`7a1740` 均在）；`index` 含 `v1.21.157-24`、无 `-23` 残留。
- **VM 真实 E2E 已过（192.168.128.129，aiadmin/123456）**：SFTP 直推 `docker/frontend`（nginx 只读挂载直读，无需重启）→ 日间命令视图辉光/扫描线消失、三栏描边清晰、遥测带白底有边界；切夜间赛博深色主题完好无回归。纯前端展示层改动，无测试数据写库需清理。

## 2026-09-12 更新（v1.21.157-23，问题18：AI 配置代理改造——删「出口模式化」，改每模型「入口具体代理条目」）

围绕「AI 配置代理概念冗余、与任务出口冲突」（待办 token/限位文档 问题18）做字段级重构。

### 1. 需求与旧设计作废原因
- 旧设计：全局 `config.use_proxy`(bool) 开关 + `config.proxy_mode`(global/smart/pool) + provider `use_proxy`(bool)，是「出口模式化」——概念冗余，且与「任务发起时指定的 AI 攻击出口（AI→目标）」语义撞车。
- 调研坐实（待办没记的关键冲突）：旧 `use_proxy`/`proxy_mode` **只对配置中心「测试连通性」按钮生效**（`_client._resolve_proxies`）；真实渗透会话的 LLM 调用轨 `_llm._proxies` 被净室迁移**写死恒直连**（`return None`）。境外中转站场景真实会话根本连不上。

### 2. 新设计（入口具体代理条目，双轨分离）
- provider 新增字段 **`proxy_id`**（string，自定义代理 `proxy_custom._id`；空串=直连），替代旧 `use_proxy`+`proxy_mode`。语义是**入口代理**（平台→中转站/LLM 出网），与任务发起时的**出口代理**（AI→目标）彻底双轨分离（记忆 dengta-ai-proxy-dual-track 铁律）。入口代理只认用户显式选的某条具体自定义代理，**绝不走攻击出口/公开代理池**。
- 全局 config **删** `use_proxy`+`proxy_mode`（入口代理下沉到 provider 级）。
- **两条 LLM 轨统一**：`_llm._proxies(provider)`（真实会话轨，核心，从恒直连改为读 `provider.proxy_id`）与 `_client._resolve_proxies(provider)`（测试按钮轨）都经 `ROLE.PROXY.custom_proxy_url(ref)` 取 URL，消除「测试走代理/真实直连」历史不一致。用户已拍板作用到**真实会话+测试两轨**。

### 3. 存量读时迁移（不写 DB 迁移脚本）
- `parse_provider_config` 读时归一（仿 `proxy.py _LEGACY_MODE_MAP`）：旧文档带 `use_proxy`/`proxy_mode` 但无 `proxy_id` → `proxy_id=""`（直连）。理由：旧模式化只作用于测试按钮、真实会话本就直连，映射直连**行为不变、不会突然改道**；旧 `proxy_mode`(动态选) 无法对应「某条具体条目」，直连是最稳兜底。无写放大。

### 4. 改动面（完全限定）
- 后端：`system/proxy.py`（`ProxyServiceImpl` 新增门面方法 `custom_proxy_url` 透出现成模块级函数，供 registry 调用）、`ai_pentest/ai_config.py`（字段定义/落库/白名单/读时迁移）、`ai_pentest/_llm.py`（真实会话轨代理解析，核心）、`ai_pentest/_client.py`（测试轨代理解析）。路由层纯透传无需改。
- 前端：`api/aiConfig.ts`（接口去 `use_proxy`/`proxy_mode`，provider 加 `proxy_id`）、`pages/ai/AiConfig.vue`（删全局「出口走代理」开关、provider 列「出口」→「代理」展示所选代理名、新增/编辑弹窗加「入口代理」下拉选自定义代理条目默认直连，下拉与 JSON 双向绑定）。

### 5. 验证
- 本地：四后端文件 `py_compile` 通过；前端 `npm run build` 零错，产物含 `-23`、无 `use_proxy`/`proxy_mode` 残留、含 `proxy_id`。
- **VM 真实 E2E（必测）**：① 全局「出口走代理」开关消失、provider 列头显示「代理」；② 新增/编辑 provider 入口代理下拉能列 enabled 自定义代理+「直连」，选中保存后列表显示代理名；③ 存量旧 provider 显示「直连」不报错；④ 点「测试」经所选入口代理连通（proxy_enabled 正确）；⑤ 真实渗透会话 `_llm.chat` 经 `provider.proxy_id` 走代理（不再恒直连）；⑥ 测完清理造的测试 provider/代理条目。

## 2026-09-12 更新（v1.21.157-22，问题14：长会话 >30min RabbitMQ ack 超时 CRITICAL 根治）

围绕「长会话 >30min 触发 RabbitMQ ack 超时 CRITICAL」（待办 token/限位文档 问题14）做架构级根治。

### 1. 根因（三方冲突，稳定引爆非偶发）
- `_celery_adapter.make_celery` 设 `task_acks_late=True`（任务**跑完才 ack**）；RabbitMQ 3.9 默认 `consumer_timeout=1800000`（30min）测量「投递→ack」间隔，且无配置覆盖。
- AI 渗透会话（`sentinel.run_session`）设计上可跑几百轮 >30min（实测 `asset.dihuangbox.com` round 451/74min）→ 该间隔超 30min → RabbitMQ 强制断 channel（`PreconditionFailed(406)`）→ consumer 主循环 Unrecoverable 崩。**只要会话跑超 30min 必稳定引爆**（问题12 的 fuzz 会话必然超）。

### 2. 关键前提确认（决定修复策略）
- 本平台崩溃恢复**不依赖 RabbitMQ 重投**：`scheduler.py` 从 DB 真相源回收——`_reclaim_on_startup`（worker/scheduler 重启即回收残留 running/dispatching 任务/会话续跑）+ `_reclaim_stalled_tasks`（running 心跳超时 watchdog 重投，带 `reclaim_count` 上限防无限重投）；停止走协作式取消（DB status，不靠 ack）。
- 即 `acks_late=True` 提供的「崩溃重投」保障与 scheduler DB-reclaim **完全冗余**；且 rabbitmq 容器**无持久卷**（compose 只挂 tz），recreate 本就丢消息，恢复全靠 DB-reclaim。

### 3. 修复（早 ack 治本 + 调大 timeout 兜底，双保险）
- **① 早 ack（治本）**：`_celery_adapter.make_celery` 改 `task_acks_late=False`（任务一领就 ack）——consumer_timeout 不再计长任务执行时长，从根上让长会话不触发 ack 超时。删除 `task_reject_on_worker_lost`（早 ack 下已无效：任务已 ack，worker 丢失不重投），崩溃回收统一由 scheduler DB-reclaim 负责。`task_track_started` 保留（web/前端看 started 态）。
- **② 调大 consumer_timeout（兜底）**：`docker-compose.yml` rabbitmq 服务加 `RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS: "-rabbit consumer_timeout 43200000"`（12h）。**用原生 ERL_ARGS 环境变量注入而非新增 rabbitmq.conf 挂载文件**——热更新 `_TRACK_FILES` 不含独立 conf 文件，存量用户拿不到会导致挂载源缺失、rabbitmq 起不来（规避 CLAUDE.md 12.4.3 坑）。docker-compose.yml 在 `_TRACK_FILES` 内，变更触发 `_updater._recreate_containers` 自动 recreate。
- **③ 治本靠问题12（已修 v1.21.157-21）**：控制单会话别无意义跑那么久（404 fuzz 收敛）。
- 同步更新 `orchestration.py` 模块 docstring 里引用 acks_late 的协作式取消注释（校准契约：协作式取消不依赖 ack 语义，崩溃恢复统一由 scheduler DB-reclaim）。

### 4. 验证
- 本地：`py_compile` 通过（celery 本地未装，conf 值 + 容器行为属 VM 验证项）。
- **VM 真实 E2E（必测）**：① 会话跑 >30min 不再出 `PreconditionFailed(406)` CRITICAL；② worker 崩溃/热更打断后 scheduler DB-reclaim 正常续跑（早 ack 后无 RabbitMQ 重投，全靠 reclaim）；③ compose recreate 后 rabbitmq consumer_timeout 生效（`rabbitmqctl environment | grep consumer_timeout` 或看长会话不再断）。

## 2026-09-12 更新（v1.21.157-21，问题11：轻量浏览器截图 + 水位资源调度体系扩容）

围绕「资产检索截图大量黑屏」（待办 token/限位文档 问题11）根治，并按用户定调把资源调度体系扩容到侦察侧。

### 1. 截图黑屏根因根治：chromium 引擎取代 phantomjs
- **根因（VM 实测坐实）**：PhantomJS 老 WebKit 不支持 ES6（`Object.assign`/Promise），现代 SPA 首屏 JS 崩→DOM 渲不出→输出**纯黑画布**（同一张 16627B 黑图被几十站点重复存）。传统 SSR 页正常。
- 新增 `recon/native/chromium_shot.py`（`ChromiumShot`，Playwright CLI 子进程 `python -m playwright screenshot`，进程级内存隔离、规避 sync API 跨线程）。pipeline `Tools.screenshot` 改 `_pick_screenshotter()`：**chromium-first → phantomjs 兜底 → skip**（诚实降级）。
- 新增 `recon/native/_shot_quality.py`（引擎无关质量门，phantomjs/chromium 都调）：尺寸下限过滤纯色/黑屏（`SCREENSHOT.MIN_BYTES` 默认 30000，实测空白16627B vs 真实280727B）+ md5 去重（同一空白图只存一份）。**不引入 Pillow**（守零依赖，用户定调）。phantomjs 黑屏也一并过滤，site.screenshot 留空不存黑图。

### 2. L3 内存池下沉为 kernel 共享基础设施
- `ai_pentest/tool_resources.py` 全部搬入新 `kernel/resource_pool.py`（AI 渗透 + 侦察/扫描/截图统一用一个池）；原文件改**兼容 shim**（re-export，历史惰性 import 调用点零改动、零循环 import 验证通过）。
- MODULES.md 铁律2 加**例外三**：`kernel/resource_pool` 共享单一权威基础设施允许被直接 import（同 activation，registry 降级语义会破坏跨 worker 内存账本一致性）。

### 3. 水位体系扩容：侦察/扫描/截图纳入资源池，优先级低于 AI
- 新增 `PRIORITY_RECON=-1`（恒低于 AI 自动会话 `_asset_priority≥0` 与人工 `PRIORITY_MANUAL`）。`acquire` 加 recon 带抢占：任何 AI 申请者内存不足时逻辑抢占 recon 预留（recon 恒让位 AI），不动 AI-vs-AI。
- **守 recon 自包含铁律**：`recon_bridge._build_resource_gate` 构建纯 callable 注入 pipeline（镜像 `_inject_cancel` 范式）——recon 内部只调注入的 gate，**绝不 import 资源池/contracts**。gate 内存足即放行、不足则阻塞轮询等待+让位 AI，`cancel_check` 真→抛 StoppedException，`RECON_GATE_MAX_WAIT_SEC` 超时→诚实降级跳过。
- 门控范围：内存重工具（screenshot/nuclei/nmap service/weakbrute，经 `ExternalTool.resource_heavy` 标志或标准类 `resource_gate` 属性）；httpx/naabu/dnsx 等 IO 密集只受 L1/L2 并发水位。
- 释放四时机 recon 侧新增：`run_recon` finally `release_session_all("recon:"+task_id)`。

### 4. 「资源等待」任务状态（工具等待可见性）
- 工具因内存等待 → `recon_bridge` 写 `task.resource_wait:{tool,since,avail_mb,reserve_mb,...}`（recon 不碰 DB，桥写）；acquire 成功/退出/降级/收尾清除；`orchestration._set_status` 终态 `$unset resource_wait`（防 worker 中途死留死徽标）。
- `task_list.list_tasks` 逐字段透传（后端无需改）；前端 `TaskList.vue` status 列加金色「资源等待」子徽标（主状态仍 running，任务内工具在排队）+ tooltip（工具名/可用MB/需MB），15s 轮询自动刷新。

### 5. 可靠性修复（Stage 6）
- 自学习防并发污染：`release` 记 peak 前查在途 holder 数，>`LEARN_MAX_CONCURRENCY`(默认1) 跳过记样本（并发 delta 不纯毒 p95）；`record_peak` 丢弃 >默认峰值×`LEARN_OUTLIER_FACTOR`(4) 的离谱样本。
- 测试：新增 `test_resource_pool`(10) + `test_shot_quality`(5) + `test_unit_reverse`/`test_icp_miit` 三态；kernel + recon 全绿。**待 VM 真实 E2E**（Playwright CLI 容器渲 SPA 为最高风险项，见待办文档验证节）。

### 7. 监管闸刀误拦读操作/探测放宽（问题13 边界优化）
- **现象（用户补充真实样本校准）**：大量读取型 POST 被误拦——① 保守 `POST .../batchOp/getResult`（明显取数据）因路径含 batch 被当"批量操作"拦；② src `POST /test`+方法覆盖探测被当"可能删资源"拦；③ VM guard_log 实测坐实——`memberInfo/query`、`staff/list/all`、`getLateList`、`getFacepayConfig` 等大量 query/get*/list/result 读语义 URL 全被当"业务功能点写入"拦。根因：监管 AI 提示词对"POST = 写操作"过度敏感，没有明确"读取型 POST"判据。
- **核查**：规则层（`_rule_check`）对这些都判 `ambiguous`（不硬拦），误拦发生在**监管 AI 提示词层**——把"批量操作""业务功能点"一刀切当危险，没区分批量读/写、没教 AI 识别读取型 POST。
- **修复（只改提示词，规则层真破坏防护零改动）**：`_GUARD_SYS`（src）+ `_GUARD_SYS_CONSERVATIVE`（保守）+ `_GUARD_SYS_DETECT`（探测）**三套全改**——核心原则"POST 不等于写操作，危险看有没有增删改数据，不看是不是批量/POST方法/路径有无 batch 字样"；明确**读取型 POST 判据**（URL 含 get*/query*/list*/search*/find*/fetch*/load*/view*/detail*/info*/export*/page*/result* 或动词+List/Data/Info/Result/Config 组合 = 读操作放行，不限 body 内容看 URL 语义即可）；批量读取/查询/导出放行、只拦批量**增删改**；方法覆盖打非资源探测路径倾向放行。**规则层真破坏防护(drop/truncate/rm-rf/批量id删改)一分未动**。guard 提示词是硬编码常量非 DB，改码即生效。test_guard 20 测全绿。

### 6. 空转规避根治：进展有效性维度 + 目录爆破识别（问题12 真缺陷·高）
- **现象**：AI 在 CDN/静态站疯狂 fuzz 路径（实测 round 451/74 分钟/404 占 83%），empty_streak/no_progress 规避没生效（还连锁引爆问题14 RabbitMQ 超时）。
- **根因**：`_progress_fingerprint` 把"打新 URL"当进展，每个新 404 让 `len(seen)` 涨→`no_progress_rounds` 永归零→`NO_PROGRESS_HARD(40)` 永不触发。
- **修复①（响应有效性维度）**：新增 `_resp_is_useful`——http 只有 2xx/3xx 或 4xx/5xx 带实质 body(>200) 才算有效产出；纯 404/空壳页不计入进展指纹。防误伤：越权验证 403→改 cookie 200 这类 body 有内容仍算有效。
- **修复②（目录爆破识别，独立于 no_progress）**：新增 `_dirbrute_signal`——近 `DIRBRUTE_WINDOW`(30) 次 http_request 里 404 占比 ≥ `DIRBRUTE_404_RATIO`(0.75) 且样本 ≥ `DIRBRUTE_MIN_SAMPLES`(20) → 软提醒一次让 AI 收敛。治"零星 200 打断 no_progress 计数让 404 爆破无限逃逸"。只看客观 404 占比不猜路径语义。
- 测试：`test_engine_loop` +3（`_resp_is_useful`/进展指纹忽略404/dirbrute），30 测全绿。

## 2026-09-12 更新（v1.21.157-20，漏洞定级根治：向量维度取代关键词黑名单 + 疑似标签文档补记）

围绕「配置缺陷类漏洞定级偏高」（待办 token/限位文档 问题6）做**根治性**修复，从"关键词黑名单追词"改为"看 CVSS 向量影响维度"。

### 1. 定级校准根治：向量治本闸取代关键词猜名字（问题6）
- **病根**：`AV:N + C:L` 会把纯配置弱项（安全响应头缺失/TLS·证书弱配置/「配置缺陷」）经 CVSS 3.1 公式结构性顶到 medium(5.3)，与其"无实际危害"不符（真实样本 ed-admin.dihuangbox.com「配置缺陷」定 medium 5.3）。原校准靠 `_INFO_LEAK_HINTS`/`_FINGERPRINT_HINTS` 词表匹配 vuln_type 猜语义——黑名单永远追不完，且字符串匹配脆（"防点击劫持头缺失"被"点击劫持"子串误判成 low）。
- **根治**：`_cvss.py` 新增 `_vector_is_info_only`（`I:N 且 A:N 且 C∈{N,L}` = 纯信息/配置型、无实质危害），作为 `calibrate_severity` 主判据——**不靠关键词，即便 vuln_type 没进任何词表也照降 info**。判定顺序（顺序即优先级）：① 指纹/配置语义→info（放最前，先收走无害项，防被②点击劫持子串误伤）→ ② 点击劫持特例→封顶 low → ③ 向量治本闸→info → ④ 向量硬闸（非低影响不降）→ ⑤ info_leak 词表兜底→low。
- **只看影响维度不看验证**：探测/保守快筛的疑似 SQLi 即便没实证，向量 C:H（本质能读/改数据）不命中降级闸 → 保留 high，快筛高危不被误埋。真危害（C:H/I 非N/A:H）任一成立即不降，绝不误伤（SQLi/XSS/RCE 保原级）。
- 词表调整：`配置缺陷`/`配置缺失`/`运维配置`/`misconfig`/`默认配置` 从 `_INFO_LEAK_HINTS`(→low) 移入 `_FINGERPRINT_HINTS`(→info)；安全响应头/TLS·证书类此前 v1.21.157 已在 info 档。词表从"决定降不降的主判据"退化为"向量缺失/legacy 时的兜底"。
- 测试：新增 `test_triage_vector_info_only_downgrade_without_wordlist`（无词表也降 info，含误伤防护样本）+ `test_triage_quickscan_suspected_sqli_not_downgraded`（疑似高危不误降）；risk_intel 26 测全绿。

### 2. 「疑似」标签机制文档补记（代码早有、文档缺载）
- 代码 `vuln_center._QUICK_SCAN_MODES={detect,conservative}` 早已实现「探测/保守快筛模式产出标疑似」，但 `云端/docs/` 零记载（契约脱节）。补进 `核心链路.md §1.1`：明确 `suspect`（验证深度/模式决定）、`verified`（证据充分度/tool_log 决定）、`severity`（影响定级/CVSS+校准）**三维度正交**，互不干扰。

### 3. 漏洞中心「LOW 及以上」漏出 severity="none" 的 0 分漏洞（问题8.B 真 bug）
- **现象**：VM 实地复现——筛「最低等级=LOW 及以上」仍显示 `配置缺陷 www.dhyct.com INFO 0`（DB 真实 `severity="none" cvss_score=0`，全零向量算出 0 分 none 档）。
- **根因**：`vuln_center._below_severities` 的 `_CANON_SEV` 不含 `none`，`min=low` 只排除 `["info"]`，`$nin` 漏放 CVSS 0 分最低档 `none`（比 info 还低）。
- **修复**：`none` 低于阈值时纳入排除（min≥low 即排除；min=info「全部含INFO」不排除仍可见）；仍不含 unknown/''/缺失（`$nin` 对字段缺失天然保留，不误杀 PoC/Nuclei）。list 与 `_unified_count` 共用同函数，列表/计数同步。补 `test_below_severities_excludes_none`。

### 4. 单位名任务 ICP 权威边界根治：三态分流 + 多单位风控（问题9 真缺陷·严重）
- **病根**：单位名任务 ICP 反查产出 unit_map 后①旧代码没写回 task 文档→归集读不到→unit 全 fallback 成「任务名_目标名」碎片（每子域一个 unit，情报共享按错误 key 存串联失效）；②`reverse_by_unit_miit` 对「查询成功但无备案」和「工具失效(WAF/风控/网络)」**都返回空 set 无法区分**→上层一律降级第三方，把不属于该单位的资产越权归属过来。
- **用户 2026-09-12 定调的 ICP 权威边界**：单位名任务中——① ICP 有效且非空→**只用 ICP 域名/IP，第三方越权资产直接丢弃**；② ICP 有效但备案空→**该单位无资产结束，不降级第三方**；③ ICP 工具失效→降级第三方；④ 多单位任务防 ICP 官方源被风控（连查触发→集体失效→误判无资产/大范围越权）。
- **实现（4 层）**：
  - `_icp_miit.reverse_by_unit_miit` 返回三态 `status`（ok/empty/unavailable）；`_query_condition` 失败返 `None`、成功空返 `[]`，让「WAF拦截/风控」与「真无备案」可区分（顺带修 `query_icp` 对 None 兜底）。
  - `ext_source._icp_official_reverse` 透传三态；`reverse_lookup_units` 按状态分流（ok只用ICP不合并第三方 / empty无资产不降级 / unavailable降级鹰图）+ 多单位风控自适应（官方源从未成功+连续失效→判疑似风控→后续单位跳过官方源直连第三方，非硬编码阈值）+ 查询间指数退避节流（`_ICP_REVERSE_BASE_INTERVAL`，测试可置 0）。返回加 `unit_status`/`risk_suspected`。
  - `orchestration._unit_handler` 区分「ICP 权威判无资产(no_asset 结束)」vs「工具失效无种子」；保留 unit_map 写回 task 顶层（归集 `asset_intel.collect_from_task` 读 `task.unit_map` 顶层，链路对齐）。
- **测试**：`test_unit_reverse` +4 条（三态分流/越权丢弃/多单位风控跳过）、`test_icp_miit` +4 条（reverse 三态区分）；修测试隔离（关节流 sleep + 补 repo 桩，30s→0.01s）。kernel + risk_intel 全绿。
- **文档**：`核心链路.md §12.5.1` 新增「单位名任务 ICP 权威边界」设计原则（三态处理表 + 多单位风控铁律）。

## 2026-09-11 更新（v1.21.157-18，情报体系：并发原子化 + 开关语义修正）

### 1. 情报写入并发原子化（P2，防多 worker 双插）
- `write_playbook` 改派生标量 `pb_key` + `update_one(upsert=True)` 原子 upsert（数组 fingerprints 无法直接唯一索引，派生标量键）；`write_unit_intel` 改 upsert 建档 + `$addToSet`/`$not.$elemMatch` 幂等推 item。
- bootstrap 补唯一索引：`intel_playbook.pb_key`(unique,sparse)、`unit_intel_profile.key`(unique)。杜绝 gunicorn 多 worker 并发 find_one→insert 双插同一情报。

### 2. 情报体系开关语义修正（intel_enabled，翻转为「关闭=不创建情报」）
- **原语义有误**：`intel_enabled=False` 原本门控查询类工具（关闭时不查），但用户定义应为「该策略任务不创建/沉淀情报」。
- **翻转**：关闭时改为门控**情报沉淀类回写**（`write_exploit_clue`/`write_unit_intel`/`record_stack`/`write_playbook`/`mark_playbook_useful`/`mark_report_useful`）+ `_engine._writeback_system_playbook` 收尾回写；**查询照常**（仍可消费现有情报打），**漏洞成果照常上报**（`report_finding`/`record_chain_step` 非跨会话情报沉淀，不受开关影响）。
- 同步改：`_tools.dispatch` 门控集 `_INTEL_WRITE_TOOLS`、核心链路 §6.8 文档、前端 PolicyEdit 文案 + policy.ts 注释。适用场景：一次性/敏感目标不想把打法/画像沉淀进共享库。

## 2026-09-11 更新（v1.21.157-17，情报体系：打法衰减 + 匹配缺陷根治）

围绕情报共享/情报库体系排查并修复一批匹配与打分缺陷（详见 云端/docs/核心链路.md §6.2）。

### 1. 打法有效分时间衰减（P1，之前只累积不衰减，陈旧霸榜）
- `match_playbook` 推荐分改 `base + eff × 0.5^(age/H) + title`，H=30天半衰期，age=距上次「被证实有用」天数。
- `mark_playbook_useful(out_high)` 刷新 `last_useful_date` → age 归零权重复原；eff 库值仍只升不降（累积语义不变），衰减只作用排序权重。陈旧打法自然沉底、新证实的浮上来，base 保底不为 0。
- 新增 `_decay_factor` + `write_playbook` 初始化 `last_useful_date`。

### 2. 组件名归一：下沉共享归一器 core/components.py（缺陷1/3）
- 历史三套词汇（vuln 别名表 / system_tags 子集 / playbook 无归一）不互通 → 打法库漏匹配；vuln 库双向子串匹配短别名（tp/u8/c6/nc）导致 `tp∈http` 海量误匹配。
- 新建 `core/components.py`（权威别名表 + `canonical_component`/`expand_aliases`/`alias_match`），**短别名(≤3字符)只精确匹配、长别名走词边界**，杜绝子串误命中。
- `asset_intel._norm_components`（打法库写入/匹配）+ `vuln_intel._expand_aliases`（漏洞库查询）共用它；`vuln_intel.COMPONENT_ALIASES` re-export core 单一事实源。

### 3. match_playbook 指纹兜底（缺陷2）
- `_t_match_playbook` 把 AI 传的 fingerprints **并入资产已存 finger_names**（经 match_asset 读），防 AI 漏传/传脏导致组合打法 issubset 静默漏匹配。

### 4. fld 提取三处口径统一：下沉 core/domains.py（缺陷4）
- 三套 fld 实现（enrich 主路径 / ext_source unit_map key / asset_intel）二级后缀表不一致 → 单位回填失灵、`*.mil.cn` 被削成 mil.cn 打歪。
- 新建 `core/domains.py`（权威二级后缀表 + `extract_fld`），三处全部委托它，口径统一；`abc.gov.cn`/`abc.mil.cn`/`x.com.au` 原样不上溯。

### 5. 指纹纠错传播门控（缺陷5，防单会话污染共享系统身份）
- `record_component`：本资产 finger_names 即时更新（影响面小），但**传播到共享 intel_system 需 high 置信 或 ≥2 个不同会话投票**（记 `_finger_votes`）。
- `remove` 也必须带 evidence（原来只加要，可零依据删真实组件→组合打法漏匹配）+ 同样门控（防误删拖累其他资产）。`confidence` 从「收了不用」变真正门控，`session_id` 贯通投票。

## 2026-09-11 更新（v1.21.157-16，第三批 5 项修复）

### 1. 新建任务备用模型选不了（修复）
- 根因：`TaskCreate.vue:backupProviderOptions` 用「同协议+排除首要」双重过滤把选项砍到只剩「不指定」（系统只有一个同协议 provider 时必现），用户以为控件坏了。
- 修复：对齐 `PentestList.setBackupOptions`——不合规选项「保留但置灰 + 说明（· 跨协议不可选 / · 已作首要）」而非删除，用户能看到为什么不能选；watch 改为「不合规（disabled/不在列表）才清空」。

### 2. 人工接管导致系统提示词泄露（修复）
- 根因：会话台/详情页展示对话时，只过滤 `role=system`，但引擎把**开局简报**（含 mission_intel/recon 快照/蜜罐预警，以「目标资产：」开头）+ 系统 nudge（「[系统]」）+ 监督者建议（「【监督者建议」）都以 `role=user` 注入历史 → 被当普通用户对话渲染泄露。
- 修复：`_console.py` 加 `_is_display_user_msg` + `session.py:get_session_messages` 加 `_is_leaky_internal`，两处展示路径统一过滤引擎内部 user 消息（system 全过滤 + user 系统级注入按前缀过滤；「【人工指令】」真人插话保留）。

### 3. 攻击告警支持按最近时间排序
- `attack_alert.list_attacks` 加 `sort_order` 参数（desc 默认/asc）；端点透传；前端「最近时间」列加 `sorter`，`onTableChange` 读排序方向传后端（服务端排序，跨页有效）。

### 4. 新增「攻击告警推送」，同 IP 5 分钟去重
- `api_keys` 飞书渠道加 `attack_alert_notify` 开关（默认开）；前端「API 密钥 > 告警推送」加开关。
- `attack_alert.py` 加 `_notify_attack`（推攻击者 IP/类型/严重度/命中次数/路径，经 ROLE.NOTIFY）+ `_attack_alert_enabled` 开关（`is not False` 默认开）+ 同 IP 5 分钟进程内去重（攻击监控靠 MongoDB 单例锁，跨 worker 只一个进程跑 → 进程内 dict 去重安全）。挂在 `record_attack_agg` 落库后。

### 5. 单位名发起任务 ICP 优先作为权威资产源
- 需求：用单位名发起 → 先用 ICP 官方备案查权威域名/IP → 用这些种子交第三方工具（鹰图/FOFA）+ 内核侦察富化资产；ICP 查不到才降级鹰图 icp.name；冲突 ICP 为准（官方一手）。
- 实现（改在来源层/线头，不动 pipeline）：
  - `_icp_miit.py` 新增 `reverse_by_unit_miit(unit)→{domains,ips}`（复用 auth/滑块验证码/queryByCondition，从备案记录多字段兜底提取域名，逗号分隔多域名，**域名原样不上溯根域**）。
  - `ext_source.reverse_lookup_units` 改 ICP-first：先 `_icp_official_reverse(u)`，查到用 ICP，查不到降级 `_hunter_by_icp_name`；冲突 ICP 为准（查到就不合并鹰图）。
  - 前端单位名文案改「ICP 官方备案优先 + 鹰图/FOFA 降级」。
- **6a 防打歪**：ICP/鹰图域名原样作种子绝不上溯（`abc.gov.cn` 不削成 `gov.cn` 打歪整个政府网段）；附带修 `asset_intel._fld_of` 天真取末两段的 bug（加二级公共后缀表 gov.cn/edu.cn/com.cn 等，`abc.gov.cn`→`abc.gov.cn`），杜绝 fld 分组/单位回填打歪。

## 2026-09-11 更新（v1.21.157-15，激活时钟统一 + 扩展商店未授权态）

本次修复 VM 实测激活状态自相矛盾（问题1）+ 扩展商店未授权态显示不当（问题2），建立独立激活时钟 + 云端一票否决机制。

### 1. 激活状态自相矛盾（剩余23h显示「已过期」vs「已激活」）
- **现象**：同一份后端数据（`activated=true, expired=false, remaining_days=0`，实际还剩约23小时未过期），顶栏徽标显示「授权已过期」（红）、激活设置页显示「已激活」（绿）、到期弹窗显示「已到期」——三处口径不一。
- **根因**：⓵ `remaining_days = int((exp-now)/86400)` 向下取整，剩不到24h算成0 → 出现「activated但remaining_days=0」的合法中间态；⓶ 三消费点判据不统一：徽标把 `licenseDays===0` 当过期哨兵（activated-but-0与真expired撞车）、设置页只看 `activated`、弹窗看 `days<=0`。
- **修复（建立独立激活时钟，本地JWT时间字段为权威）**：
  - **后端** `system/activation.py`：
    - `local_status()` 升级为「激活时钟」单一权威：`remaining_days` 改**向上取整**（`math.ceil`，剩<1天显示1天，与用户直觉一致）；补 `activated_at`/`revoked` 字段；叠加云端否决标记（`.activation_revoked` fresh读盘，吊销时即便JWT未到期也判 `expired=True`）。
    - 新增吊销标记读写：`is_revoked()` / `mark_revoked()` / `clear_revoked()`（与key同目录，fresh读盘，多worker一致）。
    - 新增 `note_remote_result(reason)`——云端一票否决入口：更新检测/扩展商店收到云端401/403(reason=unauthorized)时调用 → 落盘否决标记 → 激活时钟立即结束（吊销即时生效）；云端重新认可(reason="")时自动清除；network/http_x不动（断网不误杀）。
  - **后端** `router/endpoints/meta.py`：
    - `/activation-info` GET：remaining_days改ceil、补 `expired`/`revoked`/`activated_at` 字段，叠加吊销标记口径与 `local_status` 一致。
    - `/activation` GET：透传 `local_status` 的 `revoked`/`activated_at`。
    - `/activation` POST：激活成功后调 `clear_revoked()` 清除吊销标记（用户重新激活/云端重新认可后恢复已激活态）。
  - **前端三消费点统一**：
    - `AppLayout.vue` 徽标：不再用 `licenseDays===0` 当过期哨兵，改为独立 `licenseActivated`/`licenseExpired` 标志驱动；绿「已激活·剩余N天」(N>1)、橙「即将到期·剩余1天」(N=1，更醒目)、红「授权已过期」(expired/revoked)；402事件置 `licenseExpired=true` 而非误用 `licenseDays=0`。
    - `ActivationSetting.vue`：区分文案「已激活」/「已被吊销」/「已过期」/「未激活」，补 `expired`/`revoked` 字段。
    - `LicenseExpiryModal.vue`：兜底计算改ceil（与后端一致）；`revoked` 时不走到期提醒（吊销由独立激活向导全屏阻断）。

### 2. 扩展商店未授权态显示不当（未授权时显示「商店暂无可用扩展」）
- **现象**：实测当前VM已激活、分发服务器返回空列表（商店本身暂无扩展），显示「商店暂无可用扩展」是对的。但用户诉求：未授权/未激活/过期时不该显示成「暂无扩展」，要明确提示需激活，区分「未授权拿不到」和「真的空」。
- **设计原则（用户明确要求）**：扩展商店授权判定走**独立分发系统实时校验通道**，与本地激活时钟（纯展示）分开。激活时钟离线稳定不抖动；只有那些本就要联网的操作（更新检测/扩展商店）把云端否决结论落盘 → 时钟读标记终结。
- **修复**：
  - **后端** `_extension_store.py:catalog()`：补机读字段 `auth_state: 'ok'|'unauthorized'|'no_key'`；成功(200)调 `note_remote_result("")` 清除否决标记、401/403调 `note_remote_result("unauthorized")` 终结时钟；区分no_key(本地无key)、unauthorized(云端拒绝)、ok(真·空或成功)。
  - **后端** `about/update_check.py:remote_version`：成功调 `note_remote_result("")` 清除、401/403调 `note_remote_result("unauthorized")` 终结时钟。
  - **前端** `SystemExtension.vue`：读 `auth_state`，`!='ok'` 时显示橙色警告「授权凭证无效或已过期，请重新激活系统」+「前往激活」链接（而非灰色info）；只有 `auth_state==='ok' && 空` 才显示「商店暂无可用扩展」。

### 3. 云端一票否决机制（吊销即时生效）
- 正常：激活时钟只看本地JWT时间字段（activated_at/exp），离线、稳定、全worker一致，不因日常网络通信抖动。
- 云端否决：更新检测/扩展商店收到分发系统明确401/403(unauthorized) → 落盘 `.activation_revoked` 标记 → 激活时钟读标记 → 立即判 `expired=True, activated=False`（即便JWT未到exp）——**吊销即时生效，不等JWT自然到期**。
- 解除：⓵用户重新激活成功 → `clear_revoked()`；⓶云端后续返成功(ok) → 自动 `clear_revoked()`（稳健，不因一次误判/临时故障永久卡死）。网络错误(network/timeout)不动（断网不误杀）。

## 2026-09-11 更新（v1.21.157-14，VM 测试迭代）

本次修复 7 项 VM 实测问题（代理/单位视图/AI 模型配置/新建任务），均走热更/分发可达存量实例。

### 1. 代理保存校验可达性（问题1）
- 现象：代理中心「启用代理」选内核代理保存时不校验节点可用性，直接显示保存成功。
- 修复：`system/proxy.py` 新增 `_reachability_check_on_save()`，对「启用代理（global 强制走代理）」的保存在结构性校验通过后，用实际生效出口 URL（`_source_url` + mihomo runtime，host/端口按实际）经 `_proxy_reachable()` 真探一次；全部节点不可达则拦下保存并提示「代理失效」。smart 模式设计上不可达自动降级直连，不因探测失败拦保存。

### 2. 健康检测显示「代理失效」而非底层报错原文（问题2）
- 现象：健康检测异常展示 `HTTPSConnectionPool(...ProxyError('Cannot connect to proxy'...))` 原文。
- 修复：`system/proxy.py` 新增 `_friendly_proxy_error()`，命中连不上代理/全部节点不可达特征时统一归一为「代理失效（全部节点不可达）」，应用于 `check_health`（写库前）与 `detect_exit_ip`（p_err）；非代理连通类错误（proxy not enabled 等）保持原样不误伤。

### 3. 新增「代理告警推送」开关，默认开启（问题3）
- `system/api_keys.py` 飞书渠道新增 `proxy_down_notify` 字段（默认 True），前端「API 密钥 > 告警推送」增加开关。
- `system/proxy.py:_notify_down` 推送前查开关（只有显式 False 才关，存量空串按默认开）。
- 顺带修复 `list_keys` 对 bool 开关字段 `or ""` 成空串的回环 bug（关了会变开）。

### 4. 单位视图「未知单位」幽灵数据删不掉（问题4）
- 根因：`risk_intel/unit_view.py:delete_unit` 用字面 `{"unit":"未知单位"}`，而「未知单位」卡代表的是 unit 为空/缺失的记录 → 匹配 0 文档，幽灵永远删不掉。
- 修复：删除过滤器改为经 `_unit_filter()`（与 `unit_detail` 对齐），「未知单位」反解为空-unit `$or`；会话集合并入 source.unit 空判定；未知单位不做 `intel_system.units` 的 $pull。

### 5. AI 配置新增模型名称可自填 + 默认自增（问题5）
- 现象：换中转站配同一模型时默认名称撞车。类型（厂商 preset）与名称（name）本是两个独立字段，后端无唯一约束早已支持同名。
- 修复（纯前端 `AiConfig.vue`）：`templateFor` 经 `nextProviderName()` 生成默认名——第一个用裸 label（如 `Claude (Anthropic)`），已存在则自增 ` - 1`/` - 2`…；name 仍可在 JSON 手改。

### 6. 新建任务「备用模型」可选有效模型 + 保留「不指定」（问题6）
- `TaskCreate.vue` 备用模型下拉：`enabled && != 首要 && 同协议` 的有效模型可选，且置顶「不指定」（默认）。后端 `session._resolve_backup_provider` 校验同协议。

### 7. 新建任务「监督者」增加模型选择（问题7）
- `TaskCreate.vue` 监督者开启后显示模型下拉，数据源与首要模型一致，默认「跟随全局默认 AI」。后端 `_observer._resolve_observer_provider` 支持 observer_provider_id → observer scene → pentest_exec 回退。

## 2026-09-10 更新

### 新增功能

#### 1. 报告编辑功能
- **任务级报告**：汇总整个任务的渗透结果，包含所有会话的漏洞统计和整体评估
- **会话级报告**：单个资产的详细渗透报告，包含测试过程和发现
- **Markdown 编辑**：支持 Markdown 格式编辑和实时预览
- **AI 生成 + 手动编辑**：AI 自动生成初稿，用户可手动补充优化

**新增文件**：
- 后端：`sentinel_platform/modules/ai_pentest/report.py`
- 后端 API：`sentinel_platform/router/endpoints/ai_pentest.py`（新增报告端点）
- 前端 API：`frontend/src/api/report.ts`
- 前端页面：`frontend/src/pages/report/ReportEdit.vue`

**API 端点**：
- `POST /api/ai_config/report/task/<task_id>` - 生成任务级报告
- `POST /api/ai_config/report/session/<session_id>` - 生成会话级报告
- `GET /api/ai_config/report/<report_id>` - 获取报告详情
- `PUT /api/ai_config/report/<report_id>` - 更新报告内容
- `DELETE /api/ai_config/report/<report_id>` - 删除报告
- `GET /api/ai_config/report` - 列出报告

#### 2. 蜜罐检测功能
- **集成 honeydet**：开源蜜罐检测工具，支持多协议（SSH、HTTP、其他服务）
- **自研补充检测**：Web 特征分析（404页面、静态资源、响应时间）
- **自动检测**：AI 渗透会话派发前自动检测目标是否为蜜罐
- **AI 预警**：检测到蜜罐时提前预警 AI，由 AI 自行判断是否继续
- **蜜罐标签**：前端会话列表显示 🍯 蜜罐标签和置信度

**检测能力**：
- SSH 蜜罐（Cowrie、Kippo、Heralding 等）
- Web 蜜罐（HTTP/HTTPS）
- 其他网络服务蜜罐

**工作流程**：
```
策略配置（启用蜜罐检测，默认启用）
    ↓
派发 AI 渗透会话
    ↓
自动检测蜜罐（honeydet + 自研）
    ↓
保存检测结果到会话文档
    ↓
AI 收到预警，根据置信度判断：
    - 高置信度(≥80%): 立即结束会话
    - 中置信度(50-80%): 非侵入式探测验证
    - 低置信度(<50%): 谨慎继续
    ↓
前端显示🍯蜜罐标签
```

**新增文件**：
- 后端：`sentinel_platform/modules/honeypot_detector/__init__.py`
- Docker：`docker/honeydet-install.dockerfile`

**修改文件**：
- `sentinel_platform/modules/ai_pentest/session.py` - 会话创建集成蜜罐检测
- `sentinel_platform/modules/ai_pentest/_engine.py` - AI 系统提示词集成预警
- `frontend/src/api/policy.ts` - 策略配置添加蜜罐检测字段
- `frontend/src/pages/policy/PolicyEdit.vue` - 策略编辑页面添加 UI
- `frontend/src/pages/pentest/PentestList.vue` - 会话列表显示蜜罐标签

### 功能改进

#### 1. AI 工具资源管理
- **增强系统提示词**：明确指示 AI 收到 `resource_busy` 后要坚持 3-5 轮重试
- **防止攻击面丢失**：AI 不会因为资源繁忙而放弃目标
- **灵活切换**：本轮改用其他工具，下轮优先重试被拒绝的工具

**修改文件**：
- `sentinel_platform/modules/ai_pentest/_system_prompts.py`

### 功能确认（无需修改）

以下功能已在之前版本中完整实现，本次确认无需修改：

#### 1. 广域目标收集源勾选
- 策略配置中可勾选收集源（FOFA、鹰图等）
- 未配置的源自动变灰
- 默认全选已配置的源

#### 2. 首要模型和备用模型
- 策略配置中支持选择"首要模型"和"备用模型（可选）"
- 备用模型在首要模型自愈失败后自动切换
- 备用模型必须与首要模型同协议

#### 3. 激活到期提示
- 剩余天数 ≤ 5 时弹窗提示
- 24 小时一次，防止重复打扰
- localStorage 记录上次弹窗时间

### 依赖更新

#### 后端
- 新增：honeydet 二进制文件（蜜罐检测）

#### 前端
- 新增：marked 库（Markdown 渲染）

### 安装说明

#### 安装 honeydet
```bash
# Docker 环境（在 Dockerfile 中添加）
RUN cd /tmp && \
    wget https://github.com/referefref/honeydet/releases/latest/download/honeydet-linux-amd64 -O honeydet && \
    chmod +x honeydet && \
    mv honeydet /usr/local/bin/honeydet

ENV HONEYDET_PATH=/usr/local/bin/honeydet

# 手动安装
wget https://github.com/referefref/honeydet/releases/latest/download/honeydet-linux-amd64 -O honeydet
chmod +x honeydet
sudo mv honeydet /usr/local/bin/honeydet
honeydet -version
```

#### 安装前端依赖
```bash
cd frontend
npm install marked
```

### 数据库变更

#### 新增集合
- `pentest_report` - 报告存储集合

#### 会话文档新增字段
```python
{
    "honeypot_detection": {
        "enabled": bool,
        "is_honeypot": bool,
        "confidence": float,
        "detected_type": str,
        "indicators": [...],
        "recommendation": str,
        "detection_time": float
    },
    "tags": ["蜜罐"]  # 如果检测到蜜罐
}
```

### 配置变更

#### 策略配置新增字段
```typescript
{
    honeypot_detection: boolean  // 默认 true
}
```

### 相关文档

- [修复完成报告.md](./修复完成报告.md) - 本次修复的5个问题详细说明
- [蜜罐检测功能集成完成报告.md](./蜜罐检测功能集成完成报告.md) - 蜜罐检测功能完整文档
- [双蜜罐系统设计方案.md](./双蜜罐系统设计方案.md) - 双蜜罐系统完整设计方案
- [完整问题排查报告.md](./完整问题排查报告.md) - 5个问题的排查过程

### 测试建议

#### 报告编辑功能测试
1. 创建渗透任务，生成任务级报告
2. 编辑报告内容，保存后刷新验证
3. 创建渗透会话，生成会话级报告
4. 测试 Markdown 预览功能
5. 测试删除报告功能

#### 蜜罐检测功能测试
1. 创建启用蜜罐检测的策略
2. 对已知蜜罐目标下发任务
3. 验证会话创建时蜜罐检测被调用
4. 验证检测结果保存到会话文档
5. 验证前端显示蜜罐标签
6. 验证 AI 收到预警后的处理逻辑

#### 资源管理测试
1. 启动两个并发渗透会话
2. 两个会话同时调用 browser_navigate
3. 观察被拒绝的会话是否在下一轮重试
4. 确认最终报告中不包含"资源繁忙"字样

---

## 历史版本

### 2026-09-09
- 免责声明弹窗优化：修复偶发重复弹窗问题

### 2026-09-08
- AI 渗透首要模型和备用模型功能实现
- 代理出口重构（4模式：direct/global/rule/smart）

### 2026-09-07
- 广域目标收集源勾选功能实现
- API 密钥中心与策略配置联动

### 2026-09-06
- 激活到期提示功能实现（24小时节流）
- 工具资源管理（L3 令牌层）实现

---

## 下一步计划

### 短期（1-2周）
1. 蜜罐检测威胁情报集成（Shodan HoneyScore、GreyNoise）
2. 检测结果缓存（24小时内不重复检测）
3. 报告模板系统（预定义报告格式）

### 中期（1-2月）
1. 更多蜜罐类型检测（RDP、FTP、数据库蜜罐）
2. 检测规则优化（根据实际检测结果调整置信度）
3. 报告导出功能（PDF、Word、HTML）

### 长期（3-6月）
1. 机器学习蜜罐检测（基于历史数据训练模型）
2. 蜜罐指纹库维护（已知蜜罐 IP/域名库）
3. 防御型蜜罐实现（系统自身作为蜜罐）
