"""对外 Mongo 集合名 —— 平台与 sentinel_engine、既有数据共享的数据契约事实源（冻结）。

集合字段结构见 docs/CONTRACTS.md。平台各模块读写集合时用这里的常量，不硬编码字符串。
侦察类集合（domain/ip/site/url/cert/service/vuln/nuclei_result/fileleak/wih/npoc_service/
stat_finger/cip）由引擎产出，平台消费；平台自有集合（intel_*/ai_*/pentest_*/proxy_*/vuln_intel 等）。
"""


class Collections:
    # —— 引擎产出、平台消费（侦察结果）——
    DOMAIN = "domain"
    IP = "ip"
    SITE = "site"
    URL = "url"
    CERT = "cert"
    SERVICE = "service"
    VULN = "vuln"
    NUCLEI_RESULT = "nuclei_result"
    FILELEAK = "fileleak"
    WIH = "wih"
    NPOC_SERVICE = "npoc_service"
    STAT_FINGER = "stat_finger"
    CIP = "cip"
    TASK = "task"
    POC = "poc"  # NPoC 插件定义（app_name→可执行验证手段），vuln_intel 的 arl_npoc 抓取器读

    # —— 平台自有 ——
    # 情报中心
    INTEL_ASSET = "intel_asset"
    INTEL_SYSTEM = "intel_system"
    INTEL_CODE = "intel_code"
    INTEL_REPORT = "intel_report"          # AI 情报报告（会话收尾自动产，供 AI「往期借鉴」，勿当人看成品）
    PENTEST_REPORT = "pentest_report"      # 人看成品报告（报告编辑处人工生成/编辑，与 intel_report 物理隔离）
    REPORT_TEMPLATE = "report_template"    # 报告模板学习：原 docx 注入占位符后的可复用模板 + AI 学出的 schema
    INTEL_FINDING = "intel_finding"
    INTEL_ATTACK_CHAIN = "intel_attack_chain"
    INTEL_EXPLOIT_CLUE = "intel_exploit_clue"
    INTEL_PLAYBOOK = "intel_playbook"          # 指纹分层打法库（核心链路 §6.2，两级目录+有效分）
    UNIT_INTEL_PROFILE = "unit_intel_profile"  # 同单位情报画像（核心链路 §6.8，按 unit/IP 聚合）
    # AI 渗透
    AI_CONFIG = "ai_config"
    AI_PROVIDER = "ai_provider"
    AI_PROMPT = "ai_prompt"
    AI_USAGE = "ai_usage"
    AI_EXTENSION = "ai_extension"
    AI_EXTENSION_LOG = "ai_extension_log"
    PENTEST_SESSION = "intel_pentest_session"
    PENTEST_WHITELIST = "pentest_whitelist"
    TASK_DEDUP = "task_dedup"              # 任务级派发去重表（每任务独立，(source_task_id,dedup_key) 唯一，
                                          # 持久增量去重替代临时 seen；跨任务隔离防误去重，删任务连带清）
    FINDING_IDENTITY = "finding_identity"  # vuln_center owns: 漏洞点首次观察锚，_id=point_key 原子唯一
    # 蜜罐防御
    ATTACK_ALERT = "attack_alert"          # 攻击告警（防御型蜜罐检测到的攻击记录，v1.21.160 新增）
    ATTACKER_PROFILE = "attacker_profile"  # 攻击者画像（按 IP 聚合的攻击者信息，v1.21.160 新增）
    ATTACK_BANLIST = "attack_alert_banlist"      # IP 封禁名单（auto/manual，带 expire_at）
    ATTACK_WHITELIST = "attack_alert_whitelist"  # IP 白名单（用户维护，白名单内不检测/不封禁）
    # 代理
    PROXY_CONFIG = "proxy_config"          # 代理中心配置(mihomo 端口/模式/健康检测阈值等)——2026-07-05 追加(system/proxy 迁移补齐)
    PROXY_PROFILES = "proxy_profiles"      # 订阅/上传的机场配置档——2026-07-05 追加
    PROXY_POOL = "proxy_pool"
    PROXY_POOL_CONFIG = "proxy_pool_config"
    PROXY_TRAFFIC = "proxy_traffic"
    PROXY_CUSTOM = "proxy_custom"          # 自定义代理(手填 URL,类 Proxifier)——2026-08 代理4模式重构追加
    PROXY_RULE = "proxy_rule"              # 规则代理(命名+绑源,供策略选)——2026-08 代理4模式重构追加
    # 漏洞情报
    VULN_INTEL = "vuln_intel"
    VULN_FEED_META = "vuln_feed_meta"  # 情报源拉取元数据（上次拉取时间/各源结果/间隔）
    # 资产管理
    ASSET_SCOPE = "asset_scope"
    ASSET_DOMAIN = "asset_domain"
    ASSET_IP = "asset_ip"
    ASSET_SITE = "asset_site"
    ASSET_WIH = "asset_wih"
    # GitHub 监控
    GITHUB_TASK = "github_task"
    GITHUB_SCHEDULER = "github_scheduler"
    GITHUB_RESULT = "github_result"
    GITHUB_MONITOR_RESULT = "github_monitor_result"
    # 系统/审计/集成
    USER = "user"
    ROLE = "role"
    ACCESS_LOG = "access_log"
    LOG_MONITOR = "log_monitor"
    RESOURCE_HISTORY = "resource_history"   # 资源采样趋势(写=system/log_monitor;读=workspace/dashboard)
    GUARD_LOG = "guard_log"
    GUARD_LOG_META = "guard_log_meta"       # 拦截日志 capped 容量配置单文档(owner system/guard_log)
    LOG_RETENTION = "log_retention"
    API_KEYS = "api_keys"
    SYSTEM_TAGS = "system_tags"
    POLICY = "policy"
    SCHEDULER = "scheduler"
    ICP_CACHE = "icp_cache"
    BROKER_HEALTH = "broker_health"         # celery broker 降级状态单文档(name=default)：mode=celery/thread + 失败计数 + 切换时间
    # 探针管理
    PROBE_CONFIG = "probe_config"
    AGENT_CONFIG = "agent_config"
    # 小程序渗透（解包记录：wxid/name/接口/密钥/解包时间/结果摘要）
    MINIAPP = "miniapp"
    # APP 动态渗透（移动 DAST，见 云端/docs/App渗透子系统设计.md）
    APP_DEVICE = "app_device"      # 光纤/设备注册（device_id/在线心跳/握手态/能力清单，共用平台 platform_key）
    APP_CMD = "app_cmd"            # 光纤命令队列（含结果内联：op/args/status pending→dispatched→done/result）
    APP_TRAFFIC = "app_traffic"    # App 抓包 flow（P2 抓包层用，capped/TTL 防膨胀）
    # 工具资源管理（L3 令牌层：浏览器等有限资源的会话级占用）
    TOOL_RESOURCES = "tool_resources"
