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
    INTEL_REPORT = "intel_report"
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
