import { request } from './request'

// 平台元信息 API（对接核心路由 router/endpoints/meta.py）
// 后端统一信封 {code,message,data}，request() 已拆出 data，此处类型即 data 载荷。

export interface HealthResult {
  status: string
}

export interface VersionResult {
  name: string
  api: string
  tz_name?: string        // 服务器 OS 时区名（IANA 或缩写，如 Etc/UTC、UTC、CST）
  tz_abbr?: string        // 时区缩写
  tz_label?: string       // 人类可读中文地理名（协调世界时/美国东部时间/北京时间…；映射不到为空）
  utc_offset_min?: number // 与 UTC 的分钟偏移（东区为正，如 UTC+8=480）
}

export interface ModulesResult {
  modules: Record<string, boolean>
  ready: number
  total: number
}

export interface ActivationResult {
  activated: boolean
  expired?: boolean
  revoked?: boolean
  expires_at?: string
  activated_at?: string
  source_url: string
  remaining_days?: number
  tz_label?: string       // 激活到期/剩余天数所用的服务器时区中文名（协调世界时/北京时间…）
  utc_offset_min?: number // UTC 偏移分钟
}

/** 健康检查（公开，探活） */
export function getHealth() {
  return request<HealthResult>('/api/meta/health')
}

/** 平台版本 */
export function getVersion() {
  return request<VersionResult>('/api/meta/version')
}

/** 各模块能力就绪度（经 registry 探） */
export function getModulesStatus() {
  return request<ModulesResult>('/api/meta/modules')
}

/** 查询系统激活状态 */
export function checkActivation() {
  return request<ActivationResult>('/api/meta/activation')
}

/** 提交激活 Key */
export function submitActivation(key: string) {
  return request('/api/meta/activation', { method: 'POST', body: JSON.stringify({ key }) })
}

export interface ActivationInfoResult {
  activated: boolean
  expired: boolean
  revoked: boolean
  key_masked: string
  activated_at: string
  expires_at: string
  remaining_days: number
  auth_days: number
  username: string
}

/** 查询激活详情（key 脱敏） */
export function getActivationInfo() {
  return request<ActivationInfoResult>('/api/meta/activation-info')
}

export interface SetupStatusResult {
  activated: boolean
  expired: boolean
  ai_configured: boolean
  keys_configured: boolean
  fofa_configured: boolean
}

/** 首次配置向导状态 */
export function getSetupStatus() {
  return request<SetupStatusResult>('/api/meta/setup-status')
}

export interface DisclaimerStatus {
  accepted: boolean
  accepted_version: string
  accepted_at: string
}

/** 免责声明签署状态（服务端持久化，重启/换浏览器保留，仅重装需重签） */
export function getDisclaimerStatus() {
  return request<DisclaimerStatus>('/api/meta/disclaimer')
}

/** 记录同意免责声明（写服务端磁盘标记，携带条款版本） */
export function acceptDisclaimer(version: string) {
  return request<DisclaimerStatus & { persisted?: boolean }>(
    '/api/meta/disclaimer', { method: 'POST', body: JSON.stringify({ version }) })
}
