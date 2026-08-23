import { request, toQueryString } from './request'

// 关于系统 / 更新检测 API（对接 router/endpoints/about.py，公开端点）
// 后端统一信封 {code,message,data}，request() 已拆出 data。

export interface VersionResult {
  version: string
}

export interface UpdateCheckResult {
  server_version: string
  client_version: string
  has_update: boolean
  message: string
  latest_version?: string
  remote_ok?: boolean
  source?: string
  error_type?: string  // 'unauthorized' | 'network'
}

/** 服务端当前版本 */
export function getServerVersion() {
  return request<VersionResult>('/api/about/version')
}

/** 更新检测：携带前端构建版本，比对服务端版本 */
export function checkUpdate(client: string) {
  return request<UpdateCheckResult>(`/api/about/check${toQueryString({ client })}`)
}

/** 触发热更新（后台执行） */
export function applyUpdate() {
  return request('/api/about/apply', { method: 'POST' })
}

/** 获取热更新进度 */
export function getProgress() {
  return request<any>('/api/about/progress')
}

/** 从分发服务器获取更新日志 */
export function getChangelog() {
  return request<any[]>('/api/about/changelog')
}

export interface VersionItem {
  version: string
  published_at: string
  files: number
  prev: string
}

export interface VersionsResult {
  latest: string
  versions: VersionItem[]
  unsupported?: boolean   // 分发源尚不支持版本仓端点（确定性）
  fetch_failed?: boolean  // 转发层重试仍失败（偶发超时，非真无历史）
}

/** 历史版本列表（版本仓，供回退选择） */
export function getVersions() {
  return request<VersionsResult>('/api/about/versions')
}

export interface ChangesResult {
  from: string
  to: string
  added: string[]
  changed: string[]
  removed: string[]
  total: number
  published_at?: string
}

/** 某版相对上版的更新表（改了哪些文件） */
export function getVersionChanges(version: string) {
  return request<ChangesResult>(`/api/about/changes${toQueryString({ version })}`)
}

/** 回退到指定历史版本（高危，需 system:update 权限） */
export function rollbackTo(version: string) {
  return request<{ started: boolean; target_version?: string; msg?: string }>(
    '/api/about/rollback', { method: 'POST', body: JSON.stringify({ version }) })
}

/** 上传报错到云端分发系统（选中日志 + 描述） */
export function reportError(payload: { description: string; log_content: string; version?: string; meta?: string }) {
  return request<{ ok?: boolean; id?: number }>(
    '/api/about/report_error', { method: 'POST', body: JSON.stringify(payload) })
}

export interface Announcement {
  id: number
  ts: string
  title: string
  content: string
  level: string        // info | warning | danger（分发系统 _ANN_LEVELS）
  popup: boolean       // true = 强制弹窗；false = 仅通告栏显示
  enabled?: boolean
  starts_at?: string
  ends_at?: string
}

/** 生效中的通告（转发分发系统，失败降级空列表）。供通告栏 / 弹窗消费。 */
export function getAnnouncements() {
  return request<{ announcements: Announcement[] }>('/api/about/announcements')
}
