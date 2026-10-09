import { request } from './request'

export interface ConsoleInfo {
  device_info?: {
    cpu_percent?: number
    memory_percent?: number
    uptime_seconds?: number
    disk_usage?: Record<string, unknown>
    [key: string]: unknown
  }
  [key: string]: unknown
}

export interface ResourcePoint {
  ts: number
  cpu: number
  memory: number
  disk: number
}

export interface ResourceHistoryResult {
  days: number
  points: ResourcePoint[]
  count: number
}

export interface ResourceAlertDim {
  key: string      // memory | cpu | disk
  label: string    // 内存 | CPU | 磁盘
  value: number    // 当前使用率 %
  level: string    // tight | critical
  unit?: '%' | 'GiB'
  path?: string
}

export interface ResourceAlertResult {
  level: string                 // 综合水位 relaxed|normal|tight|critical
  mem: number | null
  cpu: number | null
  disk: number | null
  dims: ResourceAlertDim[]      // 超标维度（tight/critical）
  ts: number                    // 判定时间戳（前端去重用）
}

export const consoleApi = {
  info: () => request<ConsoleInfo>(`/api/console/info`),
  resourceHistory: (days: number) => request<ResourceHistoryResult>(`/api/console/resource_history?days=${days}`),
  resourceAlert: () => request<ResourceAlertResult>(`/api/console/resource_alert`),
}
