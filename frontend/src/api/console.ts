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

export const consoleApi = {
  info: () => request<ConsoleInfo>(`/api/console/info`),
  resourceHistory: (days: number) => request<ResourceHistoryResult>(`/api/console/resource_history?days=${days}`),
}
