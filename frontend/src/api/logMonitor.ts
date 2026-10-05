import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

const base = '/api/log_monitor'

export interface LogStat {
  ERROR: number
  WARNING: number
  CRITICAL: number
  total: number
}

export interface RetentionItem {
  label: string
  coll: string
  days: number
  default_days: number
}

export type LogRetention = Record<string, RetentionItem>

export interface GuardLogItem {
  _id: string
  method: string
  url: string
  mode: string
  allow: boolean
  level: string
  reason: string
  site?: string
  session_id?: string
  save_date: string
}
export interface GuardLogStat {
  total: number
  blocked: number
  allowed: number
  size_mb: number
  default_size_mb: number
}

export const logMonitorApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/${toQueryString(query)}`),
  delete: (ids: string[]) =>
    request<RowRecord>(`${base}/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  clear: () => request<{ delete_cnt: number }>(`${base}/clear/`),
  stat: () => request<LogStat>(`${base}/stat/`),
  getRetention: () => request<LogRetention>(`${base}/retention/`),
  setRetention: (updates: Record<string, number>) =>
    request<LogRetention>(`${base}/retention/`, { method: 'POST', body: JSON.stringify(updates) }),
  guardStat: () => request<GuardLogStat>(`${base}/guard/stat/`),
  guardList: (q: { allow?: string; mode?: string; level?: string; page?: number; size?: number } = {}) => {
    const p = new URLSearchParams()
    Object.entries(q).forEach(([k, v]) => { if (v !== undefined && v !== '') p.set(k, String(v)) })
    return request<{ items: GuardLogItem[]; total: number }>(`${base}/guard/?${p.toString()}`)
  },
  setGuardSize: (size_mb: number) =>
    request<{ size_mb: number }>(`${base}/guard/size/`, { method: 'POST', body: JSON.stringify({ size_mb }) })
}
