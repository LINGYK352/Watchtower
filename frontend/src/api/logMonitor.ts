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
  request_preview_b64?:string
  response_preview_b64?:string
  truncation_reason?:string
  capture_note?:string
  source?:string
  status_code?:number
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
  retention_days?:number
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
  guardList: (q: { session_id?:string; allow?: string; mode?: string; level?: string; page?: number; size?: number } = {}) => {
    const p = new URLSearchParams()
    p.set('metadata_only','1')
    Object.entries(q).forEach(([k, v]) => { if (v !== undefined && v !== '') p.set(k, String(v)) })
    return request<{ items: GuardLogItem[]; total: number }>(`${base}/guard/?${p.toString()}`)
  },
  trafficInteraction: (id:string)=>request<GuardLogItem>(`${base}/guard/${encodeURIComponent(id)}/`),
  setGuardSize: (size_mb: number, retention_days = 30) =>
    request<{ size_mb: number }>(`${base}/guard/size/`, { method: 'POST', body: JSON.stringify({ size_mb,retention_days }) })
}
