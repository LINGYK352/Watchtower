import { request } from './request'

export interface AccessLogItem {
  _id: string
  method: string
  path: string
  status: number
  username: string
  ip: string
  is_write: boolean
  elapsed_ms: number
  save_date: string
}

export interface AccessLogStat {
  total: number
  writes: number
  today: number
  errors: number
}

export interface AccessLogQuery {
  is_write?: string
  username?: string
  path?: string
  status?: string
  page?: number
  size?: number
}

const base = '/api/access_log'

export interface RetentionItem {
  label: string
  coll: string
  days: number
  default_days: number
}
export type LogRetention = Record<string, RetentionItem>

export const accessLogApi = {
  stat: () => request<AccessLogStat>(`${base}/stat/`),
  list: (q: AccessLogQuery = {}) => {
    const p = new URLSearchParams()
    Object.entries(q).forEach(([k, v]) => { if (v !== undefined && v !== '') p.set(k, String(v)) })
    return request<{ items: AccessLogItem[]; total: number }>(`${base}/?${p.toString()}`)
  },
  getRetention: () => request<LogRetention>(`${base}/retention/`),
  setRetention: (updates: Record<string, number>) =>
    request<LogRetention>(`${base}/retention/`, { method: 'POST', body: JSON.stringify(updates) })
}
