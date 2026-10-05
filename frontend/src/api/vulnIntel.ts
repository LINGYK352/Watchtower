import { request } from './request'

export interface VulnIntelItem {
  _id: string
  cve_id: string
  title: string
  severity: string
  in_kev: boolean
  executable: boolean
  exec_kind: string
  exec_ref: string
  products: string[]
  poc_urls: string[]
  sources: string[]
  source_labels: string[]
  published_date: string
  fetched_date: string
}

export interface FeedSource {
  name: string
  label: string
  kind: string
  url: string
  health: 'ok' | 'error' | 'empty' | 'unknown'
  fetched: number
  new: number
  error: string
  last_fetch: string
}

export interface FeedStatus {
  last_fetch: string
  interval_seconds: number
  interval_hours: number
  sources: FeedSource[]
}

export interface VulnIntelStat {
  total: number
  in_kev: number
  executable: number
  by_severity: Record<string, number>
  by_source: Record<string, number>
}

export interface VulnQuery {
  severity?: string
  source?: string
  in_kev?: string
  executable?: string
  keyword?: string
  sort?: string
  page?: number
  size?: number
}

const base = '/api/intel/vuln_feed'

export const vulnIntelApi = {
  stat: () => request<VulnIntelStat>(`${base}/stat/`),
  status: () => request<FeedStatus>(`${base}/status/`),
  list: (q: VulnQuery = {}) => {
    const p = new URLSearchParams()
    Object.entries(q).forEach(([k, v]) => { if (v !== undefined && v !== '') p.set(k, String(v)) })
    return request<{ items: VulnIntelItem[]; total: number }>(`${base}/list/?${p.toString()}`)
  },
  query: (component: string) =>
    request<{ component: string; count: number; vulns: VulnIntelItem[] }>(`${base}/query/?component=${encodeURIComponent(component)}`),
  run: (sources?: string[]) =>
    request<Record<string, unknown>>(`${base}/run/`, { method: 'POST', body: JSON.stringify(sources ? { sources } : {}) }),
  setInterval: (seconds: number) =>
    request<{ interval_seconds: number }>(`${base}/interval/`, { method: 'POST', body: JSON.stringify({ seconds }) })
}

export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'red', high: 'volcano', medium: 'orange', low: 'gold', info: 'default', unknown: 'default'
}
