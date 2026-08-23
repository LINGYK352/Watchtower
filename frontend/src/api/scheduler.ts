import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

const base = '/api/scheduler'

/** 资产监控周期任务（域名/站点/WIH 监控） */
export const schedulerApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/${toQueryString(query)}`),
  /** 添加域名监控 */
  add: (payload: { scope_id: string; domain: string; interval?: number; name?: string; policy_id?: string }) =>
    request<RowRecord>(`${base}/add/`, { method: 'POST', body: JSON.stringify(payload) }),
  addSiteMonitor: (payload: { scope_id: string; interval?: number; name?: string }) =>
    request<RowRecord>(`${base}/add/site_monitor/`, { method: 'POST', body: JSON.stringify(payload) }),
  addWihMonitor: (payload: { scope_id: string; interval?: number; name?: string }) =>
    request<RowRecord>(`${base}/add/wih_monitor/`, { method: 'POST', body: JSON.stringify(payload) }),
  delete: (jobIds: string[]) =>
    request<RowRecord>(`${base}/delete/`, { method: 'POST', body: JSON.stringify({ job_id: jobIds }) }),
  stop: (jobId: string) =>
    request<RowRecord>(`${base}/stop/`, { method: 'POST', body: JSON.stringify({ job_id: jobId }) }),
  stopBatch: (jobIds: string[]) =>
    request<RowRecord>(`${base}/stop/batch`, { method: 'POST', body: JSON.stringify({ job_id: jobIds }) }),
  recover: (jobId: string) =>
    request<RowRecord>(`${base}/recover/`, { method: 'POST', body: JSON.stringify({ job_id: jobId }) }),
  recoverBatch: (jobIds: string[]) =>
    request<RowRecord>(`${base}/recover/batch`, { method: 'POST', body: JSON.stringify({ job_id: jobIds }) })
}
