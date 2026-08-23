import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

/** GitHub 一次性任务 */
export const githubTaskApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/github_task/${toQueryString(query)}`),
  add: (payload: { name: string; keyword: string }) =>
    request<RowRecord>(`/api/github_task/`, { method: 'POST', body: JSON.stringify(payload) }),
  delete: (ids: string[]) =>
    request<RowRecord>(`/api/github_task/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  stop: (ids: string[]) =>
    request<RowRecord>(`/api/github_task/stop/`, { method: 'POST', body: JSON.stringify({ _id: ids }) })
}

/** GitHub 任务结果 */
export const githubResultApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/github_result/${toQueryString(query)}`)
}

/** GitHub 监控周期任务 */
export const githubSchedulerApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/github_scheduler/${toQueryString(query)}`),
  add: (payload: { name: string; keyword: string; cron: string }) =>
    request<RowRecord>(`/api/github_scheduler/`, { method: 'POST', body: JSON.stringify(payload) }),
  update: (payload: { _id: string; name?: string; keyword?: string; cron?: string }) =>
    request<RowRecord>(`/api/github_scheduler/update/`, { method: 'POST', body: JSON.stringify(payload) }),
  delete: (ids: string[]) =>
    request<RowRecord>(`/api/github_scheduler/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  stop: (ids: string[]) =>
    request<RowRecord>(`/api/github_scheduler/stop/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  recover: (ids: string[]) =>
    request<RowRecord>(`/api/github_scheduler/recover/`, { method: 'POST', body: JSON.stringify({ _id: ids }) })
}

/** GitHub 监控结果 */
export const githubMonitorResultApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/github_monitor_result/${toQueryString(query)}`)
}
