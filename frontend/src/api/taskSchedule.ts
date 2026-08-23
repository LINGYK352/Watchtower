import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

const base = '/api/task_schedule'

/** 计划任务（定时/周期下发扫描） */
export const taskScheduleApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/${toQueryString(query)}`),
  add: (payload: {
    name: string
    target: string
    schedule_type: 'future_scan' | 'recurrent_scan'
    policy_id: string
    task_tag: 'task' | 'risk_cruising'
    cron?: string
    start_date?: string
  }) => request<RowRecord>(`${base}/`, { method: 'POST', body: JSON.stringify(payload) }),
  delete: (ids: string[]) =>
    request<RowRecord>(`${base}/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  stop: (ids: string[]) =>
    request<RowRecord>(`${base}/stop/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  recover: (ids: string[]) =>
    request<RowRecord>(`${base}/recover/`, { method: 'POST', body: JSON.stringify({ _id: ids }) })
}
