import { request, toQueryString } from './request'
import { getToken } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

const base = '/api/fingerprint'

export const fingerprintApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/${toQueryString(query)}`),
  add: (payload: { name: string; human_rule: string }) =>
    request<RowRecord>(`${base}/`, { method: 'POST', body: JSON.stringify(payload) }),
  delete: (ids: string[]) =>
    request<RowRecord>(`${base}/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
  exportUrl: () => `${base}/export/`,
  /** 上传 YAML 指纹文件（multipart） */
  upload: async (file: File) => {
    const form = new FormData()
    form.append('file', file)
    const headers = new Headers()
    const token = getToken()
    if (token) headers.set('Token', token)
    const resp = await fetch(`${base}/upload/`, { method: 'POST', headers, body: form })
    const data = await resp.json().catch(() => ({}))
    if (!resp.ok || data.code !== 200) throw new Error(data.message || `上传失败：${resp.status}`)
    return data.data as { error_cnt: number; repeat_cnt: number; success_cnt: number }
  }
}
