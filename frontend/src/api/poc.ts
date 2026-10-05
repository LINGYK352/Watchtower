import { request, toQueryString, getToken } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

/** PoC 插件信息 */
export const pocApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/poc/${toQueryString(query)}`),
  /** 从源同步 PoC 到数据库（写操作，POST，需 vuln:write；新平台 RESTful + RBAC 按方法拦） */
  sync: () => request<{ plugin_cnt: number }>(`/api/poc/sync/`, { method: 'POST', body: '{}' }),
  /** 清空所有 PoC（写操作，POST，需 vuln:write） */
  clear: () => request<{ delete_cnt: number }>(`/api/poc/delete/`, { method: 'POST', body: '{}' }),
  /** 导入单个 .py POC（multipart，需 vuln:write） */
  importFile: async (file: File, overwrite = false) => {
    const form = new FormData()
    form.append('file', file)
    if (overwrite) form.append('overwrite', '1')
    const headers: Record<string, string> = {}
    const t = getToken(); if (t) headers['Token'] = t
    const resp = await fetch(`/api/poc/import/`, { method: 'POST', headers, body: form })
    return resp.json().catch(() => ({}))
  },
  /** 批量导入 zip（multipart，需 vuln:write） */
  batchImport: async (file: File, overwrite = false) => {
    const form = new FormData()
    form.append('file', file)
    if (overwrite) form.append('overwrite', '1')
    const headers: Record<string, string> = {}
    const t = getToken(); if (t) headers['Token'] = t
    const resp = await fetch(`/api/poc/batch_import/`, { method: 'POST', headers, body: form })
    return resp.json().catch(() => ({}))
  },
  /** 模板下载 URL（.py 骨架） */
  templateUrl: () => `/api/poc/template/`,
  /** 删除导入的 POC（按 _id，需 vuln:write） */
  remove: (ids: string[]) => request<{ deleted: number }>(`/api/poc/remove/`, { method: 'POST', body: JSON.stringify({ _id: ids }) })
}

/** 漏洞结果（PoC 命中） */
export const vulnApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/vuln/${toQueryString(query)}`),
  delete: (ids: string[]) =>
    request<RowRecord>(`/api/vuln/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) })
}

/** nuclei 扫描结果 */
export const nucleiResultApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/nuclei_result/${toQueryString(query)}`),
  delete: (ids: string[]) =>
    request<RowRecord>(`/api/nuclei_result/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) })
}

/** python 服务识别结果 */
export const npocServiceApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/npoc_service/${toQueryString(query)}`)
}
