import { request } from './request'

export interface ApiKeyItem {
  id: string
  label: string
  group: string
  site: string
  fields: string[]
  enabled: boolean
  select?: Record<string, { value: string; label: string }[]>  // 下拉字段选项(如 min_severity)
  // 动态字段:key/token/email 等,密钥字段为掩码值;<field>_set 表示是否已配置
  [k: string]: unknown
}

export interface ApiKeysResult {
  items: ApiKeyItem[]
  updated_at: string
}

const base = '/api/api_keys'

export const apiKeysApi = {
  options: () => request<Pick<ApiKeysResult, 'items'>>(`${base}/options`),
  list: () => request<ApiKeysResult>(`${base}/`),
  save: (data: Record<string, Record<string, unknown>>) =>
    request<ApiKeysResult>(`${base}/`, { method: 'POST', body: JSON.stringify(data) })
}
