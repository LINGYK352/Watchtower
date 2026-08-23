import { request, toQueryString } from './request'

export interface ExtParam { name: string; desc: string; required: boolean }
export interface ExtensionItem {
  _id?: string; extension_id: string; name: string; version: string; source: 'local' | 'store'
  ext_type?: 'ai' | 'feature'   // ai=AI 可调用工具; feature=平台功能扩展(不进 AI 工具表)
  category: string; summary: string; description: string; ai_instruction: string
  enabled: boolean; available: boolean; unavailable_reason?: string; trust?: string
  side_effect?: 'read' | 'verify_write' | 'dangerous'; permissions?: Record<string, unknown>
  params?: ExtParam[]           // 从 parameters schema 解析(前端展示用,后端 list_enabled_tools 已带;list 未带则前端不显示)
  parameters?: { properties?: Record<string, { description?: string }>; required?: string[] }
  compatibility_report?: { system: string; arch: string; python: string; reasons: string[] }
}

export interface BuiltinTool {
  name: string; category: string; summary: string; description: string
  implemented: boolean; available: boolean; unavailable_reason?: string
  params?: { name: string; desc: string; required: boolean }[]
}

const base = '/api/pentest/extensions'
export const aiExtensionApi = {
  // ext_type: '' 全部 / 'ai' AI扩展 / 'feature' 功能扩展
  list: (params: { source?: string; ext_type?: string } = {}) =>
    request<{ items: ExtensionItem[]; total: number }>(`${base}${toQueryString(params)}`),
  builtin: () => request<{ tools: BuiltinTool[]; total: number; implemented: number }>(`${base}/builtin`),
  categories: () => request<{ items: string[] }>(`${base}/categories`),
  upload: (file: File) => {
    const form = new FormData(); form.append('file', file)
    return request<{ ok: boolean; extension: ExtensionItem }>(`${base}/upload`, { method: 'POST', body: form })
  },
  enable: (id: string) => request(`${base}/${encodeURIComponent(id)}/enable`, { method: 'POST' }),
  disable: (id: string) => request(`${base}/${encodeURIComponent(id)}/disable`, { method: 'POST' }),
  check: (id: string) => request(`${base}/${encodeURIComponent(id)}/check`, { method: 'POST' }),
  remove: (id: string) => request(`${base}/${encodeURIComponent(id)}/delete`, { method: 'POST' }),
  store: () => request<{ items: ExtensionItem[]; total: number; error?: string }>(`${base}/store`),
  install: (item: ExtensionItem & { sha256?: string }) => request(`${base}/store/install`, {
    method: 'POST', body: JSON.stringify({ extension_id: item.extension_id, version: item.version, sha256: item.sha256 || '' })
  }),
  logs: (params: Record<string, unknown> = {}) => request<{ items: Record<string, unknown>[]; total: number }>(`${base}/logs${toQueryString(params)}`),
}
