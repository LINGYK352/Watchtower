import { request, toQueryString } from './request'

export interface ExtParam { name: string; desc: string; required: boolean }
export interface ExtensionItem {
  _id?: string; extension_id: string; name: string; version: string; source: 'local' | 'store'
  ext_type?: 'ai' | 'feature' | 'both'   // ai=AI工具扩展; feature=内核工具扩展(不进AI工具表); both=公共扩展(两边都注册,AI侧也可调用)
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
  origin?: 'self' | 'third_party'   // self=平台自研; third_party=封装 external/ 外部工具
  params?: { name: string; desc: string; required: boolean }[]
}

const base = '/api/pentest/extensions'
export const aiExtensionApi = {
  // ext_type: '' 全部 / 'ai' AI扩展 / 'feature' 内核扩展
  list: (params: { source?: string; ext_type?: string } = {}) =>
    request<{ items: ExtensionItem[]; total: number }>(`${base}${toQueryString(params)}`),
  builtin: () => request<{ tools: BuiltinTool[]; total: number; implemented: number }>(`${base}/builtin`),
  // 内核内置工具（内核扫描用，全局禁用于 AI）——「内核工具扩展」子页只读展示
  builtinKernel: () => request<{ tools: BuiltinTool[]; total: number; implemented: number }>(`${base}/builtin_kernel`),
  categories: () => request<{ items: string[] }>(`${base}/categories`),
  upload: (file: File) => {
    const form = new FormData(); form.append('file', file)
    return request<{ ok: boolean; extension: ExtensionItem }>(`${base}/upload`, { method: 'POST', body: form })
  },
  enable: (id: string) => request(`${base}/${encodeURIComponent(id)}/enable`, { method: 'POST' }),
  disable: (id: string) => request(`${base}/${encodeURIComponent(id)}/disable`, { method: 'POST' }),
  check: (id: string) => request(`${base}/${encodeURIComponent(id)}/check`, { method: 'POST' }),
  remove: (id: string) => request(`${base}/${encodeURIComponent(id)}/delete`, { method: 'POST' }),
  store: () => request<{ items: ExtensionItem[]; total: number; error?: string; auth_state?: 'ok' | 'unauthorized' | 'no_key' }>(`${base}/store`),
  install: (item: ExtensionItem & { sha256?: string }) => request(`${base}/store/install`, {
    method: 'POST', body: JSON.stringify({ extension_id: item.extension_id, version: item.version, sha256: item.sha256 || '' })
  }),
  logs: (params: Record<string, unknown> = {}) => request<{ items: Record<string, unknown>[]; total: number }>(`${base}/logs${toQueryString(params)}`),
}
