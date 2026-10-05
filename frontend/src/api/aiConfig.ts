import { request } from './request'

export interface AIConfig {
  _id?: string
  active_provider_id: string
  max_context_tokens: number
  max_concurrent_sessions: number
  timeout: number
  source_code_dir: string
  updated_at?: string
  recommend_concurrency?: number
  effective_concurrency?: number
}

export interface AIProvider {
  _id: string
  name: string
  type: string
  protocol?: 'openai' | 'claude'
  base_url: string
  api_key: string
  model: string
  reasoning_effort?: string
  enabled: boolean
  proxy_id?: string   // 问题18：入口代理=某条自定义代理_id，空/缺=直连（替代旧 use_proxy）
  save_date?: string
  update_date?: string
}

export interface AIPreset {
  key: string
  label: string
  protocol: 'openai' | 'claude'
  icon: string
  template: Record<string, unknown>
}

export interface AIPrompt {
  _id: string
  scene: string
  scene_name?: string
  name: string
  content: string
  provider_id?: string
  provider_name?: string
  provider_type?: string
  builtin?: boolean
  enabled: boolean
  save_date?: string
  update_date?: string
}

export type AIProviderOption = Pick<AIProvider, '_id' | 'name' | 'type' | 'protocol' | 'model' | 'enabled'>
interface AIOptions { items: AIProviderOption[]; config: Pick<AIConfig, 'active_provider_id' | 'max_context_tokens'>; prompts: AIPrompt[] }

const base = '/api/ai_config'

export interface UsageStat {
  overall: { calls: number; prompt: number; completion: number; total: number; fail_calls: number }
  by_provider: Array<{ name: string; calls: number; total: number }>
  by_scene: Array<{ name: string; calls: number; total: number }>
}

export const aiConfigApi = {
  providerOptions: async () => ({ items: (await request<AIOptions>(`${base}/options`)).items }),
  runtimeConfig: async () => (await request<AIOptions>(`${base}/options`)).config,
  promptOptions: async () => ({ items: (await request<AIOptions>(`${base}/options`)).prompts }),
  getConfig: () => request<AIConfig>(`${base}/config`),
  usageStat: () => request<UsageStat>(`${base}/usage_stat`),
  saveConfig: (data: Partial<AIConfig>) => request<AIConfig>(`${base}/config`, { method: 'POST', body: JSON.stringify(data) }),

  providers: () => request<{ items: AIProvider[] }>(`${base}/provider`),
  presets: () => request<{ items: AIPreset[] }>(`${base}/presets`),
  addProvider: (data: { config: string; type?: string } | Partial<AIProvider>) => request<{ _id: string }>(`${base}/provider`, { method: 'POST', body: JSON.stringify(data) }),
  updateProvider: (id: string, data: { config: string; type?: string } | Partial<AIProvider>) => request<{ _id: string }>(`${base}/provider/${id}`, { method: 'POST', body: JSON.stringify(data) }),
  deleteProvider: (id: string) => request<{ _id: string }>(`${base}/provider/${id}/delete`, { method: 'POST' }),
  testProvider: (id: string, message?: string) => request<{ ok: boolean; content: string; model: string; total_tokens: number; proxy_enabled: boolean; error: string }>(`${base}/provider/${id}/test`, { method: 'POST', body: JSON.stringify(message ? { message } : {}) }),
  // 校验未落库配置（新增模型保存前校验，通过才存档）
  testProviderConfig: (config: string, type: string) => request<{ ok: boolean; content: string; model: string; total_tokens: number; proxy_enabled: boolean; error: string }>(`${base}/provider/test`, { method: 'POST', body: JSON.stringify({ config, type }) }),

  // includeBuiltin=false：不返回内置 scene 提示词（控制台等非管理场景用，防内置提示词外泄）；
  // AI 配置页(管理员编辑)默认 true 返回全部。
  prompts: (includeBuiltin = true) => request<{ items: AIPrompt[] }>(`${base}/prompt${includeBuiltin ? '' : '?include_builtin=false'}`),
  addPrompt: (data: Partial<AIPrompt>) => request<{ _id: string }>(`${base}/prompt`, { method: 'POST', body: JSON.stringify(data) }),
  updatePrompt: (id: string, data: Partial<AIPrompt>) => request<{ _id: string }>(`${base}/prompt/${id}`, { method: 'POST', body: JSON.stringify(data) }),
  deletePrompt: (id: string) => request<{ _id: string }>(`${base}/prompt/${id}/delete`, { method: 'POST' }),
  seedPrompts: (force = false) => request<{ seeded: number; force: boolean; message: string }>(`${base}/prompt/seed`, { method: 'POST', body: JSON.stringify({ force }) })
}
