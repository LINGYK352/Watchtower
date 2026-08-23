import { request } from './request'

// 代理源：type=custom(自定义,ref_id=proxy_custom._id) / subscription(mihomo机场) / pool(公开池)
export interface ProxySource { type: 'custom' | 'subscription' | 'pool'; ref_id?: string }

export interface ProxyConfig {
  enabled: boolean
  mode: 'rule' | 'global' | 'direct'
  http_port: number
  socks_port: number
  mixed_port: number
  controller_port: number
  active_profile_id?: string
  auto_select: boolean
  test_url: string
  health_check_url?: string
  health_check_interval?: number
  health_fail_threshold?: number
  doh_endpoints?: string[] | string
  last_health_ok?: boolean
  last_health_error?: string
  last_health_check_time?: string
  // 平台代理模式（2026-08 4模式重构）
  global_mode_enabled?: boolean
  global_source?: ProxySource
  smart_source?: ProxySource
}

// 自定义代理（手填 URL，类 Proxifier）
export interface CustomProxy {
  _id: string
  name: string
  url: string
  enabled: boolean
  last_health_ok?: boolean | null
  last_check?: string
}

// 规则代理（命名 + 绑源，供策略下拉选）
export interface RuleProxy {
  _id: string
  name: string
  source: ProxySource
  enabled: boolean
  last_health_ok?: boolean | null
}

export interface ProxyStatus {
  config: ProxyConfig
  running: boolean
  pid?: number
  runtime_dir: string
  mihomo_bin: string
  config_path: string
  log_path: string
  proxy_url: string
  last_health_ok?: boolean
  last_health_error?: string
  last_health_check_time?: string
  last_exit_ip?: string
}

export interface ExitIpResult {
  proxy_ip: string
  direct_ip: string
  proxied: boolean
  error: string
}

export interface ProxyProfile {
  _id: string
  name: string
  source?: string
  proxy_count?: number
  group_count?: number
  created_at?: string
  updated_at?: string
}

export interface ProxyNodeGroup {
  all?: string[]
  now?: string
  type?: string
  name?: string
}

export interface ProxiesResponse {
  proxies: Record<string, ProxyNodeGroup>
}

export interface AutoSelectResult {
  group: string
  selected: { name: string; delay: number }
  results: Array<{ name: string; delay?: number; error?: string }>
}

export interface TrafficRow {
  key: string
  name: string
  profile_name?: string
  up: number
  down: number
  up_h: string
  down_h: string
}

export interface ProxyTraffic {
  running: boolean
  connections: number
  total_up: number
  total_down: number
  total_up_h: string
  total_down_h: string
  by_profile: TrafficRow[]
  by_node: TrafficRow[]
  error?: string
}

const base = '/api/proxy'

export const proxyApi = {
  status: () => request<ProxyStatus>(`${base}/status`),
  saveConfig: (data: Partial<ProxyConfig>) => request<ProxyConfig>(`${base}/config`, { method: 'POST', body: JSON.stringify(data) }),
  profiles: () => request<{ items: ProxyProfile[] }>(`${base}/profiles`),
  importUrl: (name: string, url: string) => request<ProxyProfile>(`${base}/profile/import_url`, { method: 'POST', body: JSON.stringify({ name, url }) }),
  upload: (name: string, content: string) => request<ProxyProfile>(`${base}/profile/upload`, { method: 'POST', body: JSON.stringify({ name, content }) }),
  activate: (id: string) => request<ProxyConfig>(`${base}/profile/${id}/activate`, { method: 'POST' }),
  core: (action: 'start' | 'stop' | 'restart') => request<{ running: boolean; pid?: number; message: string; health_ok?: boolean; health_error?: string }>(`${base}/core/${action}`, { method: 'POST' }),
  proxies: () => request<ProxiesResponse>(`${base}/proxies`),
  select: (group: string, name: string) => request<{ selected: boolean }>(`${base}/proxies/select`, { method: 'POST', body: JSON.stringify({ group, name }) }),
  autoSelect: (group = 'PROXY') => request<AutoSelectResult>(`${base}/proxies/auto_select`, { method: 'POST', body: JSON.stringify({ group }) }),
  logs: (lines = 200) => request<{ logs: string }>(`${base}/logs?lines=${lines}`),
  exitIp: () => request<ExitIpResult>(`${base}/exit_ip`),
  traffic: () => request<ProxyTraffic>(`${base}/traffic`),
  resetTraffic: (scope?: string, key?: string) => request<ProxyTraffic>(`${base}/traffic/reset`, { method: 'POST', body: JSON.stringify({ scope, key }) }),
  // 公开抓取代理池
  poolList: (page = 1, size = 50, status?: string) => request<PoolListResp>(`${base}/pool/list?page=${page}&size=${size}${status ? '&status=' + status : ''}`),
  poolStats: () => request<PoolStats>(`${base}/pool/stats`),
  poolCrawl: () => request<{ added: number; per_query: any[]; errors: any[] }>(`${base}/pool/crawl`, { method: 'POST' }),
  poolVerify: (ids?: string[]) => request<{ checked: number; alive: number; dropped: number }>(`${base}/pool/verify`, { method: 'POST', body: JSON.stringify({ ids }) }),
  poolEnable: (ids: string[], enabled: boolean) => request<{ modified: number }>(`${base}/pool/enable`, { method: 'POST', body: JSON.stringify({ ids, enabled }) }),
  poolDelete: (ids: string[]) => request<{ deleted: number }>(`${base}/pool/delete`, { method: 'POST', body: JSON.stringify({ ids }) }),
  poolAdd: (type: string, host: string, port: number) => request<{ ok: boolean; added: number; dup?: boolean }>(`${base}/pool/add`, { method: 'POST', body: JSON.stringify({ type, host, port }) }),
  poolConfig: () => request<PoolConfig>(`${base}/pool/config`),
  poolSaveConfig: (data: Partial<PoolConfig>) => request<PoolConfig>(`${base}/pool/config`, { method: 'POST', body: JSON.stringify(data) }),
  // 自定义代理 CRUD（4模式重构）
  customList: () => request<{ items: CustomProxy[] }>(`${base}/custom`),
  customSave: (data: Partial<CustomProxy>) => request<{ ok: boolean; _id?: string }>(`${base}/custom`, { method: 'POST', body: JSON.stringify(data) }),
  customDelete: (id: string) => request<{ ok: boolean }>(`${base}/custom/${id}`, { method: 'DELETE' }),
  customTest: (id: string) => request<{ ok: boolean; reachable: boolean }>(`${base}/custom/${id}/test`, { method: 'POST' }),
  // 规则代理 CRUD（供策略下拉）
  ruleList: () => request<{ items: RuleProxy[] }>(`${base}/rule`),
  ruleSave: (data: Partial<RuleProxy>) => request<{ ok: boolean; _id?: string }>(`${base}/rule`, { method: 'POST', body: JSON.stringify(data) }),
  ruleDelete: (id: string) => request<{ ok: boolean }>(`${base}/rule/${id}`, { method: 'DELETE' }),
  ruleTest: (id: string) => request<{ ok: boolean; reachable: boolean }>(`${base}/rule/${id}/test`, { method: 'POST' })
}

export interface PoolProxy {
  _id: string
  type: string
  host: string
  port: number
  url: string
  source: string
  country?: string
  delay: number | null
  fail_streak: number
  enabled: boolean
  last_check: string
  exit_ip?: string
}
export interface PoolListResp { items: PoolProxy[]; total: number; page: number; size: number }
export interface PoolStats { total: number; alive: number; dead: number; unchecked: number; enabled: number }
export interface PoolQuery { source: string; type: string; q: string; enabled: boolean }
export interface PoolConfig { queries: PoolQuery[]; limit: number }
