import { request } from './request'

// 攻击告警 API

export interface AttackAlert {
  _id: string
  source_ip: string
  attack_type: string
  severity: 'high' | 'medium' | 'low'
  description: string
  evidence: string
  confidence: number
  hit_count?: number
  last_path?: string
  first_seen?: number
  request: {
    method: string
    path: string
    query: string
    headers: Record<string, string>
    body: string
  }
  timestamp: number
  traced: boolean
}

export interface AttackStats {
  total_attacks: number
  today_attacks: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
  top_attackers: Array<{ ip: string; count: number }>
  recent_attacks: AttackAlert[]
}

export interface AttackerProfile {
  ip: string
  country: string
  city: string
  isp: string
  asn: string
  timezone: string
  is_proxy: boolean
  is_vpn: boolean
  threat_level: 'high' | 'medium' | 'low'
  attack_history: number
  attack_types?: string[]
  first_seen: number
  last_seen: number
}

export interface BanItem {
  _id: string          // IP
  ban_type: 'auto' | 'manual'
  reason: string
  operator: string
  banned_at: number
  expire_at: number | null   // null=永久
}

export interface WhitelistItem {
  _id: string          // IP
  operator: string
  note: string
  added_at: number
}

export const attackAlertApi = {
  /** 获取攻击统计信息 */
  getStats: () => request<AttackStats>('/api/attack_alert/stats'),

  /** 列出攻击记录 */
  list: (params?: {
    page?: number
    size?: number
    attack_type?: string
    severity?: string
    source_ip?: string
    start_time?: number
    end_time?: number
    sort_order?: string
  }) => {
    const query = new URLSearchParams()
    if (params?.page) query.set('page', String(params.page))
    if (params?.size) query.set('size', String(params.size))
    if (params?.attack_type) query.set('attack_type', params.attack_type)
    if (params?.severity) query.set('severity', params.severity)
    if (params?.source_ip) query.set('source_ip', params.source_ip)
    if (params?.start_time) query.set('start_time', String(params.start_time))
    if (params?.end_time) query.set('end_time', String(params.end_time))
    if (params?.sort_order) query.set('sort_order', params.sort_order)
    return request<{ items: AttackAlert[]; total: number; page: number; size: number }>(
      `/api/attack_alert/list?${query}`
    )
  },

  /** 溯源攻击者 */
  traceAttacker: (ip: string) => request<AttackerProfile>(`/api/attack_alert/trace/${ip}`),

  /** 手动封禁 IP */
  banIp: (ip: string, reason = '', permanent = true) =>
    request<{ ok: boolean; ip: string }>('/api/attack_alert/ban',
      { method: 'POST', body: JSON.stringify({ ip, reason, permanent }) }),

  /** 手动解封 IP */
  unbanIp: (ip: string) =>
    request<{ ok: boolean; ip: string }>('/api/attack_alert/unban',
      { method: 'POST', body: JSON.stringify({ ip }) }),

  /** 封禁名单列表 */
  banList: (page = 1, size = 50) =>
    request<{ items: BanItem[]; total: number }>(`/api/attack_alert/banlist?page=${page}&size=${size}`),

  /** 白名单列表 */
  whitelist: (page = 1, size = 100) =>
    request<{ items: WhitelistItem[]; total: number }>(`/api/attack_alert/whitelist?page=${page}&size=${size}`),

  /** 加白名单 */
  addWhitelist: (ip: string, note = '') =>
    request<{ ok: boolean; ip: string }>('/api/attack_alert/whitelist',
      { method: 'POST', body: JSON.stringify({ ip, note }) }),

  /** 移出白名单 */
  delWhitelist: (ip: string) =>
    request<{ ok: boolean; ip: string }>('/api/attack_alert/whitelist',
      { method: 'DELETE', body: JSON.stringify({ ip }) }),

  /** 手动检测攻击（测试用） */
  detectAttack: (requestData: {
    method: string
    path: string
    query?: string
    headers?: Record<string, string>
    body?: string
    source_ip?: string
  }) =>
    request<{ detected: boolean; attack_id?: string; attack_info?: any }>(
      '/api/attack_alert/detect',
      { method: 'POST', body: JSON.stringify(requestData) }
    )
}
