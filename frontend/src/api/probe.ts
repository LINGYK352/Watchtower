import { t as translate } from '../i18n'
import { request, getToken } from './request'

const base = '/api/probe'

export interface ProbeConfig {
  _id: string
  probe_id: string
  name: string
  type: string
  vps_ip: string
  port: number
  tunnel_port?: number
  auth_key?: string
  protocol: string
  status: string
  created_at: number
  build_path?: string
}

export interface AgentConfig {
  _id: string
  agent_id: string
  name: string
  probe_id: string
  probes: { host: string; port: number }[]
  platform: string
  mode: string
  listen_port: number
  reuse_port: number
  beacon_interval: number
  beacon_jitter: number
  aes_key?: string
  status: string
  created_at: number
  build_path?: string
}

function _extractFilename(resp: Response, fallback: string): string {
  const disposition = resp.headers.get('Content-Disposition') || ''
  const match = disposition.match(/filename[^;=\n]*=["']?([^"';\n]+)/)
  return match?.[1] || fallback
}

export const probeApi = {
  list: (type: string = 'red') =>
    request<ProbeConfig[]>(`${base}/list?type=${type}`),

  create: (data: { name?: string; vps_ip: string; port?: number; auth_key?: string; protocol?: string; type?: string }) =>
    request<ProbeConfig>(`${base}/create`, { method: 'POST', body: JSON.stringify(data) }),

  build: (probeId: string) =>
    request<{ build_path: string }>(`${base}/build/${probeId}`, { method: 'POST' }),

  download: (probeId: string) => {
    const a = document.createElement('a')
    a.href = `${base}/download/${probeId}`
    a.click()
  },

  downloadWithAuth: async (probeId: string) => {
    const resp = await fetch(`${base}/download/${probeId}`, {
      headers: { 'Token': getToken() },
    })
    if (!resp.ok) throw new Error(translate('ui.m_8a03e35ad323'))
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = _extractFilename(resp, `probe-${probeId.slice(0, 8)}`)
    a.click()
    URL.revokeObjectURL(url)
  },

  delete: (probeId: string) =>
    request<{ deleted: boolean }>(`${base}/delete/${probeId}`, { method: 'DELETE' }),

  status: (probeId: string) =>
    request<Record<string, unknown>>(`${base}/status/${probeId}`),

  // ── Agent API ──
  agentList: (probeId?: string) =>
    request<AgentConfig[]>(`${base}/agent/list${probeId ? '?probe_id=' + probeId : ''}`),

  agentCreate: (data: {
    name?: string; probe_id: string; probe_ids?: string[]; platform?: string;
    listen_port?: number; reuse_port?: number; beacon_interval?: number;
    beacon_jitter?: number;
  }) => request<AgentConfig>(`${base}/agent/create`, { method: 'POST', body: JSON.stringify(data) }),

  agentBuild: (agentId: string) =>
    request<{ build_path: string }>(`${base}/agent/build/${agentId}`, { method: 'POST' }),

  agentDownload: async (agentId: string) => {
    const resp = await fetch(`${base}/agent/download/${agentId}`, {
      headers: { 'Token': getToken() },
    })
    if (!resp.ok) throw new Error(translate('ui.m_8a03e35ad323'))
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = _extractFilename(resp, `agent-${agentId.slice(0, 8)}`)
    a.click()
    URL.revokeObjectURL(url)
  },

  agentDelete: (agentId: string) =>
    request<{ deleted: boolean }>(`${base}/agent/${agentId}`, { method: 'DELETE' }),

  agentStatus: (agentId: string) =>
    request<Record<string, unknown>>(`${base}/agent/status/${agentId}`),
}
