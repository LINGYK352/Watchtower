import { request } from './request'

export interface RequestApproval {
  _id: string
  state: string
  created_at: number
  expires_at: number
  method: string
  url: string
  reason: string
  packet_bytes: number
  replacement_id?: string
}
export interface ApprovalList {
  items: RequestApproval[]
  server_time: number
  full_authorization: boolean
  afk_mode:boolean
  manual_session:boolean
}
const base = (sid: string) => `/api/pentest/session/${encodeURIComponent(sid)}`
export const requestApprovalApi = {
  list: (sid: string) => request<ApprovalList>(`${base(sid)}/request_approvals`),
  authorize: (sid: string, enabled: boolean, acknowledged=false) => request<{ full_authorization: boolean }>(`${base(sid)}/authorization`, { method: 'POST', body: JSON.stringify({ enabled,acknowledged }) }),
  afk: (sid:string, enabled:boolean, acknowledged=false, strategy='') => request<{afk_mode:boolean;full_authorization:boolean}>(`${base(sid)}/afk`,{method:'POST',body:JSON.stringify({enabled,acknowledged,strategy})}),
  packet: (sid: string, id: string) => request<RequestApproval & { request_b64: string; complete: boolean }>(`${base(sid)}/request_approvals/${encodeURIComponent(id)}/packet`),
  decide: (sid: string, id: string, allow: boolean) => request<RequestApproval>(`${base(sid)}/request_approvals/${encodeURIComponent(id)}/decide`, { method: 'POST', body: JSON.stringify({ allow }) }),
  reapply: (sid: string, id: string) => request<RequestApproval>(`${base(sid)}/request_approvals/${encodeURIComponent(id)}/reapply`, { method: 'POST', body: '{}' }),
}
