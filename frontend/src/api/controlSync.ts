import { request } from './request'

export interface ControlKey { _id: string; name: string; prefix: string; owner: string; scopes: string[]; expires_at: number; revoked: boolean; last_used_at: number | null }
export interface SyncLink { confirm_expires_at?:number; reject_reason?:string; _id: string; kind: 'receiver' | 'initiator'; name: string; state: string; route_mode?: 'direct'|'node'; node_descriptor?: Record<string,unknown>; node_error?: string; peer_error?: string; peer_retry_at?: number; target?: string; local: Record<string, string>; remote?: Record<string, string>; categories: string[]; pair_expires_at: number; connection_expires_at?: number; source_confirmed: boolean; receiver_confirmed: boolean }
export interface SyncRun { confirm_expires_at?:number; _id: string; link_id: string; kind: string; flow: string; mode: string; categories: string[]; state: string; stage: string; created_at?: number; completed_at?: number; expires_at: number; transferred_bytes?: number; summary?: { counts: Record<string, number>; files: number; bytes: number; sha256: string }; result?: Record<string, number>; error?: string }
export interface ControlState { admission?: {blocked:boolean;reasons:{kind:string;count:number;paused?:number}[]}; preferences?: {group_target:string;sync_target:string;local_addresses?:string[]}; identity: Record<string, string>; keys: ControlKey[]; links: SyncLink[]; history: { target: string; name: string }[]; runs: SyncRun[]; scopes: string[]; categories: string[]; listener?: { firewall?:{state:string;profiles?:string[]};available: boolean; enabled: boolean; running: boolean; port: number; targets: string[]; error: string } }
const root = '/api/control_sync'
const post = <T>(path: string, body: Record<string, unknown> = {}, silent=false) => request<T>(root + path, { method: 'POST', body: JSON.stringify(body),silent })
export const controlSyncApi = {
  pending: (signal?:AbortSignal) => request<{links:SyncLink[];runs:SyncRun[];server_time:number}>(root+'/pending',{signal,silent:true}),
  state: () => request<ControlState>(root + '/state'),
  listener: (body: Record<string, unknown>) => post('/listener', body),
  createKey: (body: Record<string, unknown>) => post<ControlKey & { key: string }>('/keys', body),
  revokeKey: (id: string) => post('/keys/' + encodeURIComponent(id) + '/revoke'),
  deleteKey: (id: string) => request(root + '/keys/' + encodeURIComponent(id), { method: 'DELETE' }),
  createPairKey: (body: Record<string, unknown>) => post<SyncLink & { key: string }>('/pair-key', body),
  connect: (body: Record<string, unknown>) => post<SyncLink>('/connect', body),
  confirm: (id: string) => post<SyncLink>('/links/' + encodeURIComponent(id) + '/confirm'),
  refresh: (id: string, background=false) => post<SyncLink>('/links/' + encodeURIComponent(id) + '/refresh',{background},background),
  revokeLink: (id: string) => post<SyncLink>('/links/' + encodeURIComponent(id) + '/revoke'),
  deleteLink: (id: string) => post<{deleted: boolean; peer_notified: boolean | null}>('/links/' + encodeURIComponent(id) + '/delete', {confirmed: true}),
  deleteRun: (id:string) => request(root+'/runs/'+encodeURIComponent(id),{method:'DELETE',body:JSON.stringify({confirmed:true})}),
  start: (body: Record<string, unknown>) => post<SyncRun>('/runs', body),
  decide: (id: string, accepted: boolean) => post<SyncRun>('/runs/' + encodeURIComponent(id) + '/decide', { accepted }),
  progress: (id: string, background=false) => post<SyncRun>('/runs/' + encodeURIComponent(id) + '/progress',{},background),
  advance: (id: string, background=false) => post<SyncRun>('/runs/' + encodeURIComponent(id) + '/advance',{},background)
}
