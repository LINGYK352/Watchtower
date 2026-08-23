import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

export interface IntelStat {
  asset_total: number
  asset_pentested: number
  system_total: number
  code_total: number
  code_audited: number
  report_total: number
  asset_with_vuln: number
  asset_with_leak: number
  asset_with_secret: number
}

export interface IntelMatchResult {
  matched: boolean
  asset: RowRecord | null
}

export interface PentestContext {
  identity: Record<string, unknown>
  // 对齐后端 asset_intel._context 真实结构（原类型 known_findings.vulns/attack_surface.endpoints 是想当然，与后端不符）：
  // known_findings 是"已验证漏洞"数组；attack_surface 含 url_samples(端点)/fileleak_samples(文件泄露)/wih_samples。
  known_findings: RowRecord[]
  attack_surface: { ports: RowRecord[]; summary?: Record<string, unknown>;
    url_samples: RowRecord[]; wih_samples: RowRecord[]; fileleak_samples: RowRecord[] }
  history: { pentest_status: string; report_id: string }
  pointers?: Record<string, unknown>
}

export interface ReportItem { _id: string; asset_key: string; system_name?: string; max_severity?: string; save_date: string }

// 报告四级目录:任务名 > 单位 > 资产(子域名/IP) > 报告
export interface ReportTreeNode {
  task_name: string
  report_cnt: number
  units: Array<{
    unit: string
    report_cnt: number
    assets: Array<{ asset: string; report_cnt: number; reports: ReportItem[] }>
  }>
}

export type IntelCollection = 'intel_asset' | 'intel_system' | 'intel_code' | 'intel_report'

const base = '/api/intel'

export interface ChainStep {
  seq: number
  action: string
  result?: string
  target?: string
  vuln_type?: string
  severity?: string
  finding_ref?: string
  clue_ref?: string
  session_id?: string
  source_site?: string
  at?: string
}

export interface AttackChain {
  _id: string
  unit: string
  title: string
  steps: ChainStep[]
  step_count: number
  max_severity: string
  status: string
  sessions: string[]
  cross_session: boolean
  save_date: string
  update_date: string
}

export interface ChainStat {
  total: number
  cross_session: number
  by_severity: Record<string, number>
}

export const intelApi = {
  stat: () => request<IntelStat>(`${base}/stat/`),
  assets: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/asset/${toQueryString(query)}`),
  systems: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/system/${toQueryString(query)}`),
  codes: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/code/${toQueryString(query)}`),
  reports: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/report/${toQueryString(query)}`),
  reportDetail: (id: string) => request<RowRecord>(`${base}/report/${id}`),
  collect: (task_id: string) => request<{ task_id: string; site_total: number; new_asset: number; system_cnt: number }>(`${base}/collect/`, {
    method: 'POST',
    body: JSON.stringify({ task_id })
  }),
  match: (site: string) => request<IntelMatchResult>(`${base}/match/${toQueryString({ site })}`),
  context: (asset_key: string) => request<PentestContext>(`${base}/context/${toQueryString({ asset_key })}`),
  resolveIcp: (domain: string) => request<{ domain: string; unit: string; icp_no: string; source: string; updated: number }>(`${base}/resolve_icp/`, { method: 'POST', body: JSON.stringify({ domain }) }),
  reportTree: () => request<{ tree: ReportTreeNode[] }>(`${base}/report_tree/`),
  addCode: (payload: { repo_url: string; version?: string; system_id?: string; local_path?: string }) =>
    request<{ code_id: string }>(`${base}/code/add/`, { method: 'POST', body: JSON.stringify(payload) }),
  remove: (collection: IntelCollection, ids: string[]) =>
    request<{ _id: string[] }>(`${base}/delete/`, { method: 'POST', body: JSON.stringify({ collection, _id: ids }) }),
  chains: (query: ListQuery = {}) => request<ListResult<AttackChain>>(`${base}/chain/${toQueryString(query)}`),
  chainDetail: (id: string) => request<AttackChain>(`${base}/chain/${id}`),
  chainStat: (unit?: string) => request<ChainStat>(`${base}/chain/stat/${toQueryString(unit ? { unit } : {})}`),
  chainDelete: (ids: string | string[]) => request<{ deleted: number }>(`${base}/chain/delete/`, { method: 'POST', body: JSON.stringify({ _id: Array.isArray(ids) ? ids : [ids] }) }),
  units: () => request<{ units: UnitCard[] }>(`${base}/units/`),
  unitDetail: (unit: string) => request<UnitDetail>(`${base}/unit/${encodeURIComponent(unit)}`),
  deleteUnit: (unit: string) => request<{ unit: string; deleted: Record<string, number> }>(`${base}/unit/delete/`, { method: 'POST', body: JSON.stringify({ unit }) }),
}

export interface UnitCard {
  unit: string; vuln_count: number; lead_count: number; subdomain_count: number
  system_count: number; asset_count: number; report_count: number; chain_count: number; last_pentest: string
}
export interface UnitDetail extends UnitCard {
  vulns: RowRecord[]; leads: RowRecord[]; subdomains: { subdomain: string; asset_count: number }[]
  systems: { system_id: string; system_name: string }[]
  reports: RowRecord[]; chains: RowRecord[]
  intel: { fingerprints: string[]; file_leaks: RowRecord[]; secrets: RowRecord[]; endpoints: RowRecord[]; ports: RowRecord[] }
}
