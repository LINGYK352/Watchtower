import { t as translate } from '../i18n'
import { request, toQueryString, getToken } from './request'
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

// #4 报告编辑：任务级/会话级报告的详情+生成结果
export interface ReportScreenshot { name: string; caption: string; section: 'icp' | 'steps' | 'evidence'; step: number; width_percent?: number }
export interface ReportFindingData {
  finding_id: string
  reproduction_steps: { text: string }[]
  screenshots: ReportScreenshot[]
  [key: string]: unknown
}
export interface ReportData {
  source: string
  source_id: string
  report: Record<string, string>
  findings: ReportFindingData[]
}
export interface ReportAiChange { finding_id: string; field: string; step_index: number; before: string; after: string; reason: string; source_field: string; source_quote: string }
export interface ReportAiResult { ok: boolean; changes: ReportAiChange[]; warnings: string[]; provider_name: string; tokens: number }
export interface ReportDetail extends RowRecord {
  _id: string
  report_type?: 'task' | 'session' | 'finding'
  gen_mode?: string
  report_data?: ReportData
  generation_warnings?: string[]
  delivery_ready?: boolean
  title?: string
  content?: string
  max_severity?: string
  source_task_id?: string
  source_session?: string
  asset_key?: string
  edited?: boolean
  session_count?: number
  vuln_total?: number
}
export interface GenerateReportResult {
  ok: boolean
  report_id: string
  updated?: boolean
  session_count?: number
  vuln_total?: number
}

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

export type IntelCollection = 'intel_asset' | 'intel_system' | 'intel_code' | 'intel_report' | 'pentest_report'

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

export interface OverlapActiveSession {
  session_id: string; site: string; status: string; unit: string; started_at: string; ago: string
}
export interface OverlapReport {
  report_id: string; asset_key: string; site: string; unit: string
  vuln_count: number; max_severity: string; save_date: string; ago: string
}
export interface OverlapResult {
  overlap: boolean
  scope: 'precise' | 'best_effort'
  active_sessions: OverlapActiveSession[]
  last_reports: OverlapReport[]
  summary: string
}

export const intelApi = {
  stat: () => request<IntelStat>(`${base}/stat/`),
  assets: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/asset/${toQueryString(query)}`),
  systems: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/system/${toQueryString(query)}`),
  codes: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/code/${toQueryString(query)}`),
  // —— 情报报告 intel_report（情报中心报告 tab 用，会话收尾自动产，供 AI 往期借鉴）——
  reports: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/report/${toQueryString(query)}`),
  reportDetail: (id: string) => request<ReportDetail>(`${base}/report/${id}`),
  // #4 导出 docx：二进制流下载（带 Token 头 fetch 取 blob 触发下载；出错时后端返 JSON 信封）
  exportDocx: (id: string) => exportReportDocx('report', id),
  // —— 人看成品报告 pentest_report（报告编辑处专用，人工生成/编辑，与 intel_report 物理隔离）——
  pentestReports: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/pentest_report/${toQueryString(query)}`),
  pentestReportDetail: (id: string) => request<ReportDetail>(`${base}/pentest_report/${id}`),
  updatePentestReport: (id: string, payload: { content?: string; title?: string; report_data?: ReportData }) =>
    request<{ ok: boolean; report_id: string }>(`${base}/pentest_report/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  generatePentestReport: (payload: { type: 'task'; task_id: string; use_llm?: boolean } | { type: 'session'; session_id: string }) =>
    request<GenerateReportResult>(`${base}/pentest_report/generate`, { method: 'POST', body: JSON.stringify(payload) }),
  exportPentestDocx: (id: string) => exportReportDocx('pentest_report', id),
  assistPentestReport: (id: string, payload: { report_data: ReportData; instruction: string; provider_id?: string; only_empty: boolean }) =>
    request<ReportAiResult>(`${base}/pentest_report/${id}/assist`, { method: 'POST', body: JSON.stringify(payload) }),
  collect: (task_id: string) => request<{ task_id: string; site_total: number; new_asset: number; system_cnt: number }>(`${base}/collect/`, {
    method: 'POST',
    body: JSON.stringify({ task_id })
  }),
  match: (site: string) => request<IntelMatchResult>(`${base}/match/${toQueryString({ site })}`),
  // 发起/重启任务前检测同资产是否已有渗透会话或历史报告（供确认弹窗）
  checkOverlap: (payload: { targets?: string[]; target?: string; unit?: string; within_days?: number }) =>
    request<OverlapResult>(`${base}/check_overlap/`, { method: 'POST', body: JSON.stringify(payload) }),
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

// #4 docx 导出：不走 request<T>（那是 JSON 信封通道）。二进制流需带 Token 头 fetch 取 blob，
// 手动触发浏览器下载。出错时后端返 JSON 信封（application/json），据 content-type 分流抛错。
async function exportReportDocx(seg: 'report' | 'pentest_report', reportId: string): Promise<void> {
  const token = getToken()
  const headers = new Headers()
  if (token) headers.set('Token', token)
  const resp = await fetch(`${base}/${seg}/${reportId}/export.docx`, { headers, cache: 'no-store' })
  const ct = resp.headers.get('content-type') || ''
  if (ct.includes('application/json') || !resp.ok) {
    // 出错：后端返 JSON 信封（如 docx 组件未安装 / 报告不存在）
    const data = await resp.json().catch(() => ({} as { message?: string }))
    throw new Error(data.message || translate('ui.m_a53238d6cfc8', { p0: (resp.status) }))
  }
  const blob = await resp.blob()
  // 从 Content-Disposition 取文件名（filename*=UTF-8''xxx），取不到用默认
  const cd = resp.headers.get('content-disposition') || ''
  const m = cd.match(/filename\*=UTF-8''([^;]+)/i)
  const filename = m ? decodeURIComponent(m[1]) : `report_${reportId}.docx`
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
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

// ================= 报告模板学习 =================
export interface ReportTemplate {
  _id: string; name: string; status: 'learning' | 'review' | 'ready' | 'failed'
  source_filename?: string; learn_error?: string; learn_tokens?: number
  learn_provider_id?: string; learn_provider_name?: string; refine_count?: number; need_review?: boolean
  learn_phase?: string; learn_progress?: number   // 异步学习进度（learning 时前端轮询显进度条）
  schema?: Record<string, unknown>; save_date?: string; update_date?: string
}

// multipart 上传必须用原生 fetch 带 Token（request<T> 有 body 时强设 JSON header 会破坏 boundary，见 request.ts）
async function tplUpload(path: string, form: FormData): Promise<Record<string, unknown>> {
  const headers = new Headers()
  const token = getToken()
  if (token) headers.set('Token', token)
  const resp = await fetch(`${base}${path}`, { method: 'POST', headers, body: form })
  const data = await resp.json().catch(() => ({} as { code?: number; message?: string; data?: unknown }))
  if (!resp.ok || (data.code && data.code !== 200)) {
    throw new Error(data.message || translate('ui.m_47245f9bc28a', { p0: (resp.status) }))
  }
  return (data.data as Record<string, unknown>) || {}
}

// 取 docx 字节（ArrayBuffer）供前端 mammoth.js 转 HTML 在线对比。GET 带 Token；失败后端返 JSON 信封解析 message 抛错。
async function tplArrayBuffer(path: string): Promise<ArrayBuffer> {
  const headers = new Headers()
  const token = getToken()
  if (token) headers.set('Token', token)
  const resp = await fetch(`${base}${path}`, { method: 'GET', headers })
  const ct = resp.headers.get('Content-Type') || ''
  if (!resp.ok || ct.includes('application/json')) {
    const data = await resp.json().catch(() => ({} as { message?: string }))
    throw new Error(data.message || translate('ui.m_91df1b36811e', { p0: (resp.status) }))
  }
  return resp.arrayBuffer()
}

export const reportTemplateApi = {
  list: (query: ListQuery = {}) =>
    request<ListResult<RowRecord>>(`${base}/report_template/${toQueryString(query)}`),
  detail: (id: string) => request<ReportTemplate>(`${base}/report_template/${id}`),
  // 上传模板 docx（name 可选；opts.provider_id 空=跟随全局默认；opts.need_review 勾选→review 迭代态）→ 学习
  // 异步：秒回 {status:'learning', template_id}，后台学习。need_review 默认 true（显式传 false 才直接 ready）。
  upload: (file: File, name?: string, opts?: { provider_id?: string; need_review?: boolean }) => {
    const form = new FormData()
    form.append('file', file)
    if (name) form.append('name', name)
    if (opts?.provider_id) form.append('provider_id', opts.provider_id)
    form.append('need_review', opts?.need_review === false ? '0' : '1')
    return tplUpload('/report_template/upload', form)
  },
  // 人在回路重学（可换模型 + 纠正意见），仍落 review 态
  refine: (id: string, payload: { provider_id?: string; feedback?: string }) =>
    request<{ ok: boolean; status: string }>(`${base}/report_template/${id}/refine`,
      { method: 'POST', body: JSON.stringify(payload) }),
  // 确认定稿 review→ready
  confirm: (id: string) =>
    request<{ ok: boolean; status: string }>(`${base}/report_template/${id}/confirm`, { method: 'POST' }),
  // 在线并排对比（origin 原文 vs schema 判定）
  diff: (id: string) =>
    request<{ rows: RowRecord[]; summary: Record<string, number> }>(`${base}/report_template/${id}/diff`),
  // 样本回填预览 docx 下载（浏览器直接存文件）
  // 取 origin/template docx 字节供 mammoth 在线对比（which=origin 原报告 / template 打标记模板）
  docxArrayBuffer: (id: string, which: 'origin' | 'template') =>
    tplArrayBuffer(`/report_template/${id}/docx?which=${which}`),
  remove: (id: string) =>
    request<{ ok: boolean; deleted: number }>(`${base}/report_template/${id}`, { method: 'DELETE' }),
  // 用模板生成报告（生成后到「会话级/任务级/漏洞报告」列表查看/导出）
  generate: (payload: { template_id: string; type: 'task'; task_id: string }
    | { template_id: string; type: 'session'; session_id: string }
    | { template_id: string; type: 'finding'; finding_id: string }) =>
      request<{ ok: boolean; report_id: string; docx_path: string; vuln_total: number; updated: boolean; generation_warnings?: string[]; delivery_ready?: boolean }>(
      `${base}/report_template/generate`, { method: 'POST', body: JSON.stringify(payload) }),
  // 人工补充截图（绑定漏洞条目）
  manualShot: (id: string, file: File, findingId: string) => {
    const form = new FormData()
    form.append('file', file)
    form.append('finding_id', findingId)
    return tplUpload(`/report_template/${id}/manual_shot`, form)
  },
}

// 漏洞证据截图（按 finding_id 全局绑定，跨模板通用；上传后生成报告自动嵌入证据/复现区）
export const findingShotApi = {
  list: (findingId: string) =>
    request<{ shots: { name: string; url: string }[] }>(`${base}/finding_shot/${findingId}`),
  upload: (findingId: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return tplUpload(`/finding_shot/${findingId}`, form)
  },
  remove: (findingId: string, name: string) =>
    request<{ ok: boolean; deleted: number }>(`${base}/finding_shot/${findingId}/${name}`, { method: 'DELETE' }),
}
