import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

export interface TaskCreatePayload {
  name: string
  target: string
  domain_brute: boolean
  domain_brute_type: string
  port_scan_type: string
  port_scan: boolean
  service_detection: boolean
  service_brute: boolean
  os_detection: boolean
  site_identify: boolean
  site_capture: boolean
  file_leak: boolean
  search_engines: boolean
  site_spider: boolean
  arl_search: boolean
  alt_dns: boolean
  ssl_cert: boolean
  dns_query_plugin: boolean
  skip_scan_cdn_ip: boolean
  nuclei_scan: boolean
  findvhost: boolean
  web_info_hunter: boolean
  // 目标来源(可选,补天/360 等 SRC);带来源则归集时贯穿 unit/归档,且可自动套绑定策略
  'source.platform'?: string
  'source.category'?: string
  'source.unit'?: string
  'source.src_id'?: string
}

const base = '/api/task'

export const taskApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/${toQueryString(query)}`),
  create: (payload: TaskCreatePayload) => request<{ items?: RowRecord[] }>(`${base}/`, { method: 'POST', body: JSON.stringify(payload) }),
  stop: (id: string) => request<Record<string, unknown>>(`${base}/stop/${id}`),
  resume: (id: string) => request<Record<string, unknown>>(`${base}/resume/${id}`),
  restart: (ids: string[]) => request<Record<string, unknown>>(`${base}/restart/`, {
    method: 'POST',
    body: JSON.stringify({ task_id: ids })
  }),
  delete: (ids: string[], del_task_data = false) => request<Record<string, unknown>>(`${base}/delete/`, {
    method: 'POST',
    body: JSON.stringify({ task_id: ids, del_task_data })
  }),
  batchStop: (ids: string[]) => request<Record<string, unknown>>(`${base}/batch_stop/`, {
    method: 'POST',
    body: JSON.stringify({ task_id: ids })
  }),
  // 孤儿资产：task_id 指向已删除任务的残留结果记录
  scanOrphan: () => request<{ total: number; by_collection: Record<string, number>; live_task_count: number }>(`${base}/orphan_assets`),
  purgeOrphan: () => request<{ purged: number; by_collection: Record<string, number>; skipped?: string; note?: string }>(`${base}/orphan_assets/purge`, { method: 'POST' }),
  /** 将任务结果同步到资产组 */
  sync: (task_id: string, scope_id: string) => request<Record<string, unknown>>(`${base}/sync/`, {
    method: 'POST',
    body: JSON.stringify({ task_id, scope_id })
  }),
  /** 按目标反查可同步的资产分组 */
  syncScope: (target: string) => request<ListResult<RowRecord>>(`${base}/sync_scope/${toQueryString({ target })}`),
  /** 按策略下发任务 */
  policy: (payload: {
    name: string; task_tag: 'task' | 'risk_cruising'; policy_id: string; target?: string; result_set_id?: string;
    priority?: number;
    pentest_whitelist?: string;
    mission_intel?: string;
    pentest_provider_id?: string;
    pentest_egress_mode?: string;
    'source.platform'?: string; 'source.category'?: string; 'source.unit'?: string; 'source.src_id'?: string
  }) =>
    request<{ items?: RowRecord[] }>(`${base}/policy/`, { method: 'POST', body: JSON.stringify(payload) })
}

const fofaBase = '/api/task_fofa'

export const taskFofaApi = {
  // 可用测绘源列表（源查询用，前端渲染绿√+输入框）
  sources: () => request<{ sources: { id: string; name: string; placeholder: string; available: boolean }[] }>(`${fofaBase}/sources`),
  // 预估：支持 {queries:{fofa,hunter}} 多源 或 {query} 单源(兼容)。返回 per_source 各源命中数
  test: (payload: { queries?: Record<string, string>; query?: string } | string) => {
    const body = typeof payload === 'string' ? { query: payload } : payload
    return request<{ per_source?: Record<string, { size: number; ok: boolean; error: boolean; errmsg: string }>;
      size: number; ok?: boolean; error?: boolean; errmsg?: string }>(`${fofaBase}/test`, {
      method: 'POST', body: JSON.stringify(body)
    })
  },
  submit: (payload: {
    queries?: Record<string, string>; query?: string; name: string; policy_id?: string; priority?: number;
    pentest_whitelist?: string;
    mission_intel?: string;
    pentest_provider_id?: string;
    pentest_egress_mode?: string;
    'source.platform'?: string; 'source.category'?: string; 'source.unit'?: string; 'source.src_id'?: string
  }) =>
    request<RowRecord>(`${fofaBase}/submit`, { method: 'POST', body: JSON.stringify(payload) }),
  // 单位名建任务:一个任务(name)装多个单位(units 多行),worker 异步反查种子
  submitByUnit: (payload: {
    name: string; units: string; policy_id?: string; priority?: number; pentest_whitelist?: string;
    mission_intel?: string;
    pentest_provider_id?: string;
    pentest_egress_mode?: string;
    'source.platform'?: string; 'source.category'?: string; 'source.src_id'?: string
  }) =>
    request<{ task_id: string; name: string; unit_count: number }>(
      `${fofaBase}/submit_by_unit`, { method: 'POST', body: JSON.stringify(payload) })
}
