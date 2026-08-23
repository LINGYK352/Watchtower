import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

const base = '/api/policy'

export interface PolicyConfig {
  domain_config: {
    domain_brute: boolean
    domain_brute_type: string
    alt_dns: boolean
    arl_search: boolean
    dns_query_plugin: boolean
    subdomain_dict?: string      // 自定义子域名爆破字典(多行,空=内置domain_2w)
    resolvers_custom?: string    // 自定义DNS resolver(多行IP,空=内置dnsserver)
  }
  ip_config: {
    port_scan: boolean
    port_scan_type: string
    service_detection: boolean
    os_detection: boolean
    ssl_cert: boolean
    skip_scan_cdn_ip: boolean
    port_custom: string
    host_timeout_type: string
    host_timeout: number
    port_parallelism: number
    port_min_rate: number
    exclude_ports: string
  }
  site_config: {
    site_identify: boolean
    site_capture: boolean
    search_engines: boolean
    site_spider: boolean
    nuclei_scan: boolean
    web_info_hunter: boolean
  }
  file_leak: boolean
  fileleak_dict?: string        // 自定义文件泄露字典(多行,空=内置file_top_2000)
  npoc_service_detection: boolean
  collect_mode?: string
  auto_pentest?: boolean
  pentest_mode?: string
  // 代理出口 4模式（2026-08 重构，废旧 pentest_proxy/scan_proxy/proxy_source）。defaultPolicyConfig 保证有值。
  scan_egress: { mode: string; rule_id?: string }
  pentest_egress: { mode: string; rule_id?: string }
  pentest_proxy?: string      // 旧字段(迁移期兼容读)
  scan_proxy?: string
  proxy_source?: string
  dedup_level?: number        // 去重策略 1不去重/2保守(默认)/3激进
  scope_drift_level?: number  // scope偏移 1零偏移/2轻度(默认)/3中度
  intel_enabled?: boolean     // 情报体系开关(默认启用;关闭不查仍回写)
  findvhost?: boolean
  poc_config: { plugin_name: string; enable: boolean }[]
  brute_config: { plugin_name: string; enable: boolean }[]
  scope_config: { scope_id: string }
}

export const policyApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`${base}/${toQueryString(query)}`),
  add: (payload: { name: string; desc?: string; policy: PolicyConfig }) =>
    request<RowRecord>(`${base}/add/`, { method: 'POST', body: JSON.stringify(payload) }),
  edit: (policy_id: string, policy_data: Record<string, unknown>) =>
    request<RowRecord>(`${base}/edit/`, { method: 'POST', body: JSON.stringify({ policy_id, policy_data }) }),
  delete: (ids: string[]) =>
    request<RowRecord>(`${base}/delete/`, { method: 'POST', body: JSON.stringify({ policy_id: ids }) })
}

/** 默认策略配置（用于新建策略表单初值） */
export function defaultPolicyConfig(): PolicyConfig {
  return {
    domain_config: { domain_brute: true, domain_brute_type: 'big', alt_dns: true, arl_search: true, dns_query_plugin: false, subdomain_dict: '', resolvers_custom: '' },
    ip_config: {
      port_scan: true, port_scan_type: 'test', service_detection: false, os_detection: false, ssl_cert: false,
      skip_scan_cdn_ip: true, port_custom: '80,443', host_timeout_type: 'default', host_timeout: 900,
      port_parallelism: 32, port_min_rate: 60, exclude_ports: ''
    },
    site_config: { site_identify: false, site_capture: false, search_engines: false, site_spider: false, nuclei_scan: false, web_info_hunter: false },
    file_leak: false,
    fileleak_dict: '',
    npoc_service_detection: false,
    collect_mode: 'multi_brute',
    auto_pentest: false,
    pentest_mode: 'src',
    scan_egress: { mode: 'direct', rule_id: '' },
    pentest_egress: { mode: 'smart', rule_id: '' },
    dedup_level: 2,
    scope_drift_level: 2,
    intel_enabled: true,
    findvhost: false,
    poc_config: [],
    brute_config: [],
    scope_config: { scope_id: '' }
  }
}
