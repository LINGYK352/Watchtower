export interface ApiEnvelope<T = unknown> {
  code: number
  message: string
  data?: T
  items?: unknown[]
}

export interface ListQuery {
  page?: number
  size?: number
  order?: string
  [key: string]: string | number | boolean | undefined
}

export interface ListResult<T = Record<string, unknown>> {
  page: number
  size: number
  total: number
  items: T[]
  query?: Record<string, unknown>
  code?: number
}

export interface SelectOption {
  label: string
  value: string | number | boolean
}

export type RowRecord = Record<string, unknown>

/* ---------- 资产集合文档结构（据后端 routes 源码核实） ---------- */

export interface DomainRecord {
  _id: string
  domain: string
  type?: string
  record?: string[]
  ips?: string[]
  source?: string
  task_id?: string
  update_date?: string
}

export interface PortInfo {
  port_id: number
  service_name?: string
  product?: string
  version?: string
  protocol?: string
}

export interface IpRecord {
  _id: string
  ip: string
  domain?: string[]
  port_info?: PortInfo[]
  os_info?: { name?: string }
  geo_city?: { country_name?: string; region_name?: string }
  geo_asn?: { number?: number; organization?: string }
  ip_type?: string
  cdn_name?: string
  task_id?: string
}

export interface SiteRecord {
  _id: string
  site: string
  hostname?: string
  ip?: string
  title?: string
  http_server?: string
  headers?: Record<string, unknown>
  finger?: { name: string }[]
  status?: number
  favicon?: { hash?: number; data?: string }
  screenshot?: string
  tag?: string[] | string
  task_id?: string
}

export interface UrlRecord {
  _id: string
  url: string
  fld?: string
  site?: string
  content_length?: number
  status_code?: number
  title?: string
  source?: string
  task_id?: string
}

export interface CertRecord {
  _id: string
  ip: string
  port?: number
  cert?: {
    subject_dn?: string
    issuer_dn?: string
    serial_number?: string
    validity?: { start?: string; end?: string }
    fingerprint?: { sha256?: string; sha1?: string; md5?: string }
    extensions?: { subjectAltName?: string[] }
  }
  task_id?: string
}

export interface ServiceRecord {
  _id: string
  service_name: string
  service_info?: { ip?: string; port_id?: number; product?: string; version?: string }[]
  task_id?: string
}

export interface FileleakRecord {
  _id: string
  url: string
  site?: string
  content_length?: number
  status_code?: number
  title?: string
  task_id?: string
}

export interface WihRecord {
  _id: string
  record_type: string
  content?: string
  source?: string
  site?: string
  task_id?: string
}
