import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

/** 通用资产集合接口：列表 / 删除 / 导出 URL */
export const collectionApi = {
  list: (namespace: string, query: ListQuery = {}) =>
    request<ListResult<RowRecord>>(`/api/${namespace}/${toQueryString(query)}`),
  /** 站点按 域名+端口 去重查询(site 专用,返回代表行带 _group_ids) */
  listDedup: (namespace: string, query: ListQuery = {}) =>
    request<ListResult<RowRecord>>(`/api/${namespace}/dedup/${toQueryString(query)}`),
  /** 多数集合删除参数为 _id 数组 */
  deleteByIds: (namespace: string, ids: string[]) =>
    request<Record<string, unknown>>(`/api/${namespace}/delete/`, {
      method: 'POST',
      body: JSON.stringify({ _id: ids })
    }),
  /** 导出走 GET，直接返回可下载的 URL（带查询条件） */
  exportUrl: (namespace: string, query: ListQuery = {}) =>
    `/api/${namespace}/export/${toQueryString(query)}`
}

/** 站点标签（site 与 asset_site 通用，传不同 namespace） */
export const siteTagApi = {
  addTag: (namespace: 'site' | 'asset_site', id: string, tag: string) =>
    request<Record<string, unknown>>(`/api/${namespace}/add_tag/`, {
      method: 'POST',
      body: JSON.stringify({ _id: id, tag })
    }),
  deleteTag: (namespace: 'site' | 'asset_site', id: string, tag: string) =>
    request<Record<string, unknown>>(`/api/${namespace}/delete_tag/`, {
      method: 'POST',
      body: JSON.stringify({ _id: id, tag })
    })
}

/** 资产集合命名空间常量 */
export const ASSET_COLLECTIONS = {
  domain: 'domain',
  ip: 'ip',
  site: 'site',
  url: 'url',
  cert: 'cert',
  service: 'service',
  fileleak: 'fileleak',
  wih: 'wih'
} as const

export type AssetCollection = keyof typeof ASSET_COLLECTIONS

/** 截图 URL */
export function imageUrl(taskId: string, fileName: string) {
  return `/api/image/${taskId}/${fileName}`
}
