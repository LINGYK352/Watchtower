import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

/** 资产分组（asset_scope） */
export const assetScopeApi = {
  list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/asset_scope/${toQueryString(query)}`),
  add: (payload: { name: string; scope: string; black_scope?: string; scope_type?: string }) =>
    request<RowRecord>(`/api/asset_scope/`, { method: 'POST', body: JSON.stringify(payload) }),
  /** 删除整个资产组（及组内资产） */
  delete: (scopeIds: string[]) =>
    request<RowRecord>(`/api/asset_scope/delete/`, { method: 'POST', body: JSON.stringify({ scope_id: scopeIds }) }),
  /** 向资产组追加范围 */
  addScope: (scope_id: string, scope: string) =>
    request<RowRecord>(`/api/asset_scope/add/`, { method: 'POST', body: JSON.stringify({ scope_id, scope }) }),
  /** 从资产组删除单条范围 */
  deleteScope: (scope_id: string, scope: string) =>
    request<RowRecord>(`/api/asset_scope/delete/${toQueryString({ scope_id, scope })}`)
}

/** 资产组内各类资产（asset_domain / asset_ip / asset_site / asset_wih） */
function assetCollection(namespace: string) {
  return {
    list: (query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/${namespace}/${toQueryString(query)}`),
    delete: (ids: string[]) =>
      request<RowRecord>(`/api/${namespace}/delete/`, { method: 'POST', body: JSON.stringify({ _id: ids }) }),
    exportUrl: (query: ListQuery = {}) => `/api/${namespace}/export/${toQueryString(query)}`
  }
}

export const assetDomainApi = {
  ...assetCollection('asset_domain'),
  add: (payload: { domain: string; scope_id: string; policy_id?: string }) =>
    request<RowRecord>(`/api/asset_domain/`, { method: 'POST', body: JSON.stringify(payload) })
}

export const assetIpApi = assetCollection('asset_ip')

export const assetSiteApi = {
  ...assetCollection('asset_site'),
  add: (payload: { site: string; scope_id: string; policy_id?: string }) =>
    request<RowRecord>(`/api/asset_site/`, { method: 'POST', body: JSON.stringify(payload) })
}

export const assetWihApi = assetCollection('asset_wih')
