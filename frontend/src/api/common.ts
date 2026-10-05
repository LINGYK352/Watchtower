import { request, toQueryString } from './request'
import type { ListQuery, ListResult, RowRecord } from './types'

export const simpleApi = {
  list: (namespace: string, query: ListQuery = {}) => request<ListResult<RowRecord>>(`/api/${namespace}/${toQueryString(query)}`),
  remove: (namespace: string, id: string) => request<Record<string, unknown>>(`/api/${namespace}/delete/`, {
    method: 'POST',
    body: JSON.stringify({ _id: id })
  })
}
