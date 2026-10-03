import { t as translate } from '../../i18n'
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { message } from 'ant-design-vue'
import { collectionApi } from '../../api/assets'
import type { ListQuery, RowRecord } from '../../api/types'

/**
 * 资产集合列表通用逻辑：分页、查询、排序、批量删除、导出、详情抽屉。
 * 各集合组件提供 namespace 和默认 filter 字段，复用此逻辑。
 * task_id 联动：任务详情页「查看」跳转带 ?task_id=xxx，各 Tab 用它作初始过滤，
 * 只显示该任务的资产（治「查看显示全部」——原 TaskDetail.goSearch 未带参数）。
 */
export function useAssetList(namespace: string, defaultFilters: Record<string, string | number | undefined> = {}, opts: { dedup?: boolean } = {}) {
  const route = useRoute()
  const loading = ref(false)
  const items = ref<RowRecord[]>([])
  const total = ref(0)
  const selectedRowKeys = ref<string[]>([])
  const detailOpen = ref(false)
  const current = ref<RowRecord>({})
  // URL query 带 task_id 且本集合支持该过滤字段时，用它覆盖初始值（进入即按任务过滤）
  const initFilters = { ...defaultFilters }
  const qTaskId = route?.query?.task_id
  if (qTaskId !== undefined && qTaskId !== null && String(qTaskId) !== '' && 'task_id' in initFilters) {
    initFilters.task_id = String(qTaskId)
  }
  const filters = reactive<Record<string, string | number | undefined>>({ ...initFilters })
  const page = ref(1)
  const size = ref(10)
  const order = ref('-_id')

  function buildQuery(): ListQuery {
    const q: ListQuery = { page: page.value, size: size.value, order: order.value }
    Object.entries(filters).forEach(([k, v]) => { if (v !== undefined && v !== '') q[k] = v })
    return q
  }

  async function load() {
    loading.value = true
    selectedRowKeys.value = []
    try {
      const data = await (opts.dedup ? collectionApi.listDedup(namespace, buildQuery()) : collectionApi.list(namespace, buildQuery()))
      items.value = data.items || []
      total.value = data.total || 0
    } catch (error) {
      message.error(error instanceof Error ? error.message : String(error))
    } finally {
      loading.value = false
    }
  }
  function reset() {
    Object.keys(filters).forEach(k => { filters[k] = undefined })
    page.value = 1
    load()
  }
  function onChange(p: { current?: number; pageSize?: number }) {
    page.value = p.current || 1
    size.value = p.pageSize || 10
    load()
  }
  function onSelectChange(keys: (string | number)[]) { selectedRowKeys.value = keys.map(String) }
  function showDetail(record: RowRecord) { current.value = record; detailOpen.value = true }
  // dedup 模式下,代表行删除要展开为该站点所有文档 id(_group_ids),否则删了显示的那条又冒出隐藏的
  function expandIds(ids: string[]): string[] {
    if (!opts.dedup) return ids
    const out = new Set<string>()
    for (const id of ids) {
      const row = items.value.find(r => String(r._id) === id)
      const gids = (row?._group_ids as string[] | undefined) || [id]
      gids.forEach(g => out.add(String(g)))
    }
    return [...out]
  }
  async function removeSelected() {
    if (!selectedRowKeys.value.length) return
    try { await collectionApi.deleteByIds(namespace, expandIds(selectedRowKeys.value)); message.success(translate('ui.m_077a6d37719a')); load() }
    catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  }
  async function removeOne(id: string) {
    try { await collectionApi.deleteByIds(namespace, expandIds([id])); message.success(translate('ui.m_077a6d37719a')); load() }
    catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  }
  function exportCurrent() { window.open(collectionApi.exportUrl(namespace, buildQuery()), '_blank') }

  function pagination() {
    return { current: page.value, pageSize: size.value, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }
  }

  onMounted(load)

  return {
    namespace,
    loading, items, total, selectedRowKeys, detailOpen, current, filters, page, size, order,
    load, reset, onChange, onSelectChange, showDetail, removeSelected, removeOne, exportCurrent, pagination, buildQuery
  }
}
