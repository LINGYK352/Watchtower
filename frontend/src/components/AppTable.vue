<template>
  <a-table
    :columns="columns"
    :data-source="data"
    :loading="loading"
    :row-key="rowKey"
    :pagination="pagination"
    :row-selection="selectable ? rowSelection : undefined"
    size="middle"
    bordered
    @change="onChange"
  >
    <template #bodyCell="scope"><slot name="bodyCell" v-bind="scope" /></template>
  </a-table>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { computed } from 'vue'

const props = withDefaults(defineProps<{
  columns: unknown[]
  data: Record<string, unknown>[]
  loading?: boolean
  page?: number
  size?: number
  total?: number
  rowKey?: string
  selectable?: boolean
  selectedRowKeys?: string[]
}>(), { rowKey: '_id', page: 1, size: 10, total: 0, selectable: false, selectedRowKeys: () => [] })

const emit = defineEmits<{
  change: [page: number, size: number]
  'update:selectedRowKeys': [keys: string[]]
}>()

const rowSelection = computed(() => ({
  selectedRowKeys: props.selectedRowKeys,
  onChange: (keys: string[]) => emit('update:selectedRowKeys', keys)
}))

const pagination = computed(() => ({
  current: props.page,
  pageSize: props.size,
  total: props.total,
  showSizeChanger: true,
  showTotal: (total: number) => translate('ui.m_f292bcb94fe6', { p0: (total) })
}))

function onChange(pageInfo: { current?: number; pageSize?: number }) {
  emit('change', pageInfo.current || 1, pageInfo.pageSize || 10)
}
</script>
