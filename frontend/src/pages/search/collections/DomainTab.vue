<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="域名"><a-input v-model:value="ctx.filters.domain" allow-clear placeholder="域名" /></a-form-item>
      <a-form-item label="解析值"><a-input v-model:value="ctx.filters.record" allow-clear placeholder="解析值" /></a-form-item>
      <a-form-item label="类型"><a-input v-model:value="ctx.filters.type" allow-clear placeholder="A/CNAME/MX" /></a-form-item>
      <a-form-item label="任务ID"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'domain'"><CopyText :text="String(record.domain || '')" /></template>
      <template v-else-if="column.key === 'record'">{{ joinArr(record.record) }}</template>
      <template v-else-if="column.key === 'ips'">{{ joinArr(record.ips) }}</template>
      <template v-else-if="column.key === 'action'">
        <a-space size="small">
          <a-button type="link" size="small" @click="ctx.showDetail(record)">详情</a-button>
          <ConfirmAction danger title="确认删除？" @confirm="ctx.removeOne(String(record._id))">删除</ConfirmAction>
        </a-space>
      </template>
    </template>
  </AssetCollectionTable>
</template>

<script setup lang="ts">
import AssetCollectionTable from '../AssetCollectionTable.vue'
import CopyText from '../../../components/CopyText.vue'
import ConfirmAction from '../../../components/ConfirmAction.vue'
import { useAssetList } from '../useAssetList'

const ctx = useAssetList('domain', { domain: undefined, record: undefined, type: undefined, task_id: undefined })
function joinArr(v: unknown) { return Array.isArray(v) ? v.join(', ') : String(v ?? '-') }
const columns = [
  { title: '域名', key: 'domain', width: 240, ellipsis: true },
  { title: '类型', dataIndex: 'type', key: 'type', width: 80 },
  { title: '解析值', key: 'record', ellipsis: true },
  { title: 'IP', key: 'ips', width: 200, ellipsis: true },
  { title: '来源', dataIndex: 'source', key: 'source', width: 120 },
  { title: '任务ID', dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { title: '操作', key: 'action', width: 110, fixed: 'right' }
]
</script>
