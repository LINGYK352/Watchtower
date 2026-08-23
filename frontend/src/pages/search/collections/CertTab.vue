<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters.ip" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item label="端口"><a-input v-model:value="ctx.filters.port" allow-clear placeholder="端口" /></a-form-item>
      <a-form-item label="主题"><a-input v-model:value="ctx.filters['cert.subject_dn']" allow-clear placeholder="主题名称" /></a-form-item>
      <a-form-item label="任务ID"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'ip'"><CopyText :text="String(record.ip || '')" /></template>
      <template v-else-if="column.key === 'subject'">{{ certField(record, 'subject_dn') }}</template>
      <template v-else-if="column.key === 'issuer'">{{ certField(record, 'issuer_dn') }}</template>
      <template v-else-if="column.key === 'validity'">{{ validity(record) }}</template>
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
import type { RowRecord } from '../../../api/types'

const ctx = useAssetList('cert', { ip: undefined, port: undefined, 'cert.subject_dn': undefined, task_id: undefined })
type CertObj = { subject_dn?: string; issuer_dn?: string; validity?: { start?: string; end?: string } }
function certField(record: RowRecord, key: 'subject_dn' | 'issuer_dn') { return (record.cert as CertObj)?.[key] || '-' }
function validity(record: RowRecord) {
  const v = (record.cert as CertObj)?.validity
  return v ? `${v.start || '?'} ~ ${v.end || '?'}` : '-'
}
const columns = [
  { title: 'IP', key: 'ip', width: 150, fixed: 'left' },
  { title: '端口', dataIndex: 'port', key: 'port', width: 80 },
  { title: '主题', key: 'subject', ellipsis: true },
  { title: '签发者', key: 'issuer', ellipsis: true },
  { title: '有效期', key: 'validity', width: 260, ellipsis: true },
  { title: '任务ID', dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { title: '操作', key: 'action', width: 110, fixed: 'right' }
]
</script>
