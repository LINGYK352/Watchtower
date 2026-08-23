<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="服务名"><a-input v-model:value="ctx.filters.service_name" allow-clear placeholder="服务名" /></a-form-item>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters['service_info.ip']" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item label="端口"><a-input v-model:value="ctx.filters['service_info.port_id']" allow-clear placeholder="端口" /></a-form-item>
      <a-form-item label="产品"><a-input v-model:value="ctx.filters['service_info.product']" allow-clear placeholder="产品" /></a-form-item>
      <a-form-item label="任务ID"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'targets'">
        <a-space wrap size="small"><a-tag v-for="(t, i) in infoList(record)" :key="i">{{ t }}</a-tag></a-space>
      </template>
      <template v-else-if="column.key === 'action'">
        <a-button type="link" size="small" @click="ctx.showDetail(record)">详情</a-button>
      </template>
    </template>
  </AssetCollectionTable>
</template>

<script setup lang="ts">
import AssetCollectionTable from '../AssetCollectionTable.vue'
import { useAssetList } from '../useAssetList'
import type { RowRecord } from '../../../api/types'

const ctx = useAssetList('service', { service_name: undefined, 'service_info.ip': undefined, 'service_info.port_id': undefined, 'service_info.product': undefined, task_id: undefined })
type SvcInfo = { ip?: string; port_id?: number; product?: string; version?: string }
function infoList(record: RowRecord) {
  return ((record.service_info as SvcInfo[]) || []).map(s => `${s.ip || ''}:${s.port_id || ''}${s.product ? ` ${s.product}` : ''}`)
}
const columns = [
  { title: '服务名', dataIndex: 'service_name', key: 'service_name', width: 160, fixed: 'left' },
  { title: '服务实例 (IP:端口 产品)', key: 'targets', ellipsis: true },
  { title: '任务ID', dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { title: '操作', key: 'action', width: 80, fixed: 'right' }
]
</script>
