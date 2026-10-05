<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item :label="translate('ui.m_b68bf34986b6')"><a-input v-model:value="ctx.filters.service_name" allow-clear :placeholder="translate('ui.m_b68bf34986b6')" /></a-form-item>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters['service_info.ip']" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item :label="translate('ui.m_e71ac32b544b')"><a-input v-model:value="ctx.filters['service_info.port_id']" allow-clear :placeholder="translate('ui.m_e71ac32b544b')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aea82737cc01')"><a-input v-model:value="ctx.filters['service_info.product']" allow-clear :placeholder="translate('ui.m_aea82737cc01')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'targets'">
        <a-space wrap size="small"><a-tag v-for="(t, i) in infoList(record)" :key="i">{{ t }}</a-tag></a-space>
      </template>
      <template v-else-if="column.key === 'action'">
        <a-button type="link" size="small" @click="ctx.showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button>
      </template>
    </template>
  </AssetCollectionTable>
</template>

<script setup lang="ts">
import { t as translate } from '../../../i18n'

import AssetCollectionTable from '../AssetCollectionTable.vue'
import { useAssetList } from '../useAssetList'
import type { RowRecord } from '../../../api/types'

const ctx = useAssetList('service', { service_name: undefined, 'service_info.ip': undefined, 'service_info.port_id': undefined, 'service_info.product': undefined, task_id: undefined })
type SvcInfo = { ip?: string; port_id?: number; product?: string; version?: string }
function infoList(record: RowRecord) {
  return ((record.service_info as SvcInfo[]) || []).map(s => `${s.ip || ''}:${s.port_id || ''}${s.product ? ` ${s.product}` : ''}`)
}
const columns = [
  { get title() { return translate('ui.m_b68bf34986b6') }, dataIndex: 'service_name', key: 'service_name', width: 160, fixed: 'left' },
  { get title() { return translate('ui.m_73ed125b51d8') }, key: 'targets', ellipsis: true },
  { get title() { return translate('ui.m_aa2353039024') }, dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 80, fixed: 'right' }
]
</script>
