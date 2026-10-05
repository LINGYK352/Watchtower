<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters.ip" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item :label="translate('ui.m_222952431147')"><a-input v-model:value="ctx.filters.domain" allow-clear :placeholder="translate('ui.m_222952431147')" /></a-form-item>
      <a-form-item :label="translate('ui.m_e71ac32b544b')"><a-input v-model:value="ctx.filters['port_info.port_id']" allow-clear :placeholder="translate('ui.m_7830f101b9ac')" /></a-form-item>
      <a-form-item :label="translate('ui.m_ec309ab207ef')"><a-input v-model:value="ctx.filters['port_info.service_name']" allow-clear :placeholder="translate('ui.m_b68bf34986b6')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'ip'"><CopyText :text="String(record.ip || '')" /></template>
      <template v-else-if="column.key === 'ports'">
        <a-space wrap size="small"><a-tag v-for="p in portList(record)" :key="p.port_id" color="blue">{{ p.port_id }}<span v-if="p.service_name">/{{ p.service_name }}</span></a-tag></a-space>
      </template>
      <template v-else-if="column.key === 'os'">{{ osName(record) }}</template>
      <template v-else-if="column.key === 'geo'">{{ geo(record) }}</template>
      <template v-else-if="column.key === 'ip_type'"><a-tag :color="record.ip_type === 'PUBLIC' ? 'green' : 'default'">{{ record.ip_type || '-' }}</a-tag></template>
      <template v-else-if="column.key === 'action'">
        <a-space size="small">
          <a-button type="link" size="small" @click="ctx.showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button>
          <ConfirmAction danger :title="translate('ui.m_7e18d0731e35')" @confirm="ctx.removeOne(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
        </a-space>
      </template>
    </template>
  </AssetCollectionTable>
</template>

<script setup lang="ts">
import { t as translate } from '../../../i18n'

import AssetCollectionTable from '../AssetCollectionTable.vue'
import CopyText from '../../../components/CopyText.vue'
import ConfirmAction from '../../../components/ConfirmAction.vue'
import { useAssetList } from '../useAssetList'
import type { RowRecord, PortInfo } from '../../../api/types'

const ctx = useAssetList('ip', { ip: undefined, domain: undefined, 'port_info.port_id': undefined, 'port_info.service_name': undefined, task_id: undefined })
function portList(record: RowRecord): PortInfo[] { return (record.port_info as PortInfo[]) || [] }
function osName(record: RowRecord) { return (record.os_info as { name?: string })?.name || '-' }
function geo(record: RowRecord) {
  const c = record.geo_city as { country_name?: string; region_name?: string } | undefined
  return c ? [c.country_name, c.region_name].filter(Boolean).join(' ') || '-' : '-'
}
const columns = [
  { title: 'IP', key: 'ip', width: 150, fixed: 'left' },
  { get title() { return translate('ui.m_6df028d33338') }, key: 'ports', ellipsis: true },
  { get title() { return translate('ui.m_360480034cc3') }, key: 'os', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_8dc9d6d1e78d') }, key: 'geo', width: 160, ellipsis: true },
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'ip_type', width: 90 },
  { title: 'CDN', dataIndex: 'cdn_name', key: 'cdn_name', width: 110, ellipsis: true },
  { get title() { return translate('ui.m_aa2353039024') }, dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 110, fixed: 'right' }
]
</script>
