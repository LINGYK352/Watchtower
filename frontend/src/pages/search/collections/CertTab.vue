<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters.ip" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item :label="translate('ui.m_e71ac32b544b')"><a-input v-model:value="ctx.filters.port" allow-clear :placeholder="translate('ui.m_e71ac32b544b')" /></a-form-item>
      <a-form-item :label="translate('ui.m_788db1cfec2a')"><a-input v-model:value="ctx.filters['cert.subject_dn']" allow-clear :placeholder="translate('ui.m_e479c05c94a1')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'ip'"><CopyText :text="String(record.ip || '')" /></template>
      <template v-else-if="column.key === 'subject'">{{ certField(record, 'subject_dn') }}</template>
      <template v-else-if="column.key === 'issuer'">{{ certField(record, 'issuer_dn') }}</template>
      <template v-else-if="column.key === 'validity'">{{ validity(record) }}</template>
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
  { get title() { return translate('ui.m_e71ac32b544b') }, dataIndex: 'port', key: 'port', width: 80 },
  { get title() { return translate('ui.m_788db1cfec2a') }, key: 'subject', ellipsis: true },
  { get title() { return translate('ui.m_345f4e7931c6') }, key: 'issuer', ellipsis: true },
  { get title() { return translate('ui.m_9c2a28e8f98f') }, key: 'validity', width: 260, ellipsis: true },
  { get title() { return translate('ui.m_aa2353039024') }, dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 110, fixed: 'right' }
]
</script>
