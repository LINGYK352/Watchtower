<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item :label="translate('ui.m_222952431147')"><a-input v-model:value="ctx.filters.domain" allow-clear :placeholder="translate('ui.m_222952431147')" /></a-form-item>
      <a-form-item :label="translate('ui.m_5632a6a4e542')"><a-input v-model:value="ctx.filters.record" allow-clear :placeholder="translate('ui.m_5632a6a4e542')" /></a-form-item>
      <a-form-item :label="translate('ui.m_ba40014ff496')"><a-input v-model:value="ctx.filters.type" allow-clear placeholder="A/CNAME/MX" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'domain'"><CopyText :text="String(record.domain || '')" /></template>
      <template v-else-if="column.key === 'record'">{{ joinArr(record.record) }}</template>
      <template v-else-if="column.key === 'ips'">{{ joinArr(record.ips) }}</template>
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

const ctx = useAssetList('domain', { domain: undefined, record: undefined, type: undefined, task_id: undefined })
function joinArr(v: unknown) { return Array.isArray(v) ? v.join(', ') : String(v ?? '-') }
const columns = [
  { get title() { return translate('ui.m_222952431147') }, key: 'domain', width: 240, ellipsis: true },
  { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'type', key: 'type', width: 80 },
  { get title() { return translate('ui.m_5632a6a4e542') }, key: 'record', ellipsis: true },
  { title: 'IP', key: 'ips', width: 200, ellipsis: true },
  { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source', key: 'source', width: 120 },
  { get title() { return translate('ui.m_aa2353039024') }, dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 110, fixed: 'right' }
]
</script>
