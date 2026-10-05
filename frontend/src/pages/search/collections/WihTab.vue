<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item :label="translate('ui.m_ba40014ff496')"><a-input v-model:value="ctx.filters.record_type" allow-clear :placeholder="translate('ui.m_8f6363220575')" /></a-form-item>
      <a-form-item :label="translate('ui.m_7a688306423b')"><a-input v-model:value="ctx.filters.content" allow-clear :placeholder="translate('ui.m_7a688306423b')" /></a-form-item>
      <a-form-item :label="translate('ui.m_a59fe62777ff')"><a-input v-model:value="ctx.filters.site" allow-clear :placeholder="translate('ui.m_fb952476c712')" /></a-form-item>
      <a-form-item :label="translate('ui.m_a488e93d69cc')"><a-input v-model:value="ctx.filters.source" allow-clear :placeholder="translate('ui.m_54ef9c8d5332')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'content'"><CopyText :text="String(record.content || '')" /></template>
      <template v-else-if="column.key === 'record_type'"><a-tag color="purple">{{ record.record_type || '-' }}</a-tag></template>
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

const ctx = useAssetList('wih', { record_type: undefined, content: undefined, site: undefined, source: undefined, task_id: undefined })
const columns = [
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'record_type', width: 130, fixed: 'left' },
  { get title() { return translate('ui.m_7a688306423b') }, key: 'content', ellipsis: true },
  { get title() { return translate('ui.m_a59fe62777ff') }, dataIndex: 'site', key: 'site', width: 220, ellipsis: true },
  { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source', key: 'source', ellipsis: true },
  { get title() { return translate('ui.m_aa2353039024') }, dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 110, fixed: 'right' }
]
</script>
