<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="URL"><a-input v-model:value="ctx.filters.url" allow-clear placeholder="URL" /></a-form-item>
      <a-form-item :label="translate('ui.m_a59fe62777ff')"><a-input v-model:value="ctx.filters.site" allow-clear :placeholder="translate('ui.m_a59fe62777ff')" /></a-form-item>
      <a-form-item :label="translate('ui.m_c3405f8c7d9d')"><a-input v-model:value="ctx.filters.title" allow-clear :placeholder="translate('ui.m_c3405f8c7d9d')" /></a-form-item>
      <a-form-item :label="translate('ui.m_06f7d7341212')"><a-input v-model:value="ctx.filters.status_code" allow-clear :placeholder="translate('ui.m_6860be5ef3f4')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'url'"><a :href="String(record.url)" target="_blank">{{ record.url }}</a></template>
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

const ctx = useAssetList('url', { url: undefined, site: undefined, title: undefined, status_code: undefined, task_id: undefined })
const columns = [
  { title: 'URL', key: 'url', ellipsis: true, fixed: 'left', width: 300 },
  { get title() { return translate('ui.m_0d5364ae8018') }, dataIndex: 'fld', key: 'fld', width: 150, ellipsis: true },
  { get title() { return translate('ui.m_a59fe62777ff') }, dataIndex: 'site', key: 'site', width: 200, ellipsis: true },
  { get title() { return translate('ui.m_06f7d7341212') }, dataIndex: 'status_code', key: 'status_code', width: 90 },
  { get title() { return translate('ui.m_fcd53935fd79') }, dataIndex: 'content_length', key: 'content_length', width: 90 },
  { get title() { return translate('ui.m_c3405f8c7d9d') }, dataIndex: 'title', key: 'title', ellipsis: true },
  { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source', key: 'source', width: 120 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 80, fixed: 'right' }
]
</script>
