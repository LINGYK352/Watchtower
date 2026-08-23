<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="URL"><a-input v-model:value="ctx.filters.url" allow-clear placeholder="URL" /></a-form-item>
      <a-form-item label="站点"><a-input v-model:value="ctx.filters.site" allow-clear placeholder="站点" /></a-form-item>
      <a-form-item label="标题"><a-input v-model:value="ctx.filters.title" allow-clear placeholder="标题" /></a-form-item>
      <a-form-item label="状态码"><a-input v-model:value="ctx.filters.status_code" allow-clear placeholder="如 200" /></a-form-item>
      <a-form-item label="任务ID"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'url'"><a :href="String(record.url)" target="_blank">{{ record.url }}</a></template>
      <template v-else-if="column.key === 'action'">
        <a-button type="link" size="small" @click="ctx.showDetail(record)">详情</a-button>
      </template>
    </template>
  </AssetCollectionTable>
</template>

<script setup lang="ts">
import AssetCollectionTable from '../AssetCollectionTable.vue'
import { useAssetList } from '../useAssetList'

const ctx = useAssetList('url', { url: undefined, site: undefined, title: undefined, status_code: undefined, task_id: undefined })
const columns = [
  { title: 'URL', key: 'url', ellipsis: true, fixed: 'left', width: 300 },
  { title: '一级域名', dataIndex: 'fld', key: 'fld', width: 150, ellipsis: true },
  { title: '站点', dataIndex: 'site', key: 'site', width: 200, ellipsis: true },
  { title: '状态码', dataIndex: 'status_code', key: 'status_code', width: 90 },
  { title: '长度', dataIndex: 'content_length', key: 'content_length', width: 90 },
  { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
  { title: '来源', dataIndex: 'source', key: 'source', width: 120 },
  { title: '操作', key: 'action', width: 80, fixed: 'right' }
]
</script>
