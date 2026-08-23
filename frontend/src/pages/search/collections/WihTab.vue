<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="类型"><a-input v-model:value="ctx.filters.record_type" allow-clear placeholder="记录类型" /></a-form-item>
      <a-form-item label="内容"><a-input v-model:value="ctx.filters.content" allow-clear placeholder="内容" /></a-form-item>
      <a-form-item label="站点"><a-input v-model:value="ctx.filters.site" allow-clear placeholder="站点 URL" /></a-form-item>
      <a-form-item label="来源"><a-input v-model:value="ctx.filters.source" allow-clear placeholder="来源 JS URL" /></a-form-item>
      <a-form-item label="任务ID"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'content'"><CopyText :text="String(record.content || '')" /></template>
      <template v-else-if="column.key === 'record_type'"><a-tag color="purple">{{ record.record_type || '-' }}</a-tag></template>
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

const ctx = useAssetList('wih', { record_type: undefined, content: undefined, site: undefined, source: undefined, task_id: undefined })
const columns = [
  { title: '类型', key: 'record_type', width: 130, fixed: 'left' },
  { title: '内容', key: 'content', ellipsis: true },
  { title: '站点', dataIndex: 'site', key: 'site', width: 220, ellipsis: true },
  { title: '来源', dataIndex: 'source', key: 'source', ellipsis: true },
  { title: '任务ID', dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true },
  { title: '操作', key: 'action', width: 110, fixed: 'right' }
]
</script>
