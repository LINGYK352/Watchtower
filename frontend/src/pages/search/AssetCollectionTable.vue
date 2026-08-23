<template>
  <div>
    <SearchBar :model="ctx.filters" @search="ctx.load" @reset="ctx.reset">
      <slot name="filters" />
    </SearchBar>
    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px">
        <a-button @click="ctx.exportCurrent">导出</a-button>
        <a-button v-if="ctx.total.value > 0 && !allSelected" @click="selectAll">全选全部 ({{ ctx.total.value }})</a-button>
        <a-button v-if="allSelected" @click="ctx.selectedRowKeys.value = []">取消全选</a-button>
        <ConfirmAction v-if="ctx.selectedRowKeys.value.length" danger type="primary" title="确认删除选中资产？" @confirm="ctx.removeSelected">
          删除选中 ({{ ctx.selectedRowKeys.value.length }})
        </ConfirmAction>
        <slot name="toolbar" />
      </a-space>
      <a-table
        :columns="columns"
        :data-source="ctx.items.value"
        :loading="ctx.loading.value"
        row-key="_id"
        :pagination="ctx.pagination()"
        :scroll="{ x: 'max-content' }"
        size="middle"
        bordered
        :row-selection="{ selectedRowKeys: ctx.selectedRowKeys.value, onChange: ctx.onSelectChange }"
        @change="ctx.onChange"
      >
        <template #bodyCell="scope"><slot name="bodyCell" v-bind="scope" /></template>
      </a-table>
    </a-card>
    <JsonPreview v-model:open="ctx.detailOpen.value" :data="ctx.current.value" />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { message } from 'ant-design-vue'
import SearchBar from '../../components/SearchBar.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import JsonPreview from '../../components/JsonPreview.vue'
import { collectionApi } from '../../api/assets'
import type { useAssetList } from './useAssetList'

const props = defineProps<{ ctx: ReturnType<typeof useAssetList>; columns: Record<string, unknown>[] }>()

const allSelected = computed(() => props.ctx.selectedRowKeys.value.length >= props.ctx.total.value && props.ctx.total.value > 0)

async function selectAll() {
  try {
    const query = props.ctx.buildQuery()
    query.page = 1
    query.size = props.ctx.total.value
    const data = await collectionApi.list(props.ctx.namespace, query)
    const allIds = (data.items || []).map((r: any) => String(r._id))
    props.ctx.selectedRowKeys.value = allIds
    message.success(`已全选 ${allIds.length} 条`)
  } catch (e) {
    message.error('全选失败: ' + (e instanceof Error ? e.message : String(e)))
  }
}
</script>
