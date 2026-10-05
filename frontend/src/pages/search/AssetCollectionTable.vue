<template>
  <div>
    <SearchBar :model="ctx.filters" @search="ctx.load" @reset="ctx.reset">
      <slot name="filters" />
    </SearchBar>
    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px">
        <a-button @click="ctx.exportCurrent">{{ translate('ui.m_76420433f22d') }}</a-button>
        <a-button v-if="ctx.total.value > 0 && !allSelected" @click="selectAll">{{ translate('ui.m_fb581b30118e') }}{{ ctx.total.value }})</a-button>
        <a-button v-if="allSelected" @click="ctx.selectedRowKeys.value = []">{{ translate('ui.m_f4d4bae588c4') }}</a-button>
        <ConfirmAction v-if="ctx.selectedRowKeys.value.length" danger type="primary" :title="translate('ui.m_af96f361fe7b')" @confirm="ctx.removeSelected">
          {{ translate('ui.m_b2a2890c8d6e') }}{{ ctx.selectedRowKeys.value.length }})
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
import { t as translate } from '../../i18n'

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
    message.success(translate('ui.m_98b8a4c3f7c2', { p0: (allIds.length) }))
  } catch (e) {
    message.error(translate('ui.m_e2d6fd6c718a') + (e instanceof Error ? e.message : String(e)))
  }
}
</script>
