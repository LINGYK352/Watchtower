<template>
  <PageContainer :title="translate('ui.m_f5ef9152022d')" kicker="Policy" :description="translate('ui.m_df2e195bb5d4')">
    <template #extra><a-button type="primary" @click="router.push('/policy/new')">{{ translate('ui.m_bb090baf358c') }}</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_172562d5ef17')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_a903683f81f6')" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="router.push(`/policy/${record._id}`)">{{ translate('ui.m_051836569928') }}</a-button>
              <ConfirmAction danger :title="translate('ui.m_00747b6d7d06')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { policyApi } from '../../api/policy'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '' })

const columns = [
  { get title() { return translate('ui.m_172562d5ef17') }, dataIndex: 'name', key: 'name', width: 220, ellipsis: true },
  { get title() { return translate('ui.m_dc2ba467fc7a') }, dataIndex: 'desc', key: 'desc', ellipsis: true },
  { get title() { return translate('ui.m_0a5f9a892960') }, dataIndex: 'update_date', key: 'update_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 130 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

async function load() {
  loading.value = true
  try {
    const data = await policyApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
async function remove(id: string) { try { await policyApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>
