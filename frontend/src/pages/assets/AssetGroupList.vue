<template>
  <PageContainer :title="translate('ui.m_27f9488e7635')" kicker="Asset Group" :description="translate('ui.m_738f798b803b')">
    <template #extra><a-button type="primary" @click="openAdd">{{ translate('ui.m_3d49d9fcb6d1') }}</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_c72c09f05685')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_d7e266bdc806')" /></a-form-item>
      <a-form-item :label="translate('ui.m_ae72b532f4b8')"><a-input v-model:value="query.scope" allow-clear :placeholder="translate('ui.m_c3f497207f2e')" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'scope_type'"><a-tag>{{ record.scope_type || 'DOMAIN' }}</a-tag></template>
          <template v-else-if="column.key === 'scope'"><CopyText :text="String(record.scope || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="router.push(`/asset-groups/${record._id}`)">{{ translate('ui.m_f88182fcd575') }}</a-button>
              <ConfirmAction danger :title="translate('ui.m_96b002a9670d')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" :title="translate('ui.m_13912b488886')" @ok="submitAdd" :confirm-loading="adding" width="560px">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_d7e266bdc806')" required><a-input v-model:value="form.name" :placeholder="translate('ui.m_d7e266bdc806')" /></a-form-item>
        <a-form-item :label="translate('ui.m_c3f497207f2e')" required><a-textarea v-model:value="form.scope" :rows="3" :placeholder="translate('ui.m_8e14d548c0ad')" /></a-form-item>
        <a-form-item :label="translate('ui.m_4125cac07f73')"><a-textarea v-model:value="form.black_scope" :rows="2" :placeholder="translate('ui.m_b82a453f9e53')" /></a-form-item>
        <a-form-item :label="translate('ui.m_271ad2a02e79')">
          <a-radio-group v-model:value="form.scope_type">
            <a-radio value="DOMAIN">{{ translate('ui.m_222952431147') }}</a-radio>
            <a-radio value="IP">IP</a-radio>
          </a-radio-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { assetScopeApi } from '../../api/scope'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', scope: '' })

const columns = [
  { get title() { return translate('ui.m_c72c09f05685') }, dataIndex: 'name', key: 'name', width: 200, ellipsis: true },
  { get title() { return translate('ui.m_0d12cbd6562b') }, key: 'scope_type', width: 90 },
  { get title() { return translate('ui.m_ae72b532f4b8') }, key: 'scope', ellipsis: true },
  { get title() { return translate('ui.m_174ec5a4ab6a') }, dataIndex: 'black_scope', key: 'black_scope', ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 130 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

async function load() {
  loading.value = true
  try {
    const data = await assetScopeApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.scope = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }

const addOpen = ref(false)
const adding = ref(false)
const form = reactive({ name: '', scope: '', black_scope: '', scope_type: 'DOMAIN' })
function openAdd() { form.name = ''; form.scope = ''; form.black_scope = ''; form.scope_type = 'DOMAIN'; addOpen.value = true }
async function submitAdd() {
  if (!form.name || !form.scope) return message.warning(translate('ui.m_19a176c2cfbf'))
  adding.value = true
  try { await assetScopeApi.add({ ...form }); message.success(translate('ui.m_80bfa30db209')); addOpen.value = false; load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function remove(id: string) { try { await assetScopeApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>
