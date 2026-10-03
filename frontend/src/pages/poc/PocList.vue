<template>
  <PageContainer :title="translate('ui.m_45f84bbf818e')" kicker="PoC" :description="translate('ui.m_da020cd5ec55')">
    <template #extra>
      <a-space>
        <a-upload :before-upload="beforeImport" :show-upload-list="false" accept=".py">
          <a-button type="primary" :loading="importing">{{ translate('ui.m_791685dda5ef') }}</a-button>
        </a-upload>
        <a-upload :before-upload="beforeBatch" :show-upload-list="false" accept=".zip">
          <a-button :loading="batching">{{ translate('ui.m_d3d5271575f3') }}</a-button>
        </a-upload>
        <a-button @click="downloadTemplate">{{ translate('ui.m_4d920f6e3b9f') }}</a-button>
        <ConfirmAction type="default" :title="translate('ui.m_2224d13a3181')" @confirm="sync">{{ translate('ui.m_415cf936e93c') }}</ConfirmAction>
        <ConfirmAction danger type="default" :title="translate('ui.m_19b4ffabad43')" @confirm="clearAll">{{ translate('ui.m_1ef3de06b32e') }}</ConfirmAction>
      </a-space>
    </template>
    <a-alert type="warning" show-icon style="margin-bottom: 12px"
      :message="translate('ui.m_1d714761d9ec')" />
    <a-space style="margin-bottom: 12px" v-if="selectedRowKeys.length">
      <ConfirmAction danger type="primary" :title="translate('ui.m_399d04574666')" @confirm="removeSelected">{{ translate('ui.m_b2a2890c8d6e') }}{{ selectedRowKeys.length }})</ConfirmAction>
    </a-space>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_86a03bd28b9c')"><a-input v-model:value="query.plugin_name" allow-clear placeholder="plugin id" /></a-form-item>
      <a-form-item :label="translate('ui.m_c131777b2f34')"><a-input v-model:value="query.app_name" allow-clear :placeholder="translate('ui.m_c131777b2f34')" /></a-form-item>
      <a-form-item :label="translate('ui.m_cb1049ef7a06')"><a-input v-model:value="query.vul_name" allow-clear :placeholder="translate('ui.m_f9d4d157ae40')" /></a-form-item>
      <a-form-item :label="translate('ui.m_0d12cbd6562b')"><a-select v-model:value="query.plugin_type" allow-clear style="width: 120px" :options="typeOptions" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <AppTable :columns="columns" :data="items" :loading="loading" :page="query.page" :size="query.size" :total="total" @change="changePage"
        :row-selection="{ selectedRowKeys, onChange: onSelectChange }" row-key="_id">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'plugin_name'"><CopyText :text="String(record.plugin_name || '')" /></template>
          <template v-else-if="column.key === 'plugin_type'"><a-tag :color="record.plugin_type === 'brute' ? 'orange' : 'blue'">{{ record.plugin_type || '-' }}</a-tag></template>
          <template v-else-if="column.key === 'source'">
            <a-tag :color="record.source === 'imported' ? 'green' : 'default'">{{ record.source === 'imported' ? translate('ui.m_576d81bb0631') : translate('ui.m_95e35aabd9a9') }}</a-tag>
            <a-tag v-if="record.poc_format" :color="record.poc_format === 'npoc' ? 'blue' : 'purple'" style="margin-left:4px">{{ record.poc_format }}</a-tag>
          </template>
          <template v-else-if="column.key === 'action'"><a-button type="link" size="small" @click="showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button></template>
        </template>
      </AppTable>
    </a-card>
    <JsonPreview v-model:open="detailOpen" :data="current" />
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import JsonPreview from '../../components/JsonPreview.vue'
import { pocApi } from '../../api/poc'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const detailOpen = ref(false)
const current = ref<RowRecord>({})
const importing = ref(false)
const batching = ref(false)
const selectedRowKeys = ref<string[]>([])
const query = reactive({ page: 1, size: 10, order: '-_id', plugin_name: '', app_name: '', vul_name: '', plugin_type: undefined as string | undefined })

const typeOptions = [
  { label: 'PoC', value: 'poc' },
  { get label() { return translate('ui.m_caeca5ec8eeb') }, value: 'brute' }
]
const columns = [
  { get title() { return translate('ui.m_86a03bd28b9c') }, key: 'plugin_name', ellipsis: true },
  { get title() { return translate('ui.m_c131777b2f34') }, dataIndex: 'app_name', key: 'app_name', width: 150, ellipsis: true },
  { get title() { return translate('ui.m_ab2f31f30acf') }, dataIndex: 'scheme', key: 'scheme', width: 120 },
  { get title() { return translate('ui.m_cb1049ef7a06') }, dataIndex: 'vul_name', key: 'vul_name', ellipsis: true },
  { get title() { return translate('ui.m_0d12cbd6562b') }, key: 'plugin_type', width: 90 },
  { get title() { return translate('ui.m_a488e93d69cc') }, key: 'source', width: 130 },
  { get title() { return translate('ui.m_0a5f9a892960') }, dataIndex: 'update_date', key: 'update_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 80 }
]

async function load() {
  loading.value = true
  try {
    const data = await pocApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.plugin_name = ''; query.app_name = ''; query.vul_name = ''; query.plugin_type = undefined; query.page = 1; load() }
function changePage(page: number, size: number) { query.page = page; query.size = size; load() }
function showDetail(record: RowRecord) { current.value = record; detailOpen.value = true }
async function sync() {
  try { const r = await pocApi.sync(); message.success(translate('ui.m_5ac1d0946bbf', { p0: (r.plugin_cnt) })); load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function clearAll() {
  try { const r = await pocApi.clear(); message.success(translate('ui.m_883fad515312', { p0: (r.delete_cnt) })); load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
function onSelectChange(keys: (string | number)[]) { selectedRowKeys.value = keys.map(String) }
function beforeImport(file: File) {
  importing.value = true
  pocApi.importFile(file)
    .then((r: any) => {
      if (r.code === 200) message.success(translate('ui.m_e01c9a2bc5e5', { p0: (r.data?.plugin_name), p1: (r.data?.poc_format === 'npoc' ? 'npoc 结构，进内核扫描' : '脚本，供 AI 检索') }))
      else message.error(r.message || translate('ui.m_01aaebc96af1'))
      load()
    })
    .catch(e => message.error(String(e)))
    .finally(() => { importing.value = false })
  return false
}
function beforeBatch(file: File) {
  batching.value = true
  pocApi.batchImport(file)
    .then((r: any) => {
      if (r.code === 200) message.success(translate('ui.m_834b0edb9c18', { p0: (r.data?.success), p1: (r.data?.skipped), p2: (r.data?.failed) }))
      else message.error(r.message || translate('ui.m_61e969d9d07d'))
      load()
    })
    .catch(e => message.error(String(e)))
    .finally(() => { batching.value = false })
  return false
}
function downloadTemplate() { window.open(pocApi.templateUrl(), '_blank') }
async function removeSelected() {
  try { const r = await pocApi.remove(selectedRowKeys.value); message.success(translate('ui.m_61053369b9c0', { p0: (r.deleted) })); selectedRowKeys.value = []; load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
onMounted(load)
</script>
