<template>
  <PageContainer :title="translate('ui.m_a05bcd6b3701')" kicker="GitHub Monitor" :description="translate('ui.m_506cdd4b0b52')">
    <template #extra><a-button type="primary" @click="openAdd">{{ translate('ui.m_5096e19f0798') }}</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_2c43cd7db149')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_2c43cd7db149')" /></a-form-item>
      <a-form-item :label="translate('ui.m_884e461647a3')"><a-input v-model:value="query.keyword" allow-clear :placeholder="translate('ui.m_884e461647a3')" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
          <template v-else-if="column.key === 'keyword'"><CopyText :text="String(record.keyword || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="viewResult(record)">{{ translate('ui.m_bb7ef73495dd') }}</a-button>
              <a-button type="link" size="small" @click="openEdit(record)">{{ translate('ui.m_051836569928') }}</a-button>
              <ConfirmAction v-if="record.status === 'running'" :title="translate('ui.m_234e35d18e37')" @confirm="stop(String(record._id))">{{ translate('ui.m_ca4d973c0b00') }}</ConfirmAction>
              <ConfirmAction v-else :title="translate('ui.m_cf98c6fa5df9')" @confirm="recover(String(record._id))">{{ translate('ui.m_e0534b8a4e46') }}</ConfirmAction>
              <ConfirmAction danger :title="translate('ui.m_a74103363e10')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="editOpen" :title="editId ? translate('ui.m_e6169c59816d') : translate('ui.m_5096e19f0798')" @ok="submit" :confirm-loading="saving">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_2c43cd7db149')" required><a-input v-model:value="form.name" :placeholder="translate('ui.m_2c43cd7db149')" /></a-form-item>
        <a-form-item :label="translate('ui.m_884e461647a3')" required><a-input v-model:value="form.keyword" :placeholder="translate('ui.m_395bda79d892')" /></a-form-item>
        <a-form-item :label="translate('ui.m_c9657db58a07')" required><a-input v-model:value="form.cron" :placeholder="translate('ui.m_ff4f9b02dee3')" /></a-form-item>
      </a-form>
    </a-modal>

    <a-drawer v-model:open="resultOpen" :title="translate('ui.m_386f5cec85e8')" width="60%">
      <a-table :columns="resultColumns" :data-source="results" :loading="resultLoading" row-key="_id" :pagination="resultPagination" size="small" bordered @change="onResultChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'repo'"><CopyText :text="String(record.repo_full_name || '')" /></template>
          <template v-else-if="column.key === 'path'"><CopyText :text="String(record.path || '')" /></template>
        </template>
      </a-table>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import StatusTag from '../../components/StatusTag.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { githubSchedulerApi, githubMonitorResultApi } from '../../api/github'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', keyword: '' })

const columns = [
  { get title() { return translate('ui.m_2c43cd7db149') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_884e461647a3') }, key: 'keyword', ellipsis: true },
  { title: 'Cron', dataIndex: 'cron', key: 'cron', width: 130 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 90 },
  { get title() { return translate('ui.m_053641ca4902') }, dataIndex: 'run_number', key: 'run_number', width: 90 },
  { get title() { return translate('ui.m_bdedfc1bb069') }, dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 240 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

async function load() {
  loading.value = true
  try {
    const data = await githubSchedulerApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.keyword = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }

/* 新建 / 编辑 */
const editOpen = ref(false)
const saving = ref(false)
const editId = ref('')
const form = reactive({ name: '', keyword: '', cron: '' })
function openAdd() { editId.value = ''; form.name = ''; form.keyword = ''; form.cron = '0 0 * * *'; editOpen.value = true }
function openEdit(record: RowRecord) {
  editId.value = String(record._id)
  form.name = String(record.name || ''); form.keyword = String(record.keyword || ''); form.cron = String(record.cron || '')
  editOpen.value = true
}
async function submit() {
  if (!form.name || !form.keyword || !form.cron) return message.warning(translate('ui.m_b257b49b2603'))
  saving.value = true
  try {
    if (editId.value) await githubSchedulerApi.update({ _id: editId.value, ...form })
    else await githubSchedulerApi.add({ ...form })
    message.success(translate('ui.m_1bd91a7d0c53')); editOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { saving.value = false }
}
async function stop(id: string) { try { await githubSchedulerApi.stop([id]); message.success(translate('ui.m_f006455e3baf')); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await githubSchedulerApi.recover([id]); message.success(translate('ui.m_3617f737f437')); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await githubSchedulerApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }

/* 结果抽屉 */
const resultOpen = ref(false)
const resultLoading = ref(false)
const results = ref<RowRecord[]>([])
const resultTotal = ref(0)
const resultQuery = reactive({ page: 1, size: 10, order: '-_id', github_scheduler_id: '' })
const resultColumns = [
  { get title() { return translate('ui.m_89b2ecbe1f09') }, key: 'repo', ellipsis: true },
  { get title() { return translate('ui.m_77e1ea5c5688') }, key: 'path', ellipsis: true },
  { get title() { return translate('ui.m_7a688306423b') }, dataIndex: 'human_content', key: 'human_content', ellipsis: true }
]
const resultPagination = computed(() => ({ current: resultQuery.page, pageSize: resultQuery.size, total: resultTotal.value, showSizeChanger: true }))
function viewResult(record: RowRecord) { resultQuery.github_scheduler_id = String(record._id); resultQuery.page = 1; resultOpen.value = true; loadResult() }
async function loadResult() {
  resultLoading.value = true
  try {
    const data = await githubMonitorResultApi.list(resultQuery)
    results.value = data.items || []
    resultTotal.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    resultLoading.value = false
  }
}
function onResultChange(p: { current?: number; pageSize?: number }) { resultQuery.page = p.current || 1; resultQuery.size = p.pageSize || 10; loadResult() }
onMounted(load)
</script>
