<template>
  <PageContainer :title="translate('ui.m_8c09564f938a')" kicker="GitHub" :description="translate('ui.m_d11d67c21883')">
    <template #extra><a-button type="primary" @click="openAdd">{{ translate('ui.m_6bee2372805a') }}</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_2c43cd7db149')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_2c43cd7db149')" /></a-form-item>
      <a-form-item :label="translate('ui.m_884e461647a3')"><a-input v-model:value="query.keyword" allow-clear :placeholder="translate('ui.m_884e461647a3')" /></a-form-item>
      <a-form-item :label="translate('ui.m_6320b4a8722a')"><a-input v-model:value="query.status" allow-clear :placeholder="translate('ui.m_6320b4a8722a')" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
          <template v-else-if="column.key === 'keyword'"><CopyText :text="String(record.keyword || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="viewResult(record)">{{ translate('ui.m_bb7ef73495dd') }}</a-button>
              <ConfirmAction :title="translate('ui.m_12603abe3b26')" @confirm="stop(String(record._id))">{{ translate('ui.m_ca4d973c0b00') }}</ConfirmAction>
              <ConfirmAction danger :title="translate('ui.m_037648c498b6')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" :title="translate('ui.m_93c890d8183d')" @ok="submitAdd" :confirm-loading="adding">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_2c43cd7db149')" required><a-input v-model:value="addForm.name" :placeholder="translate('ui.m_2c43cd7db149')" /></a-form-item>
        <a-form-item :label="translate('ui.m_884e461647a3')" required><a-input v-model:value="addForm.keyword" :placeholder="translate('ui.m_395bda79d892')" /></a-form-item>
      </a-form>
    </a-modal>

    <a-drawer v-model:open="resultOpen" :title="translate('ui.m_40759665c9a1')" width="60%">
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
import { githubTaskApi, githubResultApi } from '../../api/github'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', keyword: '', status: '' })
const addOpen = ref(false)
const adding = ref(false)
const addForm = reactive({ name: '', keyword: '' })

const columns = [
  { get title() { return translate('ui.m_2c43cd7db149') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_884e461647a3') }, key: 'keyword', ellipsis: true },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 100 },
  { get title() { return translate('ui.m_6a9906c79f26') }, dataIndex: 'start_time', key: 'start_time', width: 170 },
  { get title() { return translate('ui.m_f50276449943') }, dataIndex: 'end_time', key: 'end_time', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 180 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

async function load() {
  loading.value = true
  try {
    const data = await githubTaskApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.keyword = ''; query.status = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
function openAdd() { addForm.name = ''; addForm.keyword = ''; addOpen.value = true }
async function submitAdd() {
  if (!addForm.name || !addForm.keyword) return message.warning(translate('ui.m_c3f3d02e46a2'))
  adding.value = true
  try { await githubTaskApi.add({ ...addForm }); message.success(translate('ui.m_80bfa30db209')); addOpen.value = false; load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function stop(id: string) { try { await githubTaskApi.stop([id]); message.success(translate('ui.m_6be0ef761b81')); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await githubTaskApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }

/* 结果抽屉 */
const resultOpen = ref(false)
const resultLoading = ref(false)
const results = ref<RowRecord[]>([])
const resultTotal = ref(0)
const resultQuery = reactive({ page: 1, size: 10, order: '-_id', github_task_id: '' })
const resultColumns = [
  { get title() { return translate('ui.m_89b2ecbe1f09') }, key: 'repo', ellipsis: true },
  { get title() { return translate('ui.m_77e1ea5c5688') }, key: 'path', ellipsis: true },
  { get title() { return translate('ui.m_7a688306423b') }, dataIndex: 'human_content', key: 'human_content', ellipsis: true }
]
const resultPagination = computed(() => ({ current: resultQuery.page, pageSize: resultQuery.size, total: resultTotal.value, showSizeChanger: true }))
function viewResult(record: RowRecord) { resultQuery.github_task_id = String(record._id); resultQuery.page = 1; resultOpen.value = true; loadResult() }
async function loadResult() {
  resultLoading.value = true
  try {
    const data = await githubResultApi.list(resultQuery)
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
