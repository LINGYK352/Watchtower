<template>
  <PageContainer :title="translate('ui.m_b61129b1fbb2')" kicker="Task Schedule" :description="translate('ui.m_91be2cb0d1ea')">
    <template #extra><a-button type="primary" @click="openAdd">{{ translate('ui.m_87bb612bfa59') }}</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_d44e9b3d3b31')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_95ce00d503eb')" /></a-form-item>
      <a-form-item :label="translate('ui.m_57060c88a36b')"><a-input v-model:value="query.target" allow-clear :placeholder="translate('ui.m_57060c88a36b')" /></a-form-item>
      <a-form-item :label="translate('ui.m_ba40014ff496')"><a-select v-model:value="query.schedule_type" allow-clear style="width: 140px" :options="typeOptions" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'target'"><CopyText :text="String(record.target || '')" /></template>
          <template v-else-if="column.key === 'schedule_type'">
            <a-tag :color="record.schedule_type === 'recurrent_scan' ? 'purple' : 'cyan'">{{ record.schedule_type === 'recurrent_scan' ? translate('ui.m_e9bf2c2feae4') : translate('ui.m_6a2b5eb8d433') }}</a-tag>
          </template>
          <template v-else-if="column.key === 'schedule_status'"><StatusTag :value="String(record.schedule_status || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <ConfirmAction v-if="record.schedule_status === 'scheduled'" :title="translate('ui.m_280deeda555e')" @confirm="stop(String(record._id))">{{ translate('ui.m_ca4d973c0b00') }}</ConfirmAction>
              <ConfirmAction v-else :title="translate('ui.m_398c8f70de1d')" @confirm="recover(String(record._id))">{{ translate('ui.m_e0534b8a4e46') }}</ConfirmAction>
              <ConfirmAction danger :title="translate('ui.m_efcd55721c5e')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" :title="translate('ui.m_4bf0c42c2d65')" @ok="submitAdd" :confirm-loading="adding" width="560px">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_d44e9b3d3b31')" required><a-input v-model:value="form.name" :placeholder="translate('ui.m_95ce00d503eb')" /></a-form-item>
        <a-form-item :label="translate('ui.m_57060c88a36b')" required><a-textarea v-model:value="form.target" :rows="2" :placeholder="translate('ui.m_64c5e550a0f8')" /></a-form-item>
        <a-form-item :label="translate('ui.m_93877a087498')" required>
          <a-radio-group v-model:value="form.task_tag">
            <a-radio value="task">{{ translate('ui.m_60d1ef084057') }}</a-radio>
            <a-radio value="risk_cruising">{{ translate('ui.m_7dc02b74d145') }}</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item :label="translate('ui.m_9c8eb75c7e58')" required>
          <a-select v-model:value="form.policy_id" :options="policyOptions" :placeholder="translate('ui.m_62ca1e390e3a')" show-search :filter-option="filterPolicy" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_c5b2429337a3')" required>
          <a-radio-group v-model:value="form.schedule_type">
            <a-radio value="future_scan">{{ translate('ui.m_6a2b5eb8d433') }}</a-radio>
            <a-radio value="recurrent_scan">{{ translate('ui.m_e9bf2c2feae4') }}</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="form.schedule_type === 'future_scan'" :label="translate('ui.m_6a9906c79f26')" required>
          <a-input v-model:value="form.start_date" placeholder="YYYY-MM-DD HH:MM:SS" />
        </a-form-item>
        <a-form-item v-else :label="translate('ui.m_c9657db58a07')" required>
          <a-input v-model:value="form.cron" :placeholder="translate('ui.m_5eee6fea4c91')" />
        </a-form-item>
      </a-form>
    </a-modal>
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
import { taskScheduleApi } from '../../api/taskSchedule'
import { policyApi } from '../../api/policy'
import type { RowRecord, SelectOption } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', target: '', schedule_type: undefined as string | undefined })

const typeOptions = [
  { get label() { return translate('ui.m_f276e9ab1e72') }, value: 'future_scan' },
  { get label() { return translate('ui.m_2bd74a2350e3') }, value: 'recurrent_scan' }
]
const columns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_57060c88a36b') }, key: 'target', ellipsis: true },
  { get title() { return translate('ui.m_9c8eb75c7e58') }, dataIndex: 'policy_name', key: 'policy_name', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'schedule_type', width: 80 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'schedule_status', width: 90 },
  { title: 'Cron', dataIndex: 'cron', key: 'cron', width: 120 },
  { get title() { return translate('ui.m_bdedfc1bb069') }, dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 170 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

async function load() {
  loading.value = true
  try {
    const data = await taskScheduleApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.target = ''; query.schedule_type = undefined; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }

/* 新建 */
const addOpen = ref(false)
const adding = ref(false)
const policyOptions = ref<SelectOption[]>([])
const form = reactive({ name: '', target: '', task_tag: 'task' as 'task' | 'risk_cruising', policy_id: undefined as string | undefined, schedule_type: 'future_scan' as 'future_scan' | 'recurrent_scan', start_date: '', cron: '' })
function filterPolicy(input: string, option: SelectOption) { return String(option.label).toLowerCase().includes(input.toLowerCase()) }
async function loadPolicies() {
  try {
    const data = await policyApi.list({ page: 1, size: 1000 })
    policyOptions.value = (data.items || []).map(p => ({ label: String(p.name), value: String(p._id) }))
  } catch { /* 忽略策略加载失败 */ }
}
function openAdd() {
  form.name = ''; form.target = ''; form.task_tag = 'task'; form.policy_id = undefined
  form.schedule_type = 'future_scan'; form.start_date = ''; form.cron = ''
  addOpen.value = true
  if (!policyOptions.value.length) loadPolicies()
}
async function submitAdd() {
  if (!form.name || !form.target || !form.policy_id) return message.warning(translate('ui.m_7f3ba0c6767e'))
  if (form.schedule_type === 'future_scan' && !form.start_date) return message.warning(translate('ui.m_aefc0bf8b8a4'))
  if (form.schedule_type === 'recurrent_scan' && !form.cron) return message.warning(translate('ui.m_bbc067b4eb88'))
  adding.value = true
  try {
    await taskScheduleApi.add({
      name: form.name, target: form.target, task_tag: form.task_tag, policy_id: form.policy_id,
      schedule_type: form.schedule_type,
      ...(form.schedule_type === 'future_scan' ? { start_date: form.start_date } : { cron: form.cron })
    })
    message.success(translate('ui.m_80bfa30db209')); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function stop(id: string) { try { await taskScheduleApi.stop([id]); message.success(translate('ui.m_f006455e3baf')); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await taskScheduleApi.recover([id]); message.success(translate('ui.m_3617f737f437')); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await taskScheduleApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>
