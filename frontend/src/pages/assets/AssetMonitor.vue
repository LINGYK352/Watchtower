<template>
  <PageContainer :title="translate('ui.m_cad3d4078857')" kicker="Monitor" :description="translate('ui.m_b83c692c37f1')">
    <template #extra>
      <a-space>
        <a-button type="primary" @click="openAdd('domain')">{{ translate('ui.m_f5262812761f') }}</a-button>
        <a-button @click="openAdd('site')">{{ translate('ui.m_137e364e3583') }}</a-button>
        <a-button @click="openAdd('wih')">{{ translate('ui.m_7933eb295d73') }}</a-button>
      </a-space>
    </template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_d44e9b3d3b31')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_40181b1f6500')" /></a-form-item>
      <a-form-item :label="translate('ui.m_222952431147')"><a-input v-model:value="query.domain" allow-clear :placeholder="translate('ui.m_639fd656b790')" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
          <template v-else-if="column.key === 'interval'">{{ humanInterval(Number(record.interval)) }}</template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <ConfirmAction v-if="record.status === 'running'" :title="translate('ui.m_234e35d18e37')" @confirm="stop(String(record._id))">{{ translate('ui.m_ca4d973c0b00') }}</ConfirmAction>
              <ConfirmAction v-else :title="translate('ui.m_cf98c6fa5df9')" @confirm="recover(String(record._id))">{{ translate('ui.m_e0534b8a4e46') }}</ConfirmAction>
              <ConfirmAction danger :title="translate('ui.m_a74103363e10')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" :title="addTitle" @ok="submitAdd" :confirm-loading="adding" width="520px">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_40181b1f6500')"><a-input v-model:value="form.name" :placeholder="translate('ui.m_47d95068555b')" /></a-form-item>
        <a-form-item :label="translate('ui.m_b17cf8a23eae')" required>
          <a-select v-model:value="form.scope_id" :options="scopeOptions" :placeholder="translate('ui.m_c63291bc3828')" show-search :filter-option="filterScope" />
        </a-form-item>
        <a-form-item v-if="addType === 'domain'" :label="translate('ui.m_639fd656b790')" required>
          <a-textarea v-model:value="form.domain" :rows="2" :placeholder="translate('ui.m_b49d6d15409f')" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_3244500e8eb1')"><a-input-number v-model:value="intervalHours" :min="6" style="width: 100%" /></a-form-item>
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
import ConfirmAction from '../../components/ConfirmAction.vue'
import { schedulerApi } from '../../api/scheduler'
import { assetScopeApi } from '../../api/scope'
import type { RowRecord, SelectOption } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', domain: '' })

const columns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_222952431147') }, dataIndex: 'domain', key: 'domain', ellipsis: true },
  { get title() { return translate('ui.m_b17cf8a23eae') }, dataIndex: 'scope_id', key: 'scope_id', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_4f5df723d99d') }, key: 'interval', width: 100 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 90 },
  { get title() { return translate('ui.m_053641ca4902') }, dataIndex: 'run_number', key: 'run_number', width: 90 },
  { get title() { return translate('ui.m_bdedfc1bb069') }, dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 170 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

function humanInterval(sec: number) { return sec ? `${Math.round(sec / 3600)}h` : '-' }
async function load() {
  loading.value = true
  try {
    const data = await schedulerApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.domain = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
async function stop(id: string) { try { await schedulerApi.stop(id); message.success(translate('ui.m_f006455e3baf')); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await schedulerApi.recover(id); message.success(translate('ui.m_3617f737f437')); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await schedulerApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }

/* 新建监控 */
const addOpen = ref(false)
const adding = ref(false)
const addType = ref<'domain' | 'site' | 'wih'>('domain')
const intervalHours = ref(24)
const scopeOptions = ref<SelectOption[]>([])
const form = reactive({ name: '', scope_id: undefined as string | undefined, domain: '' })
const addTitle = computed(() => ({ get domain() { return translate('ui.m_7d1b37535de1') }, get site() { return translate('ui.m_04731448e21d') }, get wih() { return translate('ui.m_687e5d251d36') } } as Record<string, string>)[addType.value])
function filterScope(input: string, option: SelectOption) { return String(option.label).toLowerCase().includes(input.toLowerCase()) }
async function loadScopes() {
  try {
    const data = await assetScopeApi.list({ page: 1, size: 1000 })
    scopeOptions.value = (data.items || []).map(s => ({ label: String(s.name), value: String(s._id) }))
  } catch { /* 忽略 */ }
}
function openAdd(type: 'domain' | 'site' | 'wih') {
  addType.value = type; form.name = ''; form.scope_id = undefined; form.domain = ''; intervalHours.value = 24
  addOpen.value = true
  if (!scopeOptions.value.length) loadScopes()
}
async function submitAdd() {
  if (!form.scope_id) return message.warning(translate('ui.m_432829f0ba09'))
  if (addType.value === 'domain' && !form.domain) return message.warning(translate('ui.m_b64db8ae0723'))
  adding.value = true
  const interval = intervalHours.value * 3600
  try {
    if (addType.value === 'domain') await schedulerApi.add({ scope_id: form.scope_id, domain: form.domain, interval, name: form.name || undefined })
    else if (addType.value === 'site') await schedulerApi.addSiteMonitor({ scope_id: form.scope_id, interval, name: form.name || undefined })
    else await schedulerApi.addWihMonitor({ scope_id: form.scope_id, interval, name: form.name || undefined })
    message.success(translate('ui.m_80bfa30db209')); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
onMounted(load)
</script>
