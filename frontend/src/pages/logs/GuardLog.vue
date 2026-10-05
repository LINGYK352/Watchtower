<template>
  <PageContainer :title="translate('ui.m_aa88061aca8a')" kicker="Guard Log" :description="translate('ui.m_d19626a0e24a')">
    <template #extra>
      <a-space>
        <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
        <a-button @click="sizeOpen = true">{{ translate('ui.m_b4c54bc564ef') }}</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom:16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_b2eedb867dbd')" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_bf33347e3c85')" :value="stat.blocked" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_561817f02529')" :value="stat.allowed" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_330141b9f0e2')" :value="stat.size_mb" suffix="MB" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item :label="translate('ui.m_bb7ef73495dd')">
        <a-select v-model:value="query.allow" style="width:130px" :options="allowOptions" />
      </a-form-item>
      <a-form-item :label="translate('ui.m_47a270081ab2')">
        <a-select v-model:value="query.mode" style="width:120px" :options="modeOptions" />
      </a-form-item>
    </SearchBar>

    <AppTable :columns="columns" :data="rows" :loading="loading"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'allow'">
          <a-tag :color="record.allow ? 'green' : 'red'">{{ record.allow ? translate('ui.m_561817f02529') : translate('ui.m_bf33347e3c85') }}</a-tag>
        </template>
        <template v-else-if="column.key === 'mode'">
          <a-tag :color="pentestModeColor(record.mode)">{{ pentestModeLabel(record.mode) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'method'">
          <a-tag :color="methodColor(record.method)">{{ record.method }}</a-tag>
        </template>
      </template>
    </AppTable>

    <a-modal v-model:open="sizeOpen" :title="translate('ui.m_2665d284fbf4')" :confirm-loading="saving" @ok="saveSize" :ok-text="translate('ui.m_a3030bf8f16d')" :cancel-text="translate('ui.m_2cd0f3be8738')">
      <p style="color:#888;margin-bottom:16px">{{ translate('ui.m_11f2822f9cb5') }} {{ stat.default_size_mb }} MB。<b style="color:#d46b08">{{ translate('ui.m_c64a36d50edc') }}</b></p>
      <a-input-number v-model:value="sizeMb" :min="1" addon-after="MB" style="width:180px" />
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import { logMonitorApi, type GuardLogItem, type GuardLogStat } from '../../api/logMonitor'
import { PENTEST_MODES, pentestModeLabel, pentestModeColor } from '../../api/pentest'

const loading = ref(false)
const rows = ref<GuardLogItem[]>([])
const total = ref(0)
const sizeOpen = ref(false)
const saving = ref(false)
const sizeMb = ref(500)
const stat = reactive<GuardLogStat>({ total: 0, blocked: 0, allowed: 0, size_mb: 500, default_size_mb: 500 })
const query = reactive({ allow: '' as string, mode: '' as string, page: 1, size: 20 })

const allowOptions = [{ get label() { return translate('ui.m_5c55a67935af') }, value: '' }, { get label() { return translate('ui.m_bf33347e3c85') }, value: '0' }, { get label() { return translate('ui.m_561817f02529') }, value: '1' }]
const modeOptions = [{ get label() { return translate('ui.m_5c55a67935af') }, value: '' }, ...PENTEST_MODES.map(m => ({ label: m.label, value: m.value }))]
const columns = [
  { get title() { return translate('ui.m_bb7ef73495dd') }, key: 'allow', width: 80 },
  { get title() { return translate('ui.m_47a270081ab2') }, key: 'mode', width: 80 },
  { get title() { return translate('ui.m_22b9f0b66212') }, key: 'method', width: 90 },
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { get title() { return translate('ui.m_15c58df57646') }, dataIndex: 'level', width: 110 },
  { get title() { return translate('ui.m_f029d9cb4a76') }, dataIndex: 'reason', ellipsis: true },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', width: 160 }
]
function methodColor(m: string) { return ({ GET: 'default', POST: 'green', PUT: 'orange', DELETE: 'red', PATCH: 'purple' } as Record<string, string>)[m] || 'default' }

async function loadStat() {
  try { Object.assign(stat, await logMonitorApi.guardStat()); sizeMb.value = stat.size_mb } catch { /* 忽略 */ }
}
async function loadList() {
  loading.value = true
  try {
    const res = await logMonitorApi.guardList({ allow: query.allow, mode: query.mode, page: query.page, size: query.size })
    rows.value = res.items; total.value = res.total
  } catch (e) { message.error((e as Error).message || translate('ui.m_d1d044826a45')) } finally { loading.value = false }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.allow = ''; query.mode = ''; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }
async function saveSize() {
  saving.value = true
  try { await logMonitorApi.setGuardSize(sizeMb.value); message.success(translate('ui.m_123e648594da')); sizeOpen.value = false; loadAll() }
  catch (e) { message.error((e as Error).message || translate('ui.m_6309a3bb5ba4')) } finally { saving.value = false }
}
onMounted(loadAll)
</script>
