<template>
  <PageContainer :title="translate('ui.m_b1ce859b30ae')" kicker="Access Log" :description="translate('ui.m_382d69513cda')">
    <template #extra>
      <a-space>
        <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
        <a-button @click="openRetention">{{ translate('ui.m_44078f405658') }}</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" class="stat-row">
      <a-col :span="6"><a-card size="small"><a-statistic :title="translate('ui.m_32d7621811d9')" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card size="small"><a-statistic :title="translate('ui.m_ed31fbb483ee')" :value="stat.writes" :value-style="{ color: '#1677ff' }" /></a-card></a-col>
      <a-col :span="6"><a-card size="small"><a-statistic :title="translate('ui.m_70875f128b7c')" :value="stat.today" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card size="small"><a-statistic :title="translate('ui.m_25964c1c523f')" :value="stat.errors" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
    </a-row>

    <a-tabs v-model:activeKey="tab" @change="onTabChange">
      <a-tab-pane key="all" tab="全部访问" />
      <a-tab-pane key="write" tab="操作日志" />
    </a-tabs>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item :label="translate('ui.m_0d0e1a86b3aa')"><a-input v-model:value="query.username" :placeholder="translate('ui.m_1a3f0617d6de')" allow-clear style="width: 140px" /></a-form-item>
      <a-form-item :label="translate('ui.m_c80d519245a7')"><a-input v-model:value="query.path" placeholder="/api/..." allow-clear style="width: 200px" /></a-form-item>
      <a-form-item :label="translate('ui.m_06f7d7341212')"><a-input v-model:value="query.status" :placeholder="translate('ui.m_a8508535095e')" allow-clear style="width: 110px" /></a-form-item>
    </SearchBar>

    <AppTable :columns="columns" :data="rows" :loading="loading"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'method'">
          <a-tag :color="methodColor(record.method)">{{ record.method }}</a-tag>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
        </template>
        <template v-else-if="column.key === 'is_write'">
          <a-tag v-if="record.is_write" color="blue">{{ translate('ui.m_ed31fbb483ee') }}</a-tag>
          <span v-else class="muted">{{ translate('ui.m_7c7a3cda2cb6') }}</span>
        </template>
        <template v-else-if="column.key === 'elapsed'">{{ record.elapsed_ms }}ms</template>
      </template>
    </AppTable>

    <a-modal v-model:open="retentionOpen" :title="translate('ui.m_04a0c438902d')" :confirm-loading="retentionSaving" @ok="saveRetention" :ok-text="translate('ui.m_a3030bf8f16d')" :cancel-text="translate('ui.m_2cd0f3be8738')">
      <p style="color: #888; margin-bottom: 16px">{{ translate('ui.m_c9d86e7a3247') }}</p>
      <a-form layout="horizontal" :label-col="{ span: 10 }" :wrapper-col="{ span: 14 }">
        <a-form-item v-for="(item, key) in retention" :key="key" :label="item.label">
          <a-input-number v-model:value="item.days" :min="1" :addon-after="translate('ui.m_49da61ceeea2')" style="width: 160px" />
          <span style="color: #aaa; margin-left: 8px">{{ translate('ui.m_844b8cc8dff7') }} {{ item.default_days }} {{ translate('ui.m_49da61ceeea2') }}</span>
        </a-form-item>
      </a-form>
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
import { accessLogApi, type AccessLogItem, type AccessLogStat, type LogRetention } from '../../api/accessLog'

const loading = ref(false)
const rows = ref<AccessLogItem[]>([])
const total = ref(0)
const tab = ref('all')
const stat = reactive<AccessLogStat>({ total: 0, writes: 0, today: 0, errors: 0 })
const query = reactive({ username: '', path: '', status: '', page: 1, size: 20 })

const columns = [
  { get title() { return translate('ui.m_22b9f0b66212') }, key: 'method', width: 80 },
  { get title() { return translate('ui.m_c80d519245a7') }, dataIndex: 'path', ellipsis: true },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 80 },
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'is_write', width: 70 },
  { get title() { return translate('ui.m_0d0e1a86b3aa') }, dataIndex: 'username', width: 120 },
  { title: 'IP', dataIndex: 'ip', width: 130 },
  { get title() { return translate('ui.m_e77e3d58b0dc') }, key: 'elapsed', width: 90 },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', width: 160 }
]

function methodColor(m: string) { return { GET: 'default', POST: 'green', PUT: 'orange', DELETE: 'red', PATCH: 'purple' }[m] || 'default' }
function statusColor(s: number) { return s >= 500 ? 'red' : s >= 400 ? 'orange' : s >= 200 && s < 300 ? 'green' : 'default' }

async function loadStat() {
  try { Object.assign(stat, await accessLogApi.stat()) } catch (e) { message.error((e as Error).message || translate('ui.m_bf92c72baa98')) }
}
async function loadList() {
  loading.value = true
  try {
    const res = await accessLogApi.list({
      is_write: tab.value === 'write' ? '1' : undefined,
      username: query.username || undefined, path: query.path || undefined, status: query.status || undefined,
      page: query.page, size: query.size
    })
    rows.value = res.items; total.value = res.total
  } catch (e) { message.error((e as Error).message || translate('ui.m_d1d044826a45')) } finally { loading.value = false }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadList() }
function onReset() { query.username = ''; query.path = ''; query.status = ''; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }
function onTabChange() { query.page = 1; loadList() }

const retentionOpen = ref(false)
const retentionSaving = ref(false)
const retention = ref<LogRetention>({})
async function openRetention() {
  retentionOpen.value = true
  try { retention.value = await accessLogApi.getRetention() }
  catch (e) { message.error((e as Error).message || translate('ui.m_d1d044826a45')) }
}
async function saveRetention() {
  retentionSaving.value = true
  try {
    const updates: Record<string, number> = {}
    Object.entries(retention.value).forEach(([k, v]) => { updates[k] = v.days })
    retention.value = await accessLogApi.setRetention(updates)
    message.success(translate('ui.m_123e648594da'))
    retentionOpen.value = false
  } catch (e) { message.error((e as Error).message || translate('ui.m_6309a3bb5ba4')) } finally { retentionSaving.value = false }
}

onMounted(loadAll)
</script>

<style scoped>
.stat-row { margin-bottom: 16px; }
.muted { color: #aaa; }
</style>
