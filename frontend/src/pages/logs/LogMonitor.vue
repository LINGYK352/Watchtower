<template>
  <PageContainer :title="translate('ui.m_74f80eb72df3')" kicker="Log Monitor" :description="translate('ui.m_ebe30d1f64ad')">
    <template #extra>
      <a-space>
        <a-button @click="openMyReports"><MessageOutlined /> {{ translate('ui.m_b1776ef7a9fc') }}<a-badge v-if="myReplyCount" :count="myReplyCount" :offset="[6,-2]" /></a-button>
        <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
        <a-button @click="openRetention">{{ translate('ui.m_44078f405658') }}</a-button>
        <ConfirmAction danger type="default" :title="translate('ui.m_87ef83205ba7')" @confirm="clearAll">{{ translate('ui.m_1ef3de06b32e') }}</ConfirmAction>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_5953fc09384f')" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="ERROR" :value="stat.ERROR" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="WARNING" :value="stat.WARNING" :value-style="{ color: '#d46b08' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="CRITICAL" :value="stat.CRITICAL" :value-style="{ color: '#a8071a' }" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_3d9d02e83d39')"><a-select v-model:value="query.level" allow-clear style="width: 130px" :options="levelOptions" /></a-form-item>
      <a-form-item :label="translate('ui.m_9bfb43ada1f9')"><a-select v-model:value="query.process_type" allow-clear style="width: 130px" :options="processOptions" /></a-form-item>
      <a-form-item :label="translate('ui.m_b07e5088eafa')"><a-input v-model:value="query.module" allow-clear :placeholder="translate('ui.m_a6e48adc26d6')" /></a-form-item>
      <a-form-item :label="translate('ui.m_1f7f0db90f93')"><a-input v-model:value="query.message" allow-clear :placeholder="translate('ui.m_b97249cc8c2d')" /></a-form-item>
    </SearchBar>

    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px">
        <ConfirmAction danger type="primary" :disabled="!selectedRowKeys.length" :title="translate('ui.m_278d5f2da09f')" @confirm="removeSelected">{{ translate('ui.m_469f67cf665e') }}{{ selectedRowKeys.length ? ` (${selectedRowKeys.length})` : '' }}</ConfirmAction>
        <a-button :disabled="!selectedRowKeys.length" @click="openReport"><CloudUploadOutlined /> {{ translate('ui.m_279d607a8f0f') }}{{ selectedRowKeys.length ? ` (${selectedRowKeys.length})` : '' }}</a-button>
      </a-space>
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination"
        :scroll="{ x: 'max-content' }" size="middle" bordered
        :row-selection="{ selectedRowKeys, onChange: onSelectChange }" @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'level'"><a-tag :color="levelColor(String(record.level))">{{ record.level }}</a-tag></template>
          <template v-else-if="column.key === 'process_type'"><a-tag>{{ record.process_type || '-' }}</a-tag></template>
          <template v-else-if="column.key === 'loc'">{{ record.module }}:{{ record.lineno }}</template>
          <template v-else-if="column.key === 'message'"><span class="log-msg">{{ record.message }}</span></template>
          <template v-else-if="column.key === 'action'">
            <a-button type="link" size="small" @click="showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-drawer v-model:open="detailOpen" :title="translate('ui.m_77af343f1fb7')" width="55%">
      <a-descriptions :column="1" size="small" bordered>
        <a-descriptions-item :label="translate('ui.m_8b6ff498515b')">{{ current.save_date }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_3d9d02e83d39')"><a-tag :color="levelColor(String(current.level))">{{ current.level }}</a-tag></a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_9bfb43ada1f9')">{{ current.process_type }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_1fb4d574da92')">{{ current.module }}:{{ current.lineno }} ({{ current.func }})</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_e87d9f23a3f5')">{{ current.host }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_7a688306423b')"><pre class="log-pre">{{ current.message }}</pre></a-descriptions-item>
        <a-descriptions-item v-if="current.exc_info" :label="translate('ui.m_febcfbc22f89')"><pre class="log-pre">{{ current.exc_info }}</pre></a-descriptions-item>
      </a-descriptions>
    </a-drawer>

    <a-modal v-model:open="retentionOpen" :title="translate('ui.m_04a0c438902d')" :confirm-loading="retentionSaving" @ok="saveRetention" :ok-text="translate('ui.m_a3030bf8f16d')" :cancel-text="translate('ui.m_2cd0f3be8738')">
      <p style="color: #888; margin-bottom: 16px">{{ translate('ui.m_c9d86e7a3247') }}</p>
      <a-form layout="horizontal" :label-col="{ span: 10 }" :wrapper-col="{ span: 14 }">
        <a-form-item v-for="(item, key) in retention" :key="key" :label="item.label">
          <a-input-number v-model:value="item.days" :min="1" :addon-after="translate('ui.m_49da61ceeea2')" style="width: 160px" />
          <span style="color: #aaa; margin-left: 8px">{{ translate('ui.m_844b8cc8dff7') }} {{ item.default_days }} {{ translate('ui.m_49da61ceeea2') }}</span>
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal v-model:open="reportOpen" :title="translate('ui.m_ce595c300fc2')" :confirm-loading="reporting"
      @ok="submitReport" :ok-text="translate('ui.m_9e07e3c0532d')" :cancel-text="translate('ui.m_2cd0f3be8738')" width="640px">
      <a-alert type="info" show-icon style="margin-bottom:12px"
        :message="translate('ui.m_7d84631b1da0')"
        :description="translate('ui.m_07b8f59c9080')" />
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_65c7d4155475')">
          <a-textarea v-model:value="reportDesc" :rows="3"
            :placeholder="translate('ui.m_9d3ce37cb253')" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_e161fa2331e4', { p0: (selectedRowKeys.length) })">
          <pre class="log-pre" style="max-height:220px;background:#f6f8fa;padding:10px;border-radius:6px">{{ reportPreview }}</pre>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 我的上报：本用户上传过的报错 + 开发者回复/修复进展 -->
    <a-drawer v-model:open="myOpen" :title="translate('ui.m_b1776ef7a9fc')" width="640" @open="loadMyReports">
      <a-spin :spinning="myLoading">
        <a-empty v-if="!myReports.length" :description="translate('ui.m_3b8624c5b766')" />
        <div v-for="r in myReports" :key="r.id" class="mr-card">
          <div class="mr-head">
            <span class="mr-ts">{{ r.ts }}</span>
            <a-tag :color="r.reply ? 'green' : (r.handled ? 'blue' : 'orange')">
              {{ r.reply ? translate('ui.m_6e764af4b09d') : (r.handled ? translate('ui.m_59f6c8369293') : translate('ui.m_999a459c3f3f')) }}
            </a-tag>
            <span v-if="r.version" class="mr-ver">{{ r.version }}</span>
          </div>
          <div class="mr-desc">{{ r.description || translate('ui.m_b30520db7512') }}</div>
          <pre v-if="r.log_preview" class="mr-log">{{ r.log_preview }}{{ r.log_len > 200 ? ' …' : '' }}</pre>
          <div v-if="r.reply" class="mr-reply">
            <div class="mr-reply-hd">{{ translate('ui.m_a96f1e40bb1e') }}<span v-if="r.fix_version" class="mr-fix">{{ translate('ui.m_9b1d46185c46') }}{{ r.fix_version }}</span>
              <span v-if="r.replied_at" class="mr-rat">{{ r.replied_at }}</span></div>
            <div class="mr-reply-body">{{ r.reply }}</div>
          </div>
          <div v-else class="mr-noreply">{{ translate('ui.m_25e740c08405') }}</div>
        </div>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import { CloudUploadOutlined, MessageOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { logMonitorApi, type LogStat, type LogRetention } from '../../api/logMonitor'
import { reportError, getMyReports, type MyReport } from '../../api/about'
import { APP_VERSION } from '../../config/brand'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const selectedRowKeys = ref<string[]>([])
const detailOpen = ref(false)
const current = ref<RowRecord>({})
const stat = reactive<LogStat>({ ERROR: 0, WARNING: 0, CRITICAL: 0, total: 0 })
const query = reactive({ page: 1, size: 15, order: '-_id', level: undefined as string | undefined, process_type: undefined as string | undefined, module: '', message: '' })

const levelOptions = [
  { label: 'ERROR', value: 'ERROR' },
  { label: 'WARNING', value: 'WARNING' },
  { label: 'CRITICAL', value: 'CRITICAL' }
]
const processOptions = [
  { label: 'Web', value: 'web' },
  { label: 'Scheduler', value: 'scheduler' },
  { label: 'Worker', value: 'worker' }
]
const columns = [
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', key: 'save_date', width: 180 },
  { get title() { return translate('ui.m_3d9d02e83d39') }, key: 'level', width: 100 },
  { get title() { return translate('ui.m_9bfb43ada1f9') }, key: 'process_type', width: 100 },
  { get title() { return translate('ui.m_1fb4d574da92') }, key: 'loc', width: 220, ellipsis: true },
  { get title() { return translate('ui.m_7a688306423b') }, key: 'message', ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 80, fixed: 'right' }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

function levelColor(level: string) {
  return ({ ERROR: 'red', CRITICAL: 'magenta', WARNING: 'orange' } as Record<string, string>)[level] || 'default'
}
async function load() {
  loading.value = true
  selectedRowKeys.value = []
  try {
    const data = await logMonitorApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
async function loadStat() {
  try { Object.assign(stat, await logMonitorApi.stat()) } catch { /* 统计失败忽略 */ }
}
function loadAll() { load(); loadStat() }
function reset() { query.level = undefined; query.process_type = undefined; query.module = ''; query.message = ''; query.page = 1; loadAll() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 15; load() }
function onSelectChange(keys: (string | number)[]) { selectedRowKeys.value = keys.map(String) }
function showDetail(record: RowRecord) { current.value = record; detailOpen.value = true }
async function removeSelected() {
  try { await logMonitorApi.delete(selectedRowKeys.value); message.success(translate('ui.m_077a6d37719a')); loadAll() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function clearAll() {
  try { const r = await logMonitorApi.clear(); message.success(translate('ui.m_228efe70b702', { p0: (r.delete_cnt) })); loadAll() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}

const retentionOpen = ref(false)
const retentionSaving = ref(false)
const retention = ref<LogRetention>({})
async function openRetention() {
  retentionOpen.value = true
  try { retention.value = await logMonitorApi.getRetention() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function saveRetention() {
  retentionSaving.value = true
  try {
    const updates: Record<string, number> = {}
    Object.entries(retention.value).forEach(([k, v]) => { updates[k] = v.days })
    retention.value = await logMonitorApi.setRetention(updates)
    message.success(translate('ui.m_123e648594da'))
    retentionOpen.value = false
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    retentionSaving.value = false
  }
}
// —— 报错上传到云端 ——
const reportOpen = ref(false)
const reporting = ref(false)
const reportDesc = ref('')
function _selectedLogs(): RowRecord[] {
  const keys = new Set(selectedRowKeys.value)
  return items.value.filter(r => keys.has(String(r._id)))
}
const reportPreview = computed(() => {
  return _selectedLogs().map(r =>
    `[${r.save_date}] ${r.level} ${r.module}:${r.lineno} (${r.process_type})\n${r.message}` +
    (r.exc_info ? `\n${r.exc_info}` : '')
  ).join('\n\n---\n\n') || translate('ui.m_0cd60fe760af')
})
function openReport() {
  if (!selectedRowKeys.value.length) { message.warning(translate('ui.m_25606f92bce4')); return }
  reportDesc.value = ''
  reportOpen.value = true
}
async function submitReport() {
  const logContent = reportPreview.value
  if (!reportDesc.value.trim() && !logContent.trim()) { message.warning(translate('ui.m_0b7f9bff24a8')); return }
  reporting.value = true
  try {
    await reportError({ description: reportDesc.value.trim(), log_content: logContent, version: APP_VERSION })
    message.success(translate('ui.m_7889f6d75145'))
    reportOpen.value = false
  } catch (e) {
    message.error(e instanceof Error ? e.message : translate('ui.m_219481a6dde7'))
  } finally {
    reporting.value = false
  }
}

// —— 我的上报（本用户上传过的报错 + 开发者回复）——
const myOpen = ref(false)
const myLoading = ref(false)
const myReports = ref<MyReport[]>([])
const myReplyCount = ref(0)
async function loadMyReports() {
  myLoading.value = true
  try {
    const d = await getMyReports()
    myReports.value = d.reports || []
    myReplyCount.value = myReports.value.filter(r => r.reply).length
  } catch { /* 未激活/分发系统不可达时静默降级空 */ }
  finally { myLoading.value = false }
}
function openMyReports() { myOpen.value = true; loadMyReports() }
// 进页轻量拉一次，只为在「我的上报」按钮上显示未读回复角标（失败静默）
async function _probeReplies() {
  try {
    const d = await getMyReports()
    myReplyCount.value = (d.reports || []).filter(r => r.reply).length
  } catch { /* ignore */ }
}

onMounted(() => { loadAll(); _probeReplies() })
</script>

<style scoped>
.log-msg { display: inline-block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; }
.log-pre { white-space: pre-wrap; word-break: break-all; font-family: monospace; font-size: 12px; margin: 0; max-height: 400px; overflow: auto; }
/* 我的上报卡片 */
.mr-card { border: 1px solid var(--dt-line, #eee); border-radius: 8px; padding: 12px; margin-bottom: 12px; }
.mr-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.mr-ts { color: #8a94a6; font-size: 12px; }
.mr-ver { color: #8a94a6; font-size: 12px; margin-left: auto; }
.mr-desc { font-size: 13px; margin-bottom: 6px; }
.mr-log { white-space: pre-wrap; word-break: break-all; font-family: monospace; font-size: 11px; background: #f6f8fa; padding: 8px; border-radius: 6px; margin: 0 0 8px; max-height: 140px; overflow: auto; }
.mr-reply { border-left: 3px solid #52c41a; background: rgba(82,196,26,.06); border-radius: 0 6px 6px 0; padding: 8px 10px; }
.mr-reply-hd { font-weight: 600; color: #389e0d; font-size: 13px; display: flex; align-items: center; gap: 8px; }
.mr-fix { background: #52c41a; color: #fff; font-size: 11px; padding: 0 6px; border-radius: 3px; font-weight: 400; }
.mr-rat { color: #8a94a6; font-size: 11px; font-weight: 400; margin-left: auto; }
.mr-reply-body { font-size: 13px; margin-top: 4px; white-space: pre-wrap; word-break: break-word; }
.mr-noreply { color: #8a94a6; font-size: 12px; }
</style>
