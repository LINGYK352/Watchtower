<template>
  <PageContainer title="日志监测" kicker="Log Monitor" description="监测各组件、模块、代码的报错与启动错误，自动入库(WARNING 及以上)。">
    <template #extra>
      <a-space>
        <a-button @click="openMyReports"><MessageOutlined /> 我的上报<a-badge v-if="myReplyCount" :count="myReplyCount" :offset="[6,-2]" /></a-button>
        <a-button @click="loadAll">刷新</a-button>
        <a-button @click="openRetention">保留设置</a-button>
        <ConfirmAction danger type="default" title="确认清空全部日志？" @confirm="clearAll">清空</ConfirmAction>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="总数" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="ERROR" :value="stat.ERROR" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="WARNING" :value="stat.WARNING" :value-style="{ color: '#d46b08' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="CRITICAL" :value="stat.CRITICAL" :value-style="{ color: '#a8071a' }" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="级别"><a-select v-model:value="query.level" allow-clear style="width: 130px" :options="levelOptions" /></a-form-item>
      <a-form-item label="进程"><a-select v-model:value="query.process_type" allow-clear style="width: 130px" :options="processOptions" /></a-form-item>
      <a-form-item label="模块"><a-input v-model:value="query.module" allow-clear placeholder="文件名" /></a-form-item>
      <a-form-item label="关键词"><a-input v-model:value="query.message" allow-clear placeholder="日志内容" /></a-form-item>
    </SearchBar>

    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px">
        <ConfirmAction danger type="primary" :disabled="!selectedRowKeys.length" title="确认删除选中日志？" @confirm="removeSelected">删除选中{{ selectedRowKeys.length ? ` (${selectedRowKeys.length})` : '' }}</ConfirmAction>
        <a-button :disabled="!selectedRowKeys.length" @click="openReport"><CloudUploadOutlined /> 上传到云端{{ selectedRowKeys.length ? ` (${selectedRowKeys.length})` : '' }}</a-button>
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
            <a-button type="link" size="small" @click="showDetail(record)">详情</a-button>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-drawer v-model:open="detailOpen" title="日志详情" width="55%">
      <a-descriptions :column="1" size="small" bordered>
        <a-descriptions-item label="时间">{{ current.save_date }}</a-descriptions-item>
        <a-descriptions-item label="级别"><a-tag :color="levelColor(String(current.level))">{{ current.level }}</a-tag></a-descriptions-item>
        <a-descriptions-item label="进程">{{ current.process_type }}</a-descriptions-item>
        <a-descriptions-item label="位置">{{ current.module }}:{{ current.lineno }} ({{ current.func }})</a-descriptions-item>
        <a-descriptions-item label="主机">{{ current.host }}</a-descriptions-item>
        <a-descriptions-item label="内容"><pre class="log-pre">{{ current.message }}</pre></a-descriptions-item>
        <a-descriptions-item v-if="current.exc_info" label="堆栈"><pre class="log-pre">{{ current.exc_info }}</pre></a-descriptions-item>
      </a-descriptions>
    </a-drawer>

    <a-modal v-model:open="retentionOpen" title="日志保留设置" :confirm-loading="retentionSaving" @ok="saveRetention" ok-text="保存" cancel-text="取消">
      <p style="color: #888; margin-bottom: 16px">超过保留天数的日志自动删除(MongoDB TTL,运行时即时生效,无需重启)。最少保留 1 天，不设人为上限。</p>
      <a-form layout="horizontal" :label-col="{ span: 10 }" :wrapper-col="{ span: 14 }">
        <a-form-item v-for="(item, key) in retention" :key="key" :label="item.label">
          <a-input-number v-model:value="item.days" :min="1" addon-after="天" style="width: 160px" />
          <span style="color: #aaa; margin-left: 8px">默认 {{ item.default_days }} 天</span>
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal v-model:open="reportOpen" title="上传报错到云端" :confirm-loading="reporting"
      @ok="submitReport" ok-text="上传" cancel-text="取消" width="640px">
      <a-alert type="info" show-icon style="margin-bottom:12px"
        message="将把选中的报错日志上传到云端分发系统，供开发方定位问题。"
        description="上传时会附带你的授权凭证归属、当前版本与出口 IP。请勿在描述中填写敏感信息。" />
      <a-form layout="vertical">
        <a-form-item label="问题描述（必填其一）">
          <a-textarea v-model:value="reportDesc" :rows="3"
            placeholder="简述触发场景、你的操作、期望结果等，便于定位" />
        </a-form-item>
        <a-form-item :label="`将上传 ${selectedRowKeys.length} 条日志`">
          <pre class="log-pre" style="max-height:220px;background:#f6f8fa;padding:10px;border-radius:6px">{{ reportPreview }}</pre>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 我的上报：本用户上传过的报错 + 开发者回复/修复进展 -->
    <a-drawer v-model:open="myOpen" title="我的上报" width="640" @open="loadMyReports">
      <a-spin :spinning="myLoading">
        <a-empty v-if="!myReports.length" description="你还没有上传过报错" />
        <div v-for="r in myReports" :key="r.id" class="mr-card">
          <div class="mr-head">
            <span class="mr-ts">{{ r.ts }}</span>
            <a-tag :color="r.reply ? 'green' : (r.handled ? 'blue' : 'orange')">
              {{ r.reply ? '已回复' : (r.handled ? '已处理' : '待处理') }}
            </a-tag>
            <span v-if="r.version" class="mr-ver">{{ r.version }}</span>
          </div>
          <div class="mr-desc">{{ r.description || '(无描述)' }}</div>
          <pre v-if="r.log_preview" class="mr-log">{{ r.log_preview }}{{ r.log_len > 200 ? ' …' : '' }}</pre>
          <div v-if="r.reply" class="mr-reply">
            <div class="mr-reply-hd">开发者回复<span v-if="r.fix_version" class="mr-fix">已修复：{{ r.fix_version }}</span>
              <span v-if="r.replied_at" class="mr-rat">{{ r.replied_at }}</span></div>
            <div class="mr-reply-body">{{ r.reply }}</div>
          </div>
          <div v-else class="mr-noreply">开发者暂未回复，请留意后续版本更新。</div>
        </div>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
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
  { title: '时间', dataIndex: 'save_date', key: 'save_date', width: 180 },
  { title: '级别', key: 'level', width: 100 },
  { title: '进程', key: 'process_type', width: 100 },
  { title: '位置', key: 'loc', width: 220, ellipsis: true },
  { title: '内容', key: 'message', ellipsis: true },
  { title: '操作', key: 'action', width: 80, fixed: 'right' }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

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
  try { await logMonitorApi.delete(selectedRowKeys.value); message.success('已删除'); loadAll() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function clearAll() {
  try { const r = await logMonitorApi.clear(); message.success(`已清空 ${r.delete_cnt} 条`); loadAll() }
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
    message.success('已保存,即时生效')
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
  ).join('\n\n---\n\n') || '（未选中日志）'
})
function openReport() {
  if (!selectedRowKeys.value.length) { message.warning('请先勾选要上传的日志'); return }
  reportDesc.value = ''
  reportOpen.value = true
}
async function submitReport() {
  const logContent = reportPreview.value
  if (!reportDesc.value.trim() && !logContent.trim()) { message.warning('请填写描述'); return }
  reporting.value = true
  try {
    await reportError({ description: reportDesc.value.trim(), log_content: logContent, version: APP_VERSION })
    message.success('已上传到云端，感谢反馈')
    reportOpen.value = false
  } catch (e) {
    message.error(e instanceof Error ? e.message : '上传失败')
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
