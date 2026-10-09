<template>
  <PageContainer :title="translate('ui.m_70a1534aa33c')" kicker="Dashboard" :description="translate('ui.m_ad9cb92dd002')">
    <template #extra>
      <a-space>
        <TimezoneTag />
        <span v-if="lastRefresh" class="muted refresh-ts">{{ lastRefresh }}</span>
        <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
      </a-space>
    </template>

    <div class="metric-grid">
      <div v-for="item in metrics" :key="item.key">
        <a-card :bordered="false" class="metric-card" hoverable @click="item.to && router.push(item.to)">
          <div class="metric-body">
            <div class="metric-icon" :style="{ background: item.bg, color: item.color }">
              <component :is="item.icon" />
            </div>
            <div class="metric-text">
              <div class="metric-title">{{ item.title }}</div>
              <div class="metric-value" :class="{ loading: metricLoading }">{{ item.value.toLocaleString() }}</div>
              <div v-if="item.sub" class="metric-sub">{{ item.sub }}</div>
            </div>
          </div>
        </a-card>
      </div>
    </div>

    <a-row :gutter="16" class="section-row">
      <a-col :xs="24" :lg="8">
        <a-card :title="translate('ui.m_13b1fa2f1b42')" :bordered="false" :loading="sessLoading">
          <template #extra><a-button type="link" @click="router.push('/pentest')">{{ translate('ui.m_5c55a67935af') }}</a-button></template>
          <div class="sess-grid">
            <div v-for="s in sessCards" :key="s.key" class="sess-item">
              <div class="sess-num" :style="{ color: s.color }">{{ s.value }}</div>
              <div class="sess-label">{{ s.label }}</div>
            </div>
          </div>
        </a-card>
      </a-col>
      <a-col :xs="24" :lg="8">
        <a-card :title="translate('ui.m_b90665e74c01')" :bordered="false" :loading="proxyLoading">
          <template #extra><a-button type="link" @click="router.push('/proxy')">{{ translate('ui.m_979a332955c8') }}</a-button></template>
          <a-descriptions :column="1" size="small">
            <a-descriptions-item :label="translate('ui.m_9fbd3b4f0eb2')">
              <a-tag :color="proxyModeColor">{{ proxyData.modeLabel || '—' }}</a-tag>
            </a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_6d1823525b81')">
              <span class="proxy-ip">{{ proxyData.mode === 'direct' ? (proxyData.directIp || '—') : (proxyData.exitIp || '—') }}</span>
            </a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_e2ffff7a0910')">
              <span class="proxy-ip">{{ proxyData.directIp || '—' }}</span>
            </a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_d5834c762513')">
              <span class="proxy-traffic">↑ {{ fmtBytes(proxyData.upload) }} · ↓ {{ fmtBytes(proxyData.download) }}</span>
            </a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_0da7017a387c')">
              <a-tooltip :title="proxyData.mode === 'direct' ? translate('ui.m_22a6e952da98') : proxyData.sourceLabel">
                <span class="proxy-src">{{ proxyData.mode === 'direct' ? '—' : (proxyData.sourceLabel || '—') }}</span>
              </a-tooltip>
            </a-descriptions-item>
          </a-descriptions>
        </a-card>
      </a-col>
      <a-col :xs="24" :lg="8">
        <a-card :title="translate('ui.m_d268b857582a')" :bordered="false" :loading="tokenLoading">
          <template #extra><a-button type="link" @click="router.push('/ai-config')">{{ translate('ui.m_979a332955c8') }}</a-button></template>
          <a-statistic :title="translate('ui.m_a974f197e00a')" :value="tokenStat.total" :value-style="{ color: '#1677ff' }" />
          <div class="token-sub">
            <span>{{ translate('ui.m_653b123c956d') }} {{ tokenStat.calls.toLocaleString() }} {{ translate('ui.m_172fb7e67b9b') }}</span>
            <span v-if="tokenStat.fail">{{ translate('ui.m_89661a556032') }} <b style="color:#cf1322">{{ tokenStat.fail }}</b></span>
            <span>{{ translate('ui.m_d2bf57d2794b') }} {{ fmtK(tokenStat.prompt) }} {{ translate('ui.m_ab84b8877934') }} {{ fmtK(tokenStat.completion) }}</span>
          </div>
          <div v-if="tokenStat.topScene" class="token-scene muted">{{ translate('ui.m_04a54e7cf545') }}{{ tokenStat.topScene }}</div>
        </a-card>
      </a-col>
    </a-row>

    <!-- 网络质量总评（定时监测产出，点击进网络检测页详情）-->
    <a-row :gutter="16" class="section-row" v-if="netQuality">
      <a-col :span="24">
        <a-card :bordered="false" class="netq-card" hoverable @click="router.push('/network-check')">
          <div class="netq-bar" :class="'nq-' + (netQuality.level || 'unknown')">
            <div class="netq-badge">
              <div class="netq-level">{{ netQuality.level_text || '—' }}</div>
              <div class="netq-score">{{ netQuality.score != null ? netQuality.score : '?' }}<span>{{ translate('ui.m_b6a993c256ef') }}</span></div>
            </div>
            <div class="netq-body">
              <div class="netq-title">{{ translate('ui.m_17a114b74dd3') }} <a-tag v-for="(g, k) in (netQuality.dims || {})" :key="k" :color="dimColor(String(g))" class="netq-dim">{{ dimLabel(String(k)) }}</a-tag></div>
              <div class="netq-summary">{{ netQuality.summary || translate('ui.m_1d87af6f5398') }}</div>
              <div class="netq-time" v-if="netCheckedAt">{{ translate('ui.m_755b69eb6bc3') }}{{ netCheckedAt }} {{ translate('ui.m_b6a64ebe217c') }}</div>
            </div>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <a-row :gutter="16" class="section-row">
      <a-col :xs="24" :lg="8">
        <a-card :title="translate('ui.m_240cf246ac39')" :bordered="false" :loading="deviceLoading">
          <!-- 资源分数 + 运行可靠性总评（实时，像网络质量一样评当前资源是否适合系统运行）-->
          <div v-if="resScore != null" class="res-verdict" :class="'rv-' + resLevel">
            <div class="rv-badge">
              <div class="rv-level">{{ resLevelText }}</div>
              <div class="rv-score">{{ resScore }}<span>{{ translate('ui.m_b6a993c256ef') }}</span></div>
            </div>
            <div class="rv-body">
              <div class="rv-title">{{ translate('ui.m_2b6932e6e9e9') }}</div>
              <div class="rv-verdict">{{ resVerdict }}</div>
              <div v-if="resTaskSlots != null" class="rv-slots">{{ translate('ui.m_ab748b898307') }}{{ resTaskSlots }} {{ translate('ui.m_7208d7d97cf9') }}</div>
              <div v-if="resDiskNote" class="rv-disknote">🗄 {{ resDiskNote }}</div>
            </div>
          </div>
          <div class="dev-list">
            <div class="dev-row">
              <span class="dev-label">CPU（{{ cpuCount || '-' }} {{ translate('ui.m_6a8655f976ce') }}</span>
              <div class="dev-val"><a-progress :percent="cpu" size="small" :status="cpu > 85 ? 'exception' : 'normal'" /></div>
            </div>
            <div class="dev-row">
              <span class="dev-label">{{ translate('ui.m_7d8f8c37ec78') }}</span>
              <div class="dev-val">
                <a-progress :percent="memory" size="small" :status="memory > 85 ? 'exception' : 'normal'" />
                <span v-if="memText" class="dev-sub">{{ memText }}</span>
              </div>
            </div>
            <div class="dev-row">
              <span class="dev-label">{{ translate('ui.m_de7b72a3f852') }}</span>
              <div class="dev-val">
                <a-progress :percent="disk" size="small" :status="disk > 90 ? 'exception' : 'normal'" />
                <span v-if="diskText" class="dev-sub">{{ diskText }}</span>
              </div>
            </div>
            <div class="dev-row">
              <span class="dev-label">{{ translate('ui.m_35c1852c5c65') }}</span>
              <div class="dev-val"><span class="uptime">{{ uptimeText }}</span><span class="dev-hint">{{ translate('ui.m_328e72edd309') }}</span></div>
            </div>
            <div class="dev-row">
              <span class="dev-label">{{ translate('ui.m_4ebb761ac335') }}</span>
              <div class="dev-val">
                <span class="mono">{{ exitIpText }}</span>
                <a-tag v-if="proxyEnabled" :color="proxyOk ? 'green' : 'red'" class="dev-tag">{{ proxyOk ? translate('ui.m_6edaf5a51e39') : translate('ui.m_e84ba7b04237') }}</a-tag>
              </div>
            </div>
          </div>
        </a-card>
      </a-col>
      <a-col :xs="24" :lg="16">
        <a-card :title="translate('ui.m_357e222335bd')" :bordered="false" :loading="chartLoading">
          <template #extra>
            <a-slider v-model:value="chartDays" :min="1" :max="360" :step="1" style="width: 160px; display: inline-block; margin-right: 8px;" :tip-formatter="(v: number) => v + translate('ui.m_49da61ceeea2')" @afterChange="loadChart" />
            <span class="muted">{{ chartDays }}{{ translate('ui.m_49da61ceeea2') }}</span>
          </template>
          <canvas ref="chartCanvas" class="resource-chart"></canvas>
          <div class="chart-legend">
            <span class="legend-item"><span class="legend-dot cpu-dot"></span>CPU</span>
            <span class="legend-item"><span class="legend-dot mem-dot"></span>{{ translate('ui.m_7d8f8c37ec78') }}</span>
            <span class="legend-item"><span class="legend-dot disk-dot"></span>{{ translate('ui.m_de7b72a3f852') }}</span>
            <span class="legend-item"><span class="legend-line thresh-line"></span>{{ translate('ui.m_427bbea90e6f') }}</span>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <a-row :gutter="16" class="section-row">
      <a-col :span="24">
        <a-card :title="translate('ui.m_e69968577d33')" :bordered="false">
          <template #extra><a-button type="link" @click="router.push('/tasks')">{{ translate('ui.m_5c55a67935af') }}</a-button></template>
          <a-table :columns="taskColumns" :data-source="recentTasks" :loading="taskLoading" row-key="_id" :pagination="false" size="small">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
              <template v-else-if="column.key === 'name'">
                <a @click="router.push(`/tasks/${record._id}`)">{{ record.name }}</a>
              </template>
            </template>
          </a-table>
        </a-card>
      </a-col>
    </a-row>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate, appLocale } from '../../i18n'

import { onMounted, reactive, ref, markRaw, computed, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ProfileOutlined, GlobalOutlined, ClusterOutlined, CloudServerOutlined, BugOutlined, RobotOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import StatusTag from '../../components/StatusTag.vue'
import TimezoneTag from '../../components/TimezoneTag.vue'
import { collectionApi } from '../../api/assets'
import { taskApi } from '../../api/task'
import { consoleApi } from '../../api/console'
import { pentestApi } from '../../api/pentest'
import { aiConfigApi } from '../../api/aiConfig'
import { proxyApi } from '../../api/proxy'
import { request } from '../../api/request'
import { useAutoRefresh } from '../../composables/useAutoRefresh'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const lastRefresh = ref('')

function fmtK(n: number) {
  if (!n) return '0'
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K'
  return String(n)
}
function fmtBytes(n: number) {
  if (!n) return '0 B'
  if (n >= 1e9) return (n / 1e9).toFixed(1) + ' GB'
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + ' KB'
  return n + ' B'
}

const metricLoading = ref(false)
const metrics = ref([
  { key: 'task', get title() { return translate('ui.m_f1cc96bb316f') }, value: 0, sub: '', to: '/tasks', icon: markRaw(ProfileOutlined), color: '#1677ff', bg: '#e6f4ff' },
  { key: 'domain', get title() { return translate('ui.m_222952431147') }, value: 0, sub: '', to: '/search', icon: markRaw(GlobalOutlined), color: '#13c2c2', bg: '#e6fffb' },
  { key: 'ip', title: 'IP', value: 0, sub: '', to: '/search', icon: markRaw(ClusterOutlined), color: '#722ed1', bg: '#f9f0ff' },
  { key: 'site', get title() { return translate('ui.m_a59fe62777ff') }, value: 0, sub: '', to: '/search', icon: markRaw(CloudServerOutlined), color: '#fa8c16', bg: '#fff7e6' },
  { key: 'vuln', get title() { return translate('ui.m_e4246b7d0651') }, value: 0, sub: '', to: '/vuln-center', icon: markRaw(BugOutlined), color: '#cf1322', bg: '#fff1f0' },
  { key: 'sess', get title() { return translate('ui.m_13b1fa2f1b42') }, value: 0, sub: '', to: '/pentest', icon: markRaw(RobotOutlined), color: '#2f54eb', bg: '#f0f5ff' }
])

async function loadMetrics(silent = false) {
  if (!silent) metricLoading.value = true
  const get = (k: string) => metrics.value.find(m => m.key === k)!
  await Promise.all([
    { key: 'task', ns: 'task' }, { key: 'domain', ns: 'domain' },
    { key: 'ip', ns: 'ip' }, { key: 'site', ns: 'site' }
  ].map(async ({ key, ns }) => {
    try { const d = await collectionApi.list(ns, { page: 1, size: 1 }); get(key).value = d.total || 0 }
    catch { get(key).value = 0 }
  }))
  try {
    const s = await pentestApi.findingStat()
    const v = get('vuln'); v.value = s.combined_total || 0
    v.sub = translate('ui.m_504349f8bdf7', { p0: (s.poc.total), p1: (s.ai.verified) })
  } catch { get('vuln').value = 0 }
  metricLoading.value = false
}
/* AI 渗透会话统计 */
const sessLoading = ref(false)
const sess = reactive({ total: 0, running: 0, queued: 0, waiting: 0, paused: 0, done: 0, fatal: 0, stopped: 0, active: 0 })
const sessCards = computed(() => [
  { key: 'active', get label() { return translate('ui.m_dc9591e56d50') }, value: sess.active, color: '#1677ff' },
  { key: 'running', get label() { return translate('ui.m_5026a63b58cd') }, value: sess.running, color: '#52c41a' },
  { key: 'done', get label() { return translate('ui.m_f28461bb49c8') }, value: sess.done, color: '#8c8c8c' },
  { key: 'paused', get label() { return translate('ui.m_eb0c326b60ae') }, value: sess.paused, color: '#fa8c16' },
  { key: 'fatal', get label() { return translate('ui.m_28384d7afd2e') }, value: sess.fatal, color: '#cf1322' },
  { key: 'total', get label() { return translate('ui.m_e8dc871a7fde') }, value: sess.total, color: '#2f54eb' }
])
async function loadSession(silent = false) {
  if (!silent) sessLoading.value = true
  try {
    const s = await pentestApi.sessionStat()
    Object.assign(sess, s)
    metrics.value.find(m => m.key === 'sess')!.value = s.total || 0
    metrics.value.find(m => m.key === 'sess')!.sub = translate('ui.m_7386ba27de4d', { p0: (s.active) })
  } catch { /* 忽略 */ } finally { sessLoading.value = false }
}

/* Token 消耗 */
const tokenLoading = ref(false)
const tokenStat = reactive({ total: 0, calls: 0, fail: 0, prompt: 0, completion: 0, topScene: '' })
async function loadToken(silent = false) {
  if (!silent) tokenLoading.value = true
  try {
    const u = await aiConfigApi.usageStat()
    tokenStat.total = u.overall.total || 0
    tokenStat.calls = u.overall.calls || 0
    tokenStat.fail = u.overall.fail_calls || 0
    tokenStat.prompt = u.overall.prompt || 0
    tokenStat.completion = u.overall.completion || 0
    tokenStat.topScene = u.by_scene?.[0]?.name || ''
  } catch { /* 忽略 */ } finally { tokenLoading.value = false }
}

/* 设备状态 + 运行时间 */
const deviceLoading = ref(false)
const cpu = ref(0); const memory = ref(0); const disk = ref(0); const uptime = ref(0)
const cpuCount = ref(0)
const memTotalGb = ref(0); const memUsedGb = ref(0)
const diskTotalGb = ref(0); const diskUsedGb = ref(0)
const exitIp = ref(''); const proxyOk = ref(false); const proxyEnabled = ref(false)
// 资源分数 + 运行可靠性（后端 device_info.resource 产出，实时评当前资源是否适合系统运行）
const resScore = ref<number | null>(null)
const resLevel = ref('good'); const resLevelText = ref(''); const resVerdict = ref(''); const resDiskNote = ref(''); const resTaskSlots = ref<number | null>(null)
const uptimeText = computed(() => {
  const s = uptime.value
  if (!s) return '—'
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  if (d > 0) return translate('ui.m_f214b0b89ed5', { p0: (d), p1: (h) })
  if (h > 0) return translate('ui.m_0e58ac1ec4d0', { p0: (h), p1: (m) })
  return translate('ui.m_c36f6e281671', { p0: (m) })
})
const memText = computed(() => memTotalGb.value ? `${memUsedGb.value} / ${memTotalGb.value} GB` : '')
const diskText = computed(() => diskTotalGb.value ? `${diskUsedGb.value} / ${diskTotalGb.value} GB` : '')
const cpuText = computed(() => cpuCount.value ? translate('ui.m_d73a46fc48a5', { p0: (cpu.value), p1: (cpuCount.value) }) : `${cpu.value}%`)
const exitIpText = computed(() => {
  if (!exitIp.value) return '—'
  if (!proxyEnabled.value) return translate('ui.m_d419a1a5f6a1', { p0: (exitIp.value) })
  return proxyOk.value ? translate('ui.m_1253091a0bb1', { p0: (exitIp.value) }) : translate('ui.m_55f3772c525a', { p0: (exitIp.value) })
})
async function loadDevice(silent = false) {
  if (!silent) deviceLoading.value = true
  try {
    const info = await consoleApi.info()
    const d = (info.device_info || {}) as Record<string, unknown>
    cpu.value = Math.round(Number(d.cpu_percent ?? 0))
    memory.value = Math.round(Number(d.memory_percent ?? 0))
    cpuCount.value = Number(d.cpu_count ?? 0)
    memTotalGb.value = Number(d.memory_total_gb ?? 0)
    memUsedGb.value = Number(d.memory_used_gb ?? 0)
    const du = d.disk_usage as { percent?: number; total?: number; used?: number } | undefined
    disk.value = Math.round(Number(du?.percent ?? 0))
    const g = 1024 ** 3
    diskTotalGb.value = du?.total ? Math.round((du.total / g) * 10) / 10 : 0
    diskUsedGb.value = du?.used ? Math.round((du.used / g) * 10) / 10 : 0
    uptime.value = Number(d.uptime_seconds ?? 0)
    exitIp.value = String(d.exit_ip ?? '')
    proxyOk.value = Boolean(d.proxy_ok)
    proxyEnabled.value = Boolean(d.proxy_enabled)
    // 资源分数 + 运行可靠性
    const res = d.resource as { score?: number; level?: string; level_text?: string; verdict?: string; disk_note?: string; task_slots?: number | null } | undefined
    if (res && res.score != null) {
      resScore.value = Number(res.score)
      resLevel.value = String(res.level || 'good')
      resLevelText.value = String(res.level_text || '')
      resVerdict.value = String(res.verdict || '')
      resDiskNote.value = String(res.disk_note || '')
      resTaskSlots.value = res.task_slots == null ? null : Number(res.task_slots)
    }
  } catch { /* 设备信息可选 */ } finally { deviceLoading.value = false }
}

/* 代理状态 */
const proxyLoading = ref(false)
/* 代理状态：直接反映「代理中心当前选的模式」+ 对应出口/归属（后端 current_platform_egress 单一事实源）。
   5 字段平铺：代理模式 / 代理出口 IP / 实际出口 IP / 累计流量 / 代理出口 IP 归属。
   不再前端判"生效/网络异常"三态——只如实展示当前模式与两个出口 IP，避免"没走代理却显代理出口"的误导。 */
const proxyData = reactive({ mode: 'direct', modeLabel: '', exitIp: '', directIp: '', sourceLabel: '', upload: 0, download: 0, connections: 0, node: '' })
const proxyModeColor = computed(() => (
  proxyData.mode === 'global' ? 'blue' : proxyData.mode === 'smart' ? 'green' : 'default'
))
async function loadProxy(silent = false) {
  if (!silent) proxyLoading.value = true
  try {
    const [ipData, trafficData] = await Promise.all([proxyApi.exitIp(), proxyApi.traffic()])
    // 后端 current_platform_egress 单一事实源：代理中心当前选的模式 + 对应出口/归属
    proxyData.mode = String((ipData as any).platform_mode || 'direct')
    proxyData.modeLabel = String((ipData as any).mode_label || '直连')
    proxyData.exitIp = ipData.proxy_ip || ''
    proxyData.directIp = ipData.direct_ip || ''
    proxyData.sourceLabel = String((ipData as any).source_label || '—')
    proxyData.upload = trafficData.total_up || 0
    proxyData.download = trafficData.total_down || 0
    proxyData.connections = trafficData.connections || 0
    proxyData.node = (trafficData as any).node || ''
  } catch { /* 代理信息可选 */ } finally { proxyLoading.value = false }
}

/* 最近任务 */
const taskLoading = ref(false)
const recentTasks = ref<RowRecord[]>([])
const taskColumns = [
  { get title() { return translate('ui.m_2c43cd7db149') }, key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_57060c88a36b') }, dataIndex: 'target', key: 'target', ellipsis: true },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 90 },
  { get title() { return translate('ui.m_6a9906c79f26') }, dataIndex: 'start_time', key: 'start_time', width: 160 }
]
async function loadTasks() {
  taskLoading.value = true
  try { const data = await taskApi.list({ page: 1, size: 8, order: '-_id' }); recentTasks.value = data.items || [] }
  catch { recentTasks.value = [] } finally { taskLoading.value = false }
}

// 网络质量总评（读定时监测落库的最新结果）
const netQuality = ref<Record<string, any> | null>(null)
const netCheckedAt = ref('')
function dimLabel(k: string) { return ({ get deps() { return translate('ui.m_776740486540') }, get stability() { return translate('ui.m_a0e1075d16cb') }, get ping() { return translate('ui.m_c00455239802') }, dns: 'DNS', get proxy() { return translate('ui.m_5e84ea61e838') } } as Record<string, string>)[k] || k }
function dimColor(g: string) { return ({ good: 'green', fair: 'gold', poor: 'orange', dead: 'red' } as Record<string, string>)[g] || 'default' }
async function loadNetQuality() {
  try {
    const r = await request<any>('/api/network/quality/latest')
    if (r && r.has_data && r.assess) { netQuality.value = r.assess; netCheckedAt.value = r.checked_at || '' }
    else { netQuality.value = { level: 'unknown', level_text: '待检测', score: null, get summary() { return translate('ui.m_6bfac6efef26') }, dims: {} }; netCheckedAt.value = '' }
  } catch { /* 网络质量可选，取不到不影响 */ }
}

// silent=true：静默刷新（不显 loading 骨架屏），用于 30s 自动刷新——数据已有，只更新不闪屏。
// 首次挂载 silent=false：显骨架屏。治"设备/代理卡每 30s 退回骨架屏、看着像没工作"。
let refreshInFlight: Promise<void> | null = null
function loadAll(silent = false): Promise<void> {
  if (refreshInFlight) return refreshInFlight
  refreshInFlight = Promise.allSettled([
    loadMetrics(silent), loadSession(silent), loadToken(silent), loadDevice(silent),
    loadProxy(silent), loadTasks(), loadChart(), loadNetQuality(),
  ]).then(() => { lastRefresh.value = new Date().toLocaleTimeString() })
    .finally(() => { refreshInFlight = null })
  return refreshInFlight
}
// 默认自动刷新(30s)——恒定开启且静默(不闪骨架屏);首次挂载显骨架屏。
useAutoRefresh(() => loadAll(true), 30000)
onMounted(() => loadAll(false))
watch(appLocale, () => { void loadAll(true).then(drawChart) })

/* 资源趋势图(Canvas, 后端历史数据) */
const chartCanvas = ref<HTMLCanvasElement | null>(null)
const chartDays = ref(1)
const chartLoading = ref(false)
const chartPoints = ref<Array<{ts: number; cpu: number; memory: number; disk: number}>>([])

async function loadChart() {
  chartLoading.value = true
  try {
    const data = await consoleApi.resourceHistory(chartDays.value)
    chartPoints.value = data.points || []
  } catch { chartPoints.value = [] }
  finally { chartLoading.value = false }
  // drawChart 必须在 loading=false 之后:a-card :loading 会用骨架屏卸载 canvas,
  // loading 期间画会画到即将卸载的节点上(空白)。nextTick 等 canvas 重新挂载再画。
  await nextTick()
  drawChart()
}

function drawChart() {
  const canvas = chartCanvas.value
  if (!canvas) return
  // 高清适配
  const dpr = window.devicePixelRatio || 1
  const rect = canvas.getBoundingClientRect()
  canvas.width = rect.width * dpr
  canvas.height = rect.height * dpr
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  ctx.scale(dpr, dpr)
  const w = rect.width, h = rect.height
  const pad = { top: 10, bottom: 20, left: 35, right: 10 }
  const chartW = w - pad.left - pad.right
  const chartH = h - pad.top - pad.bottom
  const points = chartPoints.value

  ctx.clearRect(0, 0, w, h)

  // Grid
  ctx.strokeStyle = '#f0f0f0'
  ctx.lineWidth = 1
  ctx.font = '10px sans-serif'
  ctx.fillStyle = '#aaa'
  for (const pct of [0, 25, 50, 75, 100]) {
    const y = pad.top + chartH * (1 - pct / 100)
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + chartW, y); ctx.stroke()
    ctx.fillText(pct + '%', 2, y + 3)
  }

  // Threshold line 80%
  const threshY = pad.top + chartH * (1 - 80 / 100)
  ctx.strokeStyle = '#ff4d4f'
  ctx.lineWidth = 1
  ctx.setLineDash([4, 4])
  ctx.beginPath(); ctx.moveTo(pad.left, threshY); ctx.lineTo(pad.left + chartW, threshY); ctx.stroke()
  ctx.setLineDash([])

  if (points.length < 2) {
    ctx.fillStyle = '#ccc'
    ctx.font = '13px sans-serif'
    ctx.fillText(translate('ui.m_bee985624afb'), w / 2 - 40, h / 2)
    return
  }

  // X 轴按【真实时间】定位(治「只有几个点却被均匀拉满全宽=显示200多天假象」根因):
  // 时间窗 = [now - chartDays 天, now]，点按其 ts 落在真实时间位置；数据只覆盖实际采集时段
  // (只跑几天就只占图左侧一小段，不再摊满全宽)。ts 单位秒。
  const nowSec = Math.floor(Date.now() / 1000)
  const t1 = nowSec
  const t0 = nowSec - chartDays.value * 86400
  const span = Math.max(1, t1 - t0)
  const tx = (ts: number) => pad.left + chartW * Math.min(1, Math.max(0, (ts - t0) / span))

  // X 轴时间刻度(4 等分，按真实时间；跨度>2天显日期，否则显时:分)
  ctx.fillStyle = '#aaa'
  ctx.font = '10px sans-serif'
  ctx.textAlign = 'center'
  const multiDay = chartDays.value > 2
  for (let k = 0; k <= 4; k++) {
    const tt = t0 + (span * k) / 4
    const x = pad.left + (chartW * k) / 4
    const dt = new Date(tt * 1000)
    const label = multiDay
      ? `${dt.getMonth() + 1}/${dt.getDate()}`
      : `${String(dt.getHours()).padStart(2, '0')}:${String(dt.getMinutes()).padStart(2, '0')}`
    ctx.fillText(label, x, h - 6)
  }
  ctx.textAlign = 'left'

  function drawLine(key: 'cpu' | 'memory' | 'disk', color: string) {
    if (!ctx || points.length < 2) return
    ctx.strokeStyle = color
    ctx.lineWidth = 1.5
    ctx.lineJoin = 'round'
    ctx.beginPath()
    let started = false
    for (let i = 0; i < points.length; i++) {
      const x = tx(points[i].ts)          // 按真实时间戳定位，非索引均匀铺满
      const y = pad.top + chartH * (1 - (points[i][key] || 0) / 100)
      if (!started) { ctx.moveTo(x, y); started = true }
      else ctx.lineTo(x, y)
    }
    ctx.stroke()
  }

  drawLine('cpu', '#1677ff')
  drawLine('memory', '#52c41a')
  drawLine('disk', '#fa8c16')
}
</script>

<style scoped>
.metric-card { cursor: pointer; transition: transform .15s ease; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(min(190px,100%),1fr)); gap: 16px; }
.metric-grid .metric-card { height: 100%; margin-bottom: 0; }
.metric-card:hover { transform: translateY(-2px); }
.metric-body { display: flex; align-items: center; gap: 14px; }
.metric-icon { width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; flex-shrink: 0; }
.metric-text { min-width: 0; }
.metric-title { font-size: 13px; color: #8c8c8c; line-height: 1.4; }
/* 数值用主题文字色变量：亮=#0f1f33 / 暗=#cfe6f5。修复夜间模式暗字压在暗卡底(#0d1424)看不清 */
.metric-value { font-size: 26px; font-weight: 600; color: var(--dt-text, #1f2937); line-height: 1.2; }
.metric-value.loading { opacity: .4; }
.metric-sub { font-size: 11px; color: #bbb; margin-top: 2px; }
.section-row { margin-top: 16px; }
/* 同行卡片等高对齐：a-row 是 flex，列默认等高；让卡片撑满列高，三卡底部齐平
   （治代理状态卡 5 行比左右两卡高、参差不齐）。 */
.section-row :deep(.ant-col) { display: flex; }
.section-row :deep(.ant-card) { width: 100%; }
.muted { color: #aaa; }
.refresh-ts { font-size: 12px; }
.sess-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.sess-item { text-align: center; padding: 6px 0; }
.sess-num { font-size: 24px; font-weight: 600; line-height: 1.1; }
.sess-label { font-size: 12px; color: #8c8c8c; margin-top: 2px; }
.token-sub { font-size: 12px; color: #8c8c8c; margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
.token-scene { font-size: 12px; margin-top: 6px; }
.uptime { font-weight: 600; color: #389e0d; }
/* 设备状态：label 固定宽 + 值区弹性，进度条与副文字同一行对齐，彻底消除 progress/文字错位 */
.dev-list { display: flex; flex-direction: column; gap: 12px; }
.dev-row { display: flex; align-items: center; gap: 10px; min-height: 24px; }
.dev-label { flex: 0 0 88px; font-size: 13px; color: #8c8c8c; white-space: nowrap; }
.dev-val { flex: 1 1 auto; min-width: 0; display: flex; align-items: center; gap: 8px; }
.dev-val :deep(.ant-progress) { flex: 1 1 auto; margin: 0; min-width: 0; }
.dev-val :deep(.ant-progress-text) { font-variant-numeric: tabular-nums; }
.dev-sub { flex: 0 0 auto; font-size: 12px; color: #888; white-space: nowrap; font-variant-numeric: tabular-nums; }
.dev-hint { font-size: 11px; color: #bbb; white-space: nowrap; }
.dev-tag { margin: 0; flex: 0 0 auto; }
.mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; word-break: break-all; }
.proxy-ok { font-size: 11px; color: #52c41a; margin-left: 6px; }
.proxy-warn { font-size: 11px; color: #fa8c16; margin-left: 6px; }
.proxy-err { font-size: 11px; color: #cf1322; margin-left: 6px; font-weight: 500; }
.proxy-traffic { font-weight: 500; color: #1f2937; }
.proxy-ip { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; }
/* 出口归属：长文本(机场订阅·profile·节点)单行省略号,不撑破窄卡片,全文见 tooltip */
.proxy-src { display: inline-block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
/* 代理卡 descriptions 值列允许收缩,长内容不溢出 */
.netq-fix, .ant-descriptions-item-content { min-width: 0; }
/* 网络质量总评卡 */
.netq-card { cursor: pointer; transition: transform .15s ease; }
.netq-card:hover { transform: translateY(-2px); }
.netq-bar { display: flex; align-items: center; gap: 18px; }
.netq-badge { display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-width: 88px; padding: 6px 14px; border-radius: 10px; color: #fff; }
.netq-level { font-size: 24px; font-weight: 700; line-height: 1.1; }
.netq-score { font-size: 13px; opacity: .95; } .netq-score span { font-size: 10px; }
.netq-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.netq-dim { margin: 0; font-size: 11px; line-height: 18px; }
.netq-summary { font-size: 14px; color: var(--dt-text, #333); }
.netq-time { font-size: 12px; color: var(--dt-muted, #999); margin-top: 4px; }
.nq-excellent .netq-badge, .nq-good .netq-badge { background: #52c41a; }
.nq-fair .netq-badge { background: #faad14; }
.nq-poor .netq-badge { background: #fa8c16; }
.nq-critical .netq-badge { background: #cf1322; }
.nq-unknown .netq-badge { background: #bfbfbf; }
/* 资源运行可靠性总评（设备状态卡内，仿网络质量徽章紧凑版）*/
/* --dt-hover 两个主题都没定义→恒 fallback #fafafa 近白；夜间模式下白板压在暗卡上刺眼。
   改用两态都有定义的 --dt-fill(亮 #fafafa / 暗 #0d1424) + --dt-border，暗色下自动跟随。 */
.res-verdict { display: flex; align-items: center; gap: 12px; padding: 10px 12px; margin-bottom: 14px;
  border-radius: 10px; background: var(--dt-fill, #fafafa); border: 1px solid var(--dt-border, #f0f0f0); }
.rv-badge { display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-width: 68px; padding: 5px 10px; border-radius: 8px; color: #fff; }
.rv-level { font-size: 15px; font-weight: 700; line-height: 1.2; white-space: nowrap; }
.rv-score { font-size: 12px; opacity: .95; } .rv-score span { font-size: 9px; }
.rv-title { font-size: 13px; font-weight: 600; margin-bottom: 3px; }
.rv-verdict { font-size: 12px; color: var(--dt-muted, #888); line-height: 1.5; }
.rv-disknote { font-size: 11px; color: #d48806; line-height: 1.5; margin-top: 2px; }
.rv-slots { font-size: 11px; color: var(--dt-muted, #888); line-height: 1.5; margin-top: 2px; }
.rv-excellent .rv-badge, .rv-good .rv-badge { background: #52c41a; }
.rv-tight .rv-badge { background: #faad14; }
.rv-critical .rv-badge { background: #cf1322; }
.resource-chart { width: 100%; height: 180px; display: block; }
.chart-legend { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: #8c8c8c; }
.legend-item { display: flex; align-items: center; gap: 4px; }
.legend-dot { width: 10px; height: 3px; border-radius: 2px; }
.legend-line { width: 14px; height: 0; border-top: 2px dashed #ff4d4f; }
.cpu-dot { background: #1677ff; }
.mem-dot { background: #52c41a; }
.disk-dot { background: #fa8c16; }
.thresh-line { }
</style>


