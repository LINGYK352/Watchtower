<template>
  <PageContainer :title="translate('ui.m_56b3909705f3')" kicker="Task Detail" :description="translate('ui.m_f42972d89f9e')">
    <template #extra><a-button @click="router.push('/tasks')">{{ translate('ui.m_e9d5ca6c1406') }}</a-button></template>
    <a-card :bordered="false" :loading="loading" style="margin-bottom: 16px">
      <a-descriptions bordered size="small" :column="2">
        <a-descriptions-item :label="translate('ui.m_68c60746f1d0')"><CopyText :text="id" /></a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_2c43cd7db149')">{{ task.name || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_57060c88a36b')">
          <!-- unit 任务 target 可能是几千字符的单位名/域名清单，定高滚动截断防撑长页面；点击 CopyText 复制全量 -->
          <div style="max-height:96px;overflow:auto;word-break:break-all"><CopyText :text="String(task.target || '')" /></div>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_6320b4a8722a')"><StatusTag :value="String(task.status || '')" /></a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_ba40014ff496')">{{ typeLabel(task.type) }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_6a9906c79f26')">{{ task.start_time || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_f50276449943')">{{ task.end_time || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_e77e3d58b0dc')">{{ duration }}</a-descriptions-item>
        <a-descriptions-item v-if="sourceLabel" :label="translate('ui.m_a488e93d69cc')">{{ sourceLabel }}</a-descriptions-item>
        <a-descriptions-item v-if="sourceQueries.length" :label="translate('ui.m_1bc215d1d147')" :span="2">
          <div v-for="q in sourceQueries" :key="q.src" style="margin-bottom:4px">
            <a-tag color="blue">{{ q.src }}</a-tag><CopyText :text="q.query" />
          </div>
        </a-descriptions-item>
      </a-descriptions>
    </a-card>

    <a-alert v-if="isEmptyDone" type="warning" show-icon style="margin-bottom: 16px"
      :message="translate('ui.m_a043b3e5f4d5')"
      :description="translate('ui.m_80f2fbda4c50')" />

    <a-card :title="translate('ui.m_0c907aa7861b')" :bordered="false" style="margin-bottom: 16px">
      <a-row :gutter="16">
        <a-col :span="4" v-for="s in statItems" :key="s.key">
          <a-statistic :title="s.title" :value="statValue(s.key)" />
          <a-button type="link" size="small" @click="goSearch(s.tab)">{{ translate('ui.m_db8db0530432') }}</a-button>
        </a-col>
      </a-row>
    </a-card>

    <a-card :title="translate('ui.m_3c21b1f29bd5')" :bordered="false">
      <a-space wrap>
        <a-tag v-for="(v, k) in enabledOptions" :key="k" color="blue">{{ k }}</a-tag>
        <span v-if="!Object.keys(enabledOptions).length">{{ translate('ui.m_484d55613910') }}</span>
      </a-space>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import CopyText from '../../components/CopyText.vue'
import StatusTag from '../../components/StatusTag.vue'
import { taskApi } from '../../api/task'
import type { RowRecord } from '../../api/types'

const route = useRoute()
const router = useRouter()
const id = computed(() => String(route.params.id || ''))
const loading = ref(false)
const task = ref<RowRecord>({})

const statItems = [
  { key: 'domain_cnt', get title() { return translate('ui.m_222952431147') }, tab: 'domain' },
  { key: 'ip_cnt', title: 'IP', tab: 'ip' },
  { key: 'site_cnt', get title() { return translate('ui.m_a59fe62777ff') }, tab: 'site' },
  { key: 'url_cnt', title: 'URL', tab: 'url' },
  { key: 'vuln_cnt', get title() { return translate('ui.m_b0475a364bcb') }, tab: 'site' },
  { key: 'wih_cnt', title: 'WIH', tab: 'wih' }
]
function statValue(key: string) {
  const stat = task.value.statistic as Record<string, unknown> | undefined
  return Number(stat?.[key] ?? 0)
}
// 任务已结束但域名/IP/站点全为 0 = 没扫到资产,顶部横幅提示
const isEmptyDone = computed(() => {
  if (String(task.value.status) !== 'done') return false
  return statValue('domain_cnt') === 0 && statValue('ip_cnt') === 0 && statValue('site_cnt') === 0
})
// BUG-008：耗时曾误绑 task_tag(值恒"task")。改为 end_time-start_time 计算，未结束显示「进行中」。
const duration = computed(() => {
  const s = String(task.value.start_time || '')
  const e = String(task.value.end_time || '')
  if (!s) return '-'
  if (!e || e === '-') return translate('ui.m_dc9591e56d50')
  const ms = new Date(e.replace(/-/g, '/')).getTime() - new Date(s.replace(/-/g, '/')).getTime()
  if (isNaN(ms) || ms < 0) return '-'
  const sec = Math.floor(ms / 1000)
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), ss = sec % 60
  return (h ? h + translate('ui.m_7d58b6422cac') : '') + (h || m ? m + translate('ui.m_b6a993c256ef') : '') + ss + translate('ui.m_9dcdc2b289b9')
})
const enabledOptions = computed(() => {
  const opts = (task.value.options as Record<string, unknown>) || {}
  const result: Record<string, boolean> = {}
  Object.entries(opts).forEach(([k, v]) => { if (v === true) result[k] = true })
  return result
})
// 来源信息（源查询任务归档 source.platform/sources；存量老任务无 source 则空，不显示）
const sourceLabel = computed(() => {
  const src = (task.value.source as Record<string, unknown>) || {}
  const platform = String(src.platform || '')
  const sources = Array.isArray(src.sources) ? (src.sources as string[]) : []
  if (sources.length) return sources.join(' + ') + (platform && platform !== 'multi_source' ? `（${platform}）` : '')
  return platform && platform !== 'multi_source' ? platform : ''
})
// 任务类型中文映射（type 内部数据值不改，仅展示友好化；未知原样兼容）
const _TYPE_LABELS: Record<string, string> = {
  get domain() { return translate('ui.m_222952431147') }, ip: 'IP', get fofa() { return translate('ui.m_6518c904a840') }, get risk_cruising() { return translate('ui.m_7dc02b74d145') },
  get asset_site_update() { return translate('ui.m_137e364e3583') }, get asset_site_add() { return translate('ui.m_2c9e47665100') }, get asset_wih_update() { return translate('ui.m_ae8c0465f059') },
}
function typeLabel(t: unknown) { return _TYPE_LABELS[String(t || '')] || String(t || '-') }
// 源查询语句（source.queries = {源名: 语句}；存量老任务无此字段则空数组，v-if 不显示）
const sourceQueries = computed(() => {
  const src = (task.value.source as Record<string, unknown>) || {}
  const q = (src.queries as Record<string, string>) || {}
  return Object.entries(q).map(([k, v]) => ({ src: k.toUpperCase(), query: String(v) })).filter(x => x.query)
})

async function load() {
  loading.value = true
  try {
    const data = await taskApi.list({ _id: id.value, page: 1, size: 1 })
    task.value = (data.items || [])[0] || {}
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
// 带 tab + task_id 跳转资产检索,只显示本任务的资产(治「查看显示全部」)
function goSearch(tab: string) { router.push({ path: '/search', query: { tab, task_id: id.value } }) }
onMounted(load)
</script>
