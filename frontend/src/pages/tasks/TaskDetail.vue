<template>
  <PageContainer title="任务详情" kicker="Task Detail" description="任务基本信息、扫描选项与结果统计，结果可跳转到资产检索。">
    <template #extra><a-button @click="router.push('/tasks')">返回列表</a-button></template>
    <a-card :bordered="false" :loading="loading" style="margin-bottom: 16px">
      <a-descriptions bordered size="small" :column="2">
        <a-descriptions-item label="任务 ID"><CopyText :text="id" /></a-descriptions-item>
        <a-descriptions-item label="任务名">{{ task.name || '-' }}</a-descriptions-item>
        <a-descriptions-item label="目标"><CopyText :text="String(task.target || '')" /></a-descriptions-item>
        <a-descriptions-item label="状态"><StatusTag :value="String(task.status || '')" /></a-descriptions-item>
        <a-descriptions-item label="类型">{{ task.type || '-' }}</a-descriptions-item>
        <a-descriptions-item label="开始时间">{{ task.start_time || '-' }}</a-descriptions-item>
        <a-descriptions-item label="结束时间">{{ task.end_time || '-' }}</a-descriptions-item>
        <a-descriptions-item label="耗时">{{ duration }}</a-descriptions-item>
      </a-descriptions>
    </a-card>

    <a-alert v-if="isEmptyDone" type="warning" show-icon style="margin-bottom: 16px"
      message="任务已结束,但未发现任何资产"
      description="域名 / IP / 站点均为 0。可能原因:目标无存活资产、扫描策略未开启对应扫描项、DNS/代理不通或目标限速。建议检查扫描策略配置,或返回列表点「重启」重跑。" />

    <a-card title="结果统计" :bordered="false" style="margin-bottom: 16px">
      <a-row :gutter="16">
        <a-col :span="4" v-for="s in statItems" :key="s.key">
          <a-statistic :title="s.title" :value="statValue(s.key)" />
          <a-button type="link" size="small" @click="goSearch(s.tab)">查看</a-button>
        </a-col>
      </a-row>
    </a-card>

    <a-card title="扫描选项" :bordered="false">
      <a-space wrap>
        <a-tag v-for="(v, k) in enabledOptions" :key="k" color="blue">{{ k }}</a-tag>
        <span v-if="!Object.keys(enabledOptions).length">无</span>
      </a-space>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
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
  { key: 'domain_cnt', title: '域名', tab: 'domain' },
  { key: 'ip_cnt', title: 'IP', tab: 'ip' },
  { key: 'site_cnt', title: '站点', tab: 'site' },
  { key: 'url_cnt', title: 'URL', tab: 'url' },
  { key: 'vuln_cnt', title: '漏洞', tab: 'site' },
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
  if (!e || e === '-') return '进行中'
  const ms = new Date(e.replace(/-/g, '/')).getTime() - new Date(s.replace(/-/g, '/')).getTime()
  if (isNaN(ms) || ms < 0) return '-'
  const sec = Math.floor(ms / 1000)
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), ss = sec % 60
  return (h ? h + '时' : '') + (h || m ? m + '分' : '') + ss + '秒'
})
const enabledOptions = computed(() => {
  const opts = (task.value.options as Record<string, unknown>) || {}
  const result: Record<string, boolean> = {}
  Object.entries(opts).forEach(([k, v]) => { if (v === true) result[k] = true })
  return result
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
