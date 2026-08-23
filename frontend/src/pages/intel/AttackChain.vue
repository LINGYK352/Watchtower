<template>
  <PageContainer title="攻击链情报" kicker="Attack Chains"
    description="渗透打通的利用链:一环扣一环串成的攻击路径。孤立低危串成链危害拉满,支持跨会话延续。">
    <template #extra><a-button @click="loadAll">刷新</a-button></template>

    <a-row :gutter="12" style="margin-bottom:16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="攻击链总数" :value="stat.total" :value-style="{ color: '#1677ff' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="跨会话链" :value="stat.cross_session" :value-style="{ color: '#722ed1' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="严重/高危链" :value="(stat.by_severity.critical || 0) + (stat.by_severity.high || 0)" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="中危链" :value="stat.by_severity.medium || 0" :value-style="{ color: '#d46b08' }" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item label="单位"><a-input v-model:value="query.unit" allow-clear placeholder="单位名" style="width:180px" /></a-form-item>
      <a-form-item label="状态">
        <a-select v-model:value="query.status" style="width:130px" :options="statusOptions" />
      </a-form-item>
    </SearchBar>

    <div style="margin-bottom:8px">
      <a-popconfirm :title="`确认删除选中的 ${selectedKeys.length} 条攻击链？`" :disabled="!selectedKeys.length" @confirm="batchDelete">
        <a-button danger :disabled="!selectedKeys.length">批量删除{{ selectedKeys.length ? `(${selectedKeys.length})` : '' }}</a-button>
      </a-popconfirm>
    </div>

    <AppTable :columns="columns" :data="rows" :loading="loading" selectable
      v-model:selectedRowKeys="selectedKeys"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'title'">
          <a class="chain-title" @click="showDetail(record)">{{ record.title }}</a>
          <a-tag v-if="record.cross_session" color="purple" style="margin-left:6px">跨会话</a-tag>
        </template>
        <template v-else-if="column.key === 'step_count'">
          <a-badge :count="record.step_count" :number-style="{ backgroundColor: '#1677ff' }" />
        </template>
        <template v-else-if="column.key === 'max_severity'">
          <a-tag :color="sevColor(record.max_severity)">{{ (record.max_severity || 'unknown').toUpperCase() }}</a-tag>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="record.status === 'done' ? 'green' : 'blue'">{{ record.status === 'done' ? '已完成' : '构建中' }}</a-tag>
        </template>
        <template v-else-if="column.key === 'outline'">
          <span class="outline">{{ chainOutline(record) }}</span>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space size="small">
            <a-button type="link" size="small" @click="showDetail(record)">详情</a-button>
            <ConfirmAction danger title="确认删除该攻击链？" @confirm="removeOne(record)">删除</ConfirmAction>
          </a-space>
        </template>
      </template>
    </AppTable>

    <a-drawer v-model:open="detailOpen" :title="cur?.title || '攻击链详情'" width="60%">
      <a-spin :spinning="detailLoading">
        <a-descriptions :column="2" size="small" bordered style="margin-bottom:16px">
          <a-descriptions-item label="单位">{{ cur?.unit || '—' }}</a-descriptions-item>
          <a-descriptions-item label="环节数">{{ cur?.step_count || 0 }}</a-descriptions-item>
          <a-descriptions-item label="最高危害"><a-tag :color="sevColor(cur?.max_severity)">{{ (cur?.max_severity || 'unknown').toUpperCase() }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="状态"><a-tag :color="cur?.status === 'done' ? 'green' : 'blue'">{{ cur?.status === 'done' ? '已完成' : '构建中' }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="跨会话">{{ cur?.cross_session ? `是（${cur?.sessions?.length || 0} 个会话接力）` : '否' }}</a-descriptions-item>
          <a-descriptions-item label="更新时间">{{ cur?.update_date || '—' }}</a-descriptions-item>
        </a-descriptions>

        <a-timeline class="chain-timeline">
          <a-timeline-item v-for="s in (cur?.steps || [])" :key="s.seq" :color="sevColor(s.severity) === 'default' ? 'blue' : sevColor(s.severity)">
            <div class="step-head">
              <b>环节 {{ s.seq }}</b>
              <a-tag v-if="s.vuln_type" :color="sevColor(s.severity)" style="margin-left:6px">{{ s.vuln_type }}</a-tag>
              <span class="step-at">{{ s.at }}</span>
            </div>
            <div class="step-action">{{ s.action }}</div>
            <div v-if="s.result" class="step-result">→ {{ s.result }}</div>
            <div v-if="s.target" class="step-target"><CopyText :text="s.target" /></div>
            <div v-if="s.finding_ref || s.clue_ref" class="step-ref">
              <a-tag v-if="s.finding_ref" color="red">漏洞: {{ s.finding_ref }}</a-tag>
              <a-tag v-if="s.clue_ref" color="cyan">线索: {{ s.clue_ref }}</a-tag>
            </div>
          </a-timeline-item>
        </a-timeline>
        <a-empty v-if="!cur?.steps?.length" description="无环节" />
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>


<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import CopyText from '../../components/CopyText.vue'
import { intelApi, type AttackChain, type ChainStat } from '../../api/intel'

const loading = ref(false)
const rows = ref<AttackChain[]>([])
const total = ref(0)
const selectedKeys = ref<string[]>([])
const stat = reactive<ChainStat>({ total: 0, cross_session: 0, by_severity: {} })
const query = reactive({ unit: '', status: '', page: 1, size: 20 })

const statusOptions = [{ label: '全部', value: '' }, { label: '构建中', value: 'building' }, { label: '已完成', value: 'done' }]
const columns = [
  { title: '攻击链', key: 'title' },
  { title: '环节', key: 'step_count', width: 70 },
  { title: '最高危害', key: 'max_severity', width: 100 },
  { title: '状态', key: 'status', width: 90 },
  { title: '路径概览', key: 'outline' },
  { title: '操作', key: 'action', width: 120 }
]

const detailOpen = ref(false)
const detailLoading = ref(false)
const cur = ref<AttackChain | null>(null)

function sevColor(s?: string) {
  const m: Record<string, string> = { critical: 'red', high: 'volcano', medium: 'orange', low: 'gold', info: 'default' }
  return m[(s || '').toLowerCase()] || 'default'
}
function chainOutline(r: AttackChain) {
  return (r.steps || []).map(s => (s.action || '').slice(0, 20)).join(' → ') || '—'
}
async function loadStat() {
  try { Object.assign(stat, await intelApi.chainStat(query.unit || undefined)) } catch (e) { /* ignore */ }
}
async function loadList() {
  loading.value = true
  try {
    const data = await intelApi.chains({ unit: query.unit || undefined, status: query.status || undefined, page: query.page, size: query.size })
    rows.value = data.items
    total.value = data.total
    selectedKeys.value = []
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function batchDelete() {
  if (!selectedKeys.value.length) return
  try {
    const res = await intelApi.chainDelete(selectedKeys.value)
    message.success(`已删除 ${res.deleted ?? selectedKeys.value.length} 条`)
    loadAll()
  } catch (e) { message.error((e as Error).message) }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.unit = ''; query.status = ''; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }
async function showDetail(r: AttackChain) {
  detailOpen.value = true
  detailLoading.value = true
  try { cur.value = await intelApi.chainDetail(r._id) } catch (e) { message.error((e as Error).message) } finally { detailLoading.value = false }
}
async function removeOne(r: AttackChain) {
  try { await intelApi.chainDelete(r._id); message.success('已删除'); loadAll() } catch (e) { message.error((e as Error).message) }
}

onMounted(loadAll)
</script>

<style scoped>
.chain-title { font-weight: 600; cursor: pointer; }
.outline { color: #888; font-size: 12px; }
.chain-timeline { margin-top: 8px; }
.step-head { display: flex; align-items: center; gap: 4px; }
.step-at { margin-left: auto; color: #aaa; font-size: 12px; }
.step-action { margin: 4px 0; }
.step-result { color: #389e0d; margin-bottom: 4px; }
.step-target { margin-bottom: 4px; }
.step-ref { margin-top: 2px; }
</style>
