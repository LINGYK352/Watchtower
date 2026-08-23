<template>
  <PageContainer title="访问日志" kicker="Access Log" description="系统所有 API 访问与操作审计:谁(用户)、何时、从哪(IP)、访问什么(接口)、结果(状态码)、耗时。写操作(增删改)标记为操作日志。保留 14 天自动过期。">
    <template #extra>
      <a-space>
        <a-button @click="loadAll">刷新</a-button>
        <a-button @click="openRetention">保留设置</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" class="stat-row">
      <a-col :span="6"><a-card size="small"><a-statistic title="访问总数" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card size="small"><a-statistic title="操作" :value="stat.writes" :value-style="{ color: '#1677ff' }" /></a-card></a-col>
      <a-col :span="6"><a-card size="small"><a-statistic title="今日访问" :value="stat.today" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card size="small"><a-statistic title="错误请求" :value="stat.errors" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
    </a-row>

    <a-tabs v-model:activeKey="tab" @change="onTabChange">
      <a-tab-pane key="all" tab="全部访问" />
      <a-tab-pane key="write" tab="操作日志" />
    </a-tabs>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item label="用户"><a-input v-model:value="query.username" placeholder="用户名" allow-clear style="width: 140px" /></a-form-item>
      <a-form-item label="接口"><a-input v-model:value="query.path" placeholder="/api/..." allow-clear style="width: 200px" /></a-form-item>
      <a-form-item label="状态码"><a-input v-model:value="query.status" placeholder="如 200/404" allow-clear style="width: 110px" /></a-form-item>
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
          <a-tag v-if="record.is_write" color="blue">操作</a-tag>
          <span v-else class="muted">读</span>
        </template>
        <template v-else-if="column.key === 'elapsed'">{{ record.elapsed_ms }}ms</template>
      </template>
    </AppTable>

    <a-modal v-model:open="retentionOpen" title="日志保留设置" :confirm-loading="retentionSaving" @ok="saveRetention" ok-text="保存" cancel-text="取消">
      <p style="color: #888; margin-bottom: 16px">超过保留天数的日志自动删除(MongoDB TTL,运行时即时生效,无需重启)。最少保留 1 天，不设人为上限。</p>
      <a-form layout="horizontal" :label-col="{ span: 10 }" :wrapper-col="{ span: 14 }">
        <a-form-item v-for="(item, key) in retention" :key="key" :label="item.label">
          <a-input-number v-model:value="item.days" :min="1" addon-after="天" style="width: 160px" />
          <span style="color: #aaa; margin-left: 8px">默认 {{ item.default_days }} 天</span>
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
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
  { title: '方法', key: 'method', width: 80 },
  { title: '接口', dataIndex: 'path', ellipsis: true },
  { title: '状态', key: 'status', width: 80 },
  { title: '类型', key: 'is_write', width: 70 },
  { title: '用户', dataIndex: 'username', width: 120 },
  { title: 'IP', dataIndex: 'ip', width: 130 },
  { title: '耗时', key: 'elapsed', width: 90 },
  { title: '时间', dataIndex: 'save_date', width: 160 }
]

function methodColor(m: string) { return { GET: 'default', POST: 'green', PUT: 'orange', DELETE: 'red', PATCH: 'purple' }[m] || 'default' }
function statusColor(s: number) { return s >= 500 ? 'red' : s >= 400 ? 'orange' : s >= 200 && s < 300 ? 'green' : 'default' }

async function loadStat() {
  try { Object.assign(stat, await accessLogApi.stat()) } catch (e) { message.error((e as Error).message || '统计失败') }
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
  } catch (e) { message.error((e as Error).message || '加载失败') } finally { loading.value = false }
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
  catch (e) { message.error((e as Error).message || '加载失败') }
}
async function saveRetention() {
  retentionSaving.value = true
  try {
    const updates: Record<string, number> = {}
    Object.entries(retention.value).forEach(([k, v]) => { updates[k] = v.days })
    retention.value = await accessLogApi.setRetention(updates)
    message.success('已保存,即时生效')
    retentionOpen.value = false
  } catch (e) { message.error((e as Error).message || '保存失败') } finally { retentionSaving.value = false }
}

onMounted(loadAll)
</script>

<style scoped>
.stat-row { margin-bottom: 16px; }
.muted { color: #aaa; }
</style>
