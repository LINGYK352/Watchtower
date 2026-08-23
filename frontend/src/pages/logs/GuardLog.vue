<template>
  <PageContainer title="闸刀拦截日志" kicker="Guard Log" description="AI 渗透智能闸刀的放行/拦截记录(独立日志,非程序报错)。固定容量环形存储,满了自动覆盖最早。">
    <template #extra>
      <a-space>
        <a-button @click="loadAll">刷新</a-button>
        <a-button @click="sizeOpen = true">容量设置</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom:16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="总记录" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="拦截" :value="stat.blocked" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="放行" :value="stat.allowed" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="日志容量" :value="stat.size_mb" suffix="MB" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item label="结果">
        <a-select v-model:value="query.allow" style="width:130px" :options="allowOptions" />
      </a-form-item>
      <a-form-item label="模式">
        <a-select v-model:value="query.mode" style="width:120px" :options="modeOptions" />
      </a-form-item>
    </SearchBar>

    <AppTable :columns="columns" :data="rows" :loading="loading"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'allow'">
          <a-tag :color="record.allow ? 'green' : 'red'">{{ record.allow ? '放行' : '拦截' }}</a-tag>
        </template>
        <template v-else-if="column.key === 'mode'">
          <a-tag :color="pentestModeColor(record.mode)">{{ pentestModeLabel(record.mode) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'method'">
          <a-tag :color="methodColor(record.method)">{{ record.method }}</a-tag>
        </template>
      </template>
    </AppTable>

    <a-modal v-model:open="sizeOpen" title="拦截日志容量设置" :confirm-loading="saving" @ok="saveSize" ok-text="保存" cancel-text="取消">
      <p style="color:#888;margin-bottom:16px">固定容量环形存储(capped),满了自动覆盖最早记录。最少 1 MB，不设人为上限，默认 {{ stat.default_size_mb }} MB。<b style="color:#d46b08">改容量会清空历史拦截日志。</b></p>
      <a-input-number v-model:value="sizeMb" :min="1" addon-after="MB" style="width:180px" />
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
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

const allowOptions = [{ label: '全部', value: '' }, { label: '拦截', value: '0' }, { label: '放行', value: '1' }]
const modeOptions = [{ label: '全部', value: '' }, ...PENTEST_MODES.map(m => ({ label: m.label, value: m.value }))]
const columns = [
  { title: '结果', key: 'allow', width: 80 },
  { title: '模式', key: 'mode', width: 80 },
  { title: '方法', key: 'method', width: 90 },
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { title: '判定', dataIndex: 'level', width: 110 },
  { title: '原因', dataIndex: 'reason', ellipsis: true },
  { title: '时间', dataIndex: 'save_date', width: 160 }
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
  } catch (e) { message.error((e as Error).message || '加载失败') } finally { loading.value = false }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.allow = ''; query.mode = ''; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }
async function saveSize() {
  saving.value = true
  try { await logMonitorApi.setGuardSize(sizeMb.value); message.success('已保存,即时生效'); sizeOpen.value = false; loadAll() }
  catch (e) { message.error((e as Error).message || '保存失败') } finally { saving.value = false }
}
onMounted(loadAll)
</script>
