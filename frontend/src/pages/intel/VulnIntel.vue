<template>
  <PageContainer title="漏洞情报" kicker="Vuln Intelligence" description="外部 CVE 情报由 Watchtower 云端情报库统一采集、去重后分发,本平台从云端拉取入库;并聚合本地可直接执行的验证(NPoC 插件 / nuclei 模板)。AI 渗透识别出组件后直接查该组件已知漏洞与可用 PoC。">
    <template #extra>
      <a-space>
        <span class="feed-meta">上次同步:{{ cloudSource?.last_fetch || status.last_fetch || '尚未同步' }}</span>
        <a-button @click="loadAll">刷新</a-button>
        <a-tooltip title="常态由调度器按间隔自动从云端同步;刚公开的高危 CVE 可点此立即同步一次">
          <a-button type="primary" ghost :loading="running" @click="runFeed">立即同步</a-button>
        </a-tooltip>
      </a-space>
    </template>

    <!-- 情报来源：云端主来源(突出) + 本地可执行源 -->
    <a-card size="small" class="page-card src-health" :bordered="false">
      <div class="src-health-head">
        <span class="sh-title">情报来源</span>
        <span class="sh-interval">
          云端同步间隔
          <a-select v-model:value="intervalSel" size="small" style="width: 120px" :options="intervalOptions" @change="saveInterval" />
        </span>
      </div>

      <!-- 云端主来源 hero -->
      <div v-if="cloudSource" class="cloud-hero" :class="cloudSource.health">
        <div class="cloud-glyph">
          <svg viewBox="0 0 48 48" aria-hidden="true"><path d="M34 40H14A10 10 0 0 1 12 20.2 13 13 0 0 1 37 22a8 8 0 0 1-3 18Z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M24 34V22m0 0-5 5m5-5 5 5" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <div class="cloud-main">
          <div class="cloud-title">
            <span class="cloud-name">Watchtower 云端情报库</span>
            <span class="cloud-badge" :class="cloudSource.health">{{ healthText(cloudSource.health) }}</span>
          </div>
          <div class="cloud-sub">
            外部 CVE 情报统一来源 · 已同步 <b>{{ (cloudSource.remote_count || cloudSource.fetched || stat.total) || 0 }}</b> 条
            <span v-if="cloudSource.last_fetch"> · 上次同步 {{ cloudSource.last_fetch }}</span>
          </div>
        </div>
        <div class="cloud-metrics">
          <div class="cm"><span class="cm-n">{{ stat.in_kev || 0 }}</span><span class="cm-l">在野</span></div>
          <div class="cm"><span class="cm-n">{{ stat.by_severity && stat.by_severity.critical || 0 }}</span><span class="cm-l">严重</span></div>
        </div>
      </div>

      <!-- 本地可执行能力源 -->
      <div v-if="localSources.length" class="local-src-wrap">
        <div class="local-src-label">本地可执行能力（本机 · 直接可打）</div>
        <div class="src-grid">
          <div v-for="s in localSources" :key="s.name" class="src-chip" :class="s.health">
            <span class="dot" :class="s.health"></span>
            <div class="src-info">
              <a v-if="s.url" :href="s.url" target="_blank" rel="noreferrer" class="src-name">{{ s.label }}</a>
              <span v-else class="src-name">{{ s.label }}</span>
              <div class="src-sub">
                <span>{{ healthText(s.health) }}</span>
                <span v-if="s.fetched"> · {{ s.fetched }} 条</span>
                <span v-if="s.error" class="src-err"> · {{ s.error.slice(0, 30) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </a-card>

    <!-- 概览卡 -->
    <a-row :gutter="16" class="stat-row">
      <a-col :span="4"><a-card size="small"><a-statistic title="漏洞总数" :value="stat.total" /></a-card></a-col>
      <a-col :span="4"><a-card size="small"><a-statistic title="在野利用" :value="stat.in_kev" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="4"><a-card size="small"><a-statistic title="本地可直接打" :value="stat.executable" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="4"><a-card size="small"><a-statistic title="严重" :value="stat.by_severity.critical || 0" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="4"><a-card size="small"><a-statistic title="高危" :value="stat.by_severity.high || 0" :value-style="{ color: '#fa541c' }" /></a-card></a-col>
      <a-col :span="4"><a-card size="small"><a-statistic title="中危" :value="stat.by_severity.medium || 0" :value-style="{ color: '#faad14' }" /></a-card></a-col>
    </a-row>

    <!-- 按组件查(AI 同款) -->
    <a-card size="small" class="page-card" title="按组件查漏洞">
      <a-input-search v-model:value="comp" placeholder="输入组件名,如 weblogic / struts / seeyon" enter-button="查询"
        style="max-width: 480px" @search="doQuery" />
      <div v-if="queryDone" class="query-hint">命中 {{ queryResult.length }} 条{{ queryResult.length ? '(可执行/在野优先)' : ',换个组件名或别名试试(中文组件可能需英文名,如 致远→seeyon)' }}</div>
    </a-card>

    <!-- 过滤 + 列表 -->
    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item label="关键词"><a-input v-model:value="query.keyword" placeholder="CVE/标题/组件" allow-clear style="width: 200px" /></a-form-item>
      <a-form-item label="等级">
        <a-select v-model:value="query.severity" allow-clear style="width: 120px" :options="sevOptions" placeholder="全部" />
      </a-form-item>
      <a-form-item label="在野"><a-switch v-model:checked="kevOnly" @change="reload" /></a-form-item>
      <a-form-item label="可执行"><a-switch v-model:checked="execOnly" @change="reload" /></a-form-item>
      <a-form-item label="排序">
        <a-switch v-model:checked="sortByExposure" checked-children="最新曝光" un-checked-children="在野优先" @change="reload" />
      </a-form-item>
    </SearchBar>

    <AppTable :columns="columns" :data="rows" :loading="loading"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'cve'">
          <span v-if="record.cve_id">{{ record.cve_id }}</span>
          <span v-else class="muted">(无 CVE)</span>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="sevColor(record.severity)">{{ record.severity }}</a-tag>
        </template>
        <template v-else-if="column.key === 'flags'">
          <a-tag v-if="record.in_kev" color="red">在野</a-tag>
          <a-tag v-if="record.executable" color="green">可打:{{ record.exec_kind }}</a-tag>
        </template>
        <template v-else-if="column.key === 'products'">
          <div class="prod-cell">
            <a-tag v-for="p in record.products.slice(0, 3)" :key="p" class="prod-tag">{{ p }}</a-tag>
            <a-tooltip v-if="record.products.length > 3" :title="record.products.join(', ')">
              <a-tag>+{{ record.products.length - 3 }}</a-tag>
            </a-tooltip>
          </div>
        </template>
        <template v-else-if="column.key === 'sources'">
          <span class="src-wt"><span class="src-wt-dot"></span>Watchtower 云端情报库</span>
        </template>
        <template v-else-if="column.key === 'poc'">
          <a v-for="(u, i) in record.poc_urls.slice(0, 2)" :key="i" :href="u" target="_blank" rel="noreferrer" class="poc-link">PoC{{ i + 1 }}</a>
          <span v-if="record.executable" class="exec-ref">[{{ record.exec_ref }}]</span>
        </template>
        <template v-else-if="column.key === 'exposure'">
          <span :class="{ muted: !record.published_date }">{{ toDay(record.published_date) }}</span>
        </template>
        <template v-else-if="column.key === 'fetched'">
          <span class="muted">{{ toDay(record.fetched_date) }}</span>
        </template>
      </template>
    </AppTable>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import { vulnIntelApi, type VulnIntelItem, type VulnIntelStat, type FeedStatus, SEVERITY_COLOR } from '../../api/vulnIntel'

const loading = ref(false)
const running = ref(false)
const rows = ref<VulnIntelItem[]>([])
const total = ref(0)
const stat = reactive<VulnIntelStat>({ total: 0, in_kev: 0, executable: 0, by_severity: {}, by_source: {} })
const status = reactive<FeedStatus>({ last_fetch: '', interval_seconds: 21600, interval_hours: 6, sources: [] })

// 云端主来源(kind=cloud) 与 本地可执行源分离展示
const cloudSource = computed<any>(() => (status.sources || []).find((s: any) => s.kind === 'cloud') || null)
const localSources = computed(() => (status.sources || []).filter((s: any) => s.kind !== 'cloud'))

const intervalSel = ref(21600)
const intervalOptions = [
  { value: 1800, label: '30 分钟' }, { value: 3600, label: '1 小时' },
  { value: 10800, label: '3 小时' }, { value: 21600, label: '6 小时' },
  { value: 43200, label: '12 小时' }, { value: 86400, label: '24 小时' }
]
function healthText(h: string) {
  return { ok: '正常', error: '异常', empty: '拉取为空', unknown: '未拉取' }[h] || h
}

const comp = ref('')
const queryResult = ref<VulnIntelItem[]>([])
const queryDone = ref(false)

const kevOnly = ref(false)
const execOnly = ref(false)
const sortByExposure = ref(true)   // 默认按最新曝光时间排序（用户要求最新曝光在前）
const query = reactive({ keyword: '', severity: undefined as string | undefined, source: undefined as string | undefined, page: 1, size: 20 })

const sevOptions = ['critical', 'high', 'medium', 'low'].map(v => ({ value: v, label: v }))
function sevColor(s: string) { return SEVERITY_COLOR[s] || 'default' }
// 时间只保留到天(YYYY-MM-DD),去掉时分秒
function toDay(v: unknown) {
  const s = v ? String(v) : ''
  return s ? s.slice(0, 10) : '—'
}

const columns = [
  { title: 'CVE', key: 'cve', width: 150 },
  { title: '标题', dataIndex: 'title', ellipsis: true, width: 280 },
  { title: '等级', key: 'severity', width: 90 },
  { title: '标记', key: 'flags', width: 140 },
  { title: '组件', key: 'products', width: 220 },
  { title: '来源', key: 'sources', width: 180, ellipsis: true },
  { title: 'PoC/可执行', key: 'poc', width: 150 },
  { title: '曝光时间', key: 'exposure', width: 160 },
  { title: '获取时间', key: 'fetched', width: 160 }
]

async function loadStat() {
  try {
    Object.assign(stat, await vulnIntelApi.stat())
  } catch (e) { message.error((e as Error).message || '统计加载失败') }
}

async function loadStatus() {
  try {
    Object.assign(status, await vulnIntelApi.status())
    intervalSel.value = status.interval_seconds
  } catch { /* 状态非关键,忽略 */ }
}

async function saveInterval(v: number) {
  try {
    await vulnIntelApi.setInterval(v)
    message.success('自动拉取间隔已更新')
    loadStatus()
  } catch (e) { message.error((e as Error).message || '设置失败') }
}

async function loadList() {
  loading.value = true
  try {
    const res = await vulnIntelApi.list({
      keyword: query.keyword || undefined, severity: query.severity, source: query.source,
      in_kev: kevOnly.value ? '1' : undefined, executable: execOnly.value ? '1' : undefined,
      sort: sortByExposure.value ? 'exposure' : 'kev',
      page: query.page, size: query.size
    })
    rows.value = res.items; total.value = res.total
  } catch (e) { message.error((e as Error).message || '列表加载失败') } finally { loading.value = false }
}

function loadAll() { loadStat(); loadStatus(); loadList() }
function reload() { query.page = 1; loadList() }
function onReset() { query.keyword = ''; query.severity = undefined; query.source = undefined; kevOnly.value = false; execOnly.value = false; sortByExposure.value = true; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }

async function doQuery() {
  if (!comp.value) return
  try {
    const r = await vulnIntelApi.query(comp.value)
    queryResult.value = r.vulns; queryDone.value = true
    // 命中结果直接填进列表展示
    rows.value = r.vulns; total.value = r.vulns.length
  } catch (e) { message.error((e as Error).message || '查询失败') }
}

async function runFeed() {
  running.value = true
  try {
    const r = await vulnIntelApi.run()
    message.success('已触发拉取: ' + JSON.stringify(r))
    loadAll()
  } catch (e) { message.error((e as Error).message || '拉取失败') } finally { running.value = false }
}

onMounted(loadAll)
</script>

<style scoped>
.stat-row { margin-bottom: 16px; }
/* 让概览行各卡等高对齐（来源分布内容多不再撑高整行） */
.stat-row > .ant-col { display: flex; }
.stat-row .ant-card { width: 100%; }
.stat-row :deep(.ant-card) { height: 100%; }
/* 表格「来源」列：统一 Watchtower 云端情报库标签 */
.src-wt { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: #00a7c4; white-space: nowrap; }
.src-wt-dot { width: 6px; height: 6px; border-radius: 50%; background: #00c8e6; box-shadow: 0 0 5px rgba(0,229,255,.5); flex-shrink: 0; }
.query-hint { margin-top: 8px; color: #888; font-size: 13px; }
.muted { color: #aaa; }
.poc-link { margin-right: 8px; }
.exec-ref { color: #3f8600; font-size: 12px; }
.feed-meta { color: #888; font-size: 12px; margin-right: 4px; }

/* 来源健康可视化 */
.src-health { margin-bottom: 16px; }
.src-health-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.sh-title { font-weight: 600; }
.sh-interval { font-size: 13px; color: var(--dt-muted); }
/* 云端主来源 hero */
.cloud-hero { display: flex; align-items: center; gap: 13px; padding: 10px 15px; border-radius: 9px; margin-bottom: 10px; position: relative; overflow: hidden;
  background: linear-gradient(120deg, rgba(0,229,255,.11), rgba(24,144,255,.05)); border: 1px solid rgba(0,229,255,.30); }
.cloud-hero::after { content: ""; position: absolute; right: -40px; top: -46px; width: 150px; height: 150px; border-radius: 50%; background: radial-gradient(circle, rgba(0,229,255,.13), transparent 70%); pointer-events: none; }
.cloud-hero.unknown { background: linear-gradient(120deg, rgba(150,150,150,.10), rgba(150,150,150,.03)); border-color: rgba(150,150,150,.28); }
.cloud-glyph { width: 34px; height: 34px; color: #00c8e6; flex-shrink: 0; filter: drop-shadow(0 0 6px rgba(0,229,255,.35)); }
.cloud-glyph svg { width: 34px; height: 34px; }
.cloud-main { flex: 1; min-width: 0; }
.cloud-title { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.cloud-name { font-size: 16px; font-weight: 650; color: var(--dt-text); letter-spacing: .3px; }
.cloud-badge { font-size: 11px; padding: 1px 9px; border-radius: 10px; }
.cloud-badge.ok { background: rgba(82,196,26,.16); color: #52c41a; }
.cloud-badge.unknown { background: rgba(150,150,150,.18); color: #999; }
.cloud-sub { font-size: 12.5px; color: var(--dt-muted); margin-top: 4px; }
.cloud-sub b { color: #00c8e6; font-weight: 600; }
.cloud-metrics { display: flex; gap: 22px; padding-left: 10px; flex-shrink: 0; }
.cm { display: flex; flex-direction: column; align-items: center; }
.cm-n { font-size: 20px; font-weight: 700; color: var(--dt-text); line-height: 1.15; }
.cm-l { font-size: 11px; color: var(--dt-muted); }
.local-src-label { font-size: 12px; color: var(--dt-muted); margin: 2px 0 8px; }
.src-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }
/* 半透明色调 + 主题文字变量：日/夜都可读（原写死浅色底在夜间字看不见） */
.src-chip { display: flex; align-items: flex-start; gap: 8px; padding: 8px 10px; border: 1px solid var(--dt-border); border-radius: 6px; background: var(--dt-fill, #fafafa); color: var(--dt-text); }
.src-chip.error { border-color: rgba(255,77,79,.45); background: rgba(255,77,79,.10); }
.src-chip.empty { border-color: rgba(250,173,20,.45); background: rgba(250,173,20,.10); }
.src-chip.ok { border-color: rgba(82,196,26,.45); background: rgba(82,196,26,.10); }
.dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 6px; flex-shrink: 0; }
.dot.ok { background: #52c41a; }
.dot.error { background: #ff4d4f; }
.dot.empty { background: #faad14; }
.dot.unknown { background: #bfbfbf; }
.src-name { font-size: 13px; font-weight: 500; }
.src-sub { font-size: 12px; color: #999; margin-top: 2px; }
.src-err { color: #ff4d4f; }
.prod-cell { display: flex; flex-wrap: nowrap; overflow: hidden; }
.prod-tag { max-width: 90px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>

