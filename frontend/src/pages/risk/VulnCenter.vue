<template>
  <PageContainer title="漏洞中心" kicker="Vulnerabilities"
    description="系统扫描(PoC/Nuclei)与 AI 渗透已验证漏洞统一视图,按来源标记。只展示经验证的真实漏洞,AI 未实证线索见渗透会话详情。">
    <template #extra>
      <a-space>
        <a-switch v-model:checked="auto.enabled.value" checked-children="自动" un-checked-children="手动" size="small" />
        <a-button @click="loadAll">刷新</a-button>
      </a-space>
    </template>

    <a-row :gutter="12" style="margin-bottom:16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="AI 已验证漏洞" :value="stat.ai.verified" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="严重/高危" :value="(stat.ai.by_severity.critical || 0) + (stat.ai.by_severity.high || 0)" :value-style="{ color: '#a8071a' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :value="stat.poc.total">
        <template #title><span>系统扫描</span>
          <a-tooltip title="PoC/Nuclei 为系统扫描来源，不区分单位；按单位筛选只作用于 AI 漏洞，此处始终为全量。">
            <QuestionCircleOutlined style="margin-left:4px;color:#aaa" /></a-tooltip>
        </template></a-statistic></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="漏洞合计" :value="stat.combined_total" :value-style="{ color: '#1677ff' }" /></a-card></a-col>
    </a-row>

    <div style="margin-bottom:12px">
      <a-segmented v-model:value="query.source" :options="sourceOptions" @change="reload" />
    </div>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item label="关键词"><a-input v-model:value="query.keyword" allow-clear placeholder="漏洞名 / 目标" style="width:200px" /></a-form-item>
      <a-form-item label="等级">
        <a-select v-model:value="query.severity" allow-clear style="width:120px" :options="sevOptions" placeholder="精确等级" />
      </a-form-item>
      <a-form-item label="最低等级">
        <a-select v-model:value="query.min_severity" style="width:120px" :options="minSevOptions"
          :disabled="!!query.severity" @change="reload" />
      </a-form-item>
      <a-form-item label="单位" v-if="query.source === '' || query.source === 'ai'">
        <a-input v-model:value="query.unit" allow-clear placeholder="仅 AI 漏洞" style="width:150px" />
      </a-form-item>
      <a-form-item label="处理状态">
        <a-select v-model:value="query.handle_status" allow-clear style="width:120px" :options="handleStatusOptions" placeholder="全部" />
      </a-form-item>
      <a-form-item label="时间范围">
        <a-range-picker v-model:value="dateRange" value-format="YYYY-MM-DD" style="width:240px" @change="reload" />
      </a-form-item>
    </SearchBar>

    <div style="margin-bottom:8px">
      <a-popconfirm :title="`确认删除选中的 ${selectedKeys.length} 条漏洞？`" :disabled="!selectedKeys.length" @confirm="batchDelete">
        <a-button danger :disabled="!selectedKeys.length">批量删除{{ selectedKeys.length ? `(${selectedKeys.length})` : '' }}</a-button>
      </a-popconfirm>
    </div>

    <AppTable :columns="columns" :data="rows" :loading="loading" selectable
      v-model:selectedRowKeys="selectedKeys"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'source'">
          <a-tag :color="srcMeta(record.source).color">{{ srcMeta(record.source).label }}</a-tag>
        </template>
        <template v-else-if="column.key === 'verified'">
          <a-tag v-if="record.source === 'ai'" :color="record.verified ? 'red' : 'orange'">{{ record.verified ? '已验证' : '线索' }}</a-tag>
          <a-tag v-else color="cyan">命中</a-tag>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="sevColor(record.severity)">{{ (record.severity || 'unknown').toUpperCase() }}</a-tag>
          <a-tooltip v-if="record.cvss_score != null" :title="cvssNote(record)">
            <span class="muted" :class="{ calibrated: isCalibrated(record) }"> {{ record.cvss_score }}{{ isCalibrated(record) ? '*' : '' }}</span>
          </a-tooltip>
        </template>
        <template v-else-if="column.key === 'target'"><CopyText :text="String(record.target || '')" /></template>
        <template v-else-if="column.key === 'task_name'">
          <span v-if="record.task_name">{{ record.task_name }}</span>
          <span v-else class="muted">—</span>
        </template>
        <template v-else-if="column.key === 'unit'">
          <span v-if="record.unit">{{ record.unit }}</span>
          <!-- AI 来源:无单位=ICP 查不到备案(哨兵扫描来源本就无单位维度,只显 —) -->
          <span v-else-if="record.source === 'ai'" class="muted">暂无备案</span>
          <span v-else class="muted">—</span>
        </template>
        <template v-else-if="column.key === 'handle_status'">
          <a-tag :color="handleMeta(record.handle_status).color">{{ handleMeta(record.handle_status).label }}</a-tag>
          <a-tooltip v-if="record.handle_by || record.handle_at" :title="`${record.handle_by || '?'} @ ${record.handle_at || '?'}`">
            <div v-if="record.handle_by" class="muted" style="font-size:11px;line-height:1.2">{{ record.handle_by }}<br/>{{ (record.handle_at || '').slice(5,16) }}</div>
          </a-tooltip>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space size="small">
            <a-button type="link" size="small" @click="showDetail(record)">详情</a-button>
            <a-dropdown>
              <a-button type="link" size="small">标记<DownOutlined /></a-button>
              <template #overlay>
                <a-menu @click="(info: any) => markOne(record, String(info.key))">
                  <a-menu-item key="submitted">标记</a-menu-item>
                  <a-menu-item key="false_positive">误报</a-menu-item>
                  <a-menu-item key="">重置</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
            <ConfirmAction v-if="record.source !== 'ai'" danger title="确认删除该记录？" @confirm="removeOne(record)">删除</ConfirmAction>
          </a-space>
        </template>
      </template>
    </AppTable>

    <a-drawer v-model:open="detailOpen" :title="detailTitle" width="62%">
      <a-spin :spinning="detailLoading">
        <!-- AI 渗透漏洞详情 -->
        <a-descriptions v-if="cur.source === 'ai'" :column="1" size="small" bordered>
          <a-descriptions-item label="漏洞类型">{{ cur.vuln_type }}</a-descriptions-item>
          <a-descriptions-item label="目标">{{ cur.target }}</a-descriptions-item>
          <a-descriptions-item label="验证状态"><a-tag :color="cur.verified ? 'red' : 'orange'">{{ cur.verified ? '已验证(有证据)' : '线索(未实证)' }}</a-tag> <span class="muted">{{ cur.evidence_level }}</span></a-descriptions-item>
          <a-descriptions-item label="CVSS">{{ cur.cvss_vector || '—' }} <b v-if="cur.cvss_score != null">({{ cur.cvss_score }} {{ String(cur.severity || '').toUpperCase() }})</b></a-descriptions-item>
          <a-descriptions-item v-if="curCalibrated" label="定级依据">
            <a-tag color="orange">原始 {{ String(cur.cvss_severity).toUpperCase() }} → 校准 {{ String(cur.severity).toUpperCase() }}</a-tag>
            <span class="muted">{{ cur.severity_basis || '信息型泄露务实校准(只降不升)' }}</span>
          </a-descriptions-item>
          <a-descriptions-item v-if="cur.chain_severity" label="攻击链提级">
            <a-tag color="red">单点 {{ String(cur.severity).toUpperCase() }} → 链危害 {{ String(cur.chain_severity).toUpperCase() }}</a-tag>
            <span class="muted">作为攻击链「{{ cur.chain_title || '—' }}」的关键环节,实际危害按整链计</span>
          </a-descriptions-item>
          <a-descriptions-item label="危害">{{ cur.impact || '—' }}</a-descriptions-item>
          <a-descriptions-item v-if="cur.verify_method" label="验证方式">{{ cur.verify_method }}</a-descriptions-item>
          <a-descriptions-item v-if="cur.key_response" label="关键响应"><pre class="ev">{{ cur.key_response }}</pre></a-descriptions-item>
          <a-descriptions-item label="任务名">{{ cur.task_name || '—' }}</a-descriptions-item>
          <a-descriptions-item label="单位">{{ cur.unit || '暂无备案' }}</a-descriptions-item>
          <a-descriptions-item label="PoC/命令"><pre class="ev">{{ cur.poc || '—' }}</pre></a-descriptions-item>
          <a-descriptions-item label="证据(工具实抓请求/响应)">
            <template v-if="evToPackets(cur).length">
              <div v-for="(p, i) in evToPackets(cur)" :key="i" class="ev-packet">
                <div class="ev-pkt-head">
                  <a-tag color="blue">{{ p.tool }}</a-tag>
                  <a-tag v-if="p.signal" :color="p.signal === 'positive' ? 'green' : 'default'">{{ p.signal }}</a-tag>
                </div>
                <a-row :gutter="8">
                  <a-col :span="12">
                    <div class="ev-label">请求包 Request</div>
                    <pre class="ev burp-req">{{ p.reqText }}</pre>
                  </a-col>
                  <a-col :span="12">
                    <div class="ev-label">响应包 Response</div>
                    <pre class="ev burp-resp">{{ p.respText }}</pre>
                  </a-col>
                </a-row>
              </div>
            </template>
            <pre v-else class="ev">{{ aiEvidenceText(cur) }}</pre>
          </a-descriptions-item>
        </a-descriptions>
        <!-- nuclei 扫描详情 -->
        <a-descriptions v-else-if="cur.source === 'nuclei'" :column="1" size="small" bordered>
          <a-descriptions-item label="模版ID">{{ cur.template_id }}</a-descriptions-item>
          <a-descriptions-item label="漏洞名">{{ cur.vuln_name }}</a-descriptions-item>
          <a-descriptions-item label="等级"><a-tag :color="sevColor(String(cur.vuln_severity || ''))">{{ String(cur.vuln_severity || '-').toUpperCase() }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="漏洞URL"><CopyText :text="String(cur.vuln_url || '')" /></a-descriptions-item>
          <a-descriptions-item label="目标">{{ cur.target }}</a-descriptions-item>
          <a-descriptions-item label="curl 命令"><pre class="ev">{{ cur.curl_command || '—' }}</pre></a-descriptions-item>
          <a-descriptions-item label="任务ID">{{ cur.task_id }}</a-descriptions-item>
        </a-descriptions>
        <!-- 系统 PoC 命中详情 -->
        <a-descriptions v-else :column="1" size="small" bordered>
          <a-descriptions-item label="插件ID">{{ cur.plg_name }}</a-descriptions-item>
          <a-descriptions-item label="类别">{{ cur.plg_type }}</a-descriptions-item>
          <a-descriptions-item label="漏洞名">{{ cur.vul_name }}</a-descriptions-item>
          <a-descriptions-item label="应用">{{ cur.app_name || '—' }}</a-descriptions-item>
          <a-descriptions-item label="目标"><CopyText :text="String(cur.target || '')" /></a-descriptions-item>
          <a-descriptions-item label="任务ID">{{ cur.task_id }}</a-descriptions-item>
          <a-descriptions-item label="原始数据"><pre class="ev">{{ rawJson(cur) }}</pre></a-descriptions-item>
        </a-descriptions>
      </a-spin>
      <div style="margin-top:12px" v-if="cur.source === 'ai' && cur.session_id">
        <a-button type="link" @click="goSession(String(cur.session_id))">查看来源渗透会话 →</a-button>
      </div>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import { DownOutlined, QuestionCircleOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { pentestApi, type UnifiedFinding, type FindingStat } from '../../api/pentest'
import { vulnApi, nucleiResultApi } from '../../api/poc'
import { useAutoRefresh } from '../../composables/useAutoRefresh'

const router = useRouter()
const loading = ref(false)
const rows = ref<UnifiedFinding[]>([])
const total = ref(0)
const selectedKeys = ref<string[]>([])
const stat = reactive<FindingStat>({ ai: { total: 0, verified: 0, leads: 0, by_severity: {}, by_type: {} }, poc: { total: 0 }, combined_total: 0, unit: '' })

const query = reactive({
  source: '' as '' | 'ai' | 'poc' | 'nuclei',
  keyword: '', severity: undefined as string | undefined,
  min_severity: 'low' as string,   // 默认只显示 low 及以上(隐藏 info 噪声);设 'info' 则显示全部
  unit: '',
  handle_status: undefined as string | undefined,
  page: 1, size: 20
})
const dateRange = ref<[string, string] | undefined>(undefined)   // 时间范围筛选 [from,to]

const sourceOptions = [
  { label: '全部来源', value: '' },
  { label: 'AI 渗透', value: 'ai' },
  { label: '系统 PoC', value: 'poc' },
  { label: 'Nuclei', value: 'nuclei' }
]
const sevOptions = ['critical', 'high', 'medium', 'low', 'info'].map(v => ({ label: v.toUpperCase(), value: v }))
// 最低等级阈值:默认 LOW(隐藏 info);选"全部(含info)"= info 阈值不过滤
const minSevOptions = [
  { label: '全部(含 INFO)', value: 'info' },
  { label: 'LOW 及以上', value: 'low' },
  { label: 'MEDIUM 及以上', value: 'medium' },
  { label: 'HIGH 及以上', value: 'high' },
  { label: '仅 CRITICAL', value: 'critical' }
]
const handleStatusOptions = [
  { label: '未处理', value: 'unhandled' },
  { label: '已提交', value: 'submitted' },
  { label: '误报', value: 'false_positive' }
]
const HANDLE_META: Record<string, { label: string; color: string }> = {
  '': { label: '未处理', color: 'default' },
  submitted: { label: '已提交', color: 'green' },
  false_positive: { label: '误报', color: 'orange' }
}
function handleMeta(s?: string) { return HANDLE_META[s || ''] || HANDLE_META[''] }

const columns = [
  { title: '来源', key: 'source', width: 90 },
  { title: '状态', key: 'verified', width: 90 },
  { title: '漏洞名', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '目标', key: 'target', ellipsis: true },
  { title: '等级/CVSS', key: 'severity', width: 140 },
  { title: '任务名', key: 'task_name', width: 150, ellipsis: true },
  { title: '单位', key: 'unit', width: 140, ellipsis: true },
  { title: '处理', key: 'handle_status', width: 110 },
  { title: '时间', dataIndex: 'save_date', width: 160 },
  { title: '操作', key: 'action', width: 150 }
]

const SRC_META: Record<string, { label: string; color: string }> = {
  ai: { label: 'AI 渗透', color: 'red' },
  poc: { label: '系统 PoC', color: 'blue' },
  nuclei: { label: 'Nuclei', color: 'green' }
}
function srcMeta(s: string) { return SRC_META[s] || { label: s, color: 'default' } }
function sevColor(s: string) {
  return ({ critical: 'magenta', high: 'red', medium: 'orange', low: 'gold', info: 'blue' } as Record<string, string>)[s.toLowerCase()] || 'default'
}
// 校准判定:AI 漏洞的原始 CVSS 等级与展示等级不同 → 发生了 triage 校准降级(信息型泄露等)
function isCalibrated(r: UnifiedFinding) {
  return r.source === 'ai' && !!r.cvss_severity && r.cvss_severity.toLowerCase() !== (r.severity || '').toLowerCase()
}
function cvssNote(r: UnifiedFinding) {
  if (isCalibrated(r)) {
    return `CVSS 基础分 ${r.cvss_score}(原始等级 ${String(r.cvss_severity).toUpperCase()}），因信息型泄露务实校准为 ${String(r.severity).toUpperCase()}。${r.severity_basis ? '依据:' + r.severity_basis : ''}`
  }
  return `CVSS 基础分 ${r.cvss_score}`
}

async function loadStat() {
  try { Object.assign(stat, await pentestApi.findingStat(query.unit || undefined)) } catch { /* 忽略 */ }
}
async function loadList() {
  loading.value = true
  try {
    const res = await pentestApi.unifiedList({
      source: query.source || undefined,
      keyword: query.keyword || undefined,
      severity: query.severity,
      // 精确等级(severity)优先;否则显式传 min_severity 阈值(含 'info'=显示全部)。
      // 必须显式传:后端缺省=low,若"全部"不传会被后端默认成 low → 显式 info 才能看全部。
      min_severity: query.severity ? undefined : (query.min_severity || 'low'),
      unit: query.unit || undefined,
      handle_status: query.handle_status,
      date_from: dateRange.value?.[0] || undefined,
      date_to: dateRange.value?.[1] || undefined,
      page: query.page, size: query.size
    })
    rows.value = res.items; total.value = res.total
    selectedKeys.value = []
  } catch (e) { message.error((e as Error).message || '加载失败') } finally { loading.value = false }
}
async function batchDelete() {
  if (!selectedKeys.value.length) return
  // 按来源分组(unified 删除按 source 删对应集合)
  const bySrc: Record<string, string[]> = {}
  for (const r of rows.value) {
    if (selectedKeys.value.includes(r._id)) {
      (bySrc[r.source] = bySrc[r.source] || []).push(r._id)
    }
  }
  try {
    let n = 0
    for (const [src, ids] of Object.entries(bySrc)) {
      const res = await pentestApi.unifiedDelete(src, ids)
      n += res.deleted || 0
    }
    message.success(`已删除 ${n} 条`)
    loadAll()
  } catch (e) { message.error((e as Error).message || '删除失败') }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.keyword = ''; query.severity = undefined; query.min_severity = 'low'; query.unit = ''; query.handle_status = undefined; dateRange.value = undefined; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }

/* 详情抽屉:按来源拉完整记录 */
const detailOpen = ref(false)
const detailLoading = ref(false)
const cur = reactive<Record<string, unknown>>({})
const detailTitle = computed(() => `漏洞详情 · ${srcMeta(String(cur.source || '')).label}`)
// 详情里是否发生了 triage 校准(原始 CVSS 等级 ≠ 展示等级)
const curCalibrated = computed(() =>
  cur.source === 'ai' && !!cur.cvss_severity &&
  String(cur.cvss_severity).toLowerCase() !== String(cur.severity || '').toLowerCase())

async function showDetail(r: UnifiedFinding) {
  Object.keys(cur).forEach(k => delete cur[k])
  cur.source = r.source
  detailOpen.value = true
  detailLoading.value = true
  try {
    const doc = await pentestApi.unifiedDetail(r.source, r._id)
    Object.assign(cur, doc)
    // task_name 是列表层反查回填的(原始文档无此字段),详情接口拉不到 → 用列表行的值补上
    if (!cur.task_name && r.task_name) cur.task_name = r.task_name
  } catch (e) { message.error((e as Error).message || '详情加载失败') } finally { detailLoading.value = false }
}
interface EvItem { tool: string; arguments: Record<string, unknown> | string; result: unknown; signal?: string }
interface EvPacket { tool: string; signal?: string; reqText: string; respText: string }

function _toObj(v: unknown): Record<string, unknown> {
  if (v && typeof v === 'object') return v as Record<string, unknown>
  if (typeof v === 'string') { try { return JSON.parse(v) } catch { return {} } }
  return {}
}
// 把 evidence 的 arguments/result 重构成 Burp 风格原始 HTTP 报文(请求包 / 响应包)
function evToPackets(f: Record<string, unknown>): EvPacket[] {
  const ev = f.evidence as EvItem[] | undefined
  if (!ev || !ev.length) return []
  return ev.map(e => {
    const args = _toObj(e.arguments)
    const res = _toObj(e.result)
    // ---- 请求包 ----
    const method = String(args.method || res.method || 'GET').toUpperCase()
    let path = '/', host = ''
    try { const u = new URL(String(args.url || res.url || '')); path = u.pathname + u.search; host = u.host } catch { path = String(args.url || '') }
    const reqLines = [`${method} ${path} HTTP/1.1`]
    if (host) reqLines.push(`Host: ${host}`)
    const reqHeaders = _toObj(args.headers)
    for (const [k, v] of Object.entries(reqHeaders)) reqLines.push(`${k}: ${v}`)
    if (args.body) { reqLines.push(''); reqLines.push(typeof args.body === 'string' ? args.body : JSON.stringify(args.body)) }
    // ---- 响应包 ----
    const sc = res.status_code != null ? res.status_code : '?'
    const respLines = [`HTTP/1.1 ${sc}`]
    const respHeaders = _toObj(res.headers)
    for (const [k, v] of Object.entries(respHeaders)) respLines.push(`${k}: ${v}`)
    respLines.push('')
    respLines.push(typeof res.body === 'string' ? res.body : JSON.stringify(res.body ?? res, null, 2))
    return { tool: e.tool, signal: e.signal, reqText: reqLines.join('\n'), respText: respLines.join('\n') }
  })
}
function aiEvidenceText(f: Record<string, unknown>) {
  const ev = f.evidence as Array<{ tool: string; arguments: unknown; result: unknown }> | undefined
  if (!ev || !ev.length) return f.verified ? '(已验证但证据为空)' : '(无实证证据,故降级为线索)'
  return ev.map(e => `# ${e.tool} ${JSON.stringify(e.arguments)}\n${typeof e.result === 'string' ? e.result : JSON.stringify(e.result)}`).join('\n\n---\n\n')
}
function rawJson(f: Record<string, unknown>) {
  const { source: _s, _id: _i, ...rest } = f
  void _s; void _i
  return JSON.stringify(rest, null, 2)
}
function goSession(id: string) { if (id) router.push(`/pentest/${id}`) }

/* 标记处理状态(三来源通用,按 source 落对应集合):submitted(标记)/false_positive(误报)/""(重置) */
async function doMark(r: UnifiedFinding, handleStatus: string) {
  try {
    await pentestApi.unifiedMark(r.source, [r._id], handleStatus)
    message.success(handleStatus === 'false_positive' ? '已标记误报(默认列表将隐藏)' : handleStatus === 'submitted' ? '已标记' : '已重置')
    loadAll()   // 刷新列表+统计卡(标误报后该行从默认列表消失)
  } catch (e) { message.error((e as Error).message || '标记失败') }
}
function markOne(r: UnifiedFinding, handleStatus: string) {
  // 重置需二次确认(清除已标记/误报状态,防误点)
  if (handleStatus === '') {
    Modal.confirm({
      title: '确认重置该记录？',
      content: '将清除当前处理标记，恢复为未处理状态。',
      okText: '确定', cancelText: '取消',
      onOk: () => doMark(r, '')
    })
    return
  }
  doMark(r, handleStatus)
}

/* 删除(仅系统扫描来源,复用各自现成接口;AI 漏洞为引擎产出不手删) */
async function removeOne(r: UnifiedFinding) {
  try {
    if (r.source === 'poc') await vulnApi.delete([r._id])
    else if (r.source === 'nuclei') await nucleiResultApi.delete([r._id])
    else return
    message.success('已删除'); loadAll()
  } catch (e) { message.error((e as Error).message || '删除失败') }
}
const auto = useAutoRefresh(loadAll, 30000)
onMounted(loadAll)
</script>

<style scoped>
.muted { color: #aaa; }
.calibrated { color: #d46b08; border-bottom: 1px dashed #d46b08; cursor: help; }
.ev { white-space: pre-wrap; word-break: break-all; font-family: monospace; font-size: 12px; margin: 0; max-height: 360px; overflow: auto; }
.ev-packet { margin-bottom: 14px; }
.ev-pkt-head { margin-bottom: 4px; }
.ev-label { font-size: 12px; color: #888; margin-bottom: 2px; }

/* 证据请求/响应包：日夜模式适配(v1.21.139 fix) */
.burp-req {
  background: #f6ffed;
  border: 1px solid #d9f7be;
  color: #000;
  padding: 6px;
  border-radius: 4px;
}
.burp-resp {
  background: #f0f5ff;
  border: 1px solid #d6e4ff;
  color: #000;
  padding: 6px;
  border-radius: 4px;
}

/* 夜间模式适配移到全局 src/styles/theme-dark.css：a-drawer 内容 teleport 到 body 脱离 scoped 作用域，
   scoped 选择器作用不到抽屉内的证据块，故必须写全局（2026-08-12 fix）。 */
</style>
