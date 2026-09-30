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
          <a class="chain-title" :title="record.title" @click="showDetail(record)">{{ record.title }}</a>
          <a-tag v-if="record.cross_session" color="purple" style="margin-left:6px">跨会话</a-tag>
        </template>
        <template v-else-if="column.key === 'step_count'">
          <a-badge :count="record.step_count" :number-style="{ backgroundColor: '#1677ff' }" />
        </template>
        <template v-else-if="column.key === 'max_severity'">
          <a-tag :color="sevColor(record.max_severity)">{{ sevLabel(record.max_severity) }}</a-tag>
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
          <a-descriptions-item label="最高危害"><a-tag :color="sevColor(cur?.max_severity)">{{ sevLabel(cur?.max_severity) }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="状态"><a-tag :color="cur?.status === 'done' ? 'green' : 'blue'">{{ cur?.status === 'done' ? '已完成' : '构建中' }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="跨会话">{{ cur?.cross_session ? `是（${cur?.sessions?.length || 0} 个会话接力）` : '否' }}</a-descriptions-item>
          <a-descriptions-item label="更新时间">{{ cur?.update_date || '—' }}</a-descriptions-item>
        </a-descriptions>

        <!-- 图形化链路图（赛博风，对齐控制台内网拓扑）：入口→环节1→…→拿下，节点按危害着色，蛇形折行适应任意环节数 -->
        <div v-if="graphNodes.length" class="chain-graph">
          <svg :viewBox="`0 0 ${GW} ${graphH}`" class="chain-svg">
            <defs>
              <marker id="acArrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="#00e5ff" fill-opacity="0.7" />
              </marker>
            </defs>
            <!-- 连线（按节点顺序，蛇形） -->
            <path v-for="(e, i) in graphEdges" :key="'e'+i" :d="e" class="ac-edge" marker-end="url(#acArrow)" />
            <!-- 节点 -->
            <g v-for="n in graphNodes" :key="n.key" :transform="`translate(${n.x},${n.y})`"
               class="ac-node" :class="'sev-'+n.sev" @click="focusStep(n.seq)" style="cursor:pointer">
              <title>{{ n.label }}：{{ n.subFull }}</title>
              <rect x="-70" y="-26" width="140" height="52" rx="9" />
              <text class="ac-n-title" y="-8">{{ n.label }}</text>
              <text class="ac-n-sub" y="10">{{ n.sub }}</text>
            </g>
          </svg>
        </div>

        <a-timeline class="chain-timeline">
          <a-timeline-item v-for="s in (cur?.steps || [])" :key="s.seq" :color="sevColor(s.severity) === 'default' ? 'blue' : sevColor(s.severity)">
            <div class="step-head" :data-step-seq="s.seq">
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
import { onMounted, reactive, ref, computed } from 'vue'
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

// 严重度归一（前端兜底存量中文数据：后端已归一英文，此处兼容旧库里遗留的中文"高/中/低/严重"）
const _SEV_ALIAS: Record<string, string> = {
  '严重': 'critical', '危急': 'critical', 'critical': 'critical', 'crit': 'critical',
  '高危': 'high', '高': 'high', 'high': 'high',
  '中危': 'medium', '中': 'medium', 'medium': 'medium', 'moderate': 'medium',
  '低危': 'low', '低': 'low', 'low': 'low',
  '信息': 'info', 'info': 'info', 'informational': 'info', '无': 'info',
}
function normSev(s?: string) {
  const k = (s || '').trim().toLowerCase()
  return _SEV_ALIAS[k] || (['critical', 'high', 'medium', 'low', 'info'].includes(k) ? k : 'unknown')
}
function sevColor(s?: string) {
  const m: Record<string, string> = { critical: 'red', high: 'volcano', medium: 'orange', low: 'gold', info: 'default' }
  return m[normSev(s)] || 'default'
}
function sevLabel(s?: string) { return normSev(s).toUpperCase() }

// —— 图形化链路图（SVG 蛇形网格布局，适应任意环节数）——
const GW = 720                       // 画布宽
const _PER_ROW = 4                   // 每行节点数
const _CELL_W = 170, _CELL_H = 92    // 单元格宽高
const _X0 = 90, _Y0 = 40             // 起始中心
// 节点：入口 + 各环节（+ done 时终点）。蛇形排布（偶数行左→右，奇数行右→左），x/y 为中心坐标。
// 问题17：SVG <text> 不自动换行/截断，节点框固定宽 140。长文本（如入口节点的完整 ICP 单位名
// "上海递煌智能科技有限公司"、长 vuln_type）会横向溢出顶破节点框。故 sub 统一截断到能塞进框的长度
// （~9 个全角字符），完整文本放 subFull 供 <title> hover 显示，不丢信息。
const _NODE_SUB_MAX = 9
function _clip(s: string): string {
  const v = String(s || '')
  return v.length > _NODE_SUB_MAX ? v.slice(0, _NODE_SUB_MAX) + '…' : v
}
const graphNodes = computed(() => {
  const steps = cur.value?.steps || []
  if (!steps.length) return [] as Array<{ key: string; seq: number; x: number; y: number; sev: string; label: string; sub: string; subFull: string }>
  const items: Array<{ seq: number; sev: string; label: string; sub: string; subFull: string }> = []
  const entryFull = cur.value?.unit || '目标'
  items.push({ seq: 0, sev: 'entry', label: '🎯 入口', sub: _clip(entryFull), subFull: entryFull })
  for (const s of steps) {
    const sf = (s.vuln_type || s.action || '') || '—'
    items.push({ seq: s.seq, sev: normSev(s.severity), label: '环节 ' + s.seq,
      sub: _clip(sf), subFull: sf })
  }
  if (cur.value?.status === 'done') { const df = sevLabel(cur.value?.max_severity); items.push({ seq: -1, sev: cur.value?.max_severity ? normSev(cur.value.max_severity) : 'high', label: '✅ 拿下', sub: _clip(df), subFull: df }) }
  return items.map((it, i) => {
    const row = Math.floor(i / _PER_ROW)
    const colRaw = i % _PER_ROW
    const col = row % 2 === 0 ? colRaw : (_PER_ROW - 1 - colRaw)   // 蛇形
    return { key: 'n' + i, seq: it.seq, sev: it.sev, label: it.label, sub: it.sub, subFull: it.subFull,
      x: _X0 + col * _CELL_W, y: _Y0 + row * _CELL_H }
  })
})
// 连线：相邻节点（含蛇形折返），三次贝塞尔平滑
const graphEdges = computed(() => {
  const ns = graphNodes.value
  const paths: string[] = []
  for (let i = 1; i < ns.length; i++) {
    const a = ns[i - 1], b = ns[i]
    if (a.y === b.y) {
      // 同行：水平箭头（留节点半宽 70 间隙）。**按方向取正确的出入边**（#9 用户 2026-09-15 修）：
      // 蛇形布局奇数行是反向的（右→左），此时 a 在 b 右侧。原代码写死 a.x+70→b.x-70（假设 a 在左），
      // 反向行会从 a 右边缘一路向左穿过 a 自己和 b 的方块 → "箭头横向穿出环节方块"。按 a、b 相对位置定：
      //   正向(a 在左)：a 右缘(a.x+70) → b 左缘(b.x-70)
      //   反向(a 在右)：a 左缘(a.x-70) → b 右缘(b.x+70)
      const fwd = a.x <= b.x
      const x1 = fwd ? a.x + 70 : a.x - 70
      const x2 = fwd ? b.x - 70 : b.x + 70
      const mx = (x1 + x2) / 2
      paths.push(`M${x1},${a.y} C${mx},${a.y} ${mx},${b.y} ${x2},${b.y}`)
    } else {                                             // 换行：从下方绕到下一行
      paths.push(`M${a.x},${a.y + 26} C${a.x},${a.y + 60} ${b.x},${b.y - 60} ${b.x},${b.y - 26}`)
    }
  }
  return paths
})
const graphH = computed(() => {
  const rows = Math.ceil(graphNodes.value.length / _PER_ROW) || 1
  return _Y0 + (rows - 1) * _CELL_H + 50
})
function focusStep(seq: number) {
  if (seq <= 0) return
  const el = document.querySelector(`[data-step-seq="${seq}"]`)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
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
/* 问题17：列表标题过长时截断省略，避免顶破单元格；hover(title 属性)看全名 */
.chain-title { font-weight: 600; cursor: pointer; display: inline-block; max-width: 360px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
.outline { color: #888; font-size: 12px; }
.chain-timeline { margin-top: 8px; }
.step-head { display: flex; align-items: center; gap: 4px; }
.step-at { margin-left: auto; color: #aaa; font-size: 12px; }
.step-action { margin: 4px 0; }
.step-result { color: #389e0d; margin-bottom: 4px; }
.step-target { margin-bottom: 4px; }
.step-ref { margin-top: 2px; }

/* 图形化链路图（赛博深色风，对齐控制台内网拓扑） */
.chain-graph { background: radial-gradient(circle at 30% 30%, #0b1526, #060a14); border: 1px solid #16233d; border-radius: 10px; margin: 0 0 16px; padding: 6px; overflow-x: auto; }
.chain-svg { width: 100%; min-width: 680px; display: block; }
.ac-edge { stroke: #00e5ff; stroke-opacity: .5; stroke-width: 1.5; fill: none; filter: drop-shadow(0 0 3px rgba(0,229,255,.4)); }
.ac-node rect { stroke-width: 1.5; }
.ac-node text { text-anchor: middle; dominant-baseline: middle; }
.ac-n-title { font-size: 13px; font-weight: 600; }
.ac-n-sub { font-size: 11px; }
/* 节点按危害着色（发光边+半透明填充） */
.ac-node.sev-entry rect { fill: rgba(0,229,255,.12); stroke: #00e5ff; filter: drop-shadow(0 0 5px rgba(0,229,255,.5)); }
.ac-node.sev-entry text { fill: #7fe9ff; }
.ac-node.sev-critical rect { fill: rgba(255,77,79,.16); stroke: #ff4d4f; filter: drop-shadow(0 0 5px rgba(255,77,79,.5)); }
.ac-node.sev-high rect { fill: rgba(255,122,69,.15); stroke: #fa541c; filter: drop-shadow(0 0 5px rgba(250,84,28,.45)); }
.ac-node.sev-medium rect { fill: rgba(250,173,20,.14); stroke: #faad14; }
.ac-node.sev-low rect { fill: rgba(250,219,20,.12); stroke: #d4b106; }
.ac-node.sev-info rect, .ac-node.sev-unknown rect { fill: rgba(140,160,190,.1); stroke: #5a7098; }
.ac-node.sev-critical text, .ac-node.sev-high text { fill: #ffd9cf; }
.ac-node.sev-medium text, .ac-node.sev-low text { fill: #ffe9a8; }
.ac-node.sev-info text, .ac-node.sev-unknown text { fill: #9fb2d0; }
.ac-node:hover rect { stroke-width: 2.5; }
</style>
