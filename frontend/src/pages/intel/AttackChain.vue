<template>
  <PageContainer class="attack-chain-page" :title="translate('ui.m_c14a89bcd889')" kicker="Sessions & Attack Chains"
    :description="translate('ui.m_513bc8798f81')">
    <template #extra><a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button></template>

    <a-row :gutter="12" style="margin-bottom:16px">
      <a-col :xs="12" :md="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_701b56ace515')" :value="stat.total" :value-style="{ color: '#1677ff' }" /></a-card></a-col>
      <a-col :xs="12" :md="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_b1665f71ff5a')" :value="stat.cross_session" :value-style="{ color: '#722ed1' }" /></a-card></a-col>
      <a-col :xs="12" :md="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_87b83957c31b')" :value="(stat.by_severity.critical || 0) + (stat.by_severity.high || 0)" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :xs="12" :md="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_f9a465a5dc89')" :value="stat.by_severity.medium || 0" :value-style="{ color: '#d46b08' }" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item :label="translate('revision17.session')"><a-input v-model:value="query.session_id" allow-clear style="width:200px" /></a-form-item><a-form-item :label="translate('revision17.target')"><a-input v-model:value="query.target" allow-clear style="width:200px" /></a-form-item>
      <a-form-item :label="translate('ui.m_80b19d68b149')"><a-input v-model:value="query.unit" allow-clear :placeholder="translate('ui.m_702aab59cae9')" style="width:180px" /></a-form-item>
      <a-form-item :label="translate('ui.m_6320b4a8722a')">
        <a-select v-model:value="query.status" style="width:130px" :options="statusOptions" />
      </a-form-item>
    </SearchBar>

    <div style="margin-bottom:8px">
      <a-popconfirm :title="translate('ui.m_e7fb57eb7037', { p0: (selectedKeys.length) })" :disabled="!selectedKeys.length" @confirm="batchDelete">
        <a-button danger :disabled="!selectedKeys.length">{{ translate('ui.m_ddae7a0fc554') }}{{ selectedKeys.length ? `(${selectedKeys.length})` : '' }}</a-button>
      </a-popconfirm>
    </div>

    <AppTable class="chain-table" data-testid="attack-chain-table" :columns="columns" :data="rows" :loading="loading" selectable table-layout="fixed" :scroll="{x:1600}"
      v-model:selectedRowKeys="selectedKeys"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'title'">
          <a class="chain-title" :title="record.title" @click="showDetail(record)">{{ record.title }}</a>
          <a-tag v-if="record.cross_session" color="purple" style="margin-left:6px">{{ translate('ui.m_385ea2980e24') }}</a-tag>
        </template>
        <template v-else-if="column.key === 'session'"><div class="chain-sources"><div class="source-cell" v-for="id in record.sessions||[]" :key="id" :title="id"><CopyText :text="id" /></div></div></template>
        <template v-else-if="column.key === 'target'"><div class="chain-sources"><div class="source-cell" v-for="target in Array.from(new Set((record.steps||[]).map((step:any)=>step.source_site||step.target).filter(Boolean)))" :key="String(target)" :title="String(target)">{{ target }}</div></div></template>
        <template v-else-if="column.key === 'step_count'">
          <a-badge :count="record.step_count" :number-style="{ backgroundColor: '#1677ff' }" />
        </template>
        <template v-else-if="column.key === 'max_severity'">
          <a-tag :color="sevColor(record.max_severity)">{{ sevLabel(record.max_severity) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="record.status === 'done' ? 'green' : 'blue'">{{ record.status === 'done' ? translate('ui.m_f28461bb49c8') : translate('ui.m_2be422c43f34') }}</a-tag>
        </template>
        <template v-else-if="column.key === 'outline'">
          <button class="chain-preview-button" @click="openGraph(record)" :aria-label="translate('chainView.open')" data-testid="chain-open-graph">
            <span class="preview-label"><NodeIndexOutlined /> {{ translate('chainView.title') }} · {{ record.step_count || 0 }}</span>
            <span class="preview-flow"><span v-for="(step,i) in (record.steps || []).slice(0,3)" :key="i" :class="'preview-'+normSev(step.severity)" :title="step.vuln_type || step.action || translate('chainView.unnamed')">{{ step.vuln_type || step.action || translate('chainView.unnamed') }}</span></span>
            <span v-if="record.steps?.length>3" class="preview-more">{{ translate('chainView.more',{n:record.steps.length-3}) }}</span>
          </button>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space size="small">
            <a-button type="link" size="small" @click="showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button>
            <ConfirmAction danger :title="translate('ui.m_241a4347c96f')" @confirm="removeOne(record)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
          </a-space>
        </template>
      </template>
    </AppTable>

    <a-drawer v-model:open="detailOpen" :title="cur?.title || translate('ui.m_bc8f61662367')" width="60%">
      <a-spin :spinning="detailLoading">
        <a-descriptions :column="2" size="small" bordered style="margin-bottom:16px">
          <a-descriptions-item :label="translate('ui.m_80b19d68b149')">{{ cur?.unit || '—' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_7d386b3adbf4')">{{ cur?.step_count || 0 }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_aea0fc420948')"><a-tag :color="sevColor(cur?.max_severity)">{{ sevLabel(cur?.max_severity) }}</a-tag></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_6320b4a8722a')"><a-tag :color="cur?.status === 'done' ? 'green' : 'blue'">{{ cur?.status === 'done' ? translate('ui.m_f28461bb49c8') : translate('ui.m_2be422c43f34') }}</a-tag></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_385ea2980e24')">{{ cur?.cross_session ? translate('ui.m_593216259821', { p0: (cur?.sessions?.length || 0) }) : translate('ui.m_0c70665b6eb6') }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_0a5f9a892960')">{{ cur?.update_date || '—' }}</a-descriptions-item>
        </a-descriptions>

        <button v-if="cur?.steps?.length" class="detail-graph-open chain-preview-button" @click="openGraph(cur)" data-testid="chain-detail-open-graph">
          <NodeIndexOutlined /> {{ translate('chainView.open') }} · {{ cur.step_count }}
          <span class="preview-more">{{ translate('chainView.orderNotice') }}</span>
        </button>

        <a-timeline class="chain-timeline">
          <a-timeline-item v-for="s in (cur?.steps || [])" :key="s.seq" :color="sevColor(s.severity) === 'default' ? 'blue' : sevColor(s.severity)">
            <div class="step-head" :data-step-seq="s.seq">
              <b>{{ translate('ui.m_28475230f056') }} {{ s.seq }}</b>
              <a-tag v-if="s.vuln_type" :color="sevColor(s.severity)" style="margin-left:6px">{{ s.vuln_type }}</a-tag>
              <span class="step-at">{{ s.at }}</span>
            </div>
            <div class="step-action">{{ s.action }}</div>
            <div v-if="s.result" class="step-result">→ {{ s.result }}</div>
            <div v-if="s.target" class="step-target"><CopyText :text="s.target" /></div>
            <div v-if="s.finding_ref || s.clue_ref" class="step-ref">
              <a-tag v-if="s.finding_ref" color="red">{{ translate('ui.m_8e059ca84801') }} {{ s.finding_ref }}</a-tag>
              <a-tag v-if="s.clue_ref" color="cyan">{{ translate('ui.m_909ae33dd968') }} {{ s.clue_ref }}</a-tag>
            </div>
          </a-timeline-item>
        </a-timeline>
        <a-empty v-if="!cur?.steps?.length" :description="translate('ui.m_ba052efe4258')" />
      </a-spin>
    </a-drawer>
    <DraggableDialog v-model:open="graphOpen" :title="graphChain?.title || translate('chainView.title')">
      <a-spin :spinning="graphLoading"><AttackChainGraph :chain="graphChain" /></a-spin>
    </DraggableDialog>
  </PageContainer>
</template>


<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { NodeIndexOutlined } from '@ant-design/icons-vue'
import DraggableDialog from '../../components/DraggableDialog.vue'
import AttackChainGraph from '../../components/AttackChainGraph.vue'
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
const query = reactive({ session_id:'',target:'',min_severity:'',unit: '', status: '', page: 1, size: 20 })

const statusOptions = [{ get label() { return translate('ui.m_5c55a67935af') }, value: '' }, { get label() { return translate('ui.m_2be422c43f34') }, value: 'building' }, { get label() { return translate('ui.m_f28461bb49c8') }, value: 'done' }]
const columns = [
  { get title() { return translate('ui.m_31f1f49cdb27') }, key: 'title', width:240 },
  {get title(){return translate('revision17.session')},key:'session',width:216},
  {get title(){return translate('revision17.target')},key:'target',width:260},
  { get title() { return translate('ui.m_28475230f056') }, key: 'step_count', width: 80 },
  { get title() { return translate('ui.m_aea0fc420948') }, key: 'max_severity', width: 140 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 140 },
  { get title() { return translate('ui.m_a1038bbab8b4') }, key: 'outline', width:320 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width:160 }
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

const graphOpen=ref(false),graphLoading=ref(false),graphChain=ref<AttackChain|null>(null)
let graphController:AbortController|undefined,detailController:AbortController|undefined,graphEpoch=0,detailEpoch=0,disposed=false
watch(graphOpen,value=>{if(!value){graphEpoch++;graphController?.abort();graphLoading.value=false}})
watch(detailOpen,value=>{if(!value){detailEpoch++;detailController?.abort();detailLoading.value=false}})
async function openGraph(record:AttackChain){
  const epoch=++graphEpoch;graphController?.abort();graphController=new AbortController()
  graphChain.value=null;graphOpen.value=true;graphLoading.value=true
  try {const value=await intelApi.chainDetail(record._id,{signal:graphController.signal});if(!disposed&&epoch===graphEpoch&&graphOpen.value)graphChain.value=value}
  catch(error){if(!disposed&&epoch===graphEpoch&&!(error instanceof Error&&error.name==='AbortError'))message.error((error as Error).message)}
  finally{if(epoch===graphEpoch)graphLoading.value=false}
}
onUnmounted(()=>{disposed=true;graphEpoch++;detailEpoch++;graphController?.abort();detailController?.abort()})

async function loadStat() {
  try { Object.assign(stat, await intelApi.chainStat(query.unit || undefined)) } catch (e) { /* ignore */ }
}
async function loadList() {
  loading.value = true
  try {
    const data = await intelApi.chains({session_id:query.session_id||undefined,target:query.target||undefined,min_severity:query.min_severity,unit: query.unit || undefined, status: query.status || undefined, page: query.page, size: query.size })
    rows.value = data.items
    total.value = data.total
    selectedKeys.value = []
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function batchDelete() {
  if (!selectedKeys.value.length) return
  try {
    const res = await intelApi.chainDelete(selectedKeys.value)
    message.success(translate('ui.m_925464646d44', { p0: (res.deleted ?? selectedKeys.value.length) }))
    loadAll()
  } catch (e) { message.error((e as Error).message) }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.session_id='';query.target='';query.unit = ''; query.status = ''; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }
async function showDetail(r: AttackChain) {
  const epoch=++detailEpoch;detailController?.abort();detailController=new AbortController()
  cur.value=null;detailOpen.value = true;detailLoading.value = true
  try {const value=await intelApi.chainDetail(r._id,{signal:detailController.signal});if(!disposed&&epoch===detailEpoch&&detailOpen.value)cur.value=value}
  catch(error){if(!disposed&&epoch===detailEpoch&&!(error instanceof Error&&error.name==='AbortError'))message.error((error as Error).message)}
  finally {if(epoch===detailEpoch)detailLoading.value = false}
}
async function removeOne(r: AttackChain) {
  try { await intelApi.chainDelete(r._id); message.success(translate('ui.m_077a6d37719a')); loadAll() } catch (e) { message.error((e as Error).message) }
}

onMounted(loadAll)
</script>

<style scoped>
.chain-table :deep(.ant-table-thead>tr>th){white-space:nowrap;word-break:normal}
.chain-table :deep(.ant-table-cell){vertical-align:top}
.chain-table :deep(.ant-table-tbody .ant-tag),.chain-table :deep(.ant-table-tbody .ant-btn),.chain-table :deep(.ant-table-tbody .ant-space){white-space:nowrap}
.chain-sources{min-width:0;max-width:100%;max-height:108px;overflow-x:hidden;overflow-y:auto}
.source-cell{min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:22px;margin:3px 0}
.source-cell :deep(.copy-text){display:block;min-width:0;max-width:100%}
.source-cell :deep(code){display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;box-sizing:border-box}
.chain-table .preview-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chain-table .chain-preview-button{box-sizing:border-box;max-width:100%;overflow:hidden}
.chain-table .preview-flow{width:100%;max-width:100%;overflow:hidden}
/* 问题17：列表标题过长时截断省略，避免顶破单元格；hover(title 属性)看全名 */
.chain-title { font-weight: 600; cursor: pointer; display: inline-block; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
.outline { color: #888; font-size: 12px; }
.chain-timeline { margin-top: 8px; }
.step-head { display: flex; align-items: center; gap: 4px; }
.step-at { margin-left: auto; color: #aaa; font-size: 12px; }
.step-action { margin: 4px 0; }
.step-result { color: #389e0d; margin-bottom: 4px; }
.step-target { margin-bottom: 4px; }
.step-ref { margin-top: 2px; }

/* Stage previews share the same semantic palette as the full graph. */
.chain-preview-button{display:block;width:100%;text-align:left;padding:10px 12px;border:1px solid var(--dt-border);border-radius:9px;background:var(--dt-card);color:var(--dt-text);cursor:pointer;min-width:0}.chain-preview-button:hover,.chain-preview-button:focus-visible{border-color:var(--dt-primary);background:var(--dt-hover)}.preview-label{display:flex;gap:7px;align-items:center;font-weight:600;font-size:12px;margin-bottom:7px}.preview-flow{display:flex;gap:6px;align-items:center;min-width:0}.preview-flow>span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;padding:3px 6px;background:var(--dt-fill);border-radius:5px}.preview-flow>.preview-high,.preview-flow>.preview-critical{background:var(--dt-danger-soft);color:var(--dt-danger)}.preview-more{display:block;font-size:11px;color:var(--dt-muted);line-height:1.6;margin-top:6px}.detail-graph-open{margin-bottom:16px}.step-head{flex-wrap:wrap}.step-action,.step-result{overflow-wrap:anywhere}.outline{color:var(--dt-muted)}
</style>
