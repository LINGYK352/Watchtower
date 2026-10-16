<template>
  <PageContainer :title="translate('ui.m_aa88061aca8a')" kicker="Traffic Log" :description="translate('trafficLog.description')">
    <template #extra>
      <a-space>
        <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
        <a-button @click="sizeOpen = true">{{ translate('ui.m_b4c54bc564ef') }}</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom:16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_b2eedb867dbd')" :value="stat.total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_bf33347e3c85')" :value="stat.blocked" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_561817f02529')" :value="stat.allowed" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_330141b9f0e2')" :value="stat.size_mb" suffix="MB" /></a-card></a-col>
    </a-row>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item :label="translate('trafficLog.session')"><a-input v-model:value="query.session_id" :placeholder="translate('trafficLog.sessionSearch')" allow-clear style="width:260px" data-testid="traffic-session-filter" /></a-form-item>
      <a-form-item :label="translate('ui.m_bb7ef73495dd')">
        <a-select v-model:value="query.allow" style="width:130px" :options="allowOptions" />
      </a-form-item>
      <a-form-item :label="translate('ui.m_47a270081ab2')">
        <a-select v-model:value="query.mode" style="width:120px" :options="modeOptions" />
      </a-form-item>
    </SearchBar>

    <AppTable :columns="columns" :data="rows" :loading="loading"
      :page="query.page" :size="query.size" :total="total" row-key="_id" :custom-row="trafficRow" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'allow'">
          <a-tag :color="record.allow ? 'green' : 'red'">{{ record.allow ? translate('ui.m_561817f02529') : translate('ui.m_bf33347e3c85') }}</a-tag>
        </template>
        <template v-else-if="column.key === 'mode'">
          <a-tag :color="pentestModeColor(record.mode)">{{ pentestModeLabel(record.mode) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'method'">
          <a-tag :color="methodColor(record.method)">{{ record.method }}</a-tag>
        </template>
      </template>
    </AppTable>
    <a-modal :open="!!previewRow" :title="translate('trafficLog.interaction')" :footer="null" width="1060px" @cancel="previewRow=null;interactionGeneration++" data-testid="traffic-interaction">
      <div class="traffic-interaction-meta"><a-tag>{{ previewRow?.method }}</a-tag><strong>{{ previewRow?.url }}</strong><span>{{ previewRow?.save_date }}</span></div>
      <a-spin :spinning="interactionLoading"><a-alert v-if="interactionError" type="error" :message="interactionError" show-icon />
        <p v-if="previewRow?.truncation_reason" class="traffic-capture-note">{{ previewRow.truncation_reason }}</p><p v-if="previewRow?.capture_note" class="traffic-capture-note">{{ previewRow.capture_note }}</p>
        <div class="traffic-encoding"><span>{{ translate('trafficLog.encoding') }}</span><a-select v-model:value="previewEncoding" :options="[{value:'utf-8',label:'UTF-8'},{value:'gb18030',label:'GB18030 / GBK'},{value:'hex',label:'Hex'},{value:'base64',label:'Base64'}]" style="width:180px" /><span>{{ translate('trafficLog.packetLimit') }}</span></div>
        <a-tabs v-model:activeKey="packetTab"><a-tab-pane key="request" :tab="translate('trafficLog.requestPacket')"><pre class="traffic-packet" data-testid="traffic-request-packet">{{ preview('request_preview_b64') || translate('trafficLog.noPacket') }}</pre></a-tab-pane><a-tab-pane key="response" :tab="translate('trafficLog.responsePacket')"><a-alert v-if="previewRow?.allow===false" type="warning" :message="translate('trafficLog.blockedPacket')" :description="previewRow?.reason" show-icon data-testid="traffic-blocked-response" /><pre v-else class="traffic-packet" data-testid="traffic-response-packet">{{ preview('response_preview_b64') || translate('trafficLog.noPacket') }}</pre></a-tab-pane></a-tabs>
      </a-spin>
    </a-modal>

    <a-modal v-model:open="sizeOpen" :title="translate('ui.m_2665d284fbf4')" :confirm-loading="saving" @ok="saveSize" :ok-text="translate('ui.m_a3030bf8f16d')" :cancel-text="translate('ui.m_2cd0f3be8738')">
      <p style="color:#888;margin-bottom:16px">{{ translate('ui.m_11f2822f9cb5') }} {{ stat.default_size_mb }} MB。<b style="color:#d46b08">{{ translate('ui.m_c64a36d50edc') }}</b></p>
      <p>{{ translate('trafficLog.retentionHint') }}</p>
      <a-form layout="vertical"><a-form-item :label="translate('trafficLog.days')"><a-input-number v-model:value="retentionDays" :min="1" :precision="0" addon-after="days" data-testid="traffic-retention-days" /></a-form-item></a-form>
      <a-input-number v-model:value="sizeMb" :min="1" addon-after="MB" style="width:180px" />
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import { logMonitorApi, type GuardLogItem, type GuardLogStat } from '../../api/logMonitor'
import { PENTEST_MODES, pentestModeLabel, pentestModeColor } from '../../api/pentest'

const loading = ref(false)
const rows = ref<GuardLogItem[]>([])
const previewRow=ref<GuardLogItem|null>(null),previewEncoding=ref('utf-8')
const interactionLoading=ref(false),interactionError=ref(''),packetTab=ref('request');let interactionGeneration=0
const trafficRow=(record:GuardLogItem)=>({onClick:()=>openInteraction(record),onKeydown:(event:KeyboardEvent)=>{if(['Enter',' '].includes(event.key)){event.preventDefault();void openInteraction(record)}},tabindex:0,role:'button','aria-label':translate('trafficLog.interaction')+' '+record.method+' '+record.url,style:{cursor:'pointer'}})
async function openInteraction(record:GuardLogItem){const current=++interactionGeneration;previewRow.value=record;packetTab.value='request';previewEncoding.value='utf-8';interactionError.value='';interactionLoading.value=true;try{const detail=await logMonitorApi.trafficInteraction(record._id);if(current===interactionGeneration && previewRow.value?._id===record._id)previewRow.value=detail}catch(error){if(current===interactionGeneration)interactionError.value=(error as Error).message}finally{if(current===interactionGeneration)interactionLoading.value=false}}
function preview(key:'request_preview_b64'|'response_preview_b64'){
  const value=previewRow.value?.[key] || '';if(!value)return ''
  if(previewEncoding.value==='base64')return value
  const bytes=Uint8Array.from(atob(value),c=>c.charCodeAt(0))
  if(previewEncoding.value==='hex')return Array.from(bytes,c=>c.toString(16).padStart(2,'0')).join(' ')
  return new TextDecoder(previewEncoding.value).decode(bytes)
}
const total = ref(0)
const sizeOpen = ref(false)
const saving = ref(false)
const sizeMb = ref(500)
const retentionDays=ref(30)
const stat = reactive<GuardLogStat>({ total: 0, blocked: 0, allowed: 0, size_mb: 500, default_size_mb: 500 })
const query = reactive({ session_id:'', allow: '' as string, mode: '' as string, page: 1, size: 20 })

const allowOptions = [{ get label() { return translate('ui.m_5c55a67935af') }, value: '' }, { get label() { return translate('ui.m_bf33347e3c85') }, value: '0' }, { get label() { return translate('ui.m_561817f02529') }, value: '1' }]
const modeOptions = [{ get label() { return translate('ui.m_5c55a67935af') }, value: '' }, ...PENTEST_MODES.map(m => ({ label: m.label, value: m.value }))]
const columns = [
  { get title() { return translate('trafficLog.response') }, dataIndex:'status_code', width:100, align:'center' as const },
  { get title() { return translate('ui.m_bb7ef73495dd') }, key: 'allow', width: 80 },
  { get title() { return translate('ui.m_47a270081ab2') }, key: 'mode', width: 80 },
  { get title() { return translate('ui.m_22b9f0b66212') }, key: 'method', width: 90 },
  { title: 'URL', dataIndex: 'url', ellipsis: true },
  { get title() { return translate('ui.m_15c58df57646') }, dataIndex: 'level', width: 110 },
  { get title() { return translate('ui.m_f029d9cb4a76') }, dataIndex: 'reason', ellipsis: true },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', width: 160 },
  { get title() { return translate('trafficLog.session') }, dataIndex:'session_id', width:220, ellipsis:true },
  { get title() { return translate('trafficLog.source') }, dataIndex:'source', width:130 }
]
function methodColor(m: string) { return ({ GET: 'default', POST: 'green', PUT: 'orange', DELETE: 'red', PATCH: 'purple' } as Record<string, string>)[m] || 'default' }

async function loadStat() {
  try { Object.assign(stat, await logMonitorApi.guardStat()); sizeMb.value = stat.size_mb;retentionDays.value=stat.retention_days || 30 } catch { /* 忽略 */ }
}
async function loadList() {
  loading.value = true
  try {
    const res = await logMonitorApi.guardList({ allow: query.allow, mode: query.mode, session_id:query.session_id.trim(), page: query.page, size: query.size })
    rows.value = res.items; total.value = res.total
  } catch (e) { message.error((e as Error).message || translate('ui.m_d1d044826a45')) } finally { loading.value = false }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.session_id=''; query.allow = ''; query.mode = ''; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }
async function saveSize() {
  saving.value = true
  try { await logMonitorApi.setGuardSize(sizeMb.value,retentionDays.value); message.success(translate('ui.m_123e648594da')); sizeOpen.value = false; loadAll() }
  catch (e) { message.error((e as Error).message || translate('ui.m_6309a3bb5ba4')) } finally { saving.value = false }
}
onMounted(loadAll)
onUnmounted(()=>interactionGeneration++)
</script>
<style scoped>
.traffic-interaction-meta{display:flex;align-items:center;gap:10px;padding:10px 0 16px;border-bottom:1px solid var(--dt-border)}.traffic-interaction-meta strong{flex:1;min-width:0;overflow-wrap:anywhere;font-weight:500;font-family:var(--dt-mono);font-size:13px}.traffic-interaction-meta>span{color:var(--dt-muted);font-size:12px;flex-shrink:0}.traffic-encoding{display:flex;align-items:center;gap:12px;margin-top:16px;font-size:12px;color:var(--dt-muted);flex-wrap:wrap}.traffic-encoding>span:last-child{margin-left:auto}.traffic-packet{max-height:55vh;min-height:180px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--dt-fill);color:var(--dt-text);border:1px solid var(--dt-border);border-radius:9px;padding:16px;font:13px/1.7 var(--dt-mono);scrollbar-gutter:stable}.traffic-capture-note{color:var(--dt-warning);font-size:12px;line-height:1.6;margin:12px 0 0}
</style>
