<template>
  <!-- #11 用户 2026-09-15：支持 embedded 嵌入资产视图 Tab——嵌入时用普通 div（不带 PageContainer 标题/边距），
       独立路由访问时仍用 PageContainer。用 component :is 动态切根容器，内容复用不重复。 -->
  <component :is="embedded ? 'div' : PageContainer"
    v-bind="embedded ? {} : { title: translate('ui.m_c0cfb43b13b4'), description: translate('ui.m_9ef649809a7a') }">
    <a-spin :spinning="loading">
      <div style="margin-bottom:16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <a-input-search v-model:value="keyword" :placeholder="translate('ui.m_df95ee84c607')" allow-clear style="max-width:320px" />
        <a-segmented v-model:value="sortBy" :options="[{label:translate('ui.m_e718ab4b4028'),value:'time'},{label:translate('ui.m_2693a11048b5'),value:'vuln'}]" />
        <span class="muted">{{ translate('ui.m_76e547a8fa54') }} {{ filteredUnits.length }} {{ translate('ui.m_a5a76ddadbe7') }}</span>
        <!-- 多选批量删除：勾选卡片后出现 -->
        <a-checkbox :checked="allChecked" :indeterminate="someChecked" @change="toggleAll">{{ translate('ui.m_4cabaad3579b') }}</a-checkbox>
        <a-popconfirm v-if="selected.length" :title="translate('ui.m_38184b6a20f6', { p0: (selected.length) })"
          :ok-text="translate('ui.m_a3ea3c17b401')" :cancel-text="translate('ui.m_2cd0f3be8738')" @confirm="batchDelete">
          <a-button danger size="small">{{ translate('ui.m_a3436403034f') }}{{ selected.length }})</a-button>
        </a-popconfirm>
      </div>
      <a-empty v-if="!filteredUnits.length" :description="units.length ? translate('ui.m_5710df22960a') : translate('ui.m_29428a68626b')" />
      <a-row :gutter="[16, 16]">
        <a-col v-for="u in filteredUnits" :key="u.unit" :xs="24" :sm="12" :md="8" :lg="6">
          <a-card hoverable class="unit-card" :class="{ 'unit-checked': selected.includes(u.unit) }" @click="openUnit(u.unit)">
            <div class="unit-name">
              <a-checkbox class="unit-check" :checked="selected.includes(u.unit)"
                @click.stop @change="toggleOne(u.unit)" />
              <span class="unit-name-txt">{{ u.unit }}</span>
              <a-popconfirm :title="translate('ui.m_f381462cee19')" :ok-text="translate('ui.m_a3ea3c17b401')" :cancel-text="translate('ui.m_2cd0f3be8738')" @confirm.stop="deleteUnit(u.unit)">
                <a-button type="text" danger size="small" class="unit-del-btn" @click.stop>{{ translate('ui.m_2f9daa828907') }}</a-button>
              </a-popconfirm>
            </div>
            <div class="unit-metrics">
              <span class="m vuln"><b>{{ u.vuln_count }}</b>{{ translate('ui.m_b0475a364bcb') }}</span>
              <span class="m"><b>{{ u.subdomain_count }}</b>{{ translate('ui.m_4b4788120c34') }}</span>
              <span class="m"><b>{{ u.system_count }}</b>{{ translate('ui.m_5b50d7c4b595') }}</span>
            </div>
            <div class="unit-metrics">
              <span class="m"><b>{{ u.report_count }}</b>{{ translate('ui.m_1e8ddd10bafe') }}</span>
              <span class="m"><b>{{ u.chain_count }}</b>{{ translate('ui.m_31f1f49cdb27') }}</span>
              <span class="m" v-if="u.lead_count"><b>{{ u.lead_count }}</b>{{ translate('ui.m_bfc935ea3355') }}</span>
            </div>
            <div class="unit-time">{{ translate('ui.m_dee61d65c28f') }}{{ u.last_pentest ? u.last_pentest.slice(0, 10) : '—' }}</div>
          </a-card>
        </a-col>
      </a-row>
    </a-spin>

    <a-drawer v-model:open="detailOpen" :title="translate('ui.m_dc61c436af11', { p0: (cur?.unit || '') })" width="68%">
      <a-spin :spinning="detailLoading">
        <template v-if="cur">
          <a-descriptions :column="4" size="small" bordered style="margin-bottom:16px">
            <a-descriptions-item :label="translate('ui.m_5265572c3a2e')">{{ cur.vuln_count }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_bfc935ea3355')">{{ cur.lead_count }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_4b4788120c34')">{{ cur.subdomain_count }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_5b50d7c4b595')">{{ cur.system_count }}</a-descriptions-item>
          </a-descriptions>
          <a-tabs>
            <a-tab-pane key="vulns" :tab="translate('ui.m_fc17f8cc1659', { p0: (cur.vulns.length) })">
              <a-table :data-source="cur.vulns" :columns="vulnCols" row-key="_id" size="small" :pagination="{ pageSize: 10 }">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'severity'"><StatusTag :status="record.severity" /></template>
                </template>
              </a-table>
            </a-tab-pane>
            <a-tab-pane key="reports" :tab="translate('ui.m_ea8b9470cb00', { p0: (cur.reports.length) })">
              <a-table :data-source="cur.reports" :columns="reportCols" row-key="report_id" size="small" :pagination="{ pageSize: 10 }">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'max_severity'"><StatusTag :status="record.max_severity" /></template>
                </template>
              </a-table>
            </a-tab-pane>
            <a-tab-pane key="chains" :tab="translate('ui.m_f0649804beca', { p0: (cur.chains.length) })">
              <a-table :data-source="cur.chains" :columns="chainCols" row-key="chain_id" size="small" :pagination="false">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'max_severity'"><StatusTag :status="record.max_severity" /></template>
                </template>
              </a-table>
            </a-tab-pane>
            <a-tab-pane key="subs" :tab="translate('ui.m_3171f225dc09', { p0: (cur.subdomain_count), p1: (cur.system_count) })">
              <a-table :data-source="cur.subdomains" :columns="subCols" row-key="subdomain" size="small" :pagination="{ pageSize: 10 }" />
              <div style="margin-top:12px"><b>{{ translate('ui.m_262d23b8dce1') }}</b> <a-tag v-for="s in cur.systems" :key="s.system_id">{{ s.system_name }}</a-tag></div>
            </a-tab-pane>
            <a-tab-pane key="intel" :tab="translate('ui.m_99d7b8b0ed58', { p0: ((cur.intel?.fingerprints?.length||0)+(cur.intel?.file_leaks?.length||0)+(cur.intel?.secrets?.length||0)) })">
              <div class="intel-block"><b>{{ translate('ui.m_afeaa9dffd01') }}{{ cur.intel?.fingerprints?.length || 0 }}):</b>
                <a-tag v-for="f in cur.intel?.fingerprints || []" :key="f" color="blue">{{ f }}</a-tag>
                <span v-if="!cur.intel?.fingerprints?.length" class="muted">{{ translate('ui.m_484d55613910') }}</span>
              </div>
              <div class="intel-block"><b>{{ translate('ui.m_6a9c3a600d4c') }}{{ cur.intel?.secrets?.length || 0 }}):</b>
                <div v-for="(s,i) in cur.intel?.secrets || []" :key="i" class="intel-row">· [{{ s.type || translate('ui.m_f67bca8f42bc') }}] {{ (s.content || s.value || '').toString().slice(0,100) }}</div>
                <span v-if="!cur.intel?.secrets?.length" class="muted">{{ translate('ui.m_484d55613910') }}</span>
              </div>
              <div class="intel-block"><b>{{ translate('ui.m_eea8c519e342') }}{{ cur.intel?.file_leaks?.length || 0 }}):</b>
                <div v-for="(l,i) in cur.intel?.file_leaks || []" :key="i" class="intel-row">· {{ l.url || l.path }} <span class="muted">[{{ l.status }}]</span></div>
                <span v-if="!cur.intel?.file_leaks?.length" class="muted">{{ translate('ui.m_484d55613910') }}</span>
              </div>
              <div class="intel-block"><b>{{ translate('ui.m_7dc997d8dadf') }}{{ cur.intel?.endpoints?.length || 0 }}):</b>
                <div v-for="(e,i) in cur.intel?.endpoints || []" :key="i" class="intel-row">· {{ e.url || e }}</div>
                <span v-if="!cur.intel?.endpoints?.length" class="muted">{{ translate('ui.m_484d55613910') }}</span>
              </div>
              <div class="intel-block"><b>{{ translate('ui.m_0608e6fe21f3') }}{{ cur.intel?.ports?.length || 0 }}):</b>
                <a-tag v-for="(p,i) in cur.intel?.ports || []" :key="i">{{ p.port }}/{{ p.service }} {{ p.product }}</a-tag>
                <span v-if="!cur.intel?.ports?.length" class="muted">{{ translate('ui.m_484d55613910') }}</span>
              </div>
            </a-tab-pane>
          </a-tabs>
        </template>
      </a-spin>
    </a-drawer>
  </component>
</template>
<script setup lang="ts">
import { t as translate } from '../../i18n'

import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'

// embedded=true 时作为资产视图页的 Tab 内嵌（不渲染外层 PageContainer，避免双标题）
defineProps<{ embedded?: boolean }>()
import StatusTag from '../../components/StatusTag.vue'
import { intelApi, type UnitCard, type UnitDetail } from '../../api/intel'

const loading = ref(false)
const detailLoading = ref(false)
const detailOpen = ref(false)
const units = ref<UnitCard[]>([])
const cur = ref<UnitDetail | null>(null)
const keyword = ref('')
const sortBy = ref<'time' | 'vuln'>('time')

const filteredUnits = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  let list = kw ? units.value.filter(u => u.unit.toLowerCase().includes(kw)) : units.value.slice()
  list.sort((a, b) => sortBy.value === 'vuln'
    ? b.vuln_count - a.vuln_count
    : (b.last_pentest || '').localeCompare(a.last_pentest || ''))
  return list
})

const vulnCols = [
  { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'vuln_type', key: 'vuln_type' },
  { get title() { return translate('ui.m_57060c88a36b') }, dataIndex: 'target', key: 'target', ellipsis: true },
  { get title() { return translate('ui.m_337717173807') }, dataIndex: 'severity', key: 'severity', width: 90 },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', key: 'save_date', width: 160 }
]
const reportCols = [
  { get title() { return translate('ui.m_c3405f8c7d9d') }, dataIndex: 'title', key: 'title', ellipsis: true },
  { get title() { return translate('ui.m_5b50d7c4b595') }, dataIndex: 'system_name', key: 'system_name', width: 140 },
  { get title() { return translate('ui.m_415760c06b97') }, dataIndex: 'vuln_count', key: 'vuln_count', width: 80 },
  { get title() { return translate('ui.m_aea0fc420948') }, dataIndex: 'max_severity', key: 'max_severity', width: 90 },
  { get title() { return translate('ui.m_bd267af71840') }, dataIndex: 'useful_count', key: 'useful_count', width: 70 },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', key: 'save_date', width: 160 }
]
const chainCols = [
  { get title() { return translate('ui.m_31f1f49cdb27') }, dataIndex: 'title', key: 'title', ellipsis: true },
  { get title() { return translate('ui.m_28475230f056') }, dataIndex: 'step_count', key: 'step_count', width: 70 },
  { get title() { return translate('ui.m_aea0fc420948') }, dataIndex: 'max_severity', key: 'max_severity', width: 90 }
]
const subCols = [
  { get title() { return translate('ui.m_4b4788120c34') }, dataIndex: 'subdomain', key: 'subdomain' },
  { get title() { return translate('ui.m_ae4728f08828') }, dataIndex: 'asset_count', key: 'asset_count', width: 90 }
]

async function load() {
  loading.value = true
  try { units.value = (await intelApi.units()).units }
  catch (e) { message.error(e instanceof Error ? e.message : String(e)) }
  finally { loading.value = false }
}
async function openUnit(unit: string) {
  detailOpen.value = true; detailLoading.value = true; cur.value = null
  try { cur.value = await intelApi.unitDetail(unit) }
  catch (e) { message.error(e instanceof Error ? e.message : String(e)) }
  finally { detailLoading.value = false }
}
async function deleteUnit(unit: string) {
  try {
    const res = await intelApi.deleteUnit(unit)
    const total = Object.values(res.deleted).reduce((a, b) => a + b, 0)
    message.success(translate('ui.m_01d374374c09', { p0: (unit), p1: (total) }))
    load()
  } catch (e) { message.error(e instanceof Error ? e.message : String(e)) }
}

// —— 多选批量删除 ——
const selected = ref<string[]>([])
const allChecked = computed(() => filteredUnits.value.length > 0 && filteredUnits.value.every(u => selected.value.includes(u.unit)))
const someChecked = computed(() => selected.value.length > 0 && !allChecked.value)
function toggleOne(unit: string) {
  const i = selected.value.indexOf(unit)
  if (i >= 0) selected.value.splice(i, 1)
  else selected.value.push(unit)
}
function toggleAll() {
  if (allChecked.value) selected.value = []
  else selected.value = filteredUnits.value.map(u => u.unit)
}
async function batchDelete() {
  const units = selected.value.slice()
  if (!units.length) return
  let ok = 0, total = 0
  for (const unit of units) {
    try {
      const res = await intelApi.deleteUnit(unit)
      total += Object.values(res.deleted).reduce((a, b) => a + b, 0)
      ok++
    } catch { /* 单个失败不中断 */ }
  }
  message.success(translate('ui.m_29b3da266df8', { p0: (ok), p1: (units.length), p2: (total) }))
  selected.value = []
  load()
}
onMounted(load)
</script>
<style scoped>
.unit-card { cursor: pointer; transition: box-shadow .2s, border-color .2s; }
.unit-card.unit-checked { border-color: #1677ff; box-shadow: 0 0 0 1px #1677ff inset, 0 2px 10px rgba(22,119,255,.15); }
.unit-name { font-weight: 600; font-size: 15px; margin-bottom: 10px; display: flex; gap: 6px; align-items: center; }
.unit-check { flex: none; }
.unit-name-txt { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.unit-del-btn { font-size: 11px; opacity: 0; transition: opacity .2s; }
.unit-card:hover .unit-del-btn { opacity: 1; }
.unit-metrics { display: flex; gap: 14px; margin-bottom: 6px; }
.unit-metrics .m { color: #888; font-size: 12px; }
.unit-metrics .m b { color: #333; font-size: 16px; margin-right: 3px; }
.unit-metrics .m.vuln b { color: #cf1322; }
.unit-time { color: #aaa; font-size: 12px; margin-top: 4px; }
.muted { color: #999; font-size: 12px; }
.intel-block { margin-bottom: 14px; }
.intel-block b { display: block; margin-bottom: 6px; }
.intel-row { font-size: 12px; color: #555; padding: 2px 0; word-break: break-all; }
</style>
