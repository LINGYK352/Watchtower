<template>
  <PageContainer title="单位视图" description="按单位汇总渗透情报,点卡片看该单位的漏洞、子域名、系统、报告与攻击链">
    <a-spin :spinning="loading">
      <div style="margin-bottom:16px;display:flex;gap:12px;align-items:center">
        <a-input-search v-model:value="keyword" placeholder="搜索单位名" allow-clear style="max-width:320px" />
        <a-segmented v-model:value="sortBy" :options="[{label:'按渗透时间',value:'time'},{label:'按漏洞数',value:'vuln'}]" />
        <span class="muted">共 {{ filteredUnits.length }} 个单位</span>
      </div>
      <a-empty v-if="!filteredUnits.length" :description="units.length ? '无匹配单位' : '暂无已渗透单位'" />
      <a-row :gutter="[16, 16]">
        <a-col v-for="u in filteredUnits" :key="u.unit" :xs="24" :sm="12" :md="8" :lg="6">
          <a-card hoverable class="unit-card" @click="openUnit(u.unit)">
            <div class="unit-name">
              {{ u.unit }}
              <a-popconfirm title="确认删除该单位所有数据？(资产/漏洞/报告/渗透会话/攻击链/线索)" ok-text="确认删除" cancel-text="取消" @confirm.stop="deleteUnit(u.unit)">
                <a-button type="text" danger size="small" class="unit-del-btn" @click.stop>删除</a-button>
              </a-popconfirm>
            </div>
            <div class="unit-metrics">
              <span class="m vuln"><b>{{ u.vuln_count }}</b>漏洞</span>
              <span class="m"><b>{{ u.subdomain_count }}</b>子域名</span>
              <span class="m"><b>{{ u.system_count }}</b>系统</span>
            </div>
            <div class="unit-metrics">
              <span class="m"><b>{{ u.report_count }}</b>报告</span>
              <span class="m"><b>{{ u.chain_count }}</b>攻击链</span>
              <span class="m" v-if="u.lead_count"><b>{{ u.lead_count }}</b>线索</span>
            </div>
            <div class="unit-time">最近渗透:{{ u.last_pentest ? u.last_pentest.slice(0, 10) : '—' }}</div>
          </a-card>
        </a-col>
      </a-row>
    </a-spin>

    <a-drawer v-model:open="detailOpen" :title="`单位详情:${cur?.unit || ''}`" width="68%">
      <a-spin :spinning="detailLoading">
        <template v-if="cur">
          <a-descriptions :column="4" size="small" bordered style="margin-bottom:16px">
            <a-descriptions-item label="已验证漏洞">{{ cur.vuln_count }}</a-descriptions-item>
            <a-descriptions-item label="线索">{{ cur.lead_count }}</a-descriptions-item>
            <a-descriptions-item label="子域名">{{ cur.subdomain_count }}</a-descriptions-item>
            <a-descriptions-item label="系统">{{ cur.system_count }}</a-descriptions-item>
          </a-descriptions>
          <a-tabs>
            <a-tab-pane key="vulns" :tab="`漏洞 (${cur.vulns.length})`">
              <a-table :data-source="cur.vulns" :columns="vulnCols" row-key="_id" size="small" :pagination="{ pageSize: 10 }">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'severity'"><StatusTag :status="record.severity" /></template>
                </template>
              </a-table>
            </a-tab-pane>
            <a-tab-pane key="reports" :tab="`报告 (${cur.reports.length})`">
              <a-table :data-source="cur.reports" :columns="reportCols" row-key="report_id" size="small" :pagination="{ pageSize: 10 }">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'max_severity'"><StatusTag :status="record.max_severity" /></template>
                </template>
              </a-table>
            </a-tab-pane>
            <a-tab-pane key="chains" :tab="`攻击链 (${cur.chains.length})`">
              <a-table :data-source="cur.chains" :columns="chainCols" row-key="chain_id" size="small" :pagination="false">
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'max_severity'"><StatusTag :status="record.max_severity" /></template>
                </template>
              </a-table>
            </a-tab-pane>
            <a-tab-pane key="subs" :tab="`子域名/系统 (${cur.subdomain_count}/${cur.system_count})`">
              <a-table :data-source="cur.subdomains" :columns="subCols" row-key="subdomain" size="small" :pagination="{ pageSize: 10 }" />
              <div style="margin-top:12px"><b>系统:</b> <a-tag v-for="s in cur.systems" :key="s.system_id">{{ s.system_name }}</a-tag></div>
            </a-tab-pane>
            <a-tab-pane key="intel" :tab="`侦察情报 (${(cur.intel?.fingerprints?.length||0)+(cur.intel?.file_leaks?.length||0)+(cur.intel?.secrets?.length||0)})`">
              <div class="intel-block"><b>指纹/组件 ({{ cur.intel?.fingerprints?.length || 0 }}):</b>
                <a-tag v-for="f in cur.intel?.fingerprints || []" :key="f" color="blue">{{ f }}</a-tag>
                <span v-if="!cur.intel?.fingerprints?.length" class="muted">无</span>
              </div>
              <div class="intel-block"><b>敏感信息/密钥 ({{ cur.intel?.secrets?.length || 0 }}):</b>
                <div v-for="(s,i) in cur.intel?.secrets || []" :key="i" class="intel-row">· [{{ s.type || '密钥' }}] {{ (s.content || s.value || '').toString().slice(0,100) }}</div>
                <span v-if="!cur.intel?.secrets?.length" class="muted">无</span>
              </div>
              <div class="intel-block"><b>文件泄露 ({{ cur.intel?.file_leaks?.length || 0 }}):</b>
                <div v-for="(l,i) in cur.intel?.file_leaks || []" :key="i" class="intel-row">· {{ l.url || l.path }} <span class="muted">[{{ l.status }}]</span></div>
                <span v-if="!cur.intel?.file_leaks?.length" class="muted">无</span>
              </div>
              <div class="intel-block"><b>关键端点 ({{ cur.intel?.endpoints?.length || 0 }}):</b>
                <div v-for="(e,i) in cur.intel?.endpoints || []" :key="i" class="intel-row">· {{ e.url || e }}</div>
                <span v-if="!cur.intel?.endpoints?.length" class="muted">无</span>
              </div>
              <div class="intel-block"><b>端口服务 ({{ cur.intel?.ports?.length || 0 }}):</b>
                <a-tag v-for="(p,i) in cur.intel?.ports || []" :key="i">{{ p.port }}/{{ p.service }} {{ p.product }}</a-tag>
                <span v-if="!cur.intel?.ports?.length" class="muted">无</span>
              </div>
            </a-tab-pane>
          </a-tabs>
        </template>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>
<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
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
  { title: '类型', dataIndex: 'vuln_type', key: 'vuln_type' },
  { title: '目标', dataIndex: 'target', key: 'target', ellipsis: true },
  { title: '等级', dataIndex: 'severity', key: 'severity', width: 90 },
  { title: '时间', dataIndex: 'save_date', key: 'save_date', width: 160 }
]
const reportCols = [
  { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
  { title: '系统', dataIndex: 'system_name', key: 'system_name', width: 140 },
  { title: '漏洞数', dataIndex: 'vuln_count', key: 'vuln_count', width: 80 },
  { title: '最高危害', dataIndex: 'max_severity', key: 'max_severity', width: 90 },
  { title: '有用值', dataIndex: 'useful_count', key: 'useful_count', width: 70 },
  { title: '时间', dataIndex: 'save_date', key: 'save_date', width: 160 }
]
const chainCols = [
  { title: '攻击链', dataIndex: 'title', key: 'title', ellipsis: true },
  { title: '环节', dataIndex: 'step_count', key: 'step_count', width: 70 },
  { title: '最高危害', dataIndex: 'max_severity', key: 'max_severity', width: 90 }
]
const subCols = [
  { title: '子域名', dataIndex: 'subdomain', key: 'subdomain' },
  { title: '资产数', dataIndex: 'asset_count', key: 'asset_count', width: 90 }
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
    message.success(`已删除单位「${unit}」的 ${total} 条数据`)
    load()
  } catch (e) { message.error(e instanceof Error ? e.message : String(e)) }
}
onMounted(load)
</script>
<style scoped>
.unit-card { cursor: pointer; }
.unit-name { font-weight: 600; font-size: 15px; margin-bottom: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: flex; justify-content: space-between; align-items: center; }
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
