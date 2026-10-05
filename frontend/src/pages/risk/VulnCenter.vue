<template>
  <PageContainer :title="translate('ui.m_756d8eeb32a5')" kicker="Vulnerabilities"
    :description="translate('ui.m_daa256b9fb37')">
    <template #extra>
      <a-space>
        <a-switch v-model:checked="auto.enabled.value" checked-children="自动" un-checked-children="手动" size="small" />
        <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
      </a-space>
    </template>

    <a-row :gutter="12" style="margin-bottom:16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_94cf4e239cf2')" :value="stat.ai.verified" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_7a668db4b7c8')" :value="(stat.ai.by_severity.critical || 0) + (stat.ai.by_severity.high || 0)" :value-style="{ color: '#a8071a' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :value="stat.poc.total">
        <template #title><span>{{ translate('ui.m_e053a02071aa') }}</span>
          <a-tooltip :title="translate('ui.m_68df28fde4b1')">
            <QuestionCircleOutlined style="margin-left:4px;color:#aaa" /></a-tooltip>
        </template></a-statistic></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_289346a2e212')" :value="stat.combined_total" :value-style="{ color: '#1677ff' }" /></a-card></a-col>
    </a-row>

    <div style="margin-bottom:12px">
      <a-segmented v-model:value="query.source" :options="sourceOptions" @change="reload" />
    </div>

    <SearchBar :model="query" @search="reload" @reset="onReset">
      <a-form-item :label="translate('ui.m_44ce7ae909bb')"><a-input v-model:value="query.keyword" allow-clear :placeholder="translate('ui.m_0137c7675a0a')" style="width:150px" /></a-form-item>
      <a-form-item :label="translate('ui.m_58c48802553a')">
        <a-select v-model:value="query.min_severity" style="width:130px" :options="minSevOptions" @change="reload" />
      </a-form-item>
      <a-form-item :label="translate('ui.m_4e1449e7d5e5')">
        <a-select v-model:value="query.dedup" style="width:130px" :options="dedupOptions" @change="reload" />
      </a-form-item>
      <a-form-item :label="translate('ui.m_80b19d68b149')" v-if="query.source === '' || query.source === 'ai'">
        <a-input v-model:value="query.unit" allow-clear :placeholder="translate('ui.m_cc25ff071e10')" style="width:150px" />
      </a-form-item>
      <a-form-item :label="translate('ui.m_d5e74de3449e')">
        <a-select v-model:value="query.handle_status" allow-clear style="width:120px" :options="handleStatusOptions" :placeholder="translate('ui.m_5c55a67935af')" />
      </a-form-item>
      <a-form-item :label="translate('ui.m_07eb730af899')">
        <a-range-picker v-model:value="dateRange" value-format="YYYY-MM-DD" style="width:240px" @change="reload" />
      </a-form-item>
    </SearchBar>

    <div style="margin-bottom:8px">
      <a-popconfirm :title="translate('ui.m_8a1cb2428e96', { p0: (selectedKeys.length) })" :disabled="!selectedKeys.length" @confirm="batchDelete">
        <a-button danger :disabled="!selectedKeys.length">{{ translate('ui.m_ddae7a0fc554') }}{{ selectedKeys.length ? `(${selectedKeys.length})` : '' }}</a-button>
      </a-popconfirm>
    </div>

    <AppTable :columns="columns" :data="rows" :loading="loading" selectable
      v-model:selectedRowKeys="selectedKeys"
      :page="query.page" :size="query.size" :total="total" row-key="_id" @change="onPage">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'source'">
          <a-tag :color="srcMeta(record.source).color">{{ srcLabel(record) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'name'">
          <div style="display:flex;align-items:center;gap:6px">
            <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ record.name }}</span>
            <a-tooltip v-if="record.suspect">
              <template #title>{{ translate('ui.m_b9458c7f9fe9') }}{{ record.mode_label || translate('ui.m_d5fea62a17c5') }}{{ translate('ui.m_ad282cad6f59') }}</template>
              <a-tag color="orange" style="flex-shrink:0">{{ translate('ui.m_f81286d3cf0a') }}</a-tag>
            </a-tooltip>
            <!-- 首次/重复发现（方案B）：抵右侧边栏。仅 AI 洞有 first_seen 语义 -->
            <a-tag v-if="record.source === 'ai'" :color="record.first_seen === true ? 'green' : record.first_seen === false ? 'gold' : 'default'"
              style="margin-left:auto;flex-shrink:0">{{ record.first_seen === true ? translate('ui.m_cfca89659bcb') : record.first_seen === false ? translate('ui.m_724fbde3a1b9') : translate('ui.m_436e50c97a21') }}<template v-if="record.occurrence_count > 1"> · {{ record.occurrence_count }} {{ translate('ui.m_172fb7e67b9b') }}</template></a-tag>
          </div>
        </template>
        <template v-else-if="column.key === 'verified'">
          <a-tag v-if="record.source === 'ai'" :color="record.verified ? 'red' : 'orange'">{{ record.verified ? translate('ui.m_0a1b6f1b57f5') : translate('ui.m_bfc935ea3355') }}</a-tag>
          <a-tag v-else color="cyan">{{ translate('ui.m_393df9bb13ea') }}</a-tag>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="sevColor(record.severity)">{{ sevLabel(record.severity) }}</a-tag>
          <a-tooltip v-if="record.cvss_score != null" :title="cvssNote(record)">
            <span class="muted" :class="{ calibrated: isCalibrated(record) }"> {{ record.cvss_score }}{{ isCalibrated(record) ? '*' : '' }}</span>
          </a-tooltip>
        </template>
        <template v-else-if="column.key === 'target'">
          <a-tag v-if="record.asset_type === 'miniapp'" color="green" style="margin-right:4px">{{ translate('ui.m_68fba79b8508') }}</a-tag>
          <CopyText :text="String(record.target || '')" />
        </template>
        <template v-else-if="column.key === 'task_name'">
          <span v-if="record.task_name">{{ record.task_name }}</span>
          <span v-else class="muted">—</span>
        </template>
        <template v-else-if="column.key === 'unit'">
          <span v-if="record.unit">{{ record.unit }}</span>
          <!-- AI 来源:无单位=ICP 查不到备案(瞭望塔扫描来源本就无单位维度,只显 —) -->
          <span v-else-if="record.source === 'ai'" class="muted">{{ translate('ui.m_6b7cdd34a561') }}</span>
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
            <a-button type="link" size="small" @click="showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button>
            <a-dropdown>
              <a-button type="link" size="small">{{ translate('ui.m_ed31fbb483ee') }}<DownOutlined /></a-button>
              <template #overlay>
                <a-menu @click="(info: any) => onAction(record, String(info.key))">
                  <a-menu-item-group :title="translate('ui.m_f6cbf22628a5')">
                    <a-menu-item key="mark:submitted">{{ translate('ui.m_269635727321') }}</a-menu-item>
                    <a-menu-item key="mark:false_positive">{{ translate('ui.m_a456f5044e3b') }}</a-menu-item>
                    <a-menu-item key="mark:">{{ translate('ui.m_cb5d682bac3d') }}</a-menu-item>
                  </a-menu-item-group>
                  <a-menu-item-group v-if="record.source === 'ai'" :title="translate('ui.m_3a3a16e6f5c0')">
                    <a-menu-item key="downgrade:medium">{{ translate('ui.m_140eb1dbbef2') }}</a-menu-item>
                    <a-menu-item key="downgrade:low">{{ translate('ui.m_d8f356f57030') }}</a-menu-item>
                    <a-menu-item key="downgrade:info">{{ translate('ui.m_60a6ab4881d3') }}</a-menu-item>
                  </a-menu-item-group>
                  <a-menu-divider />
                  <a-menu-item-group :title="translate('ui.m_a62f22586ca0')">
                    <!-- 单条漏洞直接生成漏洞级报告（只依赖漏洞自身 _id，任意来源都可用） -->
                    <a-menu-item key="report:finding">
                      {{ translate('ui.m_7db555f918fc') }}
                    </a-menu-item>
                    <!-- AI 来源才有来源会话，可生成/重生成该资产的会话级报告 -->
                    <a-menu-item key="report:session" :disabled="record.source !== 'ai' || !record.session_id">
                      {{ translate('ui.m_39ccfb6e7fc9') }}
                    </a-menu-item>
                    <!-- 任意来源只要归属某任务，即可生成整任务级总结报告 -->
                    <a-menu-item key="report:task" :disabled="!record.task_id">
                      {{ translate('ui.m_97f759e869a5') }}
                    </a-menu-item>
                  </a-menu-item-group>
                </a-menu>
              </template>
            </a-dropdown>
            <ConfirmAction v-if="record.source !== 'ai'" danger :title="translate('ui.m_0e5aa0501737')" @confirm="removeOne(record)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
          </a-space>
        </template>
      </template>
    </AppTable>

    <a-drawer v-model:open="detailOpen" :title="detailTitle" width="62%">
      <a-spin :spinning="detailLoading">
        <!-- AI 渗透漏洞详情 -->
        <a-descriptions v-if="cur.source === 'ai'" :column="1" size="small" bordered>
          <a-descriptions-item :label="translate('ui.m_5600494fad70')">{{ cur.vuln_type }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_57060c88a36b')">{{ cur.target }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_6a2176d9e5d9')"><a-tag :color="cur.verified ? 'red' : 'orange'">{{ cur.verified ? translate('ui.m_547c2da343ea') : translate('ui.m_fad75c57a8c3') }}</a-tag> <span class="muted">{{ evidenceLabel(cur) }}</span></a-descriptions-item>
          <a-descriptions-item v-if="cur.pentest_mode" :label="translate('ui.m_6a98a90067ce')">
            <a-tag color="blue">{{ translate('ui.m_859d3c618593') }}{{ modeLabelCn(String(cur.pentest_mode)) }}</a-tag>
            <a-tag v-if="isSuspectMode(String(cur.pentest_mode))" color="orange">{{ translate('ui.m_f81286d3cf0a') }}</a-tag>
            <span v-if="isSuspectMode(String(cur.pentest_mode))" class="muted">{{ translate('ui.m_2b4cde2e1e17') }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="CVSS">{{ cur.cvss_vector || '—' }} <b v-if="cur.cvss_score != null">({{ cvssLabel(cur) }})</b></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_f8b6f7daacce')">{{ String(cur.severity || 'unknown').toUpperCase() }}<span v-if="!cur.verified" class="muted"> {{ translate('ui.m_6dc3d59bba2d') }}</span></a-descriptions-item>
          <a-descriptions-item v-if="curCalibrated" :label="translate('ui.m_5f2cf12a79d0')">
            <a-tag color="orange">{{ translate('ui.m_8cb7c0a54b21') }} {{ String(cur.cvss_severity).toUpperCase() }} {{ translate('ui.m_fdbbb8e6e278') }} {{ String(cur.severity).toUpperCase() }}</a-tag>
            <span class="muted">{{ cur.severity_basis || translate('ui.m_bb787f05a6c4') }}</span>
          </a-descriptions-item>
          <a-descriptions-item v-if="cur.chain_severity" :label="translate('ui.m_ec59c0e05c98')">
            <a-tag color="red">{{ translate('ui.m_2251eaf725bf') }} {{ String(cur.severity).toUpperCase() }} {{ translate('ui.m_34ec9ce513a4') }} {{ String(cur.chain_severity).toUpperCase() }}</a-tag>
            <span class="muted">{{ translate('ui.m_f94e613acb14') }}{{ cur.chain_title || '—' }}{{ translate('ui.m_5de66bff0748') }}</span>
          </a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_fead3fda0b19')">{{ cur.impact || '—' }}</a-descriptions-item>
          <a-descriptions-item v-if="cur.verify_method" :label="translate('ui.m_52373e434217')">{{ cur.verify_method }}</a-descriptions-item>
          <a-descriptions-item v-if="cur.key_response" :label="translate('ui.m_6e2d27b6c077')"><pre class="ev">{{ cur.key_response }}</pre></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_2c43cd7db149')">{{ cur.task_name || '—' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_80b19d68b149')">{{ cur.unit || translate('ui.m_6b7cdd34a561') }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_1ce452c175aa')"><div class="muted">{{ pocLabel(cur) }}</div><pre class="ev">{{ cur.poc || translate('ui.m_97707f6d8e2b') }}</pre></a-descriptions-item>
          <a-descriptions-item v-if="cur.poc_notes" :label="translate('ui.m_a7756b6295c1')"><pre class="ev">{{ cur.poc_notes }}</pre></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_804cdc8de9e1')">
            <template v-if="evToPackets(cur).length">
              <div v-for="(p, i) in evToPackets(cur)" :key="i" class="ev-packet">
                <div class="ev-pkt-head">
                  <a-tag color="blue">{{ p.tool }}</a-tag>
                  <a-tag v-if="p.signal" :color="p.signal === 'positive' ? 'green' : 'default'">{{ p.signal }}</a-tag>
                </div>
                <a-row :gutter="8">
                  <a-col :span="12">
                    <div class="ev-label">{{ translate('ui.m_fd8725d9a3fb') }}</div>
                    <pre class="ev burp-req">{{ p.reqText }}</pre>
                  </a-col>
                  <a-col :span="12">
                    <div class="ev-label">{{ translate('ui.m_a2f7c726b2c9') }}</div>
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
          <a-descriptions-item :label="translate('ui.m_2cbd51b8f743')">{{ cur.template_id }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_cb1049ef7a06')">{{ cur.vuln_name }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_337717173807')"><a-tag :color="sevColor(String(cur.vuln_severity || ''))">{{ String(cur.vuln_severity || '-').toUpperCase() }}</a-tag></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_53d4e9d01707')"><CopyText :text="String(cur.vuln_url || '')" /></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_57060c88a36b')">{{ cur.target }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_51bab09b2d4c')"><pre class="ev">{{ cur.curl_command || '—' }}</pre></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_aa2353039024')">{{ cur.task_id }}</a-descriptions-item>
        </a-descriptions>
        <!-- 系统 PoC 命中详情 -->
        <a-descriptions v-else :column="1" size="small" bordered>
          <a-descriptions-item :label="translate('ui.m_0d20b71f0684')">{{ cur.plg_name }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_0d12cbd6562b')">{{ cur.plg_type }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_cb1049ef7a06')">{{ cur.vul_name }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_63c73c4730f4')">{{ cur.app_name || '—' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_57060c88a36b')"><CopyText :text="String(cur.target || '')" /></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_aa2353039024')">{{ cur.task_id }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_17da5eb22d21')"><pre class="ev">{{ rawJson(cur) }}</pre></a-descriptions-item>
        </a-descriptions>
      </a-spin>
      <div style="margin-top:12px" v-if="cur.source === 'ai' && cur.session_id">
        <a-button type="link" @click="goSession(String(cur.session_id))">{{ translate('ui.m_05dcf3142e02') }}</a-button>
      </div>
      <!-- 证据截图：按 finding 绑定，生成报告时自动嵌入证据/复现区 -->
      <a-divider style="margin:14px 0 10px" />
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <b>{{ translate('ui.m_c03d356dc0c9') }}</b>
          <span class="muted" style="font-size:12px">{{ translate('ui.m_441b2d188a3f') }}</span>
          <a-upload :show-upload-list="false" :before-upload="beforeShotUpload" accept="image/*" style="margin-left:auto">
            <a-button size="small" type="primary" :loading="shotUploading">{{ translate('ui.m_3495f2cca5ab') }}</a-button>
          </a-upload>
        </div>
        <a-empty v-if="!shots.length" :description="translate('ui.m_ecdb192f8eb4')" />
        <div v-else style="display:flex;flex-wrap:wrap;gap:10px">
          <div v-for="s in shots" :key="s.name" class="shot-thumb">
            <a :href="s.url" target="_blank"><img :src="s.url" /></a>
            <a-popconfirm :title="translate('ui.m_a79ed3733c73')" :ok-text="translate('ui.m_2f9daa828907')" :cancel-text="translate('ui.m_2cd0f3be8738')" @confirm="delShot(s.name)">
              <a-button danger size="small" type="link" class="shot-del">{{ translate('ui.m_2f9daa828907') }}</a-button>
            </a-popconfirm>
          </div>
        </div>
      </div>
    </a-drawer>

    <!-- 报告生成：选模板（item5，会话/任务/漏洞级各按 scope 过滤） -->
    <a-modal v-model:open="repOpen" :title="translate('ui.m_be0402e8d9cd', { p0: (repType === 'task' ? '任务级' : repType === 'finding' ? '漏洞级' : '会话级') })"
      :confirm-loading="reportGenerating" :ok-text="translate('ui.m_a62f22586ca0')" @ok="submitGenReport">
      <a-form-item :label="translate('ui.m_c745b048ca51')">
        <a-select v-model:value="repTplId" :options="repTplOptions" :loading="repTplLoading"
          :placeholder="translate('ui.m_ff93f9c4be69')" style="width:100%" />
        <div style="margin-top:6px;color:#888;font-size:12px">{{ translate('ui.m_1a76c1a30677') }}</div>
      </a-form-item>
      <a-alert v-if="!repTplLoading && !repTplOptions.length" type="warning" show-icon
        :message="translate('ui.m_5e8fc6fb7515')" />
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { cvssLabel, evidenceLabel, pocLabel } from '../../utils/findingDisplay'
import { onMounted, onUnmounted, reactive, ref, computed } from 'vue'
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
import { reportTemplateApi, findingShotApi } from '../../api/intel'
import type { SelectOption, RowRecord } from '../../api/types'
import { useAutoRefresh } from '../../composables/useAutoRefresh'

const router = useRouter()
const loading = ref(false)
const rows = ref<UnifiedFinding[]>([])
const total = ref(0)
const selectedKeys = ref<string[]>([])
const stat = reactive<FindingStat>({ ai: { total: 0, verified: 0, leads: 0, by_severity: {}, by_type: {} }, poc: { total: 0 }, combined_total: 0, unit: '' })

const query = reactive({
  source: '' as '' | 'ai' | 'poc' | 'nuclei',
  keyword: '',
  min_severity: 'low' as string,   // 漏洞等级阈值:默认 low 及以上(隐藏 info 噪声);设 'info' 则显示全部
  dedup: '1' as '1' | '0',         // 显示:1=漏洞去重(默认,同漏洞点只留最新一条);0=全部漏洞(含重复)
  unit: '',
  handle_status: undefined as string | undefined,
  page: 1, size: 20
})
const dateRange = ref<[string, string] | undefined>(undefined)   // 时间范围筛选 [from,to]

const sourceOptions = [
  { get label() { return translate('ui.m_9f357adb6100') }, value: '' },
  { get label() { return translate('ui.m_fd02482a8251') }, value: 'ai' },
  { get label() { return translate('ui.m_9c3cdde19ad9') }, value: 'poc' },
  { label: 'Nuclei', value: 'nuclei' }
]
// 显示模式:漏洞去重(默认,同资产+同接口+同类型只留最新一条,隐藏重复) / 全部漏洞(含所有重复条目)
const dedupOptions = [
  { get label() { return translate('ui.m_32d2ca748e66') }, value: '1' },
  { get label() { return translate('ui.m_9c5bb9f6b6a4') }, value: '0' }
]
// 漏洞等级阈值:默认 LOW(隐藏 info);选"全部(含info)"= info 阈值不过滤
const minSevOptions = [
  { get label() { return translate('ui.m_f07b1660fe1e') }, value: 'info' },
  { get label() { return translate('ui.m_9fcd5a4b1d71') }, value: 'low' },
  { get label() { return translate('ui.m_192f7943a931') }, value: 'medium' },
  { get label() { return translate('ui.m_15e0a5dad5e9') }, value: 'high' },
  { get label() { return translate('ui.m_ea483775f12e') }, value: 'critical' }
]
const handleStatusOptions = [
  { get label() { return translate('ui.m_83fbf42f9e87') }, value: 'unhandled' },
  { get label() { return translate('ui.m_bc37a6110a07') }, value: 'submitted' },
  { get label() { return translate('ui.m_a456f5044e3b') }, value: 'false_positive' }
]
const HANDLE_META: Record<string, { label: string; color: string }> = {
  '': { get label() { return translate('ui.m_83fbf42f9e87') }, color: 'default' },
  submitted: { get label() { return translate('ui.m_bc37a6110a07') }, color: 'green' },
  false_positive: { get label() { return translate('ui.m_a456f5044e3b') }, color: 'orange' }
}
function handleMeta(s?: string) { return HANDLE_META[s || ''] || HANDLE_META[''] }

const columns = [
  { get title() { return translate('ui.m_a488e93d69cc') }, key: 'source', width: 90 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'verified', width: 90 },
  { get title() { return translate('ui.m_cb1049ef7a06') }, key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_57060c88a36b') }, key: 'target', ellipsis: true },
  { get title() { return translate('ui.m_e54ebcd7ee6d') }, key: 'severity', width: 140 },
  { get title() { return translate('ui.m_2c43cd7db149') }, key: 'task_name', width: 150, ellipsis: true },
  { get title() { return translate('ui.m_80b19d68b149') }, key: 'unit', width: 140, ellipsis: true },
  { get title() { return translate('ui.m_e99a6717b691') }, key: 'handle_status', width: 110 },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', width: 160 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 150 }
]

const SRC_META: Record<string, { label: string; color: string }> = {
  ai: { get label() { return translate('ui.m_fd02482a8251') }, color: 'red' },
  poc: { get label() { return translate('ui.m_9c3cdde19ad9') }, color: 'blue' },
  nuclei: { label: 'Nuclei', color: 'green' }
}
function srcMeta(s: string) { return SRC_META[s] || { label: s, color: 'default' } }
// 来源标签：AI 渗透带上具体模式（AI 渗透·探测/保守/常规/红队）；poc/nuclei 不变
function srcLabel(r: UnifiedFinding) {
  const base = srcMeta(r.source).label
  return r.source === 'ai' && r.mode_label ? `${base}·${r.mode_label}` : base
}
const _MODE_CN: Record<string, string> = { detect: '探测', conservative: '保守', src: '常规', redteam: '红队' }
function modeLabelCn(m: string) { return _MODE_CN[m] || m }
function isSuspectMode(m: string) { return m === 'detect' || m === 'conservative' }
function sevColor(s: string) {
  // 问题19：none/空/unknown 归到 info 档（蓝色），别露无颜色的裸值
  const k = String(s || '').toLowerCase()
  if (k === 'none' || k === 'unknown' || k === '') return 'blue'
  return ({ critical: 'magenta', high: 'red', medium: 'orange', low: 'gold', info: 'blue' } as Record<string, string>)[k] || 'default'
}
// 问题19：severity 展示归一——CVSS 全零向量(C:N/I:N/A:N)base=0.0→规范定性 "none"，直接大写成 "NONE"
// 难看且无意义（配置缺失类）。none/空/unknown 统一显示 "INFO"（信息级），与校准后语义一致。
function sevLabel(s: unknown): string {
  const k = String(s || '').toLowerCase()
  if (k === 'none' || k === 'unknown' || k === '') return 'INFO'
  return k.toUpperCase()
}
// 校准判定:AI 漏洞的原始 CVSS 等级与展示等级不同 → 发生了 triage 校准降级(信息型泄露等)
function isCalibrated(r: UnifiedFinding) {
  return r.source === 'ai' && !!r.cvss_severity && r.cvss_severity.toLowerCase() !== (r.severity || '').toLowerCase()
}
function cvssNote(r: UnifiedFinding) {
  if (isCalibrated(r)) {
    return translate('ui.m_674078cbd5dd', { p0: (r.cvss_score), p1: (String(r.cvss_severity).toUpperCase()), p2: (String(r.severity).toUpperCase()), p3: (r.severity_basis ? '依据:' + r.severity_basis : '') })
  }
  return translate('ui.m_8360a471025b', { p0: (r.cvss_score) })
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
      // 漏洞等级阈值(含 'info'=显示全部)。显式传:后端缺省=low,"全部"须显式 info 才看全。
      min_severity: query.min_severity || 'low',
      // 显示模式:1=漏洞去重(默认,隐藏重复);0=全部漏洞(含重复条目)
      dedup: query.dedup,
      unit: query.unit || undefined,
      handle_status: query.handle_status,
      date_from: dateRange.value?.[0] || undefined,
      date_to: dateRange.value?.[1] || undefined,
      page: query.page, size: query.size
    })
    rows.value = res.items; total.value = res.total
    selectedKeys.value = []
  } catch (e) { message.error((e as Error).message || translate('ui.m_d1d044826a45')) } finally { loading.value = false }
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
    message.success(translate('ui.m_925464646d44', { p0: (n) }))
    loadAll()
  } catch (e) { message.error((e as Error).message || translate('ui.m_c228558cf257')) }
}
function loadAll() { loadStat(); loadList() }
function reload() { query.page = 1; loadAll() }
function onReset() { query.keyword = ''; query.min_severity = 'low'; query.dedup = '1'; query.unit = ''; query.handle_status = undefined; dateRange.value = undefined; reload() }
function onPage(page: number, size: number) { query.page = page; query.size = size; loadList() }

/* 详情抽屉:按来源拉完整记录 */
const detailOpen = ref(false)
const detailLoading = ref(false)
const cur = reactive<Record<string, unknown>>({})
const detailTitle = computed(() => translate('ui.m_6f626d5c7ffb', { p0: (srcMeta(String(cur.source || '')).label) }))
// 详情里是否发生了 triage 校准(原始 CVSS 等级 ≠ 展示等级)
const curCalibrated = computed(() =>
  cur.source === 'ai' && !!cur.cvss_severity &&
  String(cur.cvss_severity).toLowerCase() !== String(cur.severity || '').toLowerCase())

async function showDetail(r: UnifiedFinding) {
  Object.keys(cur).forEach(k => delete cur[k])
  cur.source = r.source
  curFindingId.value = String(r._id)
  detailOpen.value = true
  detailLoading.value = true
  loadShots(String(r._id))
  try {
    const doc = await pentestApi.unifiedDetail(r.source, r._id)
    Object.assign(cur, doc)
    // task_name 是列表层反查回填的(原始文档无此字段),详情接口拉不到 → 用列表行的值补上
    if (!cur.task_name && r.task_name) cur.task_name = r.task_name
  } catch (e) { message.error((e as Error).message || translate('ui.m_19a7ca44a09a')) } finally { detailLoading.value = false }
}

/* 漏洞证据截图（按 finding_id 全局绑定）：上传后用模板生成本漏洞报告时自动嵌入证据/复现区。 */
const curFindingId = ref('')
const shots = ref<{ name: string; url: string }[]>([])
const shotUploading = ref(false)
async function loadShots(fid: string) {
  shots.value = []
  if (!fid) return
  try { const r = await findingShotApi.list(fid); shots.value = r.shots || [] } catch { /* 无图忽略 */ }
}
function beforeShotUpload(file: File) {
  const fid = curFindingId.value
  if (!fid) return false
  shotUploading.value = true
  findingShotApi.upload(fid, file)
    .then(() => { message.success(translate('ui.m_908dbd0eb037')); return loadShots(fid) })
    .catch((e: Error) => message.error(e.message || translate('ui.m_219481a6dde7')))
    .finally(() => { shotUploading.value = false })
  return false   // 阻止 a-upload 默认上传，走自定义
}
async function delShot(name: string) {
  try {
    await findingShotApi.remove(curFindingId.value, name)
    await loadShots(curFindingId.value)
  } catch (e) { message.error((e as Error).message || translate('ui.m_c228558cf257')) }
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
  if (!ev || !ev.length) return f.verified ? translate('ui.m_8adb320d6008') : translate('ui.m_46722c1a0692')
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
    message.success(handleStatus === 'false_positive' ? translate('ui.m_42750a3cb17b') : handleStatus === 'submitted' ? translate('ui.m_4330486d0805') : translate('ui.m_d2cd2e209c5f'))
    loadAll()   // 刷新列表+统计卡(标误报后该行从默认列表消失)
  } catch (e) { message.error((e as Error).message || translate('ui.m_9944cf73eb63')) }
}
function markOne(r: UnifiedFinding, handleStatus: string) {
  // 重置需二次确认(清除已标记/误报状态,防误点)
  if (handleStatus === '') {
    Modal.confirm({
      get title() { return translate('ui.m_104f5c9986ce') },
      get content() { return translate('ui.m_e1c3b6fea19c') },
      get okText() { return translate('ui.m_fac2a67ad878') }, get cancelText() { return translate('ui.m_2cd0f3be8738') },
      onOk: () => doMark(r, '')
    })
    return
  }
  doMark(r, handleStatus)
}

/* 操作下拉分发：mark:<status> 走标记；report:<type> 走生成报告(#4) */
function onAction(r: UnifiedFinding, key: string) {
  if (key.startsWith('mark:')) { markOne(r, key.slice(5)); return }
  if (key.startsWith('downgrade:')) { doDowngrade(r, key.slice(10)); return }
  if (key === 'report:finding') { genReport(r, 'finding'); return }
  if (key === 'report:session') { genReport(r, 'session'); return }
  if (key === 'report:task') { genReport(r, 'task'); return }
}

/* 人工降级危害等级（item5，只降不升）：后端校验目标必须严格低于当前，否则该条跳过。 */
const sevCn: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
function doDowngrade(r: UnifiedFinding, target: string) {
  Modal.confirm({
    title: translate('ui.m_4b6a1638309e', { p0: (sevCn[target] || target) }),
    content: translate('ui.m_4cc1bc4f3a9d', { p0: (sevCn[String(r.severity)] || r.severity) }),
    get okText() { return translate('ui.m_5c3b1e61e415') }, get cancelText() { return translate('ui.m_2cd0f3be8738') },
    onOk: async () => {
      try {
        const res = await pentestApi.unifiedDowngrade(r.source, [r._id], target)
        if (res.updated) message.success(translate('ui.m_f70ad7983b05', { p0: (sevCn[target] || target) }))
        else message.warning(translate('ui.m_4ad9069ab343'))
        loadAll()
      } catch (e) { message.error((e as Error).message || translate('ui.m_4678ffefb554')) }
    }
  })
}

/* 生成报告(#4)：漏洞级=按单条漏洞 _id 出报告；会话级=按来源会话重生成单资产报告；任务级=聚合整任务总结。
   三档统一弹模板选择框（按 scope 过滤，默认对应内置模板），生成后引导去「报告编辑」页查看/编辑/导出。 */
const reportGenerating = ref(false)
// 报告模板选择弹窗（item5）
const repOpen = ref(false)
const repType = ref<'session' | 'task' | 'finding'>('session')
const repSourceId = ref('')
const repTplId = ref('')
const repTplLoading = ref(false)
const repTplOptions = ref<SelectOption[]>([])
// v1.21.157-48 item5：报告生成改为**弹模板选择**（此前直生成无模板选择，与任务列表不一致）。
// 会话报告选 scope=session 模板、任务报告选 scope=task 模板（list scope 过滤含无 scope 的学习模板）。
async function genReport(r: UnifiedFinding, type: 'session' | 'task' | 'finding') {
  if (type === 'session' && (r.source !== 'ai' || !r.session_id)) {
    return message.warning(translate('ui.m_cfdca3a4095d'))
  }
  if (type === 'task' && !r.task_id) {
    return message.warning(translate('ui.m_6d892f57a8de'))
  }
  repType.value = type
  repSourceId.value = type === 'session' ? String(r.session_id)
    : type === 'task' ? String(r.task_id) : String(r._id)
  repTplId.value = ''
  repOpen.value = true
  repTplLoading.value = true
  try {
    const data = await reportTemplateApi.list({ page: 1, size: 200, scope: type })
    const ready = (data.items || []).filter((t: RowRecord) => t.status === 'ready')
    repTplOptions.value = ready.map((t: RowRecord) => ({ label: String(t.name), value: String(t._id) }))
    const builtinId = type === 'task' ? 'builtin_task_v1' : type === 'finding' ? 'ncc_event_finding_v1' : 'builtin_session_v1'
    const builtin = ready.find((t: RowRecord) => t._id === builtinId)
    repTplId.value = builtin ? String(builtin._id) : (repTplOptions.value[0]?.value as string || '')
  } catch (e) { message.error((e as Error).message || translate('ui.m_ebf73320fa75')) }
  finally { repTplLoading.value = false }
}

async function submitGenReport() {
  if (!repTplId.value) return message.warning(translate('ui.m_3703d6ea60bf'))
  reportGenerating.value = true
  const hide = message.loading(translate('ui.m_f249799849b9'), 0)
  try {
    const payload = repType.value === 'session'
      ? { template_id: repTplId.value, type: 'session' as const, session_id: repSourceId.value }
      : repType.value === 'task'
        ? { template_id: repTplId.value, type: 'task' as const, task_id: repSourceId.value }
        : { template_id: repTplId.value, type: 'finding' as const, finding_id: repSourceId.value }
    const res = await reportTemplateApi.generate(payload)
    hide()
    if ((res as { ok?: boolean }).ok) {
      repOpen.value = false
      Modal.success({
        title: res.generation_warnings?.length ? translate('ui.m_09264d910759') : translate('ui.m_515ecc202f78'),
        content: res.generation_warnings?.length ? res.generation_warnings.join('；') : translate('ui.m_0f2b8d08bd2c', { p0: (res.vuln_total ?? 0) }),
        get okText() { return translate('ui.m_33a1e21d248e') }, onOk: () => router.push('/report-edit')
      })
    } else { message.error(translate('ui.m_470f92db3d64')) }
  } catch (e) { hide(); message.error((e as Error).message || translate('ui.m_c069c3f5045d')) }
  finally { reportGenerating.value = false }
}

/* 删除(仅系统扫描来源,复用各自现成接口;AI 漏洞为引擎产出不手删) */
async function removeOne(r: UnifiedFinding) {
  try {
    if (r.source === 'poc') await vulnApi.delete([r._id])
    else if (r.source === 'nuclei') await nucleiResultApi.delete([r._id])
    else return
    message.success(translate('ui.m_077a6d37719a')); loadAll()
  } catch (e) { message.error((e as Error).message || translate('ui.m_c228558cf257')) }
}
const auto = useAutoRefresh(loadAll, 30000)
onMounted(loadAll)
let revisionSeen=-1;let revisionBusy=false
const revisionTimer=window.setInterval(async()=>{
  if(document.hidden || revisionBusy)return
  revisionBusy=true
  try {
    const value=await pentestApi.findingRevision()
    if(revisionSeen>=0 && value.revision!==revisionSeen) {loadStat();if(!selectedKeys.value.length && !detailOpen.value)loadList()}
    revisionSeen=value.revision
  } catch {/* Existing manual refresh remains available. */}
  finally {revisionBusy=false}
},1000)
onUnmounted(()=>window.clearInterval(revisionTimer))
</script>

<style scoped>
.muted { color: #aaa; }
.calibrated { color: #d46b08; border-bottom: 1px dashed #d46b08; cursor: help; }
.ev { white-space: pre-wrap; word-break: break-all; font-family: monospace; font-size: 12px; margin: 0; max-height: 360px; overflow: auto; }
.ev-packet { margin-bottom: 14px; }
.ev-pkt-head { margin-bottom: 4px; }
.ev-label { font-size: 12px; color: #888; margin-bottom: 2px; }
.shot-thumb { position: relative; border: 1px solid #303030; border-radius: 4px; padding: 4px; }
.shot-thumb img { width: 168px; height: 112px; object-fit: cover; border-radius: 2px; display: block; }
.shot-del { position: absolute; top: 2px; right: 2px; background: rgba(0,0,0,.45); border-radius: 3px; padding: 0 6px; }

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
