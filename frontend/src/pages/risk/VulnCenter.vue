<template>
  <PageContainer title="漏洞中心" kicker="Vulnerabilities"
    description="统一查看漏洞与待验证线索。去重模式每个漏洞点展示一条；全部记录保留跨会话复测历史，验证状态独立标注。">
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
      <a-form-item label="搜索"><a-input v-model:value="query.keyword" allow-clear placeholder="漏洞名 / 目标" style="width:150px" /></a-form-item>
      <a-form-item label="漏洞等级">
        <a-select v-model:value="query.min_severity" style="width:130px" :options="minSevOptions" @change="reload" />
      </a-form-item>
      <a-form-item label="显示">
        <a-select v-model:value="query.dedup" style="width:130px" :options="dedupOptions" @change="reload" />
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
          <a-tag :color="srcMeta(record.source).color">{{ srcLabel(record) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'name'">
          <div style="display:flex;align-items:center;gap:6px">
            <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ record.name }}</span>
            <a-tooltip v-if="record.suspect">
              <template #title>该漏洞由「{{ record.mode_label || '快筛' }}模式」产出——此模式为快速筛查（不深入验证/不发或少发注入探针），产出多为待人工验证的疑似点，非已确证漏洞，请人工复核后再定性。</template>
              <a-tag color="orange" style="flex-shrink:0">疑似</a-tag>
            </a-tooltip>
            <!-- 首次/重复发现（方案B）：抵右侧边栏。仅 AI 洞有 first_seen 语义 -->
            <a-tag v-if="record.source === 'ai'" :color="record.first_seen === true ? 'green' : record.first_seen === false ? 'gold' : 'default'"
              style="margin-left:auto;flex-shrink:0">{{ record.first_seen === true ? '首次发现' : record.first_seen === false ? '重复发现' : '首次时间待核定' }}<template v-if="record.occurrence_count > 1"> · {{ record.occurrence_count }} 次</template></a-tag>
          </div>
        </template>
        <template v-else-if="column.key === 'verified'">
          <a-tag v-if="record.source === 'ai'" :color="record.verified ? 'red' : 'orange'">{{ record.verified ? '已验证' : '线索' }}</a-tag>
          <a-tag v-else color="cyan">命中</a-tag>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="sevColor(record.severity)">{{ sevLabel(record.severity) }}</a-tag>
          <a-tooltip v-if="record.cvss_score != null" :title="cvssNote(record)">
            <span class="muted" :class="{ calibrated: isCalibrated(record) }"> {{ record.cvss_score }}{{ isCalibrated(record) ? '*' : '' }}</span>
          </a-tooltip>
        </template>
        <template v-else-if="column.key === 'target'">
          <a-tag v-if="record.asset_type === 'miniapp'" color="green" style="margin-right:4px">小程序</a-tag>
          <CopyText :text="String(record.target || '')" />
        </template>
        <template v-else-if="column.key === 'task_name'">
          <span v-if="record.task_name">{{ record.task_name }}</span>
          <span v-else class="muted">—</span>
        </template>
        <template v-else-if="column.key === 'unit'">
          <span v-if="record.unit">{{ record.unit }}</span>
          <!-- AI 来源:无单位=ICP 查不到备案(瞭望塔扫描来源本就无单位维度,只显 —) -->
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
              <a-button type="link" size="small">操作<DownOutlined /></a-button>
              <template #overlay>
                <a-menu @click="(info: any) => onAction(record, String(info.key))">
                  <a-menu-item-group title="标记状态">
                    <a-menu-item key="mark:submitted">标记</a-menu-item>
                    <a-menu-item key="mark:false_positive">误报</a-menu-item>
                    <a-menu-item key="mark:">重置</a-menu-item>
                  </a-menu-item-group>
                  <a-menu-item-group v-if="record.source === 'ai'" title="降低危害等级(只降不升)">
                    <a-menu-item key="downgrade:medium">降为 中危</a-menu-item>
                    <a-menu-item key="downgrade:low">降为 低危</a-menu-item>
                    <a-menu-item key="downgrade:info">降为 信息</a-menu-item>
                  </a-menu-item-group>
                  <a-menu-divider />
                  <a-menu-item-group title="生成报告">
                    <!-- 单条漏洞直接生成漏洞级报告（只依赖漏洞自身 _id，任意来源都可用） -->
                    <a-menu-item key="report:finding">
                      生成漏洞报告
                    </a-menu-item>
                    <!-- AI 来源才有来源会话，可生成/重生成该资产的会话级报告 -->
                    <a-menu-item key="report:session" :disabled="record.source !== 'ai' || !record.session_id">
                      生成会话报告
                    </a-menu-item>
                    <!-- 任意来源只要归属某任务，即可生成整任务级总结报告 -->
                    <a-menu-item key="report:task" :disabled="!record.task_id">
                      生成任务报告
                    </a-menu-item>
                  </a-menu-item-group>
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
          <a-descriptions-item label="验证状态"><a-tag :color="cur.verified ? 'red' : 'orange'">{{ cur.verified ? '已验证(有证据)' : '线索(未实证)' }}</a-tag> <span class="muted">{{ evidenceLabel(cur) }}</span></a-descriptions-item>
          <a-descriptions-item v-if="cur.pentest_mode" label="产出模式">
            <a-tag color="blue">AI 渗透·{{ modeLabelCn(String(cur.pentest_mode)) }}</a-tag>
            <a-tag v-if="isSuspectMode(String(cur.pentest_mode))" color="orange">疑似</a-tag>
            <span v-if="isSuspectMode(String(cur.pentest_mode))" class="muted">快筛模式产出，未深入验证，请人工复核后定性</span>
          </a-descriptions-item>
          <a-descriptions-item label="CVSS">{{ cur.cvss_vector || '—' }} <b v-if="cur.cvss_score != null">({{ cvssLabel(cur) }})</b></a-descriptions-item>
          <a-descriptions-item label="风险评级">{{ String(cur.severity || 'unknown').toUpperCase() }}<span v-if="!cur.verified" class="muted"> · 待验证，不代表已确认漏洞</span></a-descriptions-item>
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
          <a-descriptions-item label="复现请求 / 命令"><div class="muted">{{ pocLabel(cur) }}</div><pre class="ev">{{ cur.poc || '尚未提供完整请求或命令' }}</pre></a-descriptions-item>
          <a-descriptions-item v-if="cur.poc_notes" label="影响接口与补充说明"><pre class="ev">{{ cur.poc_notes }}</pre></a-descriptions-item>
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
      <!-- 证据截图：按 finding 绑定，生成报告时自动嵌入证据/复现区 -->
      <a-divider style="margin:14px 0 10px" />
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <b>证据截图</b>
          <span class="muted" style="font-size:12px">上传后，用模板生成本漏洞报告时会自动嵌入证据/复现区。</span>
          <a-upload :show-upload-list="false" :before-upload="beforeShotUpload" accept="image/*" style="margin-left:auto">
            <a-button size="small" type="primary" :loading="shotUploading">上传截图</a-button>
          </a-upload>
        </div>
        <a-empty v-if="!shots.length" description="暂无证据截图" />
        <div v-else style="display:flex;flex-wrap:wrap;gap:10px">
          <div v-for="s in shots" :key="s.name" class="shot-thumb">
            <a :href="s.url" target="_blank"><img :src="s.url" /></a>
            <a-popconfirm title="删除这张截图？" ok-text="删除" cancel-text="取消" @confirm="delShot(s.name)">
              <a-button danger size="small" type="link" class="shot-del">删除</a-button>
            </a-popconfirm>
          </div>
        </div>
      </div>
    </a-drawer>

    <!-- 报告生成：选模板（item5，会话/任务/漏洞级各按 scope 过滤） -->
    <a-modal v-model:open="repOpen" :title="`用模板生成${repType === 'task' ? '任务级' : repType === 'finding' ? '漏洞级' : '会话级'}报告`"
      :confirm-loading="reportGenerating" ok-text="生成报告" @ok="submitGenReport">
      <a-form-item label="报告模板">
        <a-select v-model:value="repTplId" :options="repTplOptions" :loading="repTplLoading"
          placeholder="选择就绪模板" style="width:100%" />
        <div style="margin-top:6px;color:#888;font-size:12px">生成后可在「报告编辑」页查看/导出 docx。</div>
      </a-form-item>
      <a-alert v-if="!repTplLoading && !repTplOptions.length" type="warning" show-icon
        message="暂无就绪模板，请先在「报告编辑 · 模板学习」上传或使用内置模板。" />
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { cvssLabel, evidenceLabel, pocLabel } from '../../utils/findingDisplay'
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
  { label: '全部来源', value: '' },
  { label: 'AI 渗透', value: 'ai' },
  { label: '系统 PoC', value: 'poc' },
  { label: 'Nuclei', value: 'nuclei' }
]
// 显示模式:漏洞去重(默认,同资产+同接口+同类型只留最新一条,隐藏重复) / 全部漏洞(含所有重复条目)
const dedupOptions = [
  { label: '漏洞去重', value: '1' },
  { label: '全部漏洞', value: '0' }
]
// 漏洞等级阈值:默认 LOW(隐藏 info);选"全部(含info)"= info 阈值不过滤
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
  { title: '漏洞名', key: 'name', ellipsis: true },
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
function onReset() { query.keyword = ''; query.min_severity = 'low'; query.dedup = '1'; query.unit = ''; query.handle_status = undefined; dateRange.value = undefined; reload() }
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
  curFindingId.value = String(r._id)
  detailOpen.value = true
  detailLoading.value = true
  loadShots(String(r._id))
  try {
    const doc = await pentestApi.unifiedDetail(r.source, r._id)
    Object.assign(cur, doc)
    // task_name 是列表层反查回填的(原始文档无此字段),详情接口拉不到 → 用列表行的值补上
    if (!cur.task_name && r.task_name) cur.task_name = r.task_name
  } catch (e) { message.error((e as Error).message || '详情加载失败') } finally { detailLoading.value = false }
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
    .then(() => { message.success('截图已上传'); return loadShots(fid) })
    .catch((e: Error) => message.error(e.message || '上传失败'))
    .finally(() => { shotUploading.value = false })
  return false   // 阻止 a-upload 默认上传，走自定义
}
async function delShot(name: string) {
  try {
    await findingShotApi.remove(curFindingId.value, name)
    await loadShots(curFindingId.value)
  } catch (e) { message.error((e as Error).message || '删除失败') }
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
    title: `确认将该漏洞降为「${sevCn[target] || target}」？`,
    content: `当前等级 ${sevCn[String(r.severity)] || r.severity}。只能降级不能升级；降级后记审计。`,
    okText: '确认降级', cancelText: '取消',
    onOk: async () => {
      try {
        const res = await pentestApi.unifiedDowngrade(r.source, [r._id], target)
        if (res.updated) message.success(`已降为「${sevCn[target] || target}」`)
        else message.warning('未降级（目标等级不低于当前等级）')
        loadAll()
      } catch (e) { message.error((e as Error).message || '降级失败') }
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
    return message.warning('仅 AI 渗透来源的漏洞可生成会话报告')
  }
  if (type === 'task' && !r.task_id) {
    return message.warning('该记录未归属任务，无法生成任务报告')
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
  } catch (e) { message.error((e as Error).message || '加载模板失败') }
  finally { repTplLoading.value = false }
}

async function submitGenReport() {
  if (!repTplId.value) return message.warning('请选择报告模板')
  reportGenerating.value = true
  const hide = message.loading('正在用模板生成报告…', 0)
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
        title: res.generation_warnings?.length ? '报告已生成，部分材料待补齐' : '报告已生成',
        content: res.generation_warnings?.length ? res.generation_warnings.join('；') : `已用模板生成报告（${res.vuln_total ?? 0} 个漏洞）。可到「报告编辑」查看/导出。`,
        okText: '去报告编辑', onOk: () => router.push('/report-edit')
      })
    } else { message.error('生成失败') }
  } catch (e) { hide(); message.error((e as Error).message || '生成报告失败') }
  finally { reportGenerating.value = false }
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
