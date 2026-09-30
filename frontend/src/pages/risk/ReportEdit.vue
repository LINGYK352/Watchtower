<template>
  <PageContainer title="报告编辑" kicker="Report Editor"
    description="任务级(整任务渗透总结)与会话级(单资产渗透)成品报告的生成、人工修订与导出。此处报告由人工按需生成(任务ID/会话ID)，独立于会话收尾自动产出的情报报告(在情报中心)。">
    <template #extra>
      <a-button @click="reload">刷新</a-button>
    </template>

    <a-card :bordered="false">
      <a-tabs v-model:activeKey="activeTab" @change="onTabChange">
        <!-- 任务级报告 -->
        <a-tab-pane key="task" tab="任务级报告">
          <a-alert type="info" show-icon style="margin-bottom:12px"
            message="任务级报告：聚合整个任务下全部资产的渗透会话报告 + 漏洞统计，整合成一篇总结报告。可按任务重新生成（幂等更新）。" />
          <a-space style="margin-bottom:12px" wrap>
            <a-input v-model:value="genTaskId" placeholder="输入任务 ID 生成/重生成任务报告" style="width:320px" allow-clear />
            <a-button type="primary" :loading="generating" @click="doGenerateTask">生成任务报告</a-button>
            <a-button :disabled="!taskSelected.length" :loading="exporting" @click="batchExport('task')">批量导出{{ taskSelected.length ? `(${taskSelected.length})` : '' }}</a-button>
            <a-popconfirm :title="`确认删除选中的 ${taskSelected.length} 份报告？`" :disabled="!taskSelected.length" @confirm="batchDelete('task')">
              <a-button danger :disabled="!taskSelected.length">批量删除{{ taskSelected.length ? `(${taskSelected.length})` : '' }}</a-button>
            </a-popconfirm>
          </a-space>
          <AppTable :columns="taskColumns" :data="taskReports.items" :loading="loading" selectable
            v-model:selectedRowKeys="taskSelected"
            :page="taskReports.page" :size="taskReports.size" :total="taskReports.total"
            @change="(p:number, s:number) => loadTaskReports(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'max_severity'">
                <a-tag :color="sevColor(String(record.max_severity || ''))">{{ String(record.max_severity || '-').toUpperCase() }}</a-tag>
              </template>
              <template v-else-if="column.key === 'edited'">
                <a-tag v-if="record.edited" color="orange">已修订</a-tag>
                <span v-else class="muted">—</span>
              </template>
              <template v-else-if="column.key === 'action'">
                <a-space>
                  <a-button type="link" size="small" @click="openEditor(record)">编辑</a-button>
                  <a-button type="link" size="small" @click="doExport(record)">导出 docx</a-button>
                  <ConfirmAction danger type="link" size="small" title="确认删除该报告？" @confirm="removeReport(record, loadTaskReports)">删除</ConfirmAction>
                </a-space>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 会话级报告 -->
        <a-tab-pane key="session" tab="会话级报告">
          <a-alert type="info" show-icon style="margin-bottom:12px"
            message="会话级报告：单个资产渗透后的成品总结报告。按会话 ID 生成（需该会话已有漏洞记录 + AI 模型配置）。此处报告独立于会话收尾自动写的情报报告。" />
          <a-space style="margin-bottom:12px" wrap>
            <a-input v-model:value="genSessionId" placeholder="输入会话 ID 重新生成会话报告" style="width:320px" allow-clear />
            <a-button type="primary" :loading="generating" @click="doGenerateSession">重生成会话报告</a-button>
            <a-button :disabled="!sessionSelected.length" :loading="exporting" @click="batchExport('session')">批量导出{{ sessionSelected.length ? `(${sessionSelected.length})` : '' }}</a-button>
            <a-popconfirm :title="`确认删除选中的 ${sessionSelected.length} 份报告？`" :disabled="!sessionSelected.length" @confirm="batchDelete('session')">
              <a-button danger :disabled="!sessionSelected.length">批量删除{{ sessionSelected.length ? `(${sessionSelected.length})` : '' }}</a-button>
            </a-popconfirm>
          </a-space>
          <AppTable :columns="sessionColumns" :data="sessionReports.items" :loading="loading" selectable
            v-model:selectedRowKeys="sessionSelected"
            :page="sessionReports.page" :size="sessionReports.size" :total="sessionReports.total"
            @change="(p:number, s:number) => loadSessionReports(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'max_severity'">
                <a-tag :color="sevColor(String(record.max_severity || ''))">{{ String(record.max_severity || '-').toUpperCase() }}</a-tag>
              </template>
              <template v-else-if="column.key === 'edited'">
                <a-tag v-if="record.edited" color="orange">已修订</a-tag>
                <span v-else class="muted">—</span>
              </template>
              <template v-else-if="column.key === 'action'">
                <a-space>
                  <a-button type="link" size="small" @click="openEditor(record)">编辑</a-button>
                  <a-button type="link" size="small" @click="doExport(record)">导出 docx</a-button>
                  <ConfirmAction danger type="link" size="small" title="确认删除该报告？" @confirm="removeReport(record, loadSessionReports)">删除</ConfirmAction>
                </a-space>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 漏洞报告（单个漏洞级） -->
        <a-tab-pane key="finding" tab="漏洞报告">
          <a-alert type="info" show-icon style="margin-bottom:12px"
            message="漏洞报告：只针对单个漏洞出具的报告（含 POC/证据/加固建议）。可在「漏洞中心」对单条漏洞一键生成，也可在此输入漏洞 ID 生成。" />
          <a-space style="margin-bottom:12px" wrap>
            <a-input v-model:value="genFindingId" placeholder="输入漏洞 ID 生成单漏洞报告" style="width:320px" allow-clear />
            <a-button type="primary" :loading="generating" @click="doGenerateFinding">自动生成 NCC 报告</a-button>
            <a-button :disabled="!findingSelected.length" :loading="exporting" @click="batchExport('finding')">批量导出{{ findingSelected.length ? `(${findingSelected.length})` : '' }}</a-button>
            <a-popconfirm :title="`确认删除选中的 ${findingSelected.length} 份报告？`" :disabled="!findingSelected.length" @confirm="batchDelete('finding')">
              <a-button danger :disabled="!findingSelected.length">批量删除{{ findingSelected.length ? `(${findingSelected.length})` : '' }}</a-button>
            </a-popconfirm>
          </a-space>
          <AppTable :columns="findingColumns" :data="findingReports.items" :loading="loading" selectable
            v-model:selectedRowKeys="findingSelected"
            :page="findingReports.page" :size="findingReports.size" :total="findingReports.total"
            @change="(p:number, s:number) => loadFindingReports(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'max_severity'">
                <a-tag :color="sevColor(String(record.max_severity || ''))">{{ String(record.max_severity || '-').toUpperCase() }}</a-tag>
              </template>
              <template v-else-if="column.key === 'edited'">
                <a-tag v-if="record.edited" color="orange">已修订</a-tag>
                <span v-else class="muted">—</span>
              </template>
              <template v-else-if="column.key === 'action'">
                <a-space>
                  <a-button type="link" size="small" @click="openEditor(record)">编辑</a-button>
                  <a-button type="link" size="small" @click="doExport(record)">导出 docx</a-button>
                  <ConfirmAction danger type="link" size="small" title="确认删除该报告？" @confirm="removeReport(record, loadFindingReports)">删除</ConfirmAction>
                </a-space>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 模板学习 -->
        <a-tab-pane key="template" tab="模板学习">
          <a-alert type="info" show-icon style="margin-bottom:12px"
            message="上传报告模板(.docx)，AI 一次性学习成可复用模板（识别可变字段/漏洞循环表/图表位并注入占位符，保留原样式排版）。之后到「任务级/会话级报告」栏用此模板一键生成，填充走确定性程序、省 token、排版不变形。仅支持 .docx（WPS/Word 请「另存为 .docx」）。" />
          <a-space style="margin-bottom:8px" wrap>
            <a-input v-model:value="tplName" placeholder="模板名称(可选，默认取文件名)" style="width:240px" allow-clear />
            <a-select v-model:value="tplProviderId" :options="providerOptions" allow-clear
              style="width:260px" :placeholder="`学习模型：跟随全局默认${globalDefaultName ? '（' + globalDefaultName + '）' : ''}`" />
            <a-checkbox v-model:checked="tplNeedReview">需人工复核</a-checkbox>
            <a-upload :before-upload="onTplUpload" :show-upload-list="false" accept=".docx">
              <a-button type="primary" :loading="tplUploading">上传模板学习</a-button>
            </a-upload>
            <a-button @click="loadTemplates">刷新</a-button>
          </a-space>
          <a-alert type="warning" show-icon style="margin-bottom:12px"
            message="模板结构学习是一次性的复杂判断，强烈建议选用强模型（如 Claude / GPT 高配）——弱模型可能学错结构（把固定文案当可变、循环表列判错），反复重试反而多花 token。勾选「需人工复核」后可先比对再定稿、随时换更强模型重学。" />
          <AppTable :columns="tplColumns" :data="templates.items" :loading="tplLoading"
            :page="templates.page" :size="templates.size" :total="templates.total"
            @change="(p:number, s:number) => loadTemplates(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <template v-if="record.status === 'learning'">
                  <!-- 异步学习中：进度条 + 阶段文案（每 3s 轮询刷新） -->
                  <a-progress :percent="record.learn_progress || 0" size="small" status="active" style="width:120px;margin-bottom:0" />
                  <div style="color:#888;font-size:12px">{{ record.learn_phase || '学习中' }}</div>
                </template>
                <template v-else>
                  <a-tag v-if="record.builtin" color="gold">内置</a-tag>
                  <a-tag :color="record.status === 'ready' ? 'green' : record.status === 'failed' ? 'red' : record.status === 'review' ? 'orange' : 'blue'">
                    {{ record.status === 'ready' ? '就绪' : record.status === 'failed' ? '失败' : record.status === 'review' ? '待确认' : record.status }}
                  </a-tag>
                  <a-tooltip v-if="record.status === 'failed' && record.learn_error" :title="record.learn_error">
                    <span style="color:#c0392b;cursor:help"> ⓘ</span>
                  </a-tooltip>
                  <span v-if="record.learn_provider_name" style="color:#888;font-size:12px"> · {{ record.learn_provider_name }}</span>
                </template>
              </template>
              <template v-else-if="column.key === 'action'">
                <a-space>
                  <a-button v-if="record.status === 'review' || record.status === 'failed'" type="link" size="small" @click="openReview(record)">
                    {{ record.status === 'failed' ? '重学' : '复核' }}
                  </a-button>
                  <a-button type="link" size="small" :disabled="record.status !== 'ready'" @click="openGenerate(record)">用此模板生成</a-button>
                  <a-button v-if="record.builtin" type="link" size="small" @click="openReview(record)">预览</a-button>
                  <ConfirmAction v-if="!record.builtin" danger type="link" size="small" title="确认删除该模板？" @confirm="removeTemplate(record)">删除</ConfirmAction>
                </a-space>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 报告编辑抽屉：左编辑 Markdown 右实时预览 -->
    <a-drawer :open="editorOpen" @close="requestCloseEditor" :title="editorTitle" width="80%" :body-style="{ paddingTop: '8px' }">
      <template #extra>
        <a-space>
          <a-tag v-if="editorDirty" color="orange">有未保存修改</a-tag>
          <ReportAiAssist v-if="editData && editorReady" :key="editingId" :report-id="editingId" :data="editData" :providers="providerOptions" />
          <a-button size="small" :disabled="!editorReady || saving" @click="doExportCurrent">保存并导出 docx</a-button>
          <a-button size="small" type="primary" :disabled="!editorReady" :loading="saving" @click="saveEdit()">保存修订</a-button>
        </a-space>
      </template>
      <a-form layout="vertical" style="margin-bottom:8px">
        <a-alert v-for="(warning, i) in editWarnings" :key="i" type="warning" show-icon :message="warning" style="margin-bottom:8px" />
        <a-form-item label="报告标题">
          <a-input v-model:value="editTitle" placeholder="报告标题" />
        </a-form-item>
      </a-form>
      <a-spin v-if="editorLoading" />
      <ReportTemplateEditor v-else-if="editData" :data="editData" />
      <a-row v-else :gutter="12" class="editor-row">
        <a-col :span="12">
          <div class="editor-label">Markdown 正文（可编辑）</div>
          <a-textarea v-model:value="editContent" class="md-editor" :auto-size="{ minRows: 24, maxRows: 40 }" spellcheck="false" />
        </a-col>
        <a-col :span="12">
          <div class="editor-label">预览</div>
          <div class="md-preview" v-html="previewHtml"></div>
        </a-col>
      </a-row>
    </a-drawer>

    <!-- 用模板生成报告：选数据源 -->
    <a-modal v-model:open="genOpen" :title="`用模板生成报告 · ${genTpl?.name || ''}`"
      :confirm-loading="genLoading" @ok="doGenerateFromTemplate" ok-text="生成">
      <a-form layout="vertical">
        <a-form-item label="数据源">
          <a-radio-group v-model:value="genType">
            <a-radio value="task">任务级（聚合整个任务的漏洞）</a-radio>
            <a-radio value="session">会话级（单个会话的漏洞）</a-radio>
            <a-radio value="finding">漏洞级（单个漏洞）</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item :label="genType === 'task' ? '任务 ID' : genType === 'finding' ? '漏洞 ID' : '会话 ID'">
          <a-input v-model:value="genSourceId" :placeholder="genType === 'task' ? '输入任务 ID' : genType === 'finding' ? '输入漏洞 ID' : '输入会话 ID'" allow-clear />
        </a-form-item>
        <a-alert type="info" show-icon
          message="生成后报告出现在上方「任务级/会话级/漏洞报告」栏，可编辑正文标题并导出 docx。" />
      </a-form>
    </a-modal>

    <!-- 模板复核：在线左右对比（左原报告/右打标记模板）+ 结构判定表 + 换模型重学 + 确认定稿 -->
    <a-drawer v-model:open="reviewOpen" :title="`模板复核 · ${reviewTpl?.name || ''}`" width="90%"
      :body-style="{ paddingBottom: '80px' }">
      <a-alert type="info" show-icon style="margin-bottom:12px"
        message="左=原报告（真实排版渲染），右=学习后打标记、去掉原数据的「给 AI 用的模板」（可变位显 {{占位符}}、漏洞表显 {%tr%} 循环标记）。对照看 AI 学得对不对；判错就换更强模型 + 填纠正意见重学，满意后点「确认定稿」。" />
      <a-spin :spinning="reviewLoading">
        <a-row :gutter="12" style="margin-bottom:12px">
          <a-col :span="12">
            <div class="cmp-head">原报告</div>
            <div class="cmp-doc" v-html="originHtml"></div>
          </a-col>
          <a-col :span="12">
            <div class="cmp-head">给 AI 用的模板（打标记）</div>
            <div class="cmp-doc cmp-tpl" v-html="templateHtml"></div>
          </a-col>
        </a-row>
      </a-spin>
      <a-collapse style="margin-bottom:12px">
        <a-collapse-panel key="diff" header="结构判定明细（每段 AI 判成了什么）">
          <div v-if="reviewDiff?.summary" style="color:#666;margin-bottom:8px">
            共 {{ reviewDiff.summary.total }} 段 · 可变 {{ reviewDiff.summary.scalar }} · 循环 {{ reviewDiff.summary.loop }}
            · 图表 {{ reviewDiff.summary.image }} · 固定 {{ reviewDiff.summary.fixed }}
            <span v-if="reviewDiff.summary.unrecognized" style="color:#c0392b"> · 未识别 {{ reviewDiff.summary.unrecognized }}</span>
          </div>
          <a-table :columns="diffColumns" :data-source="reviewDiff?.rows || []" :pagination="false"
            size="small" row-key="idx" :scroll="{ y: 260 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'verdict'">
                <a-tag :color="record.verdict === '可变字段' ? 'blue' : record.verdict === '循环表格' ? 'purple'
                  : record.verdict === '图表位' ? 'cyan' : record.verdict === '未识别' ? 'red' : 'default'">
                  {{ record.verdict }}
                </a-tag>
                <span v-if="record.semantic" style="color:#888;font-size:12px"> {{ record.semantic }}</span>
              </template>
            </template>
          </a-table>
        </a-collapse-panel>
      </a-collapse>
      <a-alert v-if="reviewTpl?.builtin" type="info" show-icon style="margin:8px 0"
        message="内置默认模板（只读预览）"
        description="内置模板随系统分发，不可删除/重学。可在「用此模板生成」直接使用；如需定制，请上传自己的报告样本学习一份新模板。" />
      <template v-if="!reviewTpl?.builtin">
      <a-divider style="margin:8px 0">不满意？换模型 + 纠正意见重学</a-divider>
      <a-form layout="vertical">
        <a-form-item label="重学模型">
          <a-select v-model:value="refineProviderId" :options="providerOptions" allow-clear
            style="width:320px" :placeholder="`跟随全局默认${globalDefaultName ? '（' + globalDefaultName + '）' : ''}`" />
        </a-form-item>
        <a-form-item label="纠正意见（可选，告诉 AI 上一版哪里判错、这次怎么改）">
          <a-textarea v-model:value="refineFeedback" :rows="3" allow-clear
            placeholder="例：第2段「测试时间」是固定标题不要当可变；漏洞表第3列是危害等级不是证据。" />
        </a-form-item>
      </a-form>
      <div style="position:absolute;bottom:0;left:0;right:0;padding:12px 24px;border-top:1px solid #f0f0f0;background:#fff;text-align:right">
        <a-space>
          <a-button :loading="refineLoading" @click="doRefine">换模型重学</a-button>
          <a-button type="primary" :loading="confirmLoading" @click="doConfirm">确认定稿</a-button>
        </a-space>
      </div>
      </template>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, computed, type Ref } from 'vue'
import { message, Modal } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import AppTable from '../../components/AppTable.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { intelApi, reportTemplateApi, type ReportDetail, type ReportTemplate, type ReportData } from '../../api/intel'
import ReportTemplateEditor from './ReportTemplateEditor.vue'
import ReportAiAssist from './ReportAiAssist.vue'
import { useUnsavedGuard } from '../../composables/useUnsavedGuard'
import { aiConfigApi } from '../../api/aiConfig'
import type { ListResult, RowRecord } from '../../api/types'

const loading = ref(false)
const generating = ref(false)
const saving = ref(false)
const exporting = ref(false)
const activeTab = ref<'task' | 'session' | 'finding' | 'template'>('task')
// 多选（批量删除/批量导出）：任务级、会话级、漏洞级各一份选中键
const taskSelected = ref<string[]>([])
const sessionSelected = ref<string[]>([])
const findingSelected = ref<string[]>([])

const sevColorMap: Record<string, string> = { critical: 'red', high: 'volcano', medium: 'orange', low: 'gold', info: 'blue', unknown: 'default', none: 'default', '': 'default' }
const sevColor = (s: string) => sevColorMap[(s || '').toLowerCase()] || 'default'

const empty: ListResult<RowRecord> = { page: 1, size: 10, total: 0, items: [] }
const taskReports = ref<ListResult<RowRecord>>({ ...empty })
const sessionReports = ref<ListResult<RowRecord>>({ ...empty })
const findingReports = ref<ListResult<RowRecord>>({ ...empty })

const taskColumns = [
  { title: '报告标题', dataIndex: 'title', ellipsis: true },
  { title: '任务ID', dataIndex: 'source_task_id', width: 200, ellipsis: true },
  { title: '会话数', dataIndex: 'session_count', width: 80 },
  { title: '漏洞数', dataIndex: 'vuln_total', width: 80 },
  { title: '最高危', key: 'max_severity', width: 90 },
  { title: '修订', key: 'edited', width: 70 },
  { title: '时间', dataIndex: 'update_date', width: 170 },
  { title: '操作', key: 'action', width: 200 }
]
const sessionColumns = [
  { title: '报告标题', dataIndex: 'title', ellipsis: true },
  { title: '资产', dataIndex: 'asset_key', ellipsis: true },
  { title: '单位', dataIndex: 'unit', ellipsis: true },
  { title: '最高危', key: 'max_severity', width: 90 },
  { title: '修订', key: 'edited', width: 70 },
  { title: '时间', dataIndex: 'save_date', width: 170 },
  { title: '操作', key: 'action', width: 200 }
]
const findingColumns = [
  { title: '报告标题', dataIndex: 'title', ellipsis: true },
  { title: '目标', dataIndex: 'system_name', ellipsis: true },
  { title: '单位', dataIndex: 'unit', ellipsis: true },
  { title: '危害等级', key: 'max_severity', width: 90 },
  { title: '修订', key: 'edited', width: 70 },
  { title: '时间', dataIndex: 'save_date', width: 170 },
  { title: '操作', key: 'action', width: 200 }
]

// report 列表接口按 report_type 过滤（task/session）
async function loadTaskReports(page = 1, size = taskReports.value.size) {
  loading.value = true
  taskSelected.value = []   // 重新加载页清空选中，避免跨页残留
  try { taskReports.value = await intelApi.pentestReports({ page, size, report_type: 'task' }) }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function loadSessionReports(page = 1, size = sessionReports.value.size) {
  loading.value = true
  sessionSelected.value = []   // 重新加载页清空选中，避免跨页残留
  try { sessionReports.value = await intelApi.pentestReports({ page, size, report_type: 'session' }) }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function loadFindingReports(page = 1, size = findingReports.value.size) {
  loading.value = true
  findingSelected.value = []   // 重新加载页清空选中，避免跨页残留
  try { findingReports.value = await intelApi.pentestReports({ page, size, report_type: 'finding' }) }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
function reload() {
  if (activeTab.value === 'task') loadTaskReports(1)
  else if (activeTab.value === 'finding') loadFindingReports(1)
  else loadSessionReports(1)
}
function onTabChange(key: string) {
  if (key === 'template') { loadTemplates(1); loadProviders() }
  else if (key === 'task') loadTaskReports(1)
  else if (key === 'finding') loadFindingReports(1)
  else loadSessionReports(1)
}

// 生成任务级报告
const genTaskId = ref('')
async function doGenerateTask() {
  const tid = genTaskId.value.trim()
  if (!tid) return message.warning('请输入任务 ID')
  generating.value = true
  const hide = message.loading('正在生成任务报告(整合中，可能较久)…', 0)
  try {
    const res = await intelApi.generatePentestReport({ type: 'task', task_id: tid })
    hide()
    message.success(`任务报告已${res.updated ? '更新' : '生成'}：聚合 ${res.session_count ?? 0} 会话 / ${res.vuln_total ?? 0} 漏洞`)
    genTaskId.value = ''
    loadTaskReports(1)
  } catch (e) { hide(); message.error((e as Error).message || '生成失败') }
  finally { generating.value = false }
}

// 重生成会话级报告
const genSessionId = ref('')
async function doGenerateSession() {
  const sid = genSessionId.value.trim()
  if (!sid) return message.warning('请输入会话 ID')
  generating.value = true
  const hide = message.loading('正在重生成会话报告…', 0)
  try {
    await intelApi.generatePentestReport({ type: 'session', session_id: sid })
    hide()
    message.success('会话报告已重新生成')
    genSessionId.value = ''
    loadSessionReports(1)
  } catch (e) { hide(); message.error((e as Error).message || '生成失败') }
  finally { generating.value = false }
}

// 生成单漏洞报告（走漏洞级内置模板；漏洞中心一键生成也复用此 API）
const FINDING_TEMPLATE_ID = 'ncc_event_finding_v1'
const genFindingId = ref('')
async function doGenerateFinding() {
  const fid = genFindingId.value.trim()
  if (!fid) return message.warning('请输入漏洞 ID')
  generating.value = true
  const hide = message.loading('正在整理证据、生成交互图并撰写 NCC 报告…', 0)
  try {
    const r = await reportTemplateApi.generate({ template_id: FINDING_TEMPLATE_ID, type: 'finding', finding_id: fid })
    hide()
    if (r.delivery_ready) {
      message.success('NCC 报告已生成，正在下载')
      await intelApi.exportPentestDocx(r.report_id)
    } else {
      message.warning(`报告草稿已生成，${r.generation_warnings?.length || 0} 项材料待补齐，请打开报告查看`)
    }
    genFindingId.value = ''
    loadFindingReports(1)
  } catch (e) { hide(); message.error((e as Error).message || '生成失败') }
  finally { generating.value = false }
}

// 删除报告（单条）
async function removeReport(record: RowRecord, reload: (p?: number) => void) {
  try { await intelApi.remove('pentest_report', [String(record._id)]); message.success('已删除'); reload(1) }
  catch (e) { message.error((e as Error).message) }
}

// 按 tab 取对应的选中 ref + 重载函数（模板里 ref 自动解包成数组，故统一用 kind 在脚本内解析 ref）
function _selRef(kind: 'task' | 'session' | 'finding'): Ref<string[]> {
  return kind === 'task' ? taskSelected : kind === 'finding' ? findingSelected : sessionSelected
}
function _reloadOf(kind: 'task' | 'session' | 'finding') {
  return kind === 'task' ? loadTaskReports : kind === 'finding' ? loadFindingReports : loadSessionReports
}

// 批量删除：一次性把选中 id 交后端 delete_records（非空数组，禁空条件删）
async function batchDelete(kind: 'task' | 'session' | 'finding') {
  const selected = _selRef(kind)
  const ids = selected.value.slice()
  if (!ids.length) return
  try {
    await intelApi.remove('pentest_report', ids)
    message.success(`已删除 ${ids.length} 份`)
    selected.value = []
    _reloadOf(kind)(1)
  } catch (e) { message.error((e as Error).message || '批量删除失败') }
}

// 批量导出：逐份串行触发 docx 下载（复用单份导出通道；串行避免浏览器多下载拦截）。
// docx 二进制流无法在一次响应里打包（后端未提供 zip 端点），此处按份下载，逐份反馈。
async function batchExport(kind: 'task' | 'session' | 'finding') {
  const ids = _selRef(kind).value.slice()
  if (!ids.length) return
  exporting.value = true
  const hide = message.loading(`正在导出 ${ids.length} 份报告…`, 0)
  let done = 0
  const failed: string[] = []
  try {
    for (const id of ids) {
      try { await intelApi.exportPentestDocx(id); done++ }
      catch { failed.push(id) }
      await new Promise(r => setTimeout(r, 400))   // 间隔 400ms，避免浏览器把连续下载当弹窗拦掉
    }
  } finally {
    hide()
    exporting.value = false
  }
  if (failed.length) message.warning(`导出完成 ${done} 份，失败 ${failed.length} 份`)
  else message.success(`已导出 ${done} 份报告`)
}

// 编辑抽屉
const editorOpen = ref(false)
const editingId = ref('')
const editTitle = ref('')
const editContent = ref('')
const editData = ref<ReportData | null>(null)
const editWarnings = ref<string[]>([])
const editorLoading = ref(false)
const editorReady = ref(false)
const { dirty: editorDirty, markSaved: markEditorSaved } = useUnsavedGuard(() => editorOpen.value
  ? JSON.stringify([editTitle.value, editContent.value, editData.value]) : '')
const editorTitle = computed(() => `编辑报告 · ${editTitle.value || editingId.value}`)

function requestCloseEditor() {
  const close = () => { editorOpen.value = false; markEditorSaved() }
  if (!editorDirty.value) return close()
  Modal.confirm({ title: '报告有未保存的修改', content: '关闭将丢失本次文字和截图编排修改。',
    okText: '放弃修改', cancelText: '继续编辑', onOk: close })
}

async function openEditor(record: RowRecord) {
  editingId.value = String(record._id)
  const id = editingId.value
  editData.value = null
  editWarnings.value = []
  editorLoading.value = true
  editorReady.value = false
  editorOpen.value = true
  editTitle.value = String(record.title || '')
  editContent.value = typeof record.content === 'string' ? record.content : ''
  markEditorSaved()
  // 列表接口可能不带完整 content，拉详情兜底
  {
    try {
      const d: ReportDetail = await intelApi.pentestReportDetail(editingId.value)
      if (editingId.value !== id) return
      editTitle.value = String(d.title || editTitle.value)
      editContent.value = String(d.content || '')
      editData.value = d.gen_mode === 'template' ? d.report_data || null : null
      editWarnings.value = d.generation_warnings || []
      editorReady.value = d.gen_mode !== 'template' || !!editData.value
      markEditorSaved()
    } catch (e) { message.error((e as Error).message) }
    finally { if (editingId.value === id) editorLoading.value = false }
  }
}

async function saveEdit(close = true) {
  if (!editingId.value || !editorReady.value || saving.value) return false
  saving.value = true
  try {
    if (editData.value) editData.value.report.title = editTitle.value
    await intelApi.updatePentestReport(editingId.value, editData.value
      ? { report_data: editData.value, title: editTitle.value }
      : { content: editContent.value, title: editTitle.value })
    message.success('已保存修订')
    if (close) editorOpen.value = false
    markEditorSaved()
    reload()
    return true
  } catch (e) { message.error((e as Error).message || '保存失败'); return false }
  finally { saving.value = false }
}

// 导出 docx
async function doExport(record: RowRecord) {
  try { await intelApi.exportPentestDocx(String(record._id)) }
  catch (e) { message.error((e as Error).message || '导出失败') }
}
async function doExportCurrent() {
  if (!editingId.value) return
  if (!await saveEdit(false)) return
  try { await intelApi.exportPentestDocx(editingId.value) }
  catch (e) { message.error((e as Error).message || '导出失败') }
}

// ============ 模板学习 ============
const tplLoading = ref(false)
const tplUploading = ref(false)
const tplName = ref('')
const tplProviderId = ref('')        // 学习模型（空=跟随全局默认）
const tplNeedReview = ref(true)      // 需人工复核（默认勾选→学成落 review 待确认；取消勾选才直接 ready）
const templates = ref<ListResult<RowRecord>>({ ...empty })
const tplColumns = [
  { title: '模板名称', dataIndex: 'name', ellipsis: true },
  { title: '源文件', dataIndex: 'source_filename', ellipsis: true },
  { title: '状态', key: 'status', width: 150 },
  { title: '学习Token', dataIndex: 'learn_tokens', width: 100 },
  { title: '时间', dataIndex: 'update_date', width: 170 },
  { title: '操作', key: 'action', width: 220 }
]

// ---- 学习模型下拉（范式抄 TaskCreate.vue：providerOptions() + 空=跟随全局默认）----
const providers = ref<{ _id: string; name: string; protocol?: string; enabled?: boolean }[]>([])
const globalDefaultId = ref('')
const providerOptions = computed(() => providers.value.filter(p => p.enabled).map(p => ({
  label: `${p.name}（${p.protocol === 'claude' ? 'Claude' : 'OpenAI'}协议）`, value: p._id })))
const globalDefaultName = computed(() => {
  const p = providers.value.find(x => x._id === globalDefaultId.value)
  return p ? p.name : ''
})
async function loadProviders() {
  try { providers.value = (await aiConfigApi.providerOptions()).items || [] } catch { /* 取不到留空=跟随全局默认 */ }
  try { globalDefaultId.value = (await aiConfigApi.runtimeConfig()).active_provider_id || '' } catch { /* ignore */ }
}

// ---- 复核抽屉状态 ----
const reviewOpen = ref(false)
const reviewLoading = ref(false)
const reviewTpl = ref<RowRecord | null>(null)
const reviewDiff = ref<{ rows: RowRecord[]; summary: Record<string, number> } | null>(null)
const originHtml = ref('')       // 左：mammoth 渲染的原报告 HTML
const templateHtml = ref('')     // 右：mammoth 渲染的打标记模板 HTML
const refineProviderId = ref('')
const refineFeedback = ref('')
const refineLoading = ref(false)
const confirmLoading = ref(false)
const diffColumns = [
  { title: '原文 / 元素', dataIndex: 'text', ellipsis: true },
  { title: 'AI 判定', key: 'verdict', width: 220 }
]

async function loadTemplates(page = 1, size = templates.value.size) {
  tplLoading.value = true
  try {
    templates.value = await reportTemplateApi.list({ page, size })
    // 进入/刷新时若已有 learning 条目（如切走又切回），自动续上轮询
    if ((templates.value.items || []).some((t: RowRecord) => t.status === 'learning')) startTplPolling()
  }
  catch (e) { message.error((e as Error).message) } finally { tplLoading.value = false }
}

// before-upload 返回 false 阻止 antd 自动上传，改走我们的原生 fetch。
// **异步**：上传后端秒回 status=learning，后台学习；此处立即刷新列表（显示学习中+进度）+ 启动轮询，不阻塞。
function onTplUpload(file: File) {
  if (!file.name.toLowerCase().endsWith('.docx')) {
    message.warning('仅支持 .docx，请在 WPS/Word 中「另存为 .docx」后上传')
    return false
  }
  tplUploading.value = true
  reportTemplateApi.upload(file, tplName.value.trim() || undefined,
    { provider_id: tplProviderId.value || '', need_review: tplNeedReview.value })
    .then(() => {
      message.success('已提交，后台学习中——可去用其他功能，列表会自动刷新进度')
      tplName.value = ''
      loadTemplates(1)          // 立即显示新条目（学习中+进度）
      startTplPolling()         // 启动轮询直到全部学完
    })
    .catch((e) => { message.error((e as Error).message || '提交失败') })
    .finally(() => { tplUploading.value = false })
  return false
}

// 学习进度轮询：有任何 learning 模板时每 3s 刷新列表；全部离开 learning 态即停（省请求）。
let _tplPollTimer: number | undefined
function startTplPolling() {
  if (_tplPollTimer) return
  _tplPollTimer = window.setInterval(async () => {
    await loadTemplates(templates.value.page, templates.value.size)
    const anyLearning = (templates.value.items || []).some((t: RowRecord) => t.status === 'learning')
    if (!anyLearning) { clearInterval(_tplPollTimer); _tplPollTimer = undefined }
  }, 3000)
}

// ---- 复核抽屉：打开（拉 diff + mammoth 渲染左右 docx）/ 重学 / 定稿 ----
// 用 mammoth 把 origin.docx（左，真实报告）+ template.docx（右，打标记模板）转 HTML 在线并排。
async function renderCompare(id: string) {
  originHtml.value = '<div style="color:#999">加载中…</div>'
  templateHtml.value = '<div style="color:#999">加载中…</div>'
  const mammoth = (await import('mammoth')).default
  // 左：原报告（真实排版）
  try {
    const ab = await reportTemplateApi.docxArrayBuffer(id, 'origin')
    originHtml.value = (await mammoth.convertToHtml({ arrayBuffer: ab })).value || '<div style="color:#999">（空）</div>'
  } catch (e) { originHtml.value = `<div style="color:#c0392b">原报告加载失败：${(e as Error).message}</div>` }
  // 右：打标记模板（mammoth 会把 {{占位符}}/{%tr%} 当普通文字渲染出来，正是"去数据打标记"效果）
  try {
    const ab = await reportTemplateApi.docxArrayBuffer(id, 'template')
    templateHtml.value = (await mammoth.convertToHtml({ arrayBuffer: ab })).value || '<div style="color:#999">（模板未生成，可能学习失败，请换模型重学）</div>'
  } catch (e) { templateHtml.value = `<div style="color:#c0392b">模板加载失败（可能学习未完成/失败）：${(e as Error).message}</div>` }
}

async function openReview(record: RowRecord) {
  reviewTpl.value = record
  reviewDiff.value = null
  originHtml.value = ''
  templateHtml.value = ''
  refineProviderId.value = ''
  refineFeedback.value = ''
  reviewOpen.value = true
  reviewLoading.value = true
  // failed 态可能无有效 schema/模板，diff/渲染取不到不弹错——抽屉照常打开，用户可直接换模型重学
  try { reviewDiff.value = await reportTemplateApi.diff(String(record._id)) as { rows: RowRecord[]; summary: Record<string, number> } }
  catch (e) { if (record.status !== 'failed') message.error((e as Error).message || '加载对比失败') }
  await renderCompare(String(record._id))
  reviewLoading.value = false
}

async function doRefine() {
  if (!reviewTpl.value) return
  refineLoading.value = true
  const hide = message.loading('AI 正在重新学习模板…', 0)
  try {
    await reportTemplateApi.refine(String(reviewTpl.value._id),
      { provider_id: refineProviderId.value || '', feedback: refineFeedback.value.trim() || '' })
    hide(); message.success('已重学，请再次核对')
    reviewDiff.value = await reportTemplateApi.diff(String(reviewTpl.value._id)) as { rows: RowRecord[]; summary: Record<string, number> }
    await renderCompare(String(reviewTpl.value._id))
    loadTemplates(templates.value.page)
  } catch (e) { hide(); message.error((e as Error).message || '重学失败') }
  finally { refineLoading.value = false }
}

async function doConfirm() {
  if (!reviewTpl.value) return
  confirmLoading.value = true
  try {
    await reportTemplateApi.confirm(String(reviewTpl.value._id))
    message.success('已定稿，可用于生成报告')
    reviewOpen.value = false
    loadTemplates(templates.value.page)
  } catch (e) { message.error((e as Error).message || '定稿失败') }
  finally { confirmLoading.value = false }
}

async function removeTemplate(record: RowRecord) {
  try { await reportTemplateApi.remove(String(record._id)); message.success('已删除'); loadTemplates(1) }
  catch (e) { message.error((e as Error).message) }
}

// 用模板生成
const genOpen = ref(false)
const genLoading = ref(false)
const genTpl = ref<ReportTemplate | null>(null)
const genType = ref<'task' | 'session' | 'finding'>('task')
const genSourceId = ref('')
function openGenerate(record: RowRecord) {
  genTpl.value = record as unknown as ReportTemplate
  genType.value = 'task'
  genSourceId.value = ''
  genOpen.value = true
}
async function doGenerateFromTemplate() {
  const sid = genSourceId.value.trim()
  if (!genTpl.value || !sid) return message.warning('请输入数据源 ID')
  genLoading.value = true
  const hide = message.loading('正在生成报告…', 0)
  try {
    const tplId = String(genTpl.value._id)
    const payload = genType.value === 'task'
      ? { template_id: tplId, type: 'task' as const, task_id: sid }
      : genType.value === 'finding'
        ? { template_id: tplId, type: 'finding' as const, finding_id: sid }
        : { template_id: tplId, type: 'session' as const, session_id: sid }
    const r = await reportTemplateApi.generate(payload)
    hide()
    const label = genType.value === 'task' ? '任务级' : genType.value === 'finding' ? '漏洞' : '会话级'
    if (r.generation_warnings?.length) message.warning(`报告已生成，仍有 ${r.generation_warnings.length} 项材料需补齐，请在报告编辑中查看`)
    else message.success(`报告已生成（${r.vuln_total ?? 0} 个漏洞），请到「${label}报告」栏查看/导出`)
    genOpen.value = false
    if (genType.value === 'task') { loadTaskReports(1); activeTab.value = 'task' }
    else if (genType.value === 'finding') { loadFindingReports(1); activeTab.value = 'finding' }
    else { loadSessionReports(1); activeTab.value = 'session' }
  } catch (e) { hide(); message.error((e as Error).message || '生成失败') }
  finally { genLoading.value = false }
}

// 轻量 Markdown→HTML 预览（不引第三方依赖）：转义 HTML 后处理 标题/粗体/行内代码/代码块/列表/表格/段落
function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function renderMarkdown(md: string): string {
  if (!md) return '<p class="muted">（正文为空）</p>'
  const lines = escapeHtml(md).split(/\r?\n/)
  const out: string[] = []
  let inCode = false, inList = false
  const tableBuf: string[] = []
  const flushTable = () => {
    if (!tableBuf.length) return
    const rows = tableBuf.filter(r => !/^\s*\|?[\s:|-]+\|?\s*$/.test(r))  // 去分隔行
    const cells = rows.map(r => r.replace(/^\||\|$/g, '').split('|').map(c => c.trim()))
    let html = '<table class="md-tb">'
    cells.forEach((row, i) => {
      const tag = i === 0 ? 'th' : 'td'
      html += '<tr>' + row.map(c => `<${tag}>${inline(c)}</${tag}>`).join('') + '</tr>'
    })
    html += '</table>'
    out.push(html)
    tableBuf.length = 0
  }
  const inline = (t: string) => t
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
  for (const raw of lines) {
    const line = raw
    if (/^```/.test(line)) {
      flushTable()
      if (inList) { out.push('</ul>'); inList = false }
      if (inCode) { out.push('</pre>'); inCode = false } else { out.push('<pre class="md-code">'); inCode = true }
      continue
    }
    if (inCode) { out.push(line); continue }
    if (/^\s*\|.*\|\s*$/.test(line)) { if (inList) { out.push('</ul>'); inList = false } tableBuf.push(line); continue }
    flushTable()
    const h = line.match(/^(#{1,4})\s+(.*)$/)
    if (h) { if (inList) { out.push('</ul>'); inList = false } const lv = h[1].length; out.push(`<h${lv}>${inline(h[2])}</h${lv}>`); continue }
    const li = line.match(/^\s*[-*]\s+(.*)$/)
    if (li) { if (!inList) { out.push('<ul>'); inList = true } out.push(`<li>${inline(li[1])}</li>`); continue }
    if (inList) { out.push('</ul>'); inList = false }
    if (line.trim() === '') { out.push('') } else { out.push(`<p>${inline(line)}</p>`) }
  }
  flushTable()
  if (inList) out.push('</ul>')
  if (inCode) out.push('</pre>')
  return out.join('\n')
}
const previewHtml = computed(() => renderMarkdown(editContent.value))

onMounted(() => loadTaskReports(1))
onUnmounted(() => { if (_tplPollTimer) { clearInterval(_tplPollTimer); _tplPollTimer = undefined } })
</script>

<style scoped>
.muted { color: #999; }
.editor-row { min-height: 60vh; }
.editor-label { font-weight: 600; margin-bottom: 6px; color: #555; }
.md-editor { font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; line-height: 1.6; }
.md-preview { border: 1px solid var(--dt-border, #eee); border-radius: 6px; padding: 14px 18px; height: 100%; max-height: 68vh; overflow: auto; font-size: 14px; line-height: 1.7; }
.md-preview :deep(h1) { font-size: 20px; margin: 12px 0 8px; }
.md-preview :deep(h2) { font-size: 17px; margin: 12px 0 8px; }
.md-preview :deep(h3) { font-size: 15px; margin: 10px 0 6px; }
.md-preview :deep(pre.md-code) { background: rgba(127,127,127,.1); padding: 10px; border-radius: 5px; white-space: pre-wrap; word-break: break-all; font-family: 'Consolas', monospace; font-size: 13px; }
.md-preview :deep(code) { background: rgba(127,127,127,.12); padding: 1px 5px; border-radius: 3px; font-family: 'Consolas', monospace; }
.md-preview :deep(table.md-tb) { border-collapse: collapse; margin: 8px 0; width: 100%; }
.md-preview :deep(table.md-tb th), .md-preview :deep(table.md-tb td) { border: 1px solid var(--dt-border, #ddd); padding: 5px 10px; text-align: left; }
.md-preview :deep(table.md-tb th) { background: rgba(127,127,127,.08); font-weight: 600; }
/* 模板复核左右对比：docx 经 mammoth 转 HTML 的展示区 */
.cmp-head { font-weight: 600; margin-bottom: 6px; padding: 4px 8px; background: rgba(127,127,127,.08); border-radius: 5px; font-size: 13px; }
/* 报告/模板预览：docx 内容本是给白纸打印的，预览区**固定白底深色字**，不跟随暗色主题——
   否则暗色下白底继承主题浅色文字 → 灰蒙蒙看不清（用户报的问题）。:deep 锁死内容文字/表格色。 */
.cmp-doc { border: 1px solid var(--dt-border, #eee); border-radius: 6px; padding: 12px 16px; height: 52vh; overflow: auto; font-size: 13px; line-height: 1.7; background: #fff; color: #1f2328; }
.cmp-doc :deep(*) { color: #1f2328; border-color: #ddd; }
.cmp-doc :deep(table) { border-collapse: collapse; margin: 8px 0; width: 100%; }
.cmp-doc :deep(td), .cmp-doc :deep(th) { border: 1px solid #ddd; padding: 4px 8px; }
.cmp-doc :deep(th) { background: #f6f8fa; }
.cmp-doc :deep(p) { margin: 4px 0; }
.cmp-doc :deep(a) { color: #0969da; }
/* 右侧模板里的 {{占位符}}/{%tr%} 标记高亮，一眼看出"去了原数据、打了标记"的位 */
.cmp-tpl :deep(p), .cmp-tpl :deep(td) { }
</style>

