<template>
  <PageContainer :title="translate('ui.m_c5ced4b36c07')" kicker="Task" :description="translate('ui.m_3a5298a16fea')">
    <template #extra>
      <a-space>
        <a-button type="primary" @click="router.push('/tasks/create')">{{ translate('ui.m_6bee2372805a') }}</a-button>
        <a-button @click="openOrphan" :loading="orphanScanning">{{ translate('ui.m_4f0fb5d29a3d') }}</a-button>
      </a-space>
    </template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_2c43cd7db149')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_2c43cd7db149')" /></a-form-item>
      <a-form-item :label="translate('ui.m_57060c88a36b')"><a-input v-model:value="query.target" allow-clear :placeholder="translate('ui.m_e444b4d38109')" /></a-form-item>
      <a-form-item :label="translate('ui.m_6320b4a8722a')"><a-select v-model:value="query.status" allow-clear style="width: 120px" :options="statusOptions" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px" v-if="selectedRowKeys.length">
        <ConfirmAction type="primary" :title="translate('ui.m_9d21b458cf7f')" @confirm="batchStop">{{ translate('ui.m_8a0536d64f2d') }}{{ selectedRowKeys.length }})</ConfirmAction>
        <a-button danger @click="openDelete(selectedRowKeys.slice())">{{ translate('ui.m_a3436403034f') }}{{ selectedRowKeys.length }})</a-button>
      </a-space>
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination"
        :scroll="{ x: 'max-content' }" size="middle" bordered
        :row-selection="{ selectedRowKeys, onChange: onSelectChange }" @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === '_id'"><CopyText :text="shortId(record._id)" /></template>
          <template v-else-if="column.key === 'status'">
            <!-- 顽疾根治:扫描 task 已 done/stop/error 但派发的 AI 会话还 active(含各 paused_ 暂停态)时,
                 状态列主标直接显示"渗透中"而非"已完成"——只要还有 AI 会话没结束,任务就不显示已完成。
                 active=0(全终态)才走原 StatusTag。 -->
            <a-tooltip v-if="isPentestOngoing(record)" :title="translate('ui.m_b5cde5261da4', { p0: (aiProg[String(record._id)].active), p1: (aiProg[String(record._id)].done), p2: (aiProg[String(record._id)].total) })">
              <a-tag color="processing"><span class="ai-dot" />{{ translate('ui.m_864e6cee3301') }}</a-tag>
            </a-tooltip>
            <StatusTag v-else :value="record.status" />
            <a-tooltip v-if="isEmptyDone(record)" :title="translate('ui.m_38650a071d49')">
              <a-tag color="warning" style="margin-top:4px">{{ translate('ui.m_c6c454360616') }}</a-tag>
            </a-tooltip>
            <!-- 问题11：扫描/截图/poc 工具因内存不足在资源池等待（优先让位 AI 渗透）。任务主状态仍 running，
                 这是任务内部某工具在排队等内存，资源释放后自动继续。 -->
            <a-tooltip v-if="resWait(record)" :title="translate('ui.m_0a99d76954ad', { p0: (resWait(record)?.tool), p1: (resWait(record)?.avail_mb ?? '-'), p2: (resWait(record)?.reserve_mb ?? '-') })">
              <a-tag color="gold" style="margin-top:4px"><span class="ai-dot" />{{ translate('ui.m_b8cdb0a4d1f3') }}</a-tag>
            </a-tooltip>
            <a-tooltip v-if="aiProg[String(record._id)] && aiProg[String(record._id)].total > 0" :title="translate('ui.m_95888af98095', { p0: (aiProg[String(record._id)].active), p1: (aiProg[String(record._id)].done), p2: (aiProg[String(record._id)].interrupted || 0), p3: (aiProg[String(record._id)].stopped || 0), p4: (aiProg[String(record._id)].total) })">
              <a-tag v-if="aiProg[String(record._id)].active > 0" color="processing" style="margin-top:4px">
                <span class="ai-dot" />{{ translate('ui.m_0e06780f47d1') }} {{ aiProg[String(record._id)].active }}/{{ aiProg[String(record._id)].total }}
              </a-tag>
              <!-- 问题20：全终态时区分「完成」与「已停止」，别把手动停止的会话笼统算进"完成 done/total"误导成"还有N个待完成" -->
              <a-tag v-else-if="(aiProg[String(record._id)].stopped || 0) > 0" color="default" style="margin-top:4px">{{ translate('ui.m_d6dcbe10165f') }} {{ aiProg[String(record._id)].done }} {{ translate('ui.m_eb966c3a9fcc') }} {{ aiProg[String(record._id)].stopped }} {{ translate('ui.m_52d58c2a24ff') }} {{ aiProg[String(record._id)].total }}</a-tag>
              <a-tag v-else color="success" style="margin-top:4px">{{ translate('ui.m_1a9b3f1596a9') }} {{ aiProg[String(record._id)].done }}/{{ aiProg[String(record._id)].total }}</a-tag>
              <!-- 中断会话单列橙标（v1.21.157-48 item8）：paused/fatal/error 会话不再被当"渗透中"，独立提示可急救 -->
              <a-tag v-if="(aiProg[String(record._id)].interrupted || 0) > 0" color="orange" style="margin-top:4px">
                {{ translate('ui.m_1d006e05db47') }} {{ aiProg[String(record._id)].interrupted }}/{{ aiProg[String(record._id)].total }}
              </a-tag>
            </a-tooltip>
          </template>
          <template v-else-if="column.key === 'type'">{{ typeLabel(record.type) }}</template>
          <template v-else-if="column.key === 'priority'"><a-tag :color="prioMeta(record.priority).color">{{ prioMeta(record.priority).label }}</a-tag></template>
          <template v-else-if="column.key === 'target'">
            <!-- 自定义插槽下列 ellipsis 不自动生效，显式单行省略号夹住（unit 任务 target 可达数千字符）；
                 点击 CopyText 复制全量，hover 有 tooltip 提示复制 -->
            <div style="max-width:228px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><CopyText :text="record.target" /></div>
          </template>
          <template v-else-if="column.key === 'policy'">{{ (record.options || {}).policy_name || '-' }}</template>
          <template v-else-if="column.key === 'statistic'">
            <a-space size="small" wrap>
              <a-tag>{{ translate('ui.m_222952431147') }} {{ stat(record, 'domain_cnt') }}</a-tag>
              <a-tag>IP {{ stat(record, 'ip_cnt') }}</a-tag>
              <a-tag :color="['done','stop','error'].includes(String(record.status)) ? undefined : 'processing'">
                {{ translate('ui.m_a59fe62777ff') }} {{ stat(record, 'site_cnt') }}{{ ['done','stop','error'].includes(String(record.status)) ? '' : translate('ui.m_463fa583e0d3') }}
              </a-tag>
              <a-tag>WIH {{ stat(record, 'wih_cnt') }}</a-tag>
              <a-tag v-if="aiProg[String(record._id)] && aiProg[String(record._id)].total > 0" color="purple">{{ translate('ui.m_3ba0a49c8d0f') }} {{ aiProg[String(record._id)].total }}</a-tag>
              <!-- 问题7：统计列展示 AI 已完成（渗透）数量。有停止会话时区分「完成/停止」（对齐问题20，
                   否则分母含 stopped 会误导成"还有N个待完成"）；无停止时保持简洁 done/total。 -->
              <a-tag v-if="aiProg[String(record._id)] && (aiProg[String(record._id)].stopped || 0) > 0" color="cyan">{{ translate('ui.m_d5bbb5184594') }} {{ aiProg[String(record._id)].done }} {{ translate('ui.m_eb966c3a9fcc') }} {{ aiProg[String(record._id)].stopped }} {{ translate('ui.m_52d58c2a24ff') }} {{ aiProg[String(record._id)].total }}</a-tag>
              <a-tag v-else-if="aiProg[String(record._id)] && aiProg[String(record._id)].total > 0" color="cyan">{{ translate('ui.m_d5bbb5184594') }} {{ aiProg[String(record._id)].done }}/{{ aiProg[String(record._id)].total }}</a-tag>
            </a-space>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="router.push(`/tasks/${record._id}`)">{{ translate('ui.m_979a332955c8') }}</a-button>
              <a-button type="link" size="small" @click="openSync(record)">{{ translate('ui.m_dcfe516d1114') }}</a-button>
              <a-button type="link" size="small" @click="openReport(record)">{{ translate('ui.m_1e8ddd10bafe') }}</a-button>
              <ConfirmAction :title="translate('ui.m_12603abe3b26')" @confirm="stop(String(record._id))">{{ translate('ui.m_ca4d973c0b00') }}</ConfirmAction>
              <a-button v-if="['stop','error','proxy_paused','preempted'].includes(record.status)" type="link" size="small" @click="resume(String(record._id))">{{ translate('ui.m_7c9691192f1b') }}</a-button>
              <ConfirmAction :title="translate('ui.m_4454548b17b2')" @confirm="restart(String(record._id), String(record.target || ''))">{{ translate('ui.m_562822892865') }}</ConfirmAction>
              <a-button danger type="link" size="small" @click="openDelete([String(record._id)])">{{ translate('ui.m_2f9daa828907') }}</a-button>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 删除任务（可选是否级联删资产） -->
    <a-modal v-model:open="delOpen" :title="translate('ui.m_29dfebea0fda')" @ok="confirmDelete" :confirm-loading="deleting" ok-type="danger" :ok-text="translate('ui.m_2f9daa828907')">
      <p>{{ translate('ui.m_7cab32fd9ee0') }} <b>{{ delIds.length }}</b> {{ translate('ui.m_6ae0cc841335') }}</p>
      <a-checkbox v-model:checked="delAssets">{{ translate('ui.m_61c6086bae2c') }}</a-checkbox>
      <a-alert v-if="delAssets" type="warning" show-icon style="margin-top:8px"
        :message="translate('ui.m_e5d858ac1fb3')" />
      <a-alert v-else type="info" show-icon style="margin-top:8px"
        :message="translate('ui.m_fd2795ed8078')" />
      <a-checkbox v-model:checked="delSessions" style="margin-top:10px">{{ translate('ui.m_17648e4376e8') }}</a-checkbox>
      <a-alert v-if="delSessions" type="warning" show-icon style="margin-top:8px"
        :message="translate('ui.m_193c2ffffb09')" />
    </a-modal>

    <!-- 清理孤儿资产（task_id 指向已删除任务的残留结果） -->
    <a-modal v-model:open="orphanOpen" :title="translate('ui.m_4f0fb5d29a3d')" @ok="confirmPurgeOrphan"
      :confirm-loading="orphanPurging" ok-type="danger" :ok-text="translate('ui.m_9d2998cca517')"
      :ok-button-props="{ disabled: !orphanResult || orphanResult.purgeable === false || orphanResult.total === 0 }">
      <a-spin :spinning="orphanScanning">
        <template v-if="orphanResult">
          <a-alert v-if="orphanResult.purgeable === false" type="error" show-icon style="margin-bottom:12px"
            :message="orphanResult.note || translate('ui.m_ec69815d86b8')" />
          <p v-else-if="orphanResult.total === 0" style="color:#52c41a">{{ translate('ui.m_de439d4d0222') }}</p>
          <template v-else>
            <a-alert type="warning" show-icon style="margin-bottom:12px"
              :message="translate('ui.m_b33d12b15540', { p0: (orphanResult.total) })" />
            <p style="color:#888;font-size:12px;margin-bottom:8px">{{ translate('ui.m_6b64bfdf989b') }} {{ orphanResult.live_task_count }} {{ translate('ui.m_0b5afa88ab9f') }}</p>
            <div v-for="(n, coll) in orphanResult.by_collection" :key="coll" style="display:flex;justify-content:space-between;padding:2px 0">
              <span>{{ coll }}</span><b>{{ n }}</b>
            </div>
          </template>
        </template>
      </a-spin>
    </a-modal>

    <!-- 同步到资产组 -->
    <a-modal v-model:open="syncOpen" :title="translate('ui.m_8b86836ab0bd')" @ok="submitSync" :confirm-loading="syncing">
      <p>{{ translate('ui.m_9bf6abcc0b04') }}<a-typography-text code>{{ syncTaskName }}</a-typography-text></p>
      <a-form-item :label="translate('ui.m_39a13ea7a07d')">
        <a-select v-model:value="syncScopeId" :options="scopeOptions" :placeholder="translate('ui.m_c63291bc3828')" show-search :filter-option="filterOpt" style="width: 100%" />
      </a-form-item>
      <a-alert v-if="matchedScopes.length" type="info" show-icon :message="translate('ui.m_82b9e0a5a449', { p0: (matchedScopes.length) })" />
    </a-modal>

    <!-- 生成任务级报告：选模板 → 用该任务的全部漏洞聚合生成 docx -->
    <a-modal v-model:open="reportOpen" :title="translate('ui.m_85119879db1e')" @ok="submitReport" :confirm-loading="reporting"
      :ok-text="translate('ui.m_a62f22586ca0')">
      <p>{{ translate('ui.m_9bf6abcc0b04') }}<a-typography-text code>{{ reportTaskName }}</a-typography-text></p>
      <a-form-item :label="translate('ui.m_c745b048ca51')">
        <a-select v-model:value="reportTplId" :options="tplOptions" :placeholder="translate('ui.m_ff93f9c4be69')"
          :loading="tplLoading" style="width: 100%" />
        <div style="margin-top:6px;color:#888;font-size:12px">
          {{ translate('ui.m_9715b1b356e4') }}
        </div>
      </a-form-item>
      <a-alert v-if="!tplLoading && !tplOptions.length" type="warning" show-icon
        :message="translate('ui.m_5e8fc6fb7515')" />
    </a-modal>

    <!-- Fofa 任务 -->
    <a-modal v-model:open="fofaOpen" :title="translate('ui.m_3dbe7f390613')" @ok="submitFofa" :confirm-loading="fofaSubmitting">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_2c43cd7db149')" required><a-input v-model:value="fofaForm.name" :placeholder="translate('ui.m_2c43cd7db149')" /></a-form-item>
        <a-form-item :label="translate('ui.m_ef14114d0266')" required>
          <a-textarea v-model:value="fofaForm.query" :rows="3" :placeholder="translate('ui.m_2c4aa680b997')" />
          <a-button type="link" size="small" :loading="fofaTesting" @click="testFofa">{{ translate('ui.m_e1e59bfcbd89') }}</a-button>
          <span v-if="fofaSize !== null">{{ translate('ui.m_f1131cab1a72') }} {{ fofaSize }} {{ translate('ui.m_f004f1d84cf9') }}</span>
        </a-form-item>
        <a-form-item :label="translate('ui.m_47c6ff704123')">
          <a-select v-model:value="fofaForm.policy_id" allow-clear :options="policyOptions" :placeholder="translate('ui.m_8088cc83b2d5')" show-search :filter-option="filterOpt" style="width: 100%" />
        </a-form-item>
      </a-form>
    </a-modal>
    <OverlapConfirmModal v-model:open="overlapOpen" :data="overlapData"
      @confirm="onOverlapConfirm" @cancel="onOverlapCancel" />
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import StatusTag from '../../components/StatusTag.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import OverlapConfirmModal from '../../components/OverlapConfirmModal.vue'
import { taskApi, taskFofaApi } from '../../api/task'
import { intelApi, reportTemplateApi, type OverlapResult } from '../../api/intel'
import { pentestApi } from '../../api/pentest'
import { policyApi } from '../../api/policy'
import { assetScopeApi } from '../../api/scope'
import type { RowRecord, SelectOption } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const items = ref<RowRecord[]>([])
const aiProg = ref<Record<string, { total: number; active: number; done: number; stopped: number; interrupted: number }>>({})
const total = ref(0)
const selectedRowKeys = ref<string[]>([])
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', target: '', status: undefined as string | undefined })

const statusOptions = [
  { get label() { return translate('ui.m_26c8cfcbf763') }, value: 'waiting' },
  { get label() { return translate('ui.m_1f0eb99b7ed0') }, value: 'running' },
  { get label() { return translate('ui.m_49d5a8fb9591') }, value: 'proxy_paused' },
  { get label() { return translate('ui.m_f28461bb49c8') }, value: 'done' },
  { get label() { return translate('ui.m_f006455e3baf') }, value: 'stop' },
  { get label() { return translate('ui.m_428fb8bfeecf') }, value: 'error' }
]
const columns = [
  { get title() { return translate('ui.m_aa2353039024') }, key: '_id', width: 110, fixed: 'left' },
  { get title() { return translate('ui.m_2c43cd7db149') }, dataIndex: 'name', key: 'name', width: 180, ellipsis: true },
  // 目标定宽 + ellipsis 截断：unit 任务 target 是反查出的一大串域名(实测达 5567 字符)，
  // 无 width 时在 scroll.x=max-content 下会把整表横向撑爆——定宽夹住，全量靠 CopyText 点击复制。
  { get title() { return translate('ui.m_57060c88a36b') }, key: 'target', width: 240, ellipsis: true },
  { get title() { return translate('ui.m_9c8eb75c7e58') }, key: 'policy', width: 100 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 90 },
  { get title() { return translate('ui.m_565d64601d4d') }, key: 'priority', width: 80 },
  { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'type', key: 'type', width: 90 },
  { get title() { return translate('ui.m_89abe8c6ac13') }, key: 'statistic', width: 260 },
  { get title() { return translate('ui.m_6a9906c79f26') }, dataIndex: 'start_time', key: 'start_time', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 300, fixed: 'right' }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

function shortId(value: unknown) { return String(value || '').slice(-8) }
// 任务优先级标签:T0 最高(红)/T1(橙)/T2 默认(灰);历史任务无字段按 T2
function prioMeta(p: unknown) {
  const v = p == null ? 2 : Number(p)
  return ({ 0: { label: 'T0', color: 'red' }, 1: { label: 'T1', color: 'orange' }, 2: { label: 'T2', color: 'default' } } as Record<number, { label: string; color: string }>)[v] || { label: 'T2', color: 'default' }
}
function stat(record: RowRecord, key: string) { return (record.statistic as Record<string, unknown> | undefined)?.[key] ?? 0 }
// 问题11：资源等待子状态（工具因内存不足在资源池排队等待，优先让位 AI）。无则返 null（不显徽标）。
function resWait(record: RowRecord): { tool?: string; avail_mb?: number; reserve_mb?: number } | null {
  return (record.resource_wait as { tool?: string; avail_mb?: number; reserve_mb?: number } | undefined) || null
}
// 任务类型中文映射（type 是内部数据值不改，仅展示层友好化；未知值原样显示兼容）
const _TYPE_LABELS: Record<string, string> = {
  get domain() { return translate('ui.m_222952431147') }, ip: 'IP', get fofa() { return translate('ui.m_6518c904a840') }, get risk_cruising() { return translate('ui.m_7dc02b74d145') },
  get asset_site_update() { return translate('ui.m_137e364e3583') }, get asset_site_add() { return translate('ui.m_2c9e47665100') }, get asset_wih_update() { return translate('ui.m_ae8c0465f059') },
}
function typeLabel(t: unknown) { return _TYPE_LABELS[String(t || '')] || String(t || '-') }
// 任务已结束(done)但域名/IP/站点全为 0 = 没扫到任何资产,需提示而非只显示"已完成"。
// 三类核心资产任一 >0 就算有产出(域名任务看域名、IP 任务看 IP、Fofa 看站点),全 0 才提示。
function isEmptyDone(record: RowRecord) {
  if (String(record.status) !== 'done') return false
  const s = (record.statistic as Record<string, unknown> | undefined) || {}
  return Number(s.domain_cnt ?? 0) === 0 && Number(s.ip_cnt ?? 0) === 0 && Number(s.site_cnt ?? 0) === 0
}
// 顽疾根治:扫描 task 已进终态(done/stop/error) 但它派发的 AI 渗透会话还有活跃(active>0,含各 paused_
// 暂停态,由后端 _ACTIVE 全集统计)时,判为"渗透进行中"——状态列不显示"已完成",避免误导。
function isPentestOngoing(record: RowRecord) {
  if (!['done', 'stop', 'error'].includes(String(record.status))) return false
  const p = aiProg.value[String(record._id)]
  return !!(p && p.total > 0 && p.active > 0)
}
/* 生成任务级报告：选就绪模板 → 聚合该任务全部漏洞生成 docx（复用报告模板生成链路） */
const reportOpen = ref(false)
const reporting = ref(false)
const reportTaskId = ref('')
const reportTaskName = ref('')
const reportTplId = ref('')
const tplLoading = ref(false)
const tplOptions = ref<SelectOption[]>([])
async function openReport(record: RowRecord) {
  reportTaskId.value = String(record._id)
  reportTaskName.value = String(record.name || record.target || record._id)
  reportTplId.value = ''
  reportOpen.value = true
  tplLoading.value = true
  try {
    // 任务列表只生成任务级报告 → 只列 scope=task 模板（含无 scope 的学习模板），item5
    const data = await reportTemplateApi.list({ page: 1, size: 200, scope: 'task' })
    const ready = (data.items || []).filter((t: RowRecord) => t.status === 'ready')
    tplOptions.value = ready.map((t: RowRecord) => ({ label: String(t.name), value: String(t._id) }))
    // 默认选中内置任务级模板（若在列表里）
    const builtinTask = ready.find((t: RowRecord) => t._id === 'builtin_task_v1')
    reportTplId.value = builtinTask ? 'builtin_task_v1' : (tplOptions.value[0]?.value as string || '')
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    tplLoading.value = false
  }
}
async function submitReport() {
  if (!reportTplId.value) return message.warning(translate('ui.m_3703d6ea60bf'))
  reporting.value = true
  try {
    const r = await reportTemplateApi.generate({ template_id: reportTplId.value, type: 'task', task_id: reportTaskId.value })
    if ((r as { ok?: boolean }).ok) {
      message.success(translate('ui.m_cecce52666ef', { p0: ((r as { vuln_total?: number }).vuln_total ?? 0) }))
      reportOpen.value = false
      router.push('/report-edit')
    } else {
      message.error(translate('ui.m_470f92db3d64'))
    }
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    reporting.value = false
  }
}
function filterOpt(input: string, option: SelectOption) { return String(option.label).toLowerCase().includes(input.toLowerCase()) }

async function load(silent = false) {
  if (!silent) loading.value = true
  if (!silent) selectedRowKeys.value = []
  try {
    const data = await taskApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
    loadAiProgress()
  } catch (error) {
    if (!silent) message.error(error instanceof Error ? error.message : String(error))
  } finally {
    if (!silent) loading.value = false
  }
}
// 查本页任务派发的 AI 渗透会话进度(任务done但AI还在渗透时显示徽标)
async function loadAiProgress() {
  const ids = items.value.map(t => String(t._id))
  if (!ids.length) { aiProg.value = {}; return }
  try { aiProg.value = await pentestApi.progressByTasks(ids) } catch { /* 进度查询失败不影响列表 */ }
}
function reset() { query.name = ''; query.target = ''; query.status = undefined; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
function onSelectChange(keys: (string | number)[]) { selectedRowKeys.value = keys.map(String) }
async function stop(id: string) { await taskApi.stop(id); message.success(translate('ui.m_7bab4cbf6f9c')); load() }
async function resume(id: string) { await taskApi.resume(id); message.success(translate('ui.m_794f2d47c8e2')); load() }
// 重启前检测同资产是否已有渗透会话/历史报告：命中则弹 overlap 详情确认，用户确定后再重启；
// 无重叠/检测失败直接重启（best-effort 不阻断）。
async function restart(id: string, target?: string) {
  if (target) {
    try {
      const targets = target.split(/[、,;\s]+/).map(s => s.trim()).filter(Boolean)
      const ov = await intelApi.checkOverlap({ targets })
      if (ov?.overlap) {
        overlapData.value = ov
        overlapPendingId.value = id
        overlapOpen.value = true
        return
      }
    } catch { /* 检测失败不阻断 */ }
  }
  await doRestart(id)
}
async function doRestart(id: string) { await taskApi.restart([id]); message.success(translate('ui.m_5b0771723e7e')); load() }
const overlapOpen = ref(false)
const overlapData = ref<OverlapResult | null>(null)
const overlapPendingId = ref('')
function onOverlapConfirm() { if (overlapPendingId.value) doRestart(overlapPendingId.value); overlapPendingId.value = '' }
function onOverlapCancel() { overlapPendingId.value = ''; message.info(translate('ui.m_0134c3f3f1b1')) }
async function batchStop() {
  try { await taskApi.batchStop(selectedRowKeys.value); message.success(translate('ui.m_80aa1cb7e5ec')); load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
// 删除任务弹窗：让用户选是否级联删资产（默认勾选，与旧行为一致但透明可选）
const delOpen = ref(false)
const deleting = ref(false)
const delIds = ref<string[]>([])
const delAssets = ref(true)
const delSessions = ref(false)

// 孤儿资产清理
const orphanOpen = ref(false)
const orphanScanning = ref(false)
const orphanPurging = ref(false)
const orphanResult = ref<{ total: number; by_collection: Record<string, number>; live_task_count: number; purgeable?: boolean; note?: string } | null>(null)
async function openOrphan() {
  orphanResult.value = null
  orphanScanning.value = true
  orphanOpen.value = true
  try {
    orphanResult.value = await taskApi.scanOrphan()
  } catch (e) {
    message.error(e instanceof Error ? e.message : translate('ui.m_e70eca03a3dd'))
    orphanOpen.value = false
  } finally {
    orphanScanning.value = false
  }
}
async function confirmPurgeOrphan() {
  orphanPurging.value = true
  try {
    const r = await taskApi.purgeOrphan()
    if (r.skipped) message.warning(r.note || translate('ui.m_fe1fa3431481'))
    else message.success(translate('ui.m_00f71db4da81', { p0: (r.purged) }))
    orphanOpen.value = false
    load()
  } catch (e) {
    message.error(e instanceof Error ? e.message : translate('ui.m_09e7b98edc4d'))
  } finally {
    orphanPurging.value = false
  }
}
function openDelete(ids: string[]) {
  if (!ids.length) return
  delIds.value = ids
  delAssets.value = true
  delSessions.value = false
  delOpen.value = true
}
async function confirmDelete() {
  deleting.value = true
  try {
    const r = await taskApi.delete(delIds.value, delAssets.value, delSessions.value)
    const sd = Number((r as Record<string, unknown>)?.sessions_deleted || 0)
    message.success(translate('ui.m_96ff4b0955e4', { p0: (delIds.value.length), p1: (delAssets.value ? '及其资产' : ''), p2: (delSessions.value ? `，并停止+删除 ${sd} 个渗透会话` : '') }))
    delOpen.value = false
    selectedRowKeys.value = []
    load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { deleting.value = false }
}

/* 资产组 / 策略 下拉（懒加载） */
const scopeOptions = ref<SelectOption[]>([])
const policyOptions = ref<SelectOption[]>([])
async function ensureScopes() {
  if (scopeOptions.value.length) return
  const data = await assetScopeApi.list({ page: 1, size: 1000 })
  scopeOptions.value = (data.items || []).map(s => ({ label: String(s.name), value: String(s._id) }))
}
async function ensurePolicies() {
  if (policyOptions.value.length) return
  const data = await policyApi.list({ page: 1, size: 1000 })
  policyOptions.value = (data.items || []).map(p => ({ label: String(p.name), value: String(p._id) }))
}

/* 同步到资产组 */
const syncOpen = ref(false)
const syncing = ref(false)
const syncTaskId = ref('')
const syncTaskName = ref('')
const syncScopeId = ref<string | undefined>(undefined)
const matchedScopes = ref<RowRecord[]>([])
async function openSync(record: RowRecord) {
  syncTaskId.value = String(record._id)
  syncTaskName.value = String(record.name || record.target || '')
  syncScopeId.value = undefined
  matchedScopes.value = []
  syncOpen.value = true
  await ensureScopes()
  // 反查匹配该目标的资产组，优先置顶
  try {
    const m = await taskApi.syncScope(String(record.target || ''))
    matchedScopes.value = m.items || []
    if (matchedScopes.value.length) {
      const ids = new Set(matchedScopes.value.map(s => String(s._id)))
      scopeOptions.value = [
        ...scopeOptions.value.filter(o => ids.has(String(o.value))),
        ...scopeOptions.value.filter(o => !ids.has(String(o.value)))
      ]
      syncScopeId.value = String(matchedScopes.value[0]._id)
    }
  } catch { /* 反查失败不阻断手动选择 */ }
}
async function submitSync() {
  if (!syncScopeId.value) return message.warning(translate('ui.m_432829f0ba09'))
  syncing.value = true
  try { await taskApi.sync(syncTaskId.value, syncScopeId.value); message.success(translate('ui.m_1c4b71016b4a')); syncOpen.value = false }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { syncing.value = false }
}

/* Fofa 任务 */
const fofaOpen = ref(false)
const fofaSubmitting = ref(false)
const fofaTesting = ref(false)
const fofaSize = ref<number | null>(null)
const fofaForm = reactive({ name: '', query: '', policy_id: undefined as string | undefined })
async function openFofa() {
  fofaForm.name = ''; fofaForm.query = ''; fofaForm.policy_id = undefined; fofaSize.value = null
  fofaOpen.value = true
  await ensurePolicies()
}
async function testFofa() {
  if (!fofaForm.query) return message.warning(translate('ui.m_8ebfb6164eef'))
  fofaTesting.value = true
  try { const r = await taskFofaApi.test(fofaForm.query); fofaSize.value = r.size; message.success(translate('ui.m_4b9a018aeeb8')) }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { fofaTesting.value = false }
}
async function submitFofa() {
  if (!fofaForm.name || !fofaForm.query) return message.warning(translate('ui.m_b5318a47f8d2'))
  fofaSubmitting.value = true
  try {
    await taskFofaApi.submit({ name: fofaForm.name, query: fofaForm.query, policy_id: fofaForm.policy_id })
    message.success(translate('ui.m_25f1ffec7509')); fofaOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { fofaSubmitting.value = false }
}

// 终态状态(不再变化);其余视为"运行中",有运行中任务才定时刷新
const _DONE_STATUS = ['done', 'stop', 'error']
let _timer: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  load()
  // 任务扫描进度(站点/IP/WIH/AI派发)流式变化,有运行中任务时每15秒静默刷新(不闪loading)。
  // 关键(修逆优化):任务扫描 done 但 auto_pentest 派发的 AI 会话还在渗透时,任务本身已是 done、
  // 只看任务状态会误判"无运行中"→停刷新→"AI渗透中"徽标的 active 永不更新(表现为任务显示"已完成"
  // 却不更新渗透进度)。故刷新条件必须并上"任一任务的 AI 会话还 active(aiProg.active>0)"。
  _timer = setInterval(() => {
    const taskRunning = items.value.some(t => !_DONE_STATUS.includes(String(t.status)))
    const aiRunning = Object.values(aiProg.value).some(p => p && p.active > 0)
    if (taskRunning || aiRunning) load(true)
  }, 15000)
})
onUnmounted(() => { if (_timer) clearInterval(_timer) })

</script>

<style scoped>
.ai-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #1677ff; margin-right: 4px; animation: aipulse 1.2s ease-in-out infinite; }
@keyframes aipulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
/* 固定列背景：普通态继承行背景，hover 态显式底色（防底层行透出）。用主题变量适配日/夜 */
:deep(.ant-table-cell-fix-left),
:deep(.ant-table-cell-fix-right) {
  background: var(--dt-card, #fff);
}
:deep(.ant-table-row:hover > td) {
  background: var(--dt-fill, #fafafa) !important;
}
</style>
