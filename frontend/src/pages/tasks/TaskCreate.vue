<template>
  <PageContainer :title="translate('ui.m_6bee2372805a')" kicker="Create Task" :description="translate('ui.m_2ed2113990f5')">
    <a-card :bordered="false">
      <a-form layout="vertical" :model="form" @finish="submit">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12">
            <a-form-item :label="translate('ui.m_2479560deb33')" required>
              <a-input v-model:value="form.name"
                :placeholder="form.target_type === 'unit' ? translate('ui.m_8abd535b2ab9') : translate('ui.m_1f01b74c3464')" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item :label="translate('ui.m_4064b1b6e5f6')" required>
              <a-select v-model:value="form.policy_id" :options="policyOptions" :placeholder="translate('ui.m_ae88804e2014')"
                show-search :filter-option="filterPolicy" :loading="policyLoading" />
              <div class="muted">{{ translate('ui.m_5c2cd186a84b') }}</div>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="translate('ui.m_d04da2799b60')">
          <a-radio-group v-model:value="form.target_type" button-style="solid">
            <a-radio-button value="normal">{{ translate('ui.m_ee1f158b2356') }}</a-radio-button>
            <a-radio-button value="fofa">{{ translate('ui.m_6518c904a840') }}</a-radio-button>
            <a-radio-button value="unit">{{ translate('ui.m_702aab59cae9') }}</a-radio-button>
          </a-radio-group>
          <span v-if="form.target_type === 'fofa'" class="muted" style="margin-left:8px">{{ translate('ui.m_cd0c80268b80') }}</span>
          <span v-else-if="form.target_type === 'unit'" class="muted" style="margin-left:8px">{{ translate('ui.m_ceb85691e354') }}</span>
        </a-form-item>
        <!-- 普通目标 / 单位名：共用文本框 -->
        <a-form-item v-if="form.target_type !== 'fofa'"
          :label="form.target_type === 'unit' ? translate('ui.m_926e0936f410') : translate('ui.m_f617beed33b0')" required>
          <a-textarea v-model:value="form.target" :rows="3"
            :placeholder="form.target_type === 'unit' ? translate('ui.m_2cb4feacb0ff') : translate('ui.m_06a4b644d6ba')" />
        </a-form-item>

        <!-- 源查询：多测绘源各写各语法，去重互补 -->
        <a-form-item v-else :label="translate('ui.m_6518c904a840')" required>
          <div v-if="!sources.length" class="muted">{{ translate('ui.m_d72e1f5c60cf') }}</div>
          <div class="src-grid">
            <div v-for="s in sources" :key="s.id" class="src-block">
              <div class="src-head">
                <span :class="s.available ? 'src-ok' : 'src-off'">{{ s.available ? '✓' : '✗' }} {{ s.name }}</span>
                <span v-if="!s.available" class="muted">{{ translate('ui.m_72d8e42e04f1') }}</span>
                <span v-if="srcEst[s.id]" class="src-est"
                  :style="{ color: srcEst[s.id].error ? '#cf1322' : '#52c41a' }">
                  {{ srcEst[s.id].error ? (translate('ui.m_867ea0e13287') + srcEst[s.id].errmsg) : (translate('ui.m_4e6f78cbbec7') + srcEst[s.id].size + translate('ui.m_f004f1d84cf9')) }}
                </span>
                <!-- 数量限制：抵到来源行右侧对齐，默认空=无限制，填正整数则限制抓取条数 -->
                <a-input-number v-model:value="srcLimits[s.id]" :min="1" :precision="0" size="small"
                  class="src-limit" :class="{ 'src-limit-first': !srcEst[s.id] }"
                  :disabled="!s.available" :placeholder="translate('ui.m_9ee3c076a148')" :title="translate('ui.m_ff09dc036470')" />
              </div>
              <a-textarea v-model:value="srcQueries[s.id]" :rows="2" :disabled="!s.available"
                :placeholder="s.placeholder" />
            </div>
          </div>
          <div style="margin-top:6px">
            <a-button type="link" size="small" :loading="fofaTesting" @click="testSources">{{ translate('ui.m_683b99a7175f') }}</a-button>
            <span v-if="mergedTip" class="muted">{{ mergedTip }}</span>
          </div>
        </a-form-item>

        <a-form-item :label="translate('ui.m_a10abc806ce4')">
          <a-radio-group v-model:value="form.priority" button-style="solid">
            <a-radio-button :value="0">T0</a-radio-button>
            <a-radio-button :value="1">T1</a-radio-button>
            <a-radio-button :value="2">T2</a-radio-button>
          </a-radio-group>
          <div class="muted">{{ translate('ui.m_f4c7796640b6') }}</div>
        </a-form-item>

        <!-- 渗透相关选项：仅当所选策略勾了「扫描后自动 AI 渗透」才显示（避免填了没人消费的矛盾）。 -->
        <template v-if="pentestEnabled">
          <a-divider style="margin:8px 0">{{ translate('ui.m_fb5d9045edd7') }}</a-divider>

          <a-form-item :label="translate('ui.m_fec95897fa0a')">
            <a-select v-model:value="form.pentest_provider_id" :options="providerOptions" allow-clear
              style="max-width:360px" :placeholder="translate('ui.m_8b6340d797b6', { p0: (globalDefaultName) })" />
            <div v-if="!form.pentest_provider_id" class="default-hint">
              <BulbOutlined /> {{ translate('ui.m_dd87bdfbdeef') }}<b>{{ globalDefaultName }}</b>
            </div>
            <div class="muted">{{ translate('ui.m_c74262b83e29') }}</div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_ffb131c6cb5f')">
            <a-select v-model:value="form.pentest_backup_provider_id" :options="backupProviderOptions"
              style="max-width:360px" :placeholder="translate('ui.m_70d9626ae2fb')" />
            <div class="muted">
              {{ translate('ui.m_5c36c2400245') }}
            </div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_4568f2dbe40b')">
            <a-radio-group v-model:value="form.pentest_egress_mode" button-style="solid" size="small">
              <a-radio-button value="direct">{{ translate('ui.m_b06325c5660f') }}</a-radio-button>
              <a-tooltip :title="egressOpts.global && !egressOpts.global.available ? egressOpts.global.reason : ''">
                <a-radio-button value="global" :disabled="egressOpts.global && !egressOpts.global.available">{{ translate('ui.m_63d6b47116de') }}</a-radio-button>
              </a-tooltip>
              <a-tooltip :title="egressOpts.smart && !egressOpts.smart.available ? egressOpts.smart.reason : ''">
                <a-radio-button value="smart" :disabled="egressOpts.smart && !egressOpts.smart.available">{{ translate('ui.m_8fffc40833fb') }}</a-radio-button>
              </a-tooltip>
            </a-radio-group>
            <div class="muted">{{ translate('ui.m_a6ced89f4266') }}</div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_953b36326f84')">
            <a-radio-group v-model:value="form.pentest_fallback_egress_mode" button-style="solid" size="small">
              <a-radio-button value="direct">{{ translate('ui.m_b06325c5660f') }}</a-radio-button>
              <a-tooltip :title="egressOpts.global && !egressOpts.global.available ? egressOpts.global.reason : ''">
                <a-radio-button value="global" :disabled="egressOpts.global && !egressOpts.global.available">{{ translate('ui.m_63d6b47116de') }}</a-radio-button>
              </a-tooltip>
              <a-tooltip :title="egressOpts.smart && !egressOpts.smart.available ? egressOpts.smart.reason : ''">
                <a-radio-button value="smart" :disabled="egressOpts.smart && !egressOpts.smart.available">{{ translate('ui.m_8fffc40833fb') }}</a-radio-button>
              </a-tooltip>
            </a-radio-group>
            <div class="muted">{{ translate('ui.m_70984b7ac625') }}<b>{{ translate('ui.m_d0441ae44c31') }}</b>{{ translate('ui.m_feb9c4e23b28') }}</div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_d741ea4eb0ab')">
            <div class="ctx-slider">
              <a-slider :value="ctxPos" @change="onCtxSlide" :min="0" :max="CTX_MAX_POS" :step="1"
                :marks="ctxMarks" :tip-formatter="() => ctxLabel" />
              <div class="ctx-cur">
                <span>{{ translate('ui.m_660648805666') }}<b>{{ ctxLabel }}</b></span>
                <!-- 拉满名称后小输入框：滑块封顶 512K，够不到的大值（如 900k）直接输入。单位 k。 -->
                <span class="ctx-kbox">{{ translate('ui.m_e4b1f1e922c5') }}
                  <a-input-number v-model:value="ctxKInput" :min="0" :step="8" size="small"
                    :disabled="ctxNative" style="width:96px" addon-after="k" />
                </span>
                <a-checkbox v-model:checked="ctxNative" class="ctx-native-ck">{{ translate('ui.m_fe4a231a26db') }}</a-checkbox>
              </div>
            </div>
            <div class="muted">{{ translate('ui.m_9df752ffdb6d') }}<b>{{ translate('ui.m_804fede622ee') }}</b>{{ translate('ui.m_b12c858565e8') }}<b>{{ translate('ui.m_e4b1f1e922c5') }}</b>{{ translate('ui.m_a416d3fee209') }}<b>{{ translate('ui.m_50817637b499') }}</b>{{ translate('ui.m_25b579b31ed2') }}</div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_a087fd2af4ba')">
            <a-switch v-model:checked="form.observer_enabled" checked-children="启用" un-checked-children="关闭" />
            <div class="muted">
              {{ translate('ui.m_4cf034a0641a') }}<b>{{ translate('ui.m_da3b6574b935') }}</b>{{ translate('ui.m_4027c42c889f') }}<b>{{ translate('ui.m_0ab592475486') }}</b>{{ translate('ui.m_551d30e7d702') }}
            </div>
            <div v-if="form.observer_enabled" style="margin-top:10px">
              <a-select v-model:value="form.observer_provider_id" :options="providerOptions" allow-clear
                style="max-width:360px" :placeholder="translate('ui.m_8b6340d797b6', { p0: (globalDefaultName) })" />
              <div v-if="!form.observer_provider_id" class="default-hint">
                <BulbOutlined /> {{ translate('ui.m_dd87bdfbdeef') }}<b>{{ globalDefaultName }}</b>
              </div>
              <div class="muted">{{ translate('ui.m_8ef3da8bd39b') }}</div>
            </div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_cec77f7bc5e2')">
            <a-textarea v-model:value="form.pentest_whitelist" :rows="2"
              :placeholder="translate('ui.m_92f58e4f2833')" />
            <div class="muted">{{ translate('ui.m_f9f80d9cf3f7') }}</div>
          </a-form-item>

          <a-form-item :label="translate('ui.m_4535073de85b')">
            <div class="muted" style="margin-bottom:6px">
              {{ translate('ui.m_105722581e4c') }}
            </div>
            <div v-for="(mi, idx) in missionIntel" :key="idx" class="mi-row">
              <a-select v-model:value="mi.scope" :options="miScopeOptions" style="width:110px"
                @change="() => onScopeChange(mi)" />
              <a-input v-if="mi.scope==='unit'" v-model:value="mi.scopeVal" :placeholder="translate('ui.m_ca13790801eb')" style="width:160px" />
              <a-input v-else-if="mi.scope==='target'" v-model:value="mi.scopeVal" :placeholder="translate('ui.m_6399654e3013')" style="width:180px" />
              <a-textarea v-model:value="mi.text" :rows="1" :auto-size="{minRows:1,maxRows:4}"
                :placeholder="translate('ui.m_08c588d556eb')" style="flex:1" />
              <a-button type="text" danger @click="removeMi(idx)"><template #icon><DeleteOutlined /></template></a-button>
            </div>
            <a-button type="dashed" size="small" @click="addMi" style="margin-top:4px">
              <template #icon><PlusOutlined /></template>{{ translate('ui.m_cd85fc8fbbde') }}
            </a-button>
          </a-form-item>
        </template>
        <!-- 选了策略但未启用 AI 渗透：明确告知，避免用户找不到渗透选项 -->
        <a-alert v-else-if="form.policy_id" type="info" show-icon style="margin:8px 0"
          :message="translate('ui.m_a04ac0a8ca0f')"
          :description="translate('ui.m_a182699c71ea')" />

        <a-divider style="margin:8px 0">{{ translate('ui.m_fd7719273970') }}</a-divider>
        <a-form-item>
          <a-space wrap>
            <a-button @click="downloadTemplate"><template #icon><DownloadOutlined /></template>{{ translate('ui.m_e9b35c4ab08a') }}</a-button>
            <a-upload :before-upload="handleCsvUpload" :show-upload-list="false" accept=".csv">
              <a-button type="dashed"><template #icon><UploadOutlined /></template>{{ translate('ui.m_c3a654bd3919') }}</a-button>
            </a-upload>
            <span class="muted">{{ translate('ui.m_68393190b1e5') }}</span>
          </a-space>
        </a-form-item>

        <a-divider style="margin:8px 0">{{ translate('ui.m_3d7dcb8a326d') }}</a-divider>
        <a-row :gutter="16">
          <a-col :xs="24" :md="8">
            <a-form-item :label="translate('ui.m_80b19d68b149')"><a-input v-model:value="form['source.unit']" :placeholder="translate('ui.m_e967e8a3a79a')" /></a-form-item>
          </a-col>
        </a-row>

        <a-form-item>
          <a-space>
            <a-button type="primary" html-type="submit" :loading="loading">{{ translate('ui.m_36d5f450ffc8') }}</a-button>
            <a-button @click="router.push('/tasks')">{{ translate('ui.m_e9d5ca6c1406') }}</a-button>
          </a-space>
        </a-form-item>
      </a-form>
    </a-card>
    <OverlapConfirmModal v-model:open="overlapOpen" :data="overlapData"
      @confirm="onOverlapConfirm" @cancel="onOverlapCancel" />
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { DownloadOutlined, UploadOutlined, PlusOutlined, DeleteOutlined, BulbOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { taskApi, taskFofaApi } from '../../api/task'
import { intelApi, type OverlapResult } from '../../api/intel'
import OverlapConfirmModal from '../../components/OverlapConfirmModal.vue'
import { policyApi } from '../../api/policy'
import { aiConfigApi, type AIProviderOption } from '../../api/aiConfig'
import { proxyApi } from '../../api/proxy'
import { getSetupStatus, type SetupStatusResult } from '../../api/meta'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const policyLoading = ref(false)
type PolicyOption = { label: string; value: string }
const policyOptions = ref<PolicyOption[]>([])
const policyRaw = ref<RowRecord[]>([])          // 完整策略对象，用于读 auto_pentest 做分步显示
const providers = ref<AIProviderOption[]>([])         // 可选 AI 模型（渗透会话锁定用）
const globalDefaultId = ref('')                  // AI 配置页的全局默认 provider（active_provider_id），用于"留空=跟随全局默认"显示具体模型名
const setupStatus = ref<SetupStatusResult | null>(null)

const form = reactive({
  name: '',
  target: '',
  target_type: 'normal' as 'normal' | 'fofa' | 'unit',
  policy_id: undefined as string | undefined,
  priority: 2,
  pentest_whitelist: '',
  pentest_provider_id: '',                       // 首要模型（空=跟随全局默认）
  pentest_backup_provider_id: '',                // 备用模型（空=不指定）
  pentest_egress_mode: 'direct',                 // AI 攻击出口（direct/global/smart，从策略移到任务）
  pentest_fallback_egress_mode: 'direct',        // AI 封禁备用出口（用户 2026-09-15：默认应直连非智能代理，对齐代理出口规范「默认直连」）
  ctx_tokens: 0,                                 // 单会话上下文上限权威值（0=跟随全局默认 / -1=拉满原生上限 / 正数=固定 token）
  observer_enabled: false,                       // 监督者（Observer 旁路语义监督）默认不启动
  observer_provider_id: '',                      // 监督者独立模型（空=跟随全局默认）
  'source.unit': ''
})

// AI 攻击出口各模式可选性（后端 egress_options：未绑定源的模式变灰 + 悬停 reason）
const egressOpts = ref<Record<string, { available: boolean; reason: string }>>({})

// 当前所选策略的完整对象 + 是否启用扫描后 AI 渗透（决定渗透相关选项是否显示）
const selectedPolicy = computed(() => policyRaw.value.find(p => String(p._id) === String(form.policy_id)))
const pentestEnabled = computed(() => !!(selectedPolicy.value?.policy as RowRecord | undefined)?.auto_pentest)
// 可选模型选项：仅已启用 provider（带协议标注，便于识别）
const providerOptions = computed(() => providers.value.filter(p => p.enabled).map(p => ({
  label: translate('ui.m_2996e5d20567', { p0: (p.name), p1: (p.protocol === 'claude' ? 'Claude' : 'OpenAI') }), value: p._id,
})))
const effectivePrimaryProvider = computed(() => {
  const id = form.pentest_provider_id || globalDefaultId.value
  return providers.value.find(p => String(p._id) === String(id))
})
const backupProviderOptions = computed(() => {
  const primary = effectivePrimaryProvider.value
  const baseProto = (primary?.protocol || '').toLowerCase()
  // 对齐 PentestList.setBackupOptions：不合规的选项「保留但置灰 + 说明」，而非直接删除
  // （删除会让下拉看起来空的、用户以为坏了；置灰能看到为什么不能选）。
  const options = providers.value.filter(p => p.enabled).map(p => {
    const proto = (p.protocol || '').toLowerCase()
    const isPrimary = String(p._id) === String(primary?._id || '')
    const cross = !!baseProto && proto !== baseProto
    const bad = isPrimary || cross
    const note = isPrimary ? translate('ui.m_f12e2d1fb302') : (cross ? translate('ui.m_9162ded82b3f') : '')
    return {
      label: translate('ui.m_016fb7ebb1ea', { p0: (p.name), p1: (proto === 'claude' ? 'Claude' : 'OpenAI'), p2: (note) }),
      value: p._id, disabled: bad,
    }
  })
  return [{ get label() { return translate('ui.m_70d9626ae2fb') }, value: '', disabled: false }, ...options]
})
watch([() => form.pentest_provider_id, globalDefaultId, providers], () => {
  // 首要变化后若已选备用变得不合规（跨协议/成了首要自身=选项 disabled 或不在列表）→ 清空
  if (form.pentest_backup_provider_id) {
    const opt = backupProviderOptions.value.find(o => o.value === form.pentest_backup_provider_id)
    if (!opt || opt.disabled) form.pentest_backup_provider_id = ''
  }
})
// 全局默认 AI 的展示名（留空时告诉用户实际会跟随哪个模型）；取不到默认配置时退化提示
const globalDefaultName = computed(() => {
  const p = providers.value.find(x => String(x._id) === String(globalDefaultId.value))
  return p ? translate('ui.m_2996e5d20567', { p0: (p.name), p1: (p.protocol === 'claude' ? 'Claude' : 'OpenAI') }) : translate('ui.m_a10f648b9e1a')
})
const fofaTesting = ref(false)
const fofaSize = ref<number | null>(null)
const fofaErr = ref('')          // FOFA 报错原文（限流/语法/额度等），有则如实展示而非笼统归因
// 源查询：多测绘源
interface SrcItem { id: string; name: string; placeholder: string; available: boolean }
const sources = ref<SrcItem[]>([])
const srcQueries = reactive<Record<string, string>>({})       // 各源输入语句
const srcLimits = reactive<Record<string, number | null>>({}) // 各源抓取数量限制（null/空=无限制，正整数=上限）
const srcEst = reactive<Record<string, { size: number; error: boolean; errmsg: string }>>({})  // 各源预估
const mergedTip = ref('')

// 临时情报:每行 {scope, scopeVal, text},提交时转 {match:{unit,target},text} JSON
type MiScope = 'task' | 'unit' | 'target'
interface MiRow { scope: MiScope; scopeVal: string; text: string }
const missionIntel = reactive<MiRow[]>([])
const miScopeOptions = [
  { get label() { return translate('ui.m_35a56845d620') }, value: 'task' },
  { get label() { return translate('ui.m_cb1e7dbe149f') }, value: 'unit' },
  { get label() { return translate('ui.m_e9ee1592478a') }, value: 'target' }
]
function addMi() { missionIntel.push({ scope: 'task', scopeVal: '', text: '' }) }
function removeMi(i: number) { missionIntel.splice(i, 1) }
function onScopeChange(mi: MiRow) { if (mi.scope === 'task') mi.scopeVal = '' }
// 组装成后端要的 JSON 数组字符串;空 text 丢弃;'' 表示不带该字段
function buildMissionIntel(): string {
  const items = missionIntel
    .filter(mi => (mi.text || '').trim())
    .map(mi => ({
      match: {
        unit: mi.scope === 'unit' ? (mi.scopeVal || '').trim() : '',
        target: mi.scope === 'target' ? (mi.scopeVal || '').trim() : ''
      },
      text: mi.text.trim()
    }))
  return items.length ? JSON.stringify(items) : ''
}

// #3 上下文上限（v1.21.157-52 滑块 + 精确输入框）：**权威值 = form.ctx_tokens**（后端口径：
//   0=跟随全局默认 / -1=拉满原生上限 / 正数=固定 token）。滑块、k 输入框、拉满勾选是它的三个视图/写入口，
//   互不打架。滑块封顶 512K（拖不到的大值如 900k 用 k 输入框直接输入，突破滑块上限）。
const CTX_MAX_POS = 125           // 滑块最大位置 → 1000K（125×8K）；再大走 k 输入框
const CTX_TOKEN_STEP = 8000
// —— 滑块视图：位置↔token（0=默认；1..64=8K..512K）——
const ctxPos = computed(() => {
  const t = form.ctx_tokens
  if (t < 0) return CTX_MAX_POS      // 拉满时滑块停最右（视觉提示；实际值由勾选表达）
  if (t <= 0) return 0
  return Math.min(CTX_MAX_POS, Math.round(t / CTX_TOKEN_STEP))
})
function onCtxSlide(pos: number) {   // 拖滑块 → 写权威值（会自动取消拉满）
  form.ctx_tokens = pos <= 0 ? 0 : pos * CTX_TOKEN_STEP
}
// —— k 输入框视图：可写 computed，单位 k（1k=1000 token）；能输入 >512K 的大值 ——
const ctxKInput = computed<number>({
  get: () => (form.ctx_tokens > 0 ? Math.round(form.ctx_tokens / 1000) : 0),
  set: (k: number) => { form.ctx_tokens = Math.max(0, Math.round((Number(k) || 0) * 1000)) },
})
// —— 拉满勾选视图：勾=-1（原生上限），取消=回落到 0（跟随默认）——
const ctxNative = computed<boolean>({
  get: () => form.ctx_tokens < 0,
  set: (on: boolean) => { form.ctx_tokens = on ? -1 : 0 },
})
const ctxLabel = computed(() => {
  const t = form.ctx_tokens
  if (t < 0) return translate('ui.m_ed5c7ea56a5b')
  if (t === 0) return translate('ui.m_648d5731ecf5')
  return `${Math.round(t / 1000)}K tokens`
})
// 节点标记：最左「默认」、中段刻度、最右「1000K」（1000K 以上走输入框）
const ctxMarks = {
  get 0() { return translate('ui.m_844b8cc8dff7') },
  31: '250K',
  62: '500K',
  94: '750K',
  [CTX_MAX_POS]: '1000K',
} as Record<number, string>

// 把权威值转成后端 pentest_max_context_tokens（0/-1/正数）。
// 未启用 AI 渗透（pentestEnabled=false）时返回 undefined —— 不传该字段，后端不覆盖策略/全局值。
function ctxTokensPayload(): number | undefined {
  if (!pentestEnabled.value) return undefined
  return form.ctx_tokens
}

function filterPolicy(input: string, option: PolicyOption) {
  return option.label.toLowerCase().includes(input.toLowerCase())
}

async function loadPolicies() {
  policyLoading.value = true
  try {
    const data = await policyApi.list({ page: 1, size: 1000 })
    policyRaw.value = (data.items || []) as RowRecord[]   // 存完整对象，选策略后本地读 auto_pentest
    policyOptions.value = policyRaw.value.map(p => ({ label: String(p.name), value: String(p._id) }))
  } catch (e) {
    message.error((e as Error).message || translate('ui.m_06125f4aa7bd'))
  } finally {
    policyLoading.value = false
  }
}

async function loadProviders() {
  try {
    const data = await aiConfigApi.providerOptions()
    providers.value = data.items || []
  } catch { /* 取不到不阻断，模型下拉留空=跟随全局默认 */ }
  // 拉全局配置的默认 AI（active_provider_id），供"留空=跟随全局默认"显示出具体是哪个模型
  try {
    const cfg = await aiConfigApi.runtimeConfig()
    globalDefaultId.value = cfg.active_provider_id || ''
  } catch { /* 取不到不阻断，退化为不显示具体名 */ }
}

/* ---------------- 批量导入(CSV) ---------------- */
// 下载模板:目标必填,任务名/优先级可留空(优先级 0/1/2)
function downloadTemplate() {
  const csv = '目标,任务名,优先级\nexample.com,示例任务A,2\n1.1.1.1,示例任务B,0\n'
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' })  // BOM 防 Excel 中文乱码
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = 'task_batch_template.csv'
  a.click()
  URL.revokeObjectURL(a.href)
}

// 解析一行 CSV(简单实现:逗号分隔,不处理引号内逗号——目标/任务名通常无逗号)
function parseCsvRow(line: string) {
  return line.split(',').map(s => s.trim())
}

function handleCsvUpload(file: File) {
  if (!form.policy_id) { message.warning(translate('ui.m_1a92fa902de6')); return false }
  const reader = new FileReader()
  reader.onload = () => {
    const text = String(reader.result || '').replace(/\r/g, '')
    const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
    if (!lines.length) { message.warning(translate('ui.m_bf8962d5e84b')); return }
    // 跳过表头(首行含“目标”视为表头)
    const rows = lines[0].includes('目标') ? lines.slice(1) : lines
    const items = rows.map(parseCsvRow).filter(c => c[0]).map(c => ({
      target: c[0],
      name: c[1] || `批量-${c[0]}`,
      priority: c[2] !== undefined && c[2] !== '' ? Number(c[2]) : form.priority
    }))
    if (!items.length) { message.warning(translate('ui.m_c858ebe0eef0')); return }
    submitBatch(items)
  }
  reader.readAsText(file, 'utf-8')
  return false  // 阻止 a-upload 默认上传
}

async function submitBatch(items: Array<{ target: string; name: string; priority: number }>) {
  loading.value = true
  let ok = 0, fail = 0
  for (const it of items) {
    try {
      await taskApi.policy({
        name: it.name, task_tag: 'task', target: it.target,
        policy_id: form.policy_id as string, priority: Number.isNaN(it.priority) ? form.priority : it.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: buildMissionIntel(),
        pentest_provider_id: form.pentest_provider_id || '',
        pentest_backup_provider_id: form.pentest_backup_provider_id || '',
        pentest_egress_mode: pentestEnabled.value ? form.pentest_egress_mode : '',
        pentest_fallback_egress_mode: pentestEnabled.value ? form.pentest_fallback_egress_mode : '',
        pentest_max_context_tokens: ctxTokensPayload(),
        observer_enabled: pentestEnabled.value ? form.observer_enabled : false,
        observer_provider_id: (pentestEnabled.value && form.observer_enabled) ? (form.observer_provider_id || '') : '',
        'source.unit': form['source.unit'],
      })
      ok++
    } catch { fail++ }
  }
  loading.value = false
  message.success(translate('ui.m_47d77414a9f4', { p0: (ok), p1: (fail ? `,失败 ${fail} 个` : '') }))
  if (ok) router.push('/tasks')
}


async function testFofa() {
  if (!form.target) return message.warning(translate('ui.m_32628ba0bdba'))
  fofaTesting.value = true
  fofaSize.value = null
  fofaErr.value = ''
  try {
    const res = await taskFofaApi.test(form.target)
    if (res.error) {
      fofaErr.value = res.errmsg || 'FOFA 查询出错'
    } else {
      fofaSize.value = res.size
    }
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    fofaTesting.value = false
  }
}

async function loadSources() {
  try {
    const r = await taskFofaApi.sources()
    sources.value = r.sources || []
    for (const s of sources.value) {
      if (!(s.id in srcQueries)) srcQueries[s.id] = ''
      if (!(s.id in srcLimits)) srcLimits[s.id] = null      // 默认无限制
    }
  } catch { /* ignore */ }
}

// 收集非空的源查询语句 {fofa, hunter, ...}
function collectQueries(): Record<string, string> {
  const q: Record<string, string> = {}
  for (const s of sources.value) {
    const v = (srcQueries[s.id] || '').trim()
    if (v && s.available) q[s.id] = v
  }
  return q
}

// 收集各源数量限制 {fofa:N,...}：只带「有查询语句 + 填了正整数」的源；空/非正=无限制不带
function collectLimits(queries: Record<string, string>): Record<string, number> {
  const out: Record<string, number> = {}
  for (const s of sources.value) {
    if (!(s.id in queries)) continue          // 只对实际查询的源带限制
    const n = Number(srcLimits[s.id])
    if (Number.isInteger(n) && n > 0) out[s.id] = n
  }
  return out
}

async function testSources() {
  const queries = collectQueries()
  if (!Object.keys(queries).length) return message.warning(translate('ui.m_9e2ac9a31a23'))
  fofaTesting.value = true
  mergedTip.value = ''
  for (const k of Object.keys(srcEst)) delete srcEst[k]
  try {
    const res = await taskFofaApi.test({ queries })
    const per = res.per_source || {}
    for (const [sid, v] of Object.entries(per)) {
      srcEst[sid] = { size: (v as any).size || 0, error: !!(v as any).error, errmsg: (v as any).errmsg || '' }
    }
    mergedTip.value = '各源命中数如上；去重合并后实际条数以建任务为准（跨源域名/IP+端口去重互补）'
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    fofaTesting.value = false
  }
}

async function submit() {
  // unit 模式:任务名(第一级)+ 单位全称(第二级,多行)都要;其余模式需任务名+目标
  let srcQ: Record<string, string> = {}
  if (form.target_type === 'unit') {
    if (!form.name) return message.warning(translate('ui.m_dd9d9d3542ba'))
    if (!form.target) return message.warning(translate('ui.m_a8cd04de6005'))
  } else if (form.target_type === 'fofa') {
    if (!form.name) return message.warning(translate('ui.m_dd9d9d3542ba'))
    srcQ = collectQueries()
    if (!Object.keys(srcQ).length) return message.warning(translate('ui.m_9e2ac9a31a23'))
  } else if (!form.name || !form.target) {
    return message.warning(translate('ui.m_3abc138ec5a6'))
  }
  if (!form.policy_id) return message.warning(translate('ui.m_13a8bd6a155b'))
  // 发起前检测同资产是否已有渗透会话/历史报告（仅当策略启用了 AI 渗透才有意义）。
  // best-effort：检测失败不阻断，直接提交。命中则弹确认框，用户确定后走 doSubmit。
  if (pentestEnabled.value) {
    try {
      const targets = form.target_type === 'unit'
        ? [] : (form.target || '').split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean)
      const unit = form.target_type === 'unit' ? (form.target || '').split(/[\r\n]+/)[0]?.trim() || '' : ''
      if (targets.length || unit) {
        const ov = await intelApi.checkOverlap({ targets, unit })
        if (ov?.overlap) {
          overlapData.value = ov
          overlapOpen.value = true
          return   // 等用户在弹窗里决策（onOverlapConfirm → doSubmit）
        }
      }
    } catch { /* 检测失败不阻断建任务 */ }
  }
  await doSubmit()
}

// 重叠确认弹窗状态
const overlapOpen = ref(false)
const overlapData = ref<OverlapResult | null>(null)
function onOverlapConfirm() { doSubmit() }
function onOverlapCancel() { message.info(translate('ui.m_4454cee2320e')) }

async function doSubmit() {
  const srcQ: Record<string, string> = form.target_type === 'fofa' ? collectQueries() : {}
  loading.value = true
  const missionIntelJson = buildMissionIntel()
  try {
    if (form.target_type === 'unit') {
      // 单位名建任务:一个任务装多个单位,worker 异步反查种子→流式渗透
      const res = await taskFofaApi.submitByUnit({
        name: form.name,
        units: form.target,
        policy_id: form.policy_id || '',
        priority: form.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: missionIntelJson,
        pentest_provider_id: form.pentest_provider_id || '',
        pentest_backup_provider_id: form.pentest_backup_provider_id || '',
        pentest_egress_mode: pentestEnabled.value ? form.pentest_egress_mode : '',
        pentest_fallback_egress_mode: pentestEnabled.value ? form.pentest_fallback_egress_mode : '',
        pentest_max_context_tokens: ctxTokensPayload(),
        observer_enabled: pentestEnabled.value ? form.observer_enabled : false,
        observer_provider_id: (pentestEnabled.value && form.observer_enabled) ? (form.observer_provider_id || '') : '',
      })
      message.success(translate('ui.m_86f0d0b02c27', { p0: (form.name), p1: (res.unit_count) }))
      router.push('/tasks')
      return
    }
    if (form.target_type === 'fofa') {
      // 源查询:多源语句导入,去重互补(带上优先级/白名单/来源/各源数量限制)
      const srcLim = collectLimits(srcQ)
      await taskFofaApi.submit({
        name: form.name,
        queries: srcQ,
        ...(Object.keys(srcLim).length ? { limits: srcLim } : {}),
        policy_id: form.policy_id || '',
        priority: form.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: missionIntelJson,
        pentest_provider_id: form.pentest_provider_id || '',
        pentest_backup_provider_id: form.pentest_backup_provider_id || '',
        pentest_egress_mode: pentestEnabled.value ? form.pentest_egress_mode : '',
        pentest_fallback_egress_mode: pentestEnabled.value ? form.pentest_fallback_egress_mode : '',
        pentest_max_context_tokens: ctxTokensPayload(),
        observer_enabled: pentestEnabled.value ? form.observer_enabled : false,
        observer_provider_id: (pentestEnabled.value && form.observer_enabled) ? (form.observer_provider_id || '') : '',
        'source.unit': form['source.unit'],
      })
    } else {
      await taskApi.policy({
        name: form.name,
        task_tag: 'task',
        target: form.target,
        policy_id: form.policy_id || '',
        priority: form.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: missionIntelJson,
        pentest_provider_id: form.pentest_provider_id || '',
        pentest_backup_provider_id: form.pentest_backup_provider_id || '',
        pentest_egress_mode: pentestEnabled.value ? form.pentest_egress_mode : '',
        pentest_fallback_egress_mode: pentestEnabled.value ? form.pentest_fallback_egress_mode : '',
        pentest_max_context_tokens: ctxTokensPayload(),
        observer_enabled: pentestEnabled.value ? form.observer_enabled : false,
        observer_provider_id: (pentestEnabled.value && form.observer_enabled) ? (form.observer_provider_id || '') : '',
        'source.unit': form['source.unit'],
      })
    }
    message.success(translate('ui.m_20bd8551be46'))
    router.push('/tasks')
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadPolicies()
  loadProviders()
  loadSources()
  getSetupStatus().then(r => { setupStatus.value = r }).catch(() => {})
  // AI 攻击出口可选性：未绑定源的模式变灰。取不到默认全可用（不阻塞建任务）。
  proxyApi.egressOptions().then(r => { egressOpts.value = r || {} }).catch(() => {})
})
</script>

<style scoped>
.muted { color: #999; font-size: 12px; margin-top: 4px; }
.default-hint { color: #1677ff; font-size: 12px; margin-top: 6px; display: flex; align-items: center; gap: 4px; }
.default-hint b { font-weight: 600; }
.mi-row { display: flex; gap: 8px; align-items: flex-start; margin-bottom: 6px; }
/* 源查询：两个一排（2 列网格）；窄屏自动降为单列 */
.src-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; }
@media (max-width: 720px) { .src-grid { grid-template-columns: 1fr; } }
.src-block { margin-bottom: 0; min-width: 0; }
.src-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 13px; }
.src-ok { color: #52c41a; font-weight: 600; }
.src-off { color: #bbb; font-weight: 600; }
.src-est { font-size: 12px; margin-left: auto; }
/* 数量限制框：抵到来源行右侧对齐。有预估(.src-est 已 margin-left:auto)时被推到最右；无预估时自身靠右 */
.src-limit { width: 96px; }
.src-limit-first { margin-left: auto; }
/* 单会话上下文上限滑块：留出节点标记高度，右端「拉满」节点靠近顶端 */
.ctx-slider { padding: 0 8px; max-width: 560px; }
.ctx-slider :deep(.ant-slider) { margin-bottom: 22px; }
.ctx-cur { margin-top: 2px; color: #555; font-size: 12px; display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.ctx-cur b { color: #1677ff; font-weight: 600; }
.ctx-kbox { display: inline-flex; align-items: center; gap: 6px; }
.ctx-native-ck { font-size: 12px; }
</style>
