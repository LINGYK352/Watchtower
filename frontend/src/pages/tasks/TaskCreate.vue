<template>
  <PageContainer title="新建任务" kicker="Create Task" description="选择扫描策略下发任务。策略决定扫描项、PoC、指纹、弱口令等全部能力(在「策略」页维护)。可选填目标来源(补天/360 等),带来源则扫描结果自动归档到该来源。">
    <a-card :bordered="false">
      <a-form layout="vertical" :model="form" @finish="submit">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12">
            <a-form-item label="任务名称" required>
              <a-input v-model:value="form.name"
                :placeholder="form.target_type === 'unit' ? '给这批活起个名(如「六月政府专项」),单位是下一级' : '请输入任务名称'" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12">
            <a-form-item label="扫描策略" required>
              <a-select v-model:value="form.policy_id" :options="policyOptions" placeholder="选择扫描策略"
                show-search :filter-option="filterPolicy" :loading="policyLoading" />
              <div class="muted">策略决定扫描项 / PoC / 指纹 / 弱口令爆破。需自定义请到「策略」页新建/编辑。</div>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item label="目标类型">
          <a-radio-group v-model:value="form.target_type" button-style="solid">
            <a-radio-button value="normal">域名/IP</a-radio-button>
            <a-radio-button value="fofa">源查询</a-radio-button>
            <a-radio-button value="unit">单位名</a-radio-button>
          </a-radio-group>
          <span v-if="form.target_type === 'fofa'" class="muted" style="margin-left:8px">源查询:多测绘源各写各语法,结果去重互补(域名按主机名/纯IP按IP+端口)</span>
          <span v-else-if="form.target_type === 'unit'" class="muted" style="margin-left:8px">单位名:填单位全称(一行一个,可多单位),优先按 ICP 官方备案反查权威域名/IP(查不到降级鹰图/FOFA)→ 每单位建一个任务</span>
        </a-form-item>
        <!-- 普通目标 / 单位名：共用文本框 -->
        <a-form-item v-if="form.target_type !== 'fofa'"
          :label="form.target_type === 'unit' ? '单位全称(一行一个)' : '任务目标'" required>
          <a-textarea v-model:value="form.target" :rows="3"
            :placeholder="form.target_type === 'unit' ? '单位 ICP 备案全称,一行一个(带「有限公司」等全称命中率高)。如:\n北京某某科技有限公司\n某某市人民政府' : '支持域名、IP、IP段；多目标换行'" />
        </a-form-item>

        <!-- 源查询：多测绘源各写各语法，去重互补 -->
        <a-form-item v-else label="源查询" required>
          <div v-if="!sources.length" class="muted">加载可用测绘源中…</div>
          <div class="src-grid">
            <div v-for="s in sources" :key="s.id" class="src-block">
              <div class="src-head">
                <span :class="s.available ? 'src-ok' : 'src-off'">{{ s.available ? '✓' : '✗' }} {{ s.name }}</span>
                <span v-if="!s.available" class="muted">（未配 key）</span>
                <span v-if="srcEst[s.id]" class="src-est"
                  :style="{ color: srcEst[s.id].error ? '#cf1322' : '#52c41a' }">
                  {{ srcEst[s.id].error ? ('错误: ' + srcEst[s.id].errmsg) : ('命中约 ' + srcEst[s.id].size + ' 条') }}
                </span>
                <!-- 数量限制：抵到来源行右侧对齐，默认空=无限制，填正整数则限制抓取条数 -->
                <a-input-number v-model:value="srcLimits[s.id]" :min="1" :precision="0" size="small"
                  class="src-limit" :class="{ 'src-limit-first': !srcEst[s.id] }"
                  :disabled="!s.available" placeholder="无限制" title="抓取数量限制（留空=无限制，填正整数则限制该源抓取条数）" />
              </div>
              <a-textarea v-model:value="srcQueries[s.id]" :rows="2" :disabled="!s.available"
                :placeholder="s.placeholder" />
            </div>
          </div>
          <div style="margin-top:6px">
            <a-button type="link" size="small" :loading="fofaTesting" @click="testSources">测试查询(各源预估)</a-button>
            <span v-if="mergedTip" class="muted">{{ mergedTip }}</span>
          </div>
        </a-form-item>

        <a-form-item label="任务优先级">
          <a-radio-group v-model:value="form.priority" button-style="solid">
            <a-radio-button :value="0">T0</a-radio-button>
            <a-radio-button :value="1">T1</a-radio-button>
            <a-radio-button :value="2">T2</a-radio-button>
          </a-radio-group>
          <div class="muted">高优先级会中断正在跑的低优扫描并让其排队续扫。</div>
        </a-form-item>

        <!-- 渗透相关选项：仅当所选策略勾了「扫描后自动 AI 渗透」才显示（避免填了没人消费的矛盾）。 -->
        <template v-if="pentestEnabled">
          <a-divider style="margin:8px 0">AI 渗透（当前策略已启用）</a-divider>

          <a-form-item label="首要模型">
            <a-select v-model:value="form.pentest_provider_id" :options="providerOptions" allow-clear
              style="max-width:360px" :placeholder="`跟随全局默认：${globalDefaultName}`" />
            <div v-if="!form.pentest_provider_id" class="default-hint">
              <BulbOutlined /> 留空将跟随全局默认 AI：<b>{{ globalDefaultName }}</b>
            </div>
            <div class="muted">锁定本任务派发的渗透会话所用 AI 模型，全程不受后续全局默认切换影响。留空=跟随全局默认（如上）。切换限同协议（OpenAI 系互切 / Claude 系互切），跨协议需新开会话。</div>
          </a-form-item>

          <a-form-item label="备用模型">
            <a-select v-model:value="form.pentest_backup_provider_id" :options="backupProviderOptions"
              style="max-width:360px" placeholder="不指定" />
            <div class="muted">
              默认不指定。只有首要模型完成自身重试与同服务故障转移后仍不可用，才自动切换到备用模型；
              为保证会话历史兼容，只能选择与首要模型相同协议的其他模型。
            </div>
          </a-form-item>

          <a-form-item label="AI 攻击出口">
            <a-radio-group v-model:value="form.pentest_egress_mode" button-style="solid" size="small">
              <a-radio-button value="direct">直连</a-radio-button>
              <a-tooltip :title="egressOpts.global && !egressOpts.global.available ? egressOpts.global.reason : ''">
                <a-radio-button value="global" :disabled="egressOpts.global && !egressOpts.global.available">全局</a-radio-button>
              </a-tooltip>
              <a-tooltip :title="egressOpts.smart && !egressOpts.smart.available ? egressOpts.smart.reason : ''">
                <a-radio-button value="smart" :disabled="egressOpts.smart && !egressOpts.smart.available">智能</a-radio-button>
              </a-tooltip>
            </a-radio-group>
            <div class="muted">AI 渗透打目标的出口。直连=不走代理;全局=走代理中心「全局代理」绑定的源;智能=代理可达走代理、不可达自动降级直连(推荐)。未绑定代理源的模式已置灰(去代理中心配置)。留空跟随所选策略默认。</div>
          </a-form-item>

          <a-form-item label="AI 封禁备用出口">
            <a-radio-group v-model:value="form.pentest_fallback_egress_mode" button-style="solid" size="small">
              <a-radio-button value="direct">直连</a-radio-button>
              <a-tooltip :title="egressOpts.global && !egressOpts.global.available ? egressOpts.global.reason : ''">
                <a-radio-button value="global" :disabled="egressOpts.global && !egressOpts.global.available">全局</a-radio-button>
              </a-tooltip>
              <a-tooltip :title="egressOpts.smart && !egressOpts.smart.available ? egressOpts.smart.reason : ''">
                <a-radio-button value="smart" :disabled="egressOpts.smart && !egressOpts.smart.available">智能</a-radio-button>
              </a-tooltip>
            </a-radio-group>
            <div class="muted">主出口被目标封禁(整站拦截/CDN Forbid)时，AI 可<b>自主</b>切到此备用出口继续打，而非直接放弃。也按模式选，默认直连。用不用由 AI 判断——相当于多给它一个出口选项。</div>
          </a-form-item>

          <a-form-item label="单会话上下文上限">
            <div class="ctx-slider">
              <a-slider :value="ctxPos" @change="onCtxSlide" :min="0" :max="CTX_MAX_POS" :step="1"
                :marks="ctxMarks" :tip-formatter="() => ctxLabel" />
              <div class="ctx-cur">
                <span>当前：<b>{{ ctxLabel }}</b></span>
                <!-- 拉满名称后小输入框：滑块封顶 512K，够不到的大值（如 900k）直接输入。单位 k。 -->
                <span class="ctx-kbox">精确值
                  <a-input-number v-model:value="ctxKInput" :min="0" :step="8" size="small"
                    :disabled="ctxNative" style="width:96px" addon-after="k" />
                </span>
                <a-checkbox v-model:checked="ctxNative" class="ctx-native-ck">拉满（原生上限）</a-checkbox>
              </div>
            </div>
            <div class="muted">拖动长条设置本任务每个渗透会话的上下文窗口上限（达上限 90% 即强制收尾）。最左=<b>跟随全局默认</b>（用 AI 配置里的全局值，0k）；中段=自定义 token（可拖到 1000K）；更大值（如 1200k）在右侧<b>精确值</b>框直接输入。勾<b>拉满</b>=按所选模型原生最大上下文（如 Claude 1M 版本自动识别），不设人为上限。此项仅对本任务生效，不改全局/策略。</div>
          </a-form-item>

          <a-form-item label="监督者">
            <a-switch v-model:checked="form.observer_enabled" checked-children="启用" un-checked-children="关闭" />
            <div class="muted">
              独立的旁路「监督者」AI，在主渗透 AI 每跑若干轮后回看其最近轨迹，做<b>语义判断</b>——
              发现方向跑偏、打在 WAF/蜜罐假象上、证据不实、低质量重复、该收尾却磨蹭时，注入一句纠偏建议（仅供参考，主 AI 自行实测确认）。
              内置冷却+去重防刷屏。<b>默认关闭</b>；开启会额外消耗少量 token（建议给监督者选便宜模型）。
            </div>
            <div v-if="form.observer_enabled" style="margin-top:10px">
              <a-select v-model:value="form.observer_provider_id" :options="providerOptions" allow-clear
                style="max-width:360px" :placeholder="`跟随全局默认：${globalDefaultName}`" />
              <div v-if="!form.observer_provider_id" class="default-hint">
                <BulbOutlined /> 留空将跟随全局默认 AI：<b>{{ globalDefaultName }}</b>
              </div>
              <div class="muted">监督者用的 AI 模型。它只做轻量审查，可单独选一个便宜/快速的模型省成本，与主渗透 AI 互不影响。留空=跟随全局默认。</div>
            </div>
          </a-form-item>

          <a-form-item label="禁渗透白名单">
            <a-textarea v-model:value="form.pentest_whitelist" :rows="2"
              placeholder="暂不允许渗透的域名,多个换行/逗号分隔。完整子域名如 oa.example.com 精确匹配;主域用 *.example.com 通配(含其所有子域)" />
            <div class="muted">扫描照常进行,但自动派发 AI 渗透时跳过命中白名单的站点。</div>
          </a-form-item>

          <a-form-item label="临时情报">
            <div class="muted" style="margin-bottom:6px">
              授权方交代的自由情报(账号密码/后台位置/工号规则/WAF类型/内网可达/测试重点),按提示词注入 AI 渗透会话开局。
              作用范围:留空=整个任务;填单位=只该单位资产;填目标=只该域名/host。
            </div>
            <div v-for="(mi, idx) in missionIntel" :key="idx" class="mi-row">
              <a-select v-model:value="mi.scope" :options="miScopeOptions" style="width:110px"
                @change="() => onScopeChange(mi)" />
              <a-input v-if="mi.scope==='unit'" v-model:value="mi.scopeVal" placeholder="单位全称" style="width:160px" />
              <a-input v-else-if="mi.scope==='target'" v-model:value="mi.scopeVal" placeholder="域名/host 如 oa.x.com" style="width:180px" />
              <a-textarea v-model:value="mi.text" :rows="1" :auto-size="{minRows:1,maxRows:4}"
                placeholder="如:账号 admin/Passw0rd 登录 /admin;重点测支付模块;WAF 是安恒" style="flex:1" />
              <a-button type="text" danger @click="removeMi(idx)"><template #icon><DeleteOutlined /></template></a-button>
            </div>
            <a-button type="dashed" size="small" @click="addMi" style="margin-top:4px">
              <template #icon><PlusOutlined /></template>添加一条临时情报
            </a-button>
          </a-form-item>
        </template>
        <!-- 选了策略但未启用 AI 渗透：明确告知，避免用户找不到渗透选项 -->
        <a-alert v-else-if="form.policy_id" type="info" show-icon style="margin:8px 0"
          message="当前策略未启用「扫描后自动 AI 渗透」"
          description="如需为本任务配置 AI 模型/临时情报/禁渗透白名单,请到「策略」页勾选该策略的「扫描完成后自动 AI 渗透」。" />

        <a-divider style="margin:8px 0">批量导入</a-divider>
        <a-form-item>
          <a-space wrap>
            <a-button @click="downloadTemplate"><template #icon><DownloadOutlined /></template>下载 CSV 模板</a-button>
            <a-upload :before-upload="handleCsvUpload" :show-upload-list="false" accept=".csv">
              <a-button type="dashed"><template #icon><UploadOutlined /></template>上传 CSV 批量建任务</a-button>
            </a-upload>
            <span class="muted">按模板填写后上传,每行一个任务(共用上方所选策略)。目标必填,任务名/优先级可留空。</span>
          </a-space>
        </a-form-item>

        <a-divider style="margin:8px 0">目标归属(可选)</a-divider>
        <a-row :gutter="16">
          <a-col :xs="24" :md="8">
            <a-form-item label="单位"><a-input v-model:value="form['source.unit']" placeholder="厂商/单位名" /></a-form-item>
          </a-col>
        </a-row>

        <a-form-item>
          <a-space>
            <a-button type="primary" html-type="submit" :loading="loading">提交任务</a-button>
            <a-button @click="router.push('/tasks')">返回列表</a-button>
          </a-space>
        </a-form-item>
      </a-form>
    </a-card>
    <OverlapConfirmModal v-model:open="overlapOpen" :data="overlapData"
      @confirm="onOverlapConfirm" @cancel="onOverlapCancel" />
  </PageContainer>
</template>

<script setup lang="ts">
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
  label: `${p.name}（${p.protocol === 'claude' ? 'Claude' : 'OpenAI'}协议）`, value: p._id,
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
    const note = isPrimary ? ' · 已作首要' : (cross ? ' · 跨协议不可选' : '')
    return {
      label: `${p.name}（${proto === 'claude' ? 'Claude' : 'OpenAI'}协议）${note}`,
      value: p._id, disabled: bad,
    }
  })
  return [{ label: '不指定', value: '', disabled: false }, ...options]
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
  return p ? `${p.name}（${p.protocol === 'claude' ? 'Claude' : 'OpenAI'}协议）` : '未设置全局默认 AI（请先到「AI 配置」设置）'
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
  { label: '整个任务', value: 'task' },
  { label: '指定单位', value: 'unit' },
  { label: '指定目标', value: 'target' }
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
  if (t < 0) return '拉满 · 模型原生上限'
  if (t === 0) return '跟随全局默认（0k）'
  return `${Math.round(t / 1000)}K tokens`
})
// 节点标记：最左「默认」、中段刻度、最右「1000K」（1000K 以上走输入框）
const ctxMarks = {
  0: '默认',
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
    message.error((e as Error).message || '加载策略失败')
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
  if (!form.policy_id) { message.warning('请先选择扫描策略,批量任务共用该策略'); return false }
  const reader = new FileReader()
  reader.onload = () => {
    const text = String(reader.result || '').replace(/\r/g, '')
    const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
    if (!lines.length) { message.warning('文件为空'); return }
    // 跳过表头(首行含“目标”视为表头)
    const rows = lines[0].includes('目标') ? lines.slice(1) : lines
    const items = rows.map(parseCsvRow).filter(c => c[0]).map(c => ({
      target: c[0],
      name: c[1] || `批量-${c[0]}`,
      priority: c[2] !== undefined && c[2] !== '' ? Number(c[2]) : form.priority
    }))
    if (!items.length) { message.warning('未解析到有效目标'); return }
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
  message.success(`批量提交完成:成功 ${ok} 个${fail ? `,失败 ${fail} 个` : ''}`)
  if (ok) router.push('/tasks')
}


async function testFofa() {
  if (!form.target) return message.warning('请先填写 FOFA 查询语句')
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
  if (!Object.keys(queries).length) return message.warning('请至少填写一个可用源的查询语句')
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
    if (!form.name) return message.warning('请填写任务名称')
    if (!form.target) return message.warning('请填写单位全称(一行一个)')
  } else if (form.target_type === 'fofa') {
    if (!form.name) return message.warning('请填写任务名称')
    srcQ = collectQueries()
    if (!Object.keys(srcQ).length) return message.warning('请至少填写一个可用源的查询语句')
  } else if (!form.name || !form.target) {
    return message.warning('请填写任务名称和目标')
  }
  if (!form.policy_id) return message.warning('请选择扫描策略')
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
function onOverlapCancel() { message.info('已取消任务') }

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
      message.success(`任务「${form.name}」已建(${res.unit_count} 个单位,后台反查中)`)
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
    message.success('任务已提交')
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
