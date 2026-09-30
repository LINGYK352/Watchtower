<template>
  <PageContainer title="AI 配置中心" kicker="AI Config" description="配置 AI 渗透所需的大模型接入、提示词模板与全局参数。">
    <template #extra>
      <a-button @click="loadAll">刷新</a-button>
    </template>

    <!-- 全局参数 -->
    <a-card class="page-card" title="全局参数" size="small">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :span="8">
            <a-form-item label="默认 AI">
              <a-select v-model:value="config.active_provider_id" allow-clear :options="providerOptions" placeholder="任务环节未单独绑定 AI 时回退用它" />
            </a-form-item>
          </a-col>
          <a-col :span="6"><a-form-item label="超时(秒)"><a-input-number v-model:value="config.timeout" :min="1" style="width: 100%" /></a-form-item></a-col>
          <!-- 问题18：删全局「出口走代理」开关。入口代理下沉到每个 provider 的「入口代理」（新增/编辑里选具体自定义代理条目）。 -->
        </a-row>
        <a-form-item label="代码审计源码落地目录">
          <a-input v-model:value="config.source_code_dir" placeholder="开源系统拉取源码的服务器根目录" />
        </a-form-item>
        <a-form-item label="AI 渗透会话并发上限">
          <a-row :gutter="12" align="middle">
            <a-col :span="8">
              <a-input-number v-model:value="config.max_concurrent_sessions" :min="0" style="width: 100%"
                :placeholder="`0=自动推荐(${config.recommend_concurrency || '-'})`" />
            </a-col>
            <a-col :span="16">
              <span class="hint">同时运行的 AI 渗透会话数上限。<b>0 = 按服务器资源自动推荐(当前推荐 {{ config.recommend_concurrency ?? '-' }})</b>;当前生效 {{ config.effective_concurrency ?? '-' }}。超限的会话进排队,有空位自动放行。</span>
            </a-col>
          </a-row>
        </a-form-item>
        <a-button type="primary" :loading="loading" @click="saveConfig">保存全局参数</a-button>
      </a-form>
    </a-card>

    <!-- Token 消耗仪表盘 -->
    <a-card class="page-card" title="Token 消耗仪表盘" size="small">
      <template #extra><a-button size="small" @click="loadUsage">刷新</a-button></template>
      <a-row :gutter="16" style="margin-bottom: 12px">
        <a-col :span="6"><a-statistic title="总调用次数" :value="usage.overall.calls" /></a-col>
        <a-col :span="6"><a-statistic title="总 Token" :value="usage.overall.total" /></a-col>
        <a-col :span="6"><a-statistic title="输入 / 输出" :value="usage.overall.prompt" :suffix="`/ ${usage.overall.completion}`" /></a-col>
        <a-col :span="6"><a-statistic title="失败调用" :value="usage.overall.fail_calls" :value-style="{ color: usage.overall.fail_calls ? '#cf1322' : undefined }" /></a-col>
      </a-row>
      <a-row :gutter="16">
        <a-col :span="12">
          <p style="margin:4px 0"><b>按 Provider</b></p>
          <a-table :columns="usageCols" :data-source="usage.by_provider" :pagination="false" size="small" row-key="name" bordered>
            <template #emptyText>暂无调用记录(AI 引擎接入后自动统计)</template>
          </a-table>
        </a-col>
        <a-col :span="12">
          <p style="margin:4px 0"><b>按任务环节</b></p>
          <a-table :columns="usageCols" :data-source="usage.by_scene" :pagination="false" size="small" row-key="name" bordered>
            <template #emptyText>暂无调用记录</template>
          </a-table>
        </a-col>
      </a-row>
    </a-card>

    <!-- Provider -->
    <a-card class="page-card" title="大模型接入" size="small">
      <template #extra><a-button type="primary" size="small" @click="openProvider()">新增 Provider</a-button></template>
      <a-table :columns="providerColumns" :data-source="providers" :loading="loading" row-key="_id"
        :pagination="false" size="middle" bordered :scroll="{ x: 1200 }" :row-class-name="(r: any) => r.enabled ? 'row-enabled' : ''">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'type'">
            <span class="provider-type">
              <span class="provider-icon" v-html="providerIcon(iconKey(String(record.type)))"></span>
              <a-tag>{{ typeLabel(String(record.type)) }}</a-tag>
            </span>
          </template>
          <template v-else-if="column.key === 'enabled'">
            <a-badge v-if="record.enabled" status="success" text="已启用" />
            <a-tag v-else color="default">停用</a-tag>
          </template>
          <template v-else-if="column.key === 'proxy_id'">
            <!-- 问题18：入口代理列。按 proxy_id 在已加载自定义代理列表里查名字，空/查不到=直连 -->
            <a-tag :color="record.proxy_id ? 'blue' : 'default'">{{ proxyName(record.proxy_id) }}</a-tag>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space>
              <a-button type="link" size="small" @click="openTest(record as AIProvider)">测试</a-button>
              <a-button type="link" size="small" @click="openProvider(record as AIProvider)">编辑</a-button>
              <ConfirmAction danger type="link" size="small" title="确认删除该 Provider？" @confirm="removeProvider(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- AI 测试面板:选已配 AI(绿色=已启用)→ 输入(默认你好)→ 看回复 -->
    <a-card class="page-card" title="AI 测试" size="small">
      <a-row :gutter="12" align="bottom">
        <a-col :span="9">
          <div class="t-label">选择 AI</div>
          <a-select v-model:value="testId" style="width:100%" placeholder="选一个已配置的 AI" :options="testOptions">
            <template #option="{ label, enabled }">
              <span><a-badge :status="enabled ? 'success' : 'default'" /> {{ label }}</span>
            </template>
          </a-select>
        </a-col>
        <a-col :span="10">
          <div class="t-label">测试输入</div>
          <a-input v-model:value="testMsg" placeholder="你好" @press-enter="runTest" />
        </a-col>
        <a-col :span="5">
          <a-button type="primary" block :loading="testing" :disabled="!testId" @click="runTest">发送测试</a-button>
        </a-col>
      </a-row>
      <div v-if="testResult" class="t-result" :class="testResult.ok ? 'ok' : 'fail'">
        <div class="t-meta">
          <a-tag :color="testResult.ok ? 'green' : 'red'">{{ testResult.ok ? '成功' : '失败' }}</a-tag>
          <span v-if="testResult.model">模型 {{ testResult.model }}</span>
          <span v-if="testResult.total_tokens">· {{ testResult.total_tokens }} tokens</span>
          <span>· {{ testResult.proxy_enabled ? '经代理' : '直连' }}</span>
        </div>
        <pre class="t-reply">{{ testResult.ok ? testResult.content : testResult.error }}</pre>
      </div>
    </a-card>

    <!-- Prompt -->
    <a-card class="page-card" title="AI 任务环节" size="small">
      <template #extra><a-button type="primary" size="small" @click="openPrompt()">新增环节</a-button></template>
      <a-alert type="info" show-icon style="margin-bottom: 12px"
        message="每个环节可单独勾选启用、编辑该环节专属提示词。AI 模型已改在「新建任务」时按任务选择，环节「绑定 AI」已冻结（存量绑定仍生效，未绑定回退上方“默认 AI”）。" />
      <a-table :columns="sceneColumns" :data-source="prompts" :loading="loading" row-key="_id"
        :pagination="false" size="middle" bordered>
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enabled'">
            <!-- 内置环节属系统核心，启用开关变灰强制启用不可关（防误关坏渗透/审查链路）；自定义环节可自由启停 -->
            <a-tooltip v-if="(record as AIPrompt).builtin" title="内置环节属系统核心，强制启用不可关闭">
              <a-switch :checked="true" size="small" disabled />
            </a-tooltip>
            <a-switch v-else :checked="record.enabled" size="small" @change="(v: any) => toggleScene(record as AIPrompt, !!v)" />
          </template>
          <template v-else-if="column.key === 'scene'">
            <span class="scene-cell">
              <a-tag color="purple" class="scene-tag">{{ record.scene_name || record.scene }}</a-tag>
              <span v-if="record.name && record.name !== (record.scene_name || record.scene)" class="scene-name">{{ record.name }}</span>
            </span>
          </template>
          <template v-else-if="column.key === 'provider'">
            <!-- v1.21.157-47 冻结：模型改在「新建任务」按任务选（pentest_provider_id 等），scene 绑定已废弃。
                 只读展示已绑定值(存量保留可解析)，不允许改。 -->
            <a-tooltip title="已改为在「新建任务」时按任务选择 AI 模型，此处不再绑定">
              <a-tag :color="(record as AIPrompt).provider_id ? 'blue' : 'default'">
                {{ (record as AIPrompt).provider_name || '默认 AI (兜底)' }}
              </a-tag>
            </a-tooltip>
          </template>
          <template v-else-if="column.key === 'content'">
            <a-tooltip v-if="(record as AIPrompt).builtin" title="内置提示词,不可编辑(防误改坏渗透/审查质量)">
              <a-tag color="blue">内置</a-tag>
            </a-tooltip>
            <a-tag v-else-if="!record.content" color="orange">未填写</a-tag>
            <span v-else class="content-snippet">{{ String(record.content).slice(0, 40) }}…</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space>
              <a-tooltip v-if="(record as AIPrompt).builtin" title="内置提示词不可编辑(防误改)；AI 模型改在「新建任务」按任务选">
                <a-button type="link" size="small" disabled>编辑提示词</a-button>
              </a-tooltip>
              <a-button v-else type="link" size="small" @click="openPrompt(record as AIPrompt)">编辑提示词</a-button>
              <ConfirmAction v-if="!(record as AIPrompt).builtin" danger type="link" size="small" title="确认删除该环节？" @confirm="removePrompt(record._id as string)">删除</ConfirmAction>
              <a-tooltip v-else title="内置环节属系统核心，只能停用不可删除">
                <a-tag color="blue">内置</a-tag>
              </a-tooltip>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 模型校验中弹窗（保存前校验有效性，通过才存档） -->
    <a-modal :open="validating" :footer="null" :closable="false" :mask-closable="false" width="360" centered>
      <div style="text-align:center;padding:16px 0">
        <a-spin size="large" />
        <p style="margin-top:16px;color:#555">正在校验模型有效性（连通性 + 密钥）…<br/>校验通过后才会存档</p>
      </div>
    </a-modal>

    <!-- Provider 编辑弹窗:选厂商 → 生成原生 JSON → 改 key/base_url → 提交 -->
    <a-modal v-model:open="providerOpen" :title="editingId ? '编辑 Provider' : '新增 Provider'" :confirm-loading="loading" width="640" @ok="saveProvider">
      <a-form layout="vertical">
        <a-row :gutter="12" align="bottom">
          <a-col :span="16">
            <a-form-item label="厂商" style="margin-bottom:8px">
              <a-select v-model:value="cfgType" :options="typeOptions" @change="(v: any) => applyTemplate(String(v))">
                <template #option="{ value: v, label }">
                  <span class="provider-opt">
                    <span class="provider-icon" v-html="providerIcon(iconKey(String(v)))"></span>
                    <span>{{ label }}</span>
                  </span>
                </template>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item style="margin-bottom:8px">
              <a-button block @click="resetTemplate">重置为该厂商模板</a-button>
            </a-form-item>
          </a-col>
        </a-row>
        <!-- 问题18：入口代理选择——调用 AI(访问中转站/LLM)的入口代理，选具体自定义代理条目，默认直连。
             与任务发起时的攻击出口(AI→目标)彻底双轨分离。选中即写入下方 JSON 的 proxy_id(JSON 仍是提交源)。 -->
        <a-form-item label="入口代理（访问中转站/LLM 出网）">
          <a-select v-model:value="ingressProxyId" :options="ingressProxyOptions" style="width:100%"
            placeholder="默认直连；可选一条已启用的自定义代理" />
          <span class="hint">仅用于平台调用 AI 时的出网（境外中转站可选代理连通）。与「任务发起→AI 攻击目标」的出口代理是两回事，互不影响。可选条目来自「代理中心 · 自定义代理」（仅列已启用）。</span>
        </a-form-item>
        <a-form-item label="配置">
          <a-alert v-if="editingId" type="info" style="margin-bottom:8px" show-icon
            message="api_key 留空保持原值，输入新值覆盖。base_url 可直接修改。" />
          <a-textarea v-model:value="cfgText" :rows="14" spellcheck="false"
            style="font-family: monospace; font-size: 13px"
            placeholder='选厂商自动生成模板,在此填 api_key、按需改 base_url/model/reasoning_effort' />
          <div class="field-guide">
            <div class="fg-title">各字段说明（直接编辑上方 JSON）：</div>
            <div class="fg-item"><b>base_url</b>：接口地址。填 AI 服务/中转站的 API 根地址（如 <code>https://api.openai.com/v1</code>、<code>https://api.deepseek.com</code>；本地部署填 <code>http://localhost:11434/v1</code> 等 OpenAI 兼容地址）。选厂商已自动填好，用中转站才需改。</div>
            <div class="fg-item"><b>api_key</b>：你的密钥。填 AI 服务商或中转站给你的 API Key（<code>sk-...</code> 之类）。<span v-if="editingId">编辑时留空=保留原 key。</span></div>
            <div class="fg-item"><b>model</b>：模型名。填要用的模型标识（如 <code>gpt-4o</code>、<code>claude-opus-4-8</code>、<code>deepseek-chat</code>）。以服务商文档为准，选厂商已带默认。</div>
            <div class="fg-item"><b>reasoning_effort</b>：思考程度（推理投入）。<b>默认 high（高）</b>——想更快/更省可改 <code>medium</code>/<code>low</code>；Claude 系可填数字 thinking budget；DeepSeek 等不支持的填空串 <code>""</code>。</div>
            <div class="fg-item"><b>protocol</b>：调用协议。<code>openai</code>（OpenAI 兼容）或 <code>claude</code>（Anthropic），决定按哪种格式调用，选厂商已自动定。</div>
            <div class="fg-note">也支持直接粘贴 Claude Code 的 settings.json（含 env.ANTHROPIC_*）。</div>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Prompt 编辑弹窗 -->
    <a-modal v-model:open="promptOpen" :title="promptForm._id ? '编辑任务环节' : '新增任务环节'" :confirm-loading="loading" width="760" @ok="savePrompt">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :span="8">
            <a-form-item label="场景">
              <a-select v-model:value="promptForm.scene" :options="sceneOptions" />
            </a-form-item>
          </a-col>
          <a-col :span="8"><a-form-item label="环节名"><a-input v-model:value="promptForm.name" /></a-form-item></a-col>
          <a-col :span="8">
            <a-form-item label="绑定 AI">
              <!-- v1.21.157-47 冻结：改在「新建任务」按任务选 AI 模型；此处只读展示，不再绑定 -->
              <a-select v-model:value="promptForm.provider_id" disabled placeholder="默认 AI (兜底)">
                <a-select-option value="">默认 AI (兜底)</a-select-option>
                <a-select-option v-for="p in providers" :key="p._id" :value="p._id">{{ p.name }}</a-select-option>
              </a-select>
              <div class="hint">模型已改在「新建任务」时按任务选择，此处不再绑定。</div>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item label="提示词内容">
          <a-textarea v-model:value="promptForm.content" :rows="14" placeholder="按该环节绑定的 AI 特性编写系统提示词,例如 Claude 用 XML 结构、推理模型避免手把手分解步骤..." />
        </a-form-item>
        <a-space><span>启用该环节</span><a-switch v-model:checked="promptForm.enabled" /></a-space>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { aiConfigApi, type AIConfig, type AIProvider, type AIPrompt, type AIPreset, type UsageStat } from '../../api/aiConfig'
import { proxyApi, type CustomProxy } from '../../api/proxy'
import { providerIcon } from '../../config/providerIcons'

const loading = ref(false)

const usageCols = [
  { title: '名称', dataIndex: 'name', ellipsis: true },
  { title: '调用', dataIndex: 'calls', width: 80 },
  { title: 'Token', dataIndex: 'total', width: 100 }
]
const usage = ref<UsageStat>({ overall: { calls: 0, prompt: 0, completion: 0, total: 0, fail_calls: 0 }, by_provider: [], by_scene: [] })

const config = reactive<AIConfig>({
  active_provider_id: '', max_context_tokens: 400000, max_concurrent_sessions: 0, timeout: 300,
  source_code_dir: ''
} as AIConfig)
// 问题18：入口代理下拉数据源（只列 enabled 的自定义代理条目），provider.proxy_id 引用其 _id
const customProxies = ref<CustomProxy[]>([])
// 入口代理下拉选项：默认「直连」(value='')，其后是各 enabled 自定义代理
const ingressProxyOptions = computed(() => [
  { label: '直连（不走代理）', value: '' },
  ...customProxies.value.map(c => ({ label: c.name || c.url, value: c._id }))
])
// 按 proxy_id 查代理名（供列表列展示），空/查不到=直连
function proxyName(id?: string): string {
  if (!id) return '直连'
  return customProxies.value.find(c => c._id === id)?.name || '直连'
}
const providers = ref<AIProvider[]>([])
const presets = ref<AIPreset[]>([])
const prompts = ref<AIPrompt[]>([])

// 厂商选项由后端预设驱动(带图标);选厂商自动填 base_url + 默认模型
const typeOptions = computed(() => presets.value.map(p => ({ label: p.label, value: p.key })))
const presetMap = computed<Record<string, AIPreset>>(() =>
  Object.fromEntries(presets.value.map(p => [p.key, p])))
const typeLabel = (t: string) => presetMap.value[t]?.label || t
const iconKey = (t: string) => presetMap.value[t]?.icon || t || 'custom'
const sceneOptions = [
  { label: '渗透执行(探测模式)', value: 'pentest_exec_detect' },
  { label: '渗透执行(保守模式)', value: 'pentest_exec_conservative' },
  { label: '渗透执行(常规模式)', value: 'pentest_exec' },
  { label: '渗透执行(红队模式)', value: 'pentest_exec_redteam' },
  { label: '安全闸刀·标准(常规模式)', value: 'guard' },
  { label: '安全闸刀·保守(保守模式)', value: 'guard_conservative' },
  { label: '安全闸刀·探测(探测模式)', value: 'guard_detect' },
  { label: '代码审计', value: 'code_audit' },
  { label: '自定义', value: 'custom' }
]

const providerOptions = computed(() => providers.value.map(p => ({ label: `${p.name} (${p.model || p.type})`, value: p._id })))

const providerColumns = [
  { title: '名称', dataIndex: 'name', width: 150, ellipsis: true },
  { title: '类型', key: 'type', width: 160 },
  { title: '模型', dataIndex: 'model', width: 180, ellipsis: true },
  { title: '接口地址', dataIndex: 'base_url', width: 200, ellipsis: true },
  { title: 'API Key', dataIndex: 'api_key', width: 160, ellipsis: true },
  { title: '状态', key: 'enabled', width: 84 },
  { title: '代理', key: 'proxy_id', width: 120 },
  { title: '操作', key: 'action', width: 180, fixed: 'right' }
]

const sceneColumns = [
  { title: '启用', key: 'enabled', width: 70 },
  { title: '任务环节', key: 'scene', width: 260 },
  { title: '绑定 AI', key: 'provider', width: 220 },
  { title: '提示词', key: 'content', ellipsis: true },
  { title: '操作', key: 'action', width: 180 }
]

async function loadConfig() {
  try { Object.assign(config, await aiConfigApi.getConfig()) } catch (e) { message.error((e as Error).message) }
}
async function loadProviders() {
  try {
    providers.value = (await aiConfigApi.providers()).items
    // 默认 AI 未设置时，自动选并显示第一个已配置的模型（优先已启用的）
    if (!config.active_provider_id && providers.value.length) {
      const first = providers.value.find(p => p.enabled) || providers.value[0]
      if (first?._id) config.active_provider_id = first._id
    }
  } catch (e) { message.error((e as Error).message) }
}
// 任务环节展示顺序：渗透执行四档按强度(探测→保守→常规→红队)在最前，其余(闸刀三档/代码审计/自定义)排后
const SCENE_ORDER = ['pentest_exec_detect', 'pentest_exec_conservative', 'pentest_exec', 'pentest_exec_redteam',
  'guard', 'guard_conservative', 'guard_detect', 'code_audit']
function sceneRank(scene: string): number {
  const i = SCENE_ORDER.indexOf(scene)
  return i === -1 ? SCENE_ORDER.length : i
}
async function loadPrompts() {
  try {
    const items = (await aiConfigApi.prompts()).items
    items.sort((a, b) => sceneRank(a.scene) - sceneRank(b.scene))
    prompts.value = items
  } catch (e) { message.error((e as Error).message) }
}
async function loadPresets() {
  try { presets.value = (await aiConfigApi.presets()).items } catch (e) { message.error((e as Error).message) }
}
async function loadUsage() {
  try { usage.value = await aiConfigApi.usageStat() } catch (e) { message.error((e as Error).message) }
}
// 问题18：加载可选入口代理（只列 enabled 的自定义代理供 provider 选）；失败静默降级空列表
async function loadCustomProxies() {
  try { customProxies.value = (await proxyApi.customList()).items.filter(c => c.enabled) }
  catch { customProxies.value = [] }
}
function loadAll() { loadPresets(); loadConfig(); loadProviders(); loadPrompts(); loadUsage(); loadCustomProxies() }

// AI 测试面板
const testId = ref<string | undefined>(undefined)
const testMsg = ref('你好')
const testing = ref(false)
const testResult = ref<{ ok: boolean; content: string; model: string; total_tokens: number; proxy_enabled: boolean; error: string } | null>(null)
const testOptions = computed(() => providers.value.map(p => ({
  label: `${p.name} (${p.model || p.type})${p.enabled ? '' : ' [停用]'}`, value: p._id, enabled: p.enabled
})))
function openTest(record: AIProvider) {
  testId.value = record._id
  testResult.value = null
  // 滚到测试面板
  setTimeout(() => document.querySelector('.t-result, .t-label')?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 50)
}
async function runTest() {
  if (!testId.value) return message.warning('请选择一个 AI')
  testing.value = true
  testResult.value = null
  try {
    testResult.value = await aiConfigApi.testProvider(testId.value, testMsg.value || '你好')
  } catch (e) {
    testResult.value = { ok: false, content: '', model: '', total_tokens: 0, proxy_enabled: false, error: (e as Error).message || '请求失败' }
  } finally { testing.value = false }
}

async function saveConfig() {
  loading.value = true
  try {
    Object.assign(config, await aiConfigApi.saveConfig({
      active_provider_id: config.active_provider_id,
      max_context_tokens: config.max_context_tokens,
      max_concurrent_sessions: config.max_concurrent_sessions, timeout: config.timeout,
      source_code_dir: config.source_code_dir
    }))
    message.success('已保存')
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

// Provider 编辑:选厂商 → 原生 JSON 编辑框
const providerOpen = ref(false)
const editingId = ref<string | undefined>(undefined)
const cfgType = ref('openai')
const cfgText = ref('')
const validating = ref(false)   // 保存前模型校验中（弹窗遮罩）

// 问题18：入口代理下拉与 JSON(cfgText) 双向绑定——JSON 仍是提交源，下拉只是便捷入口。
// 读：解析 cfgText 取 proxy_id（解析失败=空）；写：把选中值回填进 JSON 的 proxy_id 再序列化。
const ingressProxyId = computed<string>({
  get() {
    try { return (JSON.parse(cfgText.value || '{}').proxy_id as string) || '' } catch { return '' }
  },
  set(v: string) {
    let obj: Record<string, unknown>
    try { obj = JSON.parse(cfgText.value || '{}') } catch { return }  // JSON 手改坏时不覆盖，避免丢用户输入
    obj.proxy_id = v || ''
    cfgText.value = JSON.stringify(obj, null, 2)
  }
})

// 默认模型名自增（需求5）：类型(厂商 preset key)与名称(name)是两个东西——名称可自填，
// 用默认名时同名冲突（换中转站配同一模型）要能新增。规则：第一个用裸 label（如 "Claude (Anthropic)"），
// 已存在则取首个空位后缀 " - 1"/" - 2"…。仅生成默认值，用户仍可在 JSON 里手改 name。
function nextProviderName(label: string): string {
  if (!label) return ''
  const existing = new Set(providers.value.map(p => (p.name || '').trim()))
  if (!existing.has(label)) return label
  for (let i = 1; ; i++) {
    const candidate = `${label} - ${i}`
    if (!existing.has(candidate)) return candidate
  }
}
function templateFor(t: string): string {
  const p = presetMap.value[t]
  const tpl = { ...(p?.template ?? { name: '', protocol: 'openai', base_url: '', api_key: '', model: '', reasoning_effort: '', enabled: true, proxy_id: '' }) }
  // 默认名基于 preset.label 自增；无 preset（自定义）保持模板原 name
  const label = (p?.label ?? '').trim() || (typeof tpl.name === 'string' ? tpl.name : '')
  if (label) tpl.name = nextProviderName(label)
  // 思考程度默认「高」：模板未显式指定 reasoning_effort 时填 high（用户可在 JSON 里改 medium/low/""）
  if (tpl.reasoning_effort === undefined || tpl.reasoning_effort === '') tpl.reasoning_effort = 'high'
  return JSON.stringify(tpl, null, 2)
}
function applyTemplate(t: string) {
  cfgType.value = t
  cfgText.value = templateFor(t)
}
function resetTemplate() {
  cfgText.value = templateFor(cfgType.value)
  message.success('已重置为该厂商模板')
}
function openProvider(record?: AIProvider) {
  if (record) {
    editingId.value = record._id
    cfgType.value = record.type || 'custom'
    // 编辑:展示现有配置(api_key 用掩码占位,留空=保留原 key)
    cfgText.value = JSON.stringify({
      name: record.name, protocol: record.protocol, base_url: record.base_url,
      api_key: '', model: record.model, reasoning_effort: record.reasoning_effort || 'high',
      enabled: record.enabled, proxy_id: record.proxy_id || ''
    }, null, 2)
  } else {
    editingId.value = undefined
    cfgType.value = 'openai'
    cfgText.value = templateFor('openai')
  }
  providerOpen.value = true
}
async function saveProvider() {
  try { JSON.parse(cfgText.value) } catch { return message.error('JSON 格式错误,请检查') }
  loading.value = true
  try {
    // 保存前先校验模型有效性（连通性+key），通过才存档；校验期间弹窗提示
    validating.value = true
    let vr
    try {
      vr = await aiConfigApi.testProviderConfig(cfgText.value, cfgType.value)
    } finally { validating.value = false }
    if (!vr.ok) {
      return message.error(`模型校验未通过，未存档：${vr.error || '连通失败'}`)
    }
    message.success(`模型校验通过（${vr.model || ''}），正在存档`)
    const payload = { config: cfgText.value, type: cfgType.value }
    if (editingId.value) await aiConfigApi.updateProvider(editingId.value, payload)
    else await aiConfigApi.addProvider(payload)
    message.success('已保存'); providerOpen.value = false; loadProviders()
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function removeProvider(id: string) {
  try { await aiConfigApi.deleteProvider(id); message.success('已删除'); loadProviders(); loadConfig() }
  catch (e) { message.error((e as Error).message) }
}

// Prompt 编辑
const promptOpen = ref(false)
const promptForm = reactive<Partial<AIPrompt>>({ scene: 'pentest_exec', name: '', content: '', provider_id: '', enabled: true })
function openPrompt(record?: AIPrompt) {
  if (record) Object.assign(promptForm, { ...record, provider_id: record.provider_id || '' })
  else Object.assign(promptForm, { _id: undefined, scene: 'pentest_exec', name: '', content: '', provider_id: '', enabled: true })
  promptOpen.value = true
}
async function savePrompt() {
  loading.value = true
  try {
    if (promptForm._id) await aiConfigApi.updatePrompt(promptForm._id, promptForm)
    else await aiConfigApi.addPrompt(promptForm)
    message.success('已保存'); promptOpen.value = false; loadPrompts()
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
// 行内快捷:切换启用 / 绑定 AI(不进编辑弹窗)
async function toggleScene(record: AIPrompt, enabled: boolean) {
  try { await aiConfigApi.updatePrompt(record._id, { enabled }); record.enabled = enabled }
  catch (e) { message.error((e as Error).message); loadPrompts() }
}
// bindScene 已随「绑定 AI」冻结移除（v1.21.157-47，模型改在新建任务按任务选）。
async function removePrompt(id: string) {
  try { await aiConfigApi.deletePrompt(id); message.success('已删除'); loadPrompts() }
  catch (e) { message.error((e as Error).message) }
}
onMounted(loadAll)
</script>

<style scoped>
.page-card { margin-bottom: 16px; }
.hint { margin-left: 8px; color: #999; font-size: 12px; }
.prompt-preview { white-space: pre-wrap; word-break: break-all; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; line-height: 1.6; max-height: 360px; overflow: auto; margin: 0; }
/* 任务环节列：tag 与环节名垂直居中对齐，tag 定宽起点一致，各行整齐。
   cell 占满列宽 + 子项正确收缩，防长环节名(如"安全闸刀(写操作审查)")撑破列宽溢出(超模)。 */
.scene-cell { display: flex; align-items: center; gap: 8px; min-width: 0; width: 100%; }
.scene-cell .scene-tag { margin: 0; flex: 0 0 auto; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.scene-cell .scene-name { flex: 1 1 auto; min-width: 0; color: var(--dt-muted, #888); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.content-snippet { color: var(--dt-muted, #888); font-size: 12px; }
.provider-type, .provider-opt { display: inline-flex; align-items: center; gap: 6px; }
.provider-icon { display: inline-flex; width: 18px; height: 18px; flex: none; }
.provider-icon :deep(svg) { width: 18px; height: 18px; }
.row-enabled > :deep(td) { background: #f6ffed; }
.t-label { font-size: 12px; color: #666; margin-bottom: 4px; }
.t-result { margin-top: 14px; padding: 12px; border-radius: 6px; border: 1px solid #eee; }
.t-result.ok { background: #f6ffed; border-color: #b7eb8f; }
.t-result.fail { background: #fff2f0; border-color: #ffccc7; }
.t-meta { font-size: 12px; color: #888; margin-bottom: 8px; }
.t-meta span { margin-left: 6px; }
.t-reply { white-space: pre-wrap; word-break: break-word; font-size: 13px; line-height: 1.6; margin: 0; max-height: 320px; overflow: auto; color: var(--dt-text, #1f2328); }
/* 夜间模式：测试结果区暗底亮字（此前硬编码浅绿/浅红底+默认文字→暗色下白底看不清） */
[data-theme="dark"] .t-result { border-color: rgba(255,255,255,.12); }
[data-theme="dark"] .t-result.ok { background: rgba(82,196,26,.12); border-color: rgba(82,196,26,.4); }
[data-theme="dark"] .t-result.fail { background: rgba(255,77,79,.12); border-color: rgba(255,77,79,.4); }
[data-theme="dark"] .t-reply { color: #e6edf3; }
[data-theme="dark"] .t-label, [data-theme="dark"] .t-meta { color: #9aa7b4; }
/* Provider 字段说明块（逐字段解释该填什么，夜间适配走 CSS 变量） */
.field-guide { margin-top: 8px; padding: 10px 12px; border-radius: 6px; background: var(--dt-hover, #f6f8fa);
  border: 1px solid var(--dt-border, #eaecef); font-size: 12px; line-height: 1.75; color: var(--dt-text, #444); }
.field-guide .fg-title { font-weight: 600; margin-bottom: 4px; color: var(--dt-text, #1f2328); }
.field-guide .fg-item { margin: 2px 0; }
.field-guide .fg-item b { color: var(--dt-link, #0969da); }
.field-guide code { padding: 1px 5px; border-radius: 3px; background: var(--dt-code-bg, rgba(175,184,193,.2)); font-size: 12px; }
.field-guide .fg-note { margin-top: 6px; color: var(--dt-muted, #888); }
[data-theme="dark"] .field-guide { background: rgba(255,255,255,.04); border-color: rgba(255,255,255,.12); color: #c9d1d9; }
[data-theme="dark"] .field-guide .fg-title { color: #e6edf3; }
[data-theme="dark"] .field-guide .fg-item b { color: #6cb6ff; }
[data-theme="dark"] .field-guide code { background: rgba(110,118,129,.4); color: #e6edf3; }
</style>
