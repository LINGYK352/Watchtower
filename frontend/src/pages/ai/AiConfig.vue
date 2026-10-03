<template>
  <PageContainer :title="translate('ui.m_234f4428e0ea')" kicker="AI Config" :description="translate('ui.m_f8c40caa5acd')">
    <template #extra>
      <a-button @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button>
    </template>

    <!-- 全局参数 -->
    <a-card class="page-card" :title="translate('ui.m_c49aa5cd5e39')" size="small">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :span="8">
            <a-form-item :label="translate('ui.m_ff75a04c666b')">
              <a-select v-model:value="config.active_provider_id" allow-clear :options="providerOptions" :placeholder="translate('ui.m_24da1d202ee0')" />
            </a-form-item>
          </a-col>
          <a-col :span="6"><a-form-item :label="translate('ui.m_4e99705e0137')"><a-input-number v-model:value="config.timeout" :min="1" style="width: 100%" /></a-form-item></a-col>
          <!-- 问题18：删全局「出口走代理」开关。入口代理下沉到每个 provider 的「入口代理」（新增/编辑里选具体自定义代理条目）。 -->
        </a-row>
        <a-form-item :label="translate('ui.m_af32f1346f76')">
          <a-input v-model:value="config.source_code_dir" :placeholder="translate('ui.m_2aec072f5156')" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_ab79241df410')">
          <a-row :gutter="12" align="middle">
            <a-col :span="8">
              <a-input-number v-model:value="config.max_concurrent_sessions" :min="0" style="width: 100%"
                :placeholder="translate('ui.m_a8752c5e47db', { p0: (config.recommend_concurrency || '-') })" />
            </a-col>
            <a-col :span="16">
              <span class="hint">{{ translate('ui.m_03dc1d1e84f1') }}<b>{{ translate('ui.m_13661d7fdc60') }} {{ config.recommend_concurrency ?? '-' }})</b>{{ translate('ui.m_5095f0748579') }} {{ config.effective_concurrency ?? '-' }}{{ translate('ui.m_b47156c4b7b9') }}</span>
            </a-col>
          </a-row>
        </a-form-item>
        <a-button type="primary" :loading="loading" @click="saveConfig">{{ translate('ui.m_bcc5da2cf6c1') }}</a-button>
      </a-form>
    </a-card>

    <!-- Token 消耗仪表盘 -->
    <a-card class="page-card" :title="translate('ui.m_8cf9282cd067')" size="small">
      <template #extra><a-button size="small" @click="loadUsage">{{ translate('ui.m_aee887434131') }}</a-button></template>
      <a-row :gutter="16" style="margin-bottom: 12px">
        <a-col :span="6"><a-statistic :title="translate('ui.m_e3716dc029bc')" :value="usage.overall.calls" /></a-col>
        <a-col :span="6"><a-statistic :title="translate('ui.m_9638021caee5')" :value="usage.overall.total" /></a-col>
        <a-col :span="6"><a-statistic :title="translate('ui.m_ef899af5d2c2')" :value="usage.overall.prompt" :suffix="`/ ${usage.overall.completion}`" /></a-col>
        <a-col :span="6"><a-statistic :title="translate('ui.m_73b3bb0ff90c')" :value="usage.overall.fail_calls" :value-style="{ color: usage.overall.fail_calls ? '#cf1322' : undefined }" /></a-col>
      </a-row>
      <a-row :gutter="16">
        <a-col :span="12">
          <p style="margin:4px 0"><b>{{ translate('ui.m_7b7a9c815742') }}</b></p>
          <a-table :columns="usageCols" :data-source="usage.by_provider" :pagination="false" size="small" row-key="name" bordered>
            <template #emptyText>{{ translate('ui.m_4ed5091ab695') }}</template>
          </a-table>
        </a-col>
        <a-col :span="12">
          <p style="margin:4px 0"><b>{{ translate('ui.m_0d71724b0cc2') }}</b></p>
          <a-table :columns="usageCols" :data-source="usage.by_scene" :pagination="false" size="small" row-key="name" bordered>
            <template #emptyText>{{ translate('ui.m_a380125a40e0') }}</template>
          </a-table>
        </a-col>
      </a-row>
    </a-card>

    <!-- Provider -->
    <a-card class="page-card" :title="translate('ui.m_ec4d10343b70')" size="small">
      <template #extra><a-button type="primary" size="small" @click="openProvider()">{{ translate('ui.m_7add78b882c2') }}</a-button></template>
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
            <a-tag v-else color="default">{{ translate('ui.m_4e6fd0e28c55') }}</a-tag>
          </template>
          <template v-else-if="column.key === 'proxy_id'">
            <!-- 问题18：入口代理列。按 proxy_id 在已加载自定义代理列表里查名字，空/查不到=直连 -->
            <a-tag :color="record.proxy_id ? 'blue' : 'default'">{{ proxyName(record.proxy_id) }}</a-tag>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space>
              <a-button type="link" size="small" @click="openTest(record as AIProvider)">{{ translate('ui.m_6aa8f49cc992') }}</a-button>
              <a-button type="link" size="small" @click="openProvider(record as AIProvider)">{{ translate('ui.m_051836569928') }}</a-button>
              <ConfirmAction danger type="link" size="small" :title="translate('ui.m_d56c71c888b9')" @confirm="removeProvider(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- AI 测试面板:选已配 AI(绿色=已启用)→ 输入(默认你好)→ 看回复 -->
    <a-card class="page-card" :title="translate('ui.m_47cefd711383')" size="small">
      <a-row :gutter="12" align="bottom">
        <a-col :span="9">
          <div class="t-label">{{ translate('ui.m_352d74a36760') }}</div>
          <a-select v-model:value="testId" style="width:100%" :placeholder="translate('ui.m_9e12968953cd')" :options="testOptions">
            <template #option="{ label, enabled }">
              <span><a-badge :status="enabled ? 'success' : 'default'" /> {{ label }}</span>
            </template>
          </a-select>
        </a-col>
        <a-col :span="10">
          <div class="t-label">{{ translate('ui.m_d8f6a43cde83') }}</div>
          <a-input v-model:value="testMsg" :placeholder="translate('ui.m_670d9743542c')" @press-enter="runTest" />
        </a-col>
        <a-col :span="5">
          <a-button type="primary" block :loading="testing" :disabled="!testId" @click="runTest">{{ translate('ui.m_a49d32136de1') }}</a-button>
        </a-col>
      </a-row>
      <div v-if="testResult" class="t-result" :class="testResult.ok ? 'ok' : 'fail'">
        <div class="t-meta">
          <a-tag :color="testResult.ok ? 'green' : 'red'">{{ testResult.ok ? translate('ui.m_053461ce86d2') : translate('ui.m_28384d7afd2e') }}</a-tag>
          <span v-if="testResult.model">{{ translate('ui.m_c98e118e0a43') }} {{ testResult.model }}</span>
          <span v-if="testResult.total_tokens">· {{ testResult.total_tokens }} tokens</span>
          <span>· {{ testResult.proxy_enabled ? translate('ui.m_c49b87cc96bc') : translate('ui.m_b06325c5660f') }}</span>
        </div>
        <pre class="t-reply">{{ testResult.ok ? testResult.content : testResult.error }}</pre>
      </div>
    </a-card>

    <!-- Prompt -->
    <a-card class="page-card" :title="translate('ui.m_5dbfa8f40be0')" size="small">
      <template #extra><a-button type="primary" size="small" @click="openPrompt()">{{ translate('ui.m_6e0894828d03') }}</a-button></template>
      <a-alert type="info" show-icon style="margin-bottom: 12px"
        :message="translate('ui.m_afdc4588e6dc')" />
      <a-table :columns="sceneColumns" :data-source="prompts" :loading="loading" row-key="_id"
        :pagination="false" size="middle" bordered>
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enabled'">
            <!-- 内置环节属系统核心，启用开关变灰强制启用不可关（防误关坏渗透/审查链路）；自定义环节可自由启停 -->
            <a-tooltip v-if="(record as AIPrompt).builtin" :title="translate('ui.m_19f27e5badc3')">
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
            <a-tooltip :title="translate('ui.m_cb03e918971a')">
              <a-tag :color="(record as AIPrompt).provider_id ? 'blue' : 'default'">
                {{ (record as AIPrompt).provider_name || translate('ui.m_877d315f3402') }}
              </a-tag>
            </a-tooltip>
          </template>
          <template v-else-if="column.key === 'content'">
            <a-tooltip v-if="(record as AIPrompt).builtin" :title="translate('ui.m_a9291a8bdf9c')">
              <a-tag color="blue">{{ translate('ui.m_95e35aabd9a9') }}</a-tag>
            </a-tooltip>
            <a-tag v-else-if="!record.content" color="orange">{{ translate('ui.m_7f05190592e5') }}</a-tag>
            <span v-else class="content-snippet">{{ String(record.content).slice(0, 40) }}…</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space>
              <a-tooltip v-if="(record as AIPrompt).builtin" :title="translate('ui.m_c634aa6e9297')">
                <a-button type="link" size="small" disabled>{{ translate('ui.m_b52f59e63937') }}</a-button>
              </a-tooltip>
              <a-button v-else type="link" size="small" @click="openPrompt(record as AIPrompt)">{{ translate('ui.m_b52f59e63937') }}</a-button>
              <ConfirmAction v-if="!(record as AIPrompt).builtin" danger type="link" size="small" :title="translate('ui.m_a2f3324d913a')" @confirm="removePrompt(record._id as string)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
              <a-tooltip v-else :title="translate('ui.m_111c26cf5bf6')">
                <a-tag color="blue">{{ translate('ui.m_95e35aabd9a9') }}</a-tag>
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
        <p style="margin-top:16px;color:#555">{{ translate('ui.m_5175d77acf69') }}<br/>{{ translate('ui.m_868571ca7166') }}</p>
      </div>
    </a-modal>

    <!-- Provider 编辑弹窗:选厂商 → 生成原生 JSON → 改 key/base_url → 提交 -->
    <a-modal v-model:open="providerOpen" :title="editingId ? translate('ui.m_2610596303f5') : translate('ui.m_7add78b882c2')" :confirm-loading="loading" width="640" @ok="saveProvider">
      <a-form layout="vertical">
        <a-row :gutter="12" align="bottom">
          <a-col :span="16">
            <a-form-item :label="translate('ui.m_2e10281b39c0')" style="margin-bottom:8px">
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
              <a-button block @click="resetTemplate">{{ translate('ui.m_20212e1b72e2') }}</a-button>
            </a-form-item>
          </a-col>
        </a-row>
        <!-- 问题18：入口代理选择——调用 AI(访问中转站/LLM)的入口代理，选具体自定义代理条目，默认直连。
             与任务发起时的攻击出口(AI→目标)彻底双轨分离。选中即写入下方 JSON 的 proxy_id(JSON 仍是提交源)。 -->
        <a-form-item :label="translate('ui.m_bec10871e163')">
          <a-select v-model:value="ingressProxyId" :options="ingressProxyOptions" style="width:100%"
            :placeholder="translate('ui.m_b2905b610811')" />
          <span class="hint">{{ translate('ui.m_a16d6315091e') }}</span>
        </a-form-item>
        <a-form-item :label="translate('ui.m_148d195e21b0')">
          <a-alert v-if="editingId" type="info" style="margin-bottom:8px" show-icon
            :message="translate('ui.m_beac9b863d57')" />
          <a-textarea v-model:value="cfgText" :rows="14" spellcheck="false"
            style="font-family: monospace; font-size: 13px"
            :placeholder="translate('ui.m_86f000a63190')" />
          <div class="field-guide">
            <div class="fg-title">{{ translate('ui.m_0c0e2813d013') }}</div>
            <div class="fg-item"><b>base_url</b>{{ translate('ui.m_c09e014d8eb8') }} <code>https://api.openai.com/v1</code>、<code>https://api.deepseek.com</code>{{ translate('ui.m_90fb670e966a') }} <code>http://localhost:11434/v1</code> {{ translate('ui.m_6c4c949ca8fe') }}</div>
            <div class="fg-item"><b>api_key</b>{{ translate('ui.m_040800e2d6b2') }}<code>sk-...</code> {{ translate('ui.m_da5fd7787056') }}<span v-if="editingId">{{ translate('ui.m_6c84a55ca127') }}</span></div>
            <div class="fg-item"><b>model</b>{{ translate('ui.m_b927b3285993') }} <code>gpt-4o</code>、<code>claude-opus-4-8</code>、<code>deepseek-chat</code>{{ translate('ui.m_49631f1acbd5') }}</div>
            <div class="fg-item"><b>reasoning_effort</b>{{ translate('ui.m_d80b2d77d882') }}<b>{{ translate('ui.m_a54ae376ff80') }}</b>{{ translate('ui.m_2e85422136a2') }} <code>medium</code>/<code>low</code>{{ translate('ui.m_9a1bf9331a0b') }} <code>""</code>。</div>
            <div class="fg-item"><b>protocol</b>{{ translate('ui.m_4c496a63e41f') }}<code>openai</code>{{ translate('ui.m_23d2d62a0a04') }} <code>claude</code>{{ translate('ui.m_422fd7aa0925') }}</div>
            <div class="fg-note">{{ translate('ui.m_e8f92affe31b') }}</div>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- Prompt 编辑弹窗 -->
    <a-modal v-model:open="promptOpen" :title="promptForm._id ? translate('ui.m_f758056d328a') : translate('ui.m_5d25920d5682')" :confirm-loading="loading" width="760" @ok="savePrompt">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :span="8">
            <a-form-item :label="translate('ui.m_7f72f06a8877')">
              <a-select v-model:value="promptForm.scene" :options="sceneOptions" />
            </a-form-item>
          </a-col>
          <a-col :span="8"><a-form-item :label="translate('ui.m_b55134fb6456')"><a-input v-model:value="promptForm.name" /></a-form-item></a-col>
          <a-col :span="8">
            <a-form-item :label="translate('ui.m_2797f5c06fe8')">
              <!-- v1.21.157-47 冻结：改在「新建任务」按任务选 AI 模型；此处只读展示，不再绑定 -->
              <a-select v-model:value="promptForm.provider_id" disabled :placeholder="translate('ui.m_877d315f3402')">
                <a-select-option value="">{{ translate('ui.m_877d315f3402') }}</a-select-option>
                <a-select-option v-for="p in providers" :key="p._id" :value="p._id">{{ p.name }}</a-select-option>
              </a-select>
              <div class="hint">{{ translate('ui.m_756578a7f081') }}</div>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="translate('ui.m_cc1ab53aea16')">
          <a-textarea v-model:value="promptForm.content" :rows="14" :placeholder="translate('ui.m_f5c468a5adc5')" />
        </a-form-item>
        <a-space><span>{{ translate('ui.m_1769c58bedc4') }}</span><a-switch v-model:checked="promptForm.enabled" /></a-space>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { aiConfigApi, type AIConfig, type AIProvider, type AIPrompt, type AIPreset, type UsageStat } from '../../api/aiConfig'
import { proxyApi, type CustomProxy } from '../../api/proxy'
import { providerIcon } from '../../config/providerIcons'

const loading = ref(false)

const usageCols = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', ellipsis: true },
  { get title() { return translate('ui.m_653b123c956d') }, dataIndex: 'calls', width: 80 },
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
  { get label() { return translate('ui.m_93aa13174271') }, value: '' },
  ...customProxies.value.map(c => ({ label: c.name || c.url, value: c._id }))
])
// 按 proxy_id 查代理名（供列表列展示），空/查不到=直连
function proxyName(id?: string): string {
  if (!id) return translate('ui.m_b06325c5660f')
  return customProxies.value.find(c => c._id === id)?.name || translate('ui.m_b06325c5660f')
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
  { get label() { return translate('ui.m_779c969ce9de') }, value: 'pentest_exec_detect' },
  { get label() { return translate('ui.m_d21f22ecd734') }, value: 'pentest_exec_conservative' },
  { get label() { return translate('ui.m_95a8ac01594a') }, value: 'pentest_exec' },
  { get label() { return translate('ui.m_64772a7b6938') }, value: 'pentest_exec_redteam' },
  { get label() { return translate('ui.m_a94a7511a1e9') }, value: 'guard' },
  { get label() { return translate('ui.m_aa6e44a6f822') }, value: 'guard_conservative' },
  { get label() { return translate('ui.m_b3a34f2bc2a6') }, value: 'guard_detect' },
  { get label() { return translate('ui.m_3dad33aa3b74') }, value: 'code_audit' },
  { get label() { return translate('ui.m_4eafa9e925b3') }, value: 'custom' }
]

const providerOptions = computed(() => providers.value.map(p => ({ label: `${p.name} (${p.model || p.type})`, value: p._id })))

const providerColumns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', width: 150, ellipsis: true },
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'type', width: 160 },
  { get title() { return translate('ui.m_c98e118e0a43') }, dataIndex: 'model', width: 180, ellipsis: true },
  { get title() { return translate('ui.m_03b11112dc97') }, dataIndex: 'base_url', width: 200, ellipsis: true },
  { title: 'API Key', dataIndex: 'api_key', width: 160, ellipsis: true },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'enabled', width: 84 },
  { get title() { return translate('ui.m_5e84ea61e838') }, key: 'proxy_id', width: 120 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 180, fixed: 'right' }
]

const sceneColumns = [
  { get title() { return translate('ui.m_f4f0ead1116b') }, key: 'enabled', width: 70 },
  { get title() { return translate('ui.m_cede383a35ed') }, key: 'scene', width: 260 },
  { get title() { return translate('ui.m_2797f5c06fe8') }, key: 'provider', width: 220 },
  { get title() { return translate('ui.m_4b47dbae97ba') }, key: 'content', ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 180 }
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
  label: `${p.name} (${p.model || p.type})${p.enabled ? '' : translate('ui.m_d2bd0f4a5529')}`, value: p._id, enabled: p.enabled
})))
function openTest(record: AIProvider) {
  testId.value = record._id
  testResult.value = null
  // 滚到测试面板
  setTimeout(() => document.querySelector('.t-result, .t-label')?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 50)
}
async function runTest() {
  if (!testId.value) return message.warning(translate('ui.m_ff0f2d4f4c78'))
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
    message.success(translate('ui.m_1bd91a7d0c53'))
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
  message.success(translate('ui.m_22cb090aff39'))
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
  try { JSON.parse(cfgText.value) } catch { return message.error(translate('ui.m_492b2d911474')) }
  loading.value = true
  try {
    // 保存前先校验模型有效性（连通性+key），通过才存档；校验期间弹窗提示
    validating.value = true
    let vr
    try {
      vr = await aiConfigApi.testProviderConfig(cfgText.value, cfgType.value)
    } finally { validating.value = false }
    if (!vr.ok) {
      return message.error(translate('ui.m_d8a6611758de', { p0: (vr.error || '连通失败') }))
    }
    message.success(translate('ui.m_4e6685e0f3e6', { p0: (vr.model || '') }))
    const payload = { config: cfgText.value, type: cfgType.value }
    if (editingId.value) await aiConfigApi.updateProvider(editingId.value, payload)
    else await aiConfigApi.addProvider(payload)
    message.success(translate('ui.m_1bd91a7d0c53')); providerOpen.value = false; loadProviders()
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function removeProvider(id: string) {
  try { await aiConfigApi.deleteProvider(id); message.success(translate('ui.m_077a6d37719a')); loadProviders(); loadConfig() }
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
    message.success(translate('ui.m_1bd91a7d0c53')); promptOpen.value = false; loadPrompts()
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
// 行内快捷:切换启用 / 绑定 AI(不进编辑弹窗)
async function toggleScene(record: AIPrompt, enabled: boolean) {
  try { await aiConfigApi.updatePrompt(record._id, { enabled }); record.enabled = enabled }
  catch (e) { message.error((e as Error).message); loadPrompts() }
}
// bindScene 已随「绑定 AI」冻结移除（v1.21.157-47，模型改在新建任务按任务选）。
async function removePrompt(id: string) {
  try { await aiConfigApi.deletePrompt(id); message.success(translate('ui.m_077a6d37719a')); loadPrompts() }
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
