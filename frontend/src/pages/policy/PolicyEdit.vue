<template>
  <PageContainer :title="isNew ? translate('ui.m_bb090baf358c') : translate('ui.m_072377fbb0a3')" kicker="Policy" :description="translate('ui.m_b7ce377a5f9a')">
    <a-card :bordered="false" :loading="loading">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12"><a-form-item :label="translate('ui.m_a903683f81f6')" required><a-input v-model:value="name" :placeholder="translate('ui.m_a903683f81f6')" /></a-form-item></a-col>
          <a-col :xs="24" :md="12"><a-form-item :label="translate('ui.m_dc2ba467fc7a')"><a-input v-model:value="desc" :placeholder="translate('ui.m_2927ded9428b')" /></a-form-item></a-col>
        </a-row>

        <a-divider orientation="left">{{ translate('ui.m_2c6b55fdab6c') }}</a-divider>
        <a-form-item :label="translate('ui.m_045de1543346')">
          <a-radio-group v-model:value="cfg.collect_mode" button-style="solid" size="small" class="collect-mode-group">
            <a-radio-button value="single">{{ translate('ui.m_eebe96e369fc') }}</a-radio-button>
            <a-radio-button value="multi_brute">{{ translate('ui.m_986831d241ec') }}</a-radio-button>
          </a-radio-group>
          <div style="margin-top:4px;color:#888;font-size:12px">
            <span v-if="cfg.collect_mode === 'single'">{{ translate('ui.m_0f63417a3343') }}</span>
            <span v-else>{{ translate('ui.m_1c5687713d34') }}</span>
          </div>
        </a-form-item>
        <a-form-item v-if="cfg.collect_mode === 'multi_brute'" :label="translate('ui.m_47ec8c50aa96')">
          <a-checkbox-group v-model:value="cfg.collect_sources" class="collect-source-grid">
            <a-tooltip v-for="s in collectionSources" :key="s.id"
              :title="s.available ? translate('ui.m_10dd6b7d3d1c', { p0: (s.label) }) : translate('ui.m_9a7d543b5633', { p0: (s.label) })">
              <a-checkbox :value="s.id" :disabled="!s.available">
                {{ s.label }}
                <span :class="s.available ? 'source-ready' : 'source-missing'">{{ s.available ? translate('ui.m_de8184da1ef8') : translate('ui.m_80a57e03f071') }}</span>
              </a-checkbox>
            </a-tooltip>
          </a-checkbox-group>
          <div v-if="!collectionSources.some(s => s.available)" class="source-empty">
            {{ translate('ui.m_7f62e39de2e0') }}
          </div>
          <div v-else style="margin-top:6px;color:#888;font-size:12px">
            {{ translate('ui.m_ea897b18bc1f') }}
          </div>
        </a-form-item>
        <a-space wrap>
          <span style="color:#888">{{ translate('ui.m_5adcba9a1985') }}</span>
          <a-select v-model:value="cfg.domain_config.domain_brute_type" style="width: 120px" :options="bruteTypeOptions" :disabled="cfg.collect_mode === 'single'" />
        </a-space>
        <div style="margin-top:4px;color:#888;font-size:12px">
          {{ translate('ui.m_1395981472dd') }}
        </div>
        <a-collapse ghost style="margin-top:8px">
          <a-collapse-panel key="dict" header="自定义爆破字典 / DNS Resolver（可选，留空用内置默认）">
            <a-row :gutter="16">
              <a-col :xs="24" :md="12">
                <a-form-item :label="translate('ui.m_7e21eba9fce3')">
                  <a-textarea v-model:value="cfg.domain_config.subdomain_dict" :rows="4" :placeholder="translate('ui.m_fd46c53924bc')" />
                </a-form-item>
              </a-col>
              <a-col :xs="24" :md="12">
                <a-form-item label="DNS Resolver">
                  <a-textarea v-model:value="cfg.domain_config.resolvers_custom" :rows="4" :placeholder="translate('ui.m_58fc67eda48b')" />
                </a-form-item>
              </a-col>
            </a-row>
          </a-collapse-panel>
        </a-collapse>

        <a-divider orientation="left">{{ translate('ui.m_d1f4a911b325') }}</a-divider>
        <a-space wrap>
          <span style="color:#888">{{ translate('ui.m_877a15bf7b5f') }}</span>
          <a-select v-model:value="cfg.ip_config.port_scan_type" style="width: 130px" :options="portTypeOptions" />
          <a-checkbox v-model:checked="cfg.ip_config.service_detection">{{ translate('ui.m_43eee26f6c05') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.ip_config.os_detection">{{ translate('ui.m_b4f8fc78bbdd') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.ip_config.ssl_cert">{{ translate('ui.m_dca908ed4fae') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.ip_config.skip_scan_cdn_ip">{{ translate('ui.m_76b7f9a3e76a') }}</a-checkbox>
        </a-space>
        <div style="margin-top:4px;color:#888;font-size:12px">
          {{ translate('ui.m_854cc793b58d') }}
        </div>
        <a-row :gutter="16" style="margin-top: 12px">
          <a-col :xs="24" :md="8" v-if="cfg.ip_config.port_scan_type === 'custom'"><a-form-item :label="translate('ui.m_7f7683678a7b')"><a-input v-model:value="cfg.ip_config.port_custom" placeholder="80,443" /></a-form-item></a-col>
          <a-col :xs="24" :md="8"><a-form-item :label="translate('ui.m_70095a8024d3')"><a-input v-model:value="cfg.ip_config.exclude_ports" :placeholder="translate('ui.m_096d5b34aa50')" /></a-form-item></a-col>
          <a-col :xs="12" :md="4"><a-form-item :label="translate('ui.m_547f4fd3593f')"><a-input-number v-model:value="cfg.ip_config.host_timeout" style="width: 100%" /></a-form-item></a-col>
          <a-col :xs="12" :md="4"><a-form-item :label="translate('ui.m_75c90014cd07')"><a-input-number v-model:value="cfg.ip_config.port_parallelism" style="width: 100%" /></a-form-item></a-col>
          <a-col :xs="12" :md="4"><a-form-item :label="translate('ui.m_885acdc69070')"><a-input-number v-model:value="cfg.ip_config.port_min_rate" style="width: 100%" /></a-form-item></a-col>
        </a-row>

        <a-divider orientation="left">{{ translate('ui.m_11258110296f') }}</a-divider>
        <a-space wrap>
          <a-checkbox v-model:checked="cfg.site_config.site_identify">{{ translate('ui.m_d2a21dfc7b65') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.site_capture">{{ translate('ui.m_c7ce7d5484c9') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.search_engines">{{ translate('ui.m_82cbe72ab9d9') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.site_spider">{{ translate('ui.m_22577abc1cef') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.nuclei_scan">{{ translate('ui.m_8e3e65a096d0') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.web_info_hunter">WIH</a-checkbox>
        </a-space>

        <a-divider orientation="left">{{ translate('ui.m_d2909f1647e7') }}</a-divider>
        <a-space wrap>
          <a-checkbox v-model:checked="cfg.file_leak">{{ translate('ui.m_ddca902e3201') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.npoc_service_detection">{{ translate('ui.m_cc7415825f0d') }}</a-checkbox>
          <a-checkbox v-model:checked="cfg.auto_pentest">{{ translate('ui.m_8607b3118600') }}</a-checkbox>
        </a-space>
        <a-collapse v-if="cfg.file_leak" ghost style="margin-top:8px">
          <a-collapse-panel key="fileleak" header="自定义文件泄露字典（可选，留空用内置默认）">
            <a-form-item>
              <a-textarea v-model:value="cfg.fileleak_dict" :rows="4" :placeholder="translate('ui.m_66310d8a1a6c')" />
            </a-form-item>
          </a-collapse-panel>
        </a-collapse>
        <div style="margin-top:10px">
          <span style="margin-right:8px">{{ translate('ui.m_a7e123b57fdd') }}</span>
          <a-radio-group v-model:value="cfg.scan_egress.mode" button-style="solid" size="small">
            <a-radio-button value="direct">{{ translate('ui.m_b06325c5660f') }}</a-radio-button>
            <a-radio-button value="global">{{ translate('ui.m_63d6b47116de') }}</a-radio-button>
            <a-radio-button value="smart">{{ translate('ui.m_8fffc40833fb') }}</a-radio-button>
          </a-radio-group>
          <div style="margin-top:6px;color:#888;font-size:12px">
            {{ translate('ui.m_99679565de29') }}
            <span v-if="cfg.scan_egress.mode === 'direct' && globalOn" style="color:#d46b08">{{ translate('ui.m_22e060d3c70b') }}</span>
          </div>
        </div>
        <div v-if="cfg.auto_pentest" style="margin-top:8px;color:#888;font-size:12px">{{ translate('ui.m_905c7468d710') }}</div>
        <div v-if="cfg.auto_pentest" style="margin-top:10px">
          <span style="margin-right:8px">{{ translate('ui.m_e9a48548c635') }}</span>
          <a-radio-group v-model:value="cfg.pentest_mode" button-style="solid" size="small">
            <a-radio-button v-for="m in PENTEST_MODES" :key="m.value" :value="m.value">{{ m.label }}</a-radio-button>
          </a-radio-group>
          <div style="margin-top:6px;color:#d46b08;font-size:12px" v-if="currentModeWarn">⚠ {{ currentModeWarn }}</div>
          <!-- 蜜罐检测选项 -->
          <div style="margin-top:10px">
            <a-checkbox v-model:checked="cfg.honeypot_detection">
              <span>{{ translate('ui.m_9366e88b6a72') }}</span>
              <a-tooltip :title="translate('ui.m_279f822a4730')">
                <QuestionCircleOutlined style="margin-left:4px;color:#888" />
              </a-tooltip>
            </a-checkbox>
            <div style="margin-left:24px;margin-top:4px;color:#888;font-size:12px">
              {{ translate('ui.m_cc70fa71b23e') }}
            </div>
          </div>
          <!-- AI 攻击出口已移到「新建任务」页选择（cfg.pentest_egress 仍作策略默认兜底，任务传了则覆盖）。 -->
          <div style="margin-top:10px;color:#888;font-size:12px">
            {{ translate('ui.m_bfaf8c58ca9f') }}<b>{{ translate('ui.m_6bee2372805a') }}</b>{{ translate('ui.m_ce2988c5d6fb') }}{{ cfg.pentest_egress?.mode === 'global' ? translate('ui.m_63d6b47116de') : cfg.pentest_egress?.mode === 'smart' ? translate('ui.m_8fffc40833fb') : translate('ui.m_b06325c5660f') }}。
          </div>
          <div style="margin-top:10px">
            <span style="margin-right:8px">{{ translate('ui.m_472f14d7d666') }}</span>
            <a-radio-group v-model:value="cfg.dedup_level" button-style="solid" size="small">
              <a-radio-button :value="1">{{ translate('ui.m_a8262f529f2d') }}</a-radio-button>
              <a-radio-button :value="2">{{ translate('ui.m_69346ce15d5a') }}</a-radio-button>
              <a-radio-button :value="3">{{ translate('ui.m_e0ad64155632') }}</a-radio-button>
            </a-radio-group>
            <div style="margin-top:6px;color:#888;font-size:12px">{{ translate('ui.m_fd2631545f59') }}</div>
          </div>
          <div style="margin-top:10px">
            <span style="margin-right:8px">{{ translate('ui.m_08da50eac159') }}</span>
            <a-radio-group v-model:value="cfg.scope_drift_level" button-style="solid" size="small">
              <a-radio-button :value="1">{{ translate('ui.m_111a0abb2051') }}</a-radio-button>
              <a-radio-button :value="2">{{ translate('ui.m_dab4ad500f41') }}</a-radio-button>
              <a-radio-button :value="3">{{ translate('ui.m_51f190b423bb') }}</a-radio-button>
            </a-radio-group>
            <div style="margin-top:6px;color:#888;font-size:12px">{{ translate('ui.m_16910f648da7') }}</div>
          </div>
          <div style="margin-top:10px">
            <a-checkbox v-model:checked="cfg.intel_enabled">{{ translate('ui.m_c5af328ec024') }}</a-checkbox>
            <div style="margin-top:6px;color:#888;font-size:12px">{{ translate('ui.m_59b66d8f656b') }}<b>{{ translate('ui.m_8c807987cd70') }}</b>{{ translate('ui.m_0ae6c915d9f7') }}</div>
          </div>
          <!-- #3 用户 2026-09-15：单会话上下文上限已从策略移到「新建任务」（仅绑定 AI 渗透的策略可配，
               拉满=模型原生上限）。此处 UI 移除；后端 policy.max_context_tokens 字段保留作兜底（任务不传时用），
               任务传了则覆盖。 -->
        </div>
        <a-form-item :label="translate('ui.m_aebc25ea3860')" style="margin-top: 12px; max-width: 420px">
          <a-select v-model:value="cfg.scope_config.scope_id" allow-clear :placeholder="translate('ui.m_f2d5f8ca66e6')" :options="scopeOptions" show-search :filter-option="filterScope" />
        </a-form-item>

        <a-divider orientation="left">{{ translate('ui.m_e8dace61df4d') }} <a-tag color="blue">{{ pocKeys.length }} {{ translate('ui.m_7ecf1cde6486') }}</a-tag></a-divider>
        <a-transfer
          :data-source="pocPlugins"
          :target-keys="pocKeys"
          :titles="[translate('ui.m_6b548da2629c'), translate('ui.m_dfb802238b38')]"
          :list-style="{ width: '46%', height: '260px' }"
          show-search
          :filter-option="filterPlugin"
          :render="renderPlugin"
          @change="(keys: string[]) => pocKeys = keys"
        />

        <a-divider orientation="left">{{ translate('ui.m_c1bdcf1799c2') }} <a-tag color="orange">{{ bruteKeys.length }} {{ translate('ui.m_7ecf1cde6486') }}</a-tag></a-divider>
        <a-transfer
          :data-source="brutePlugins"
          :target-keys="bruteKeys"
          :titles="[translate('ui.m_239b349c6f8d'), translate('ui.m_dfb802238b38')]"
          :list-style="{ width: '46%', height: '260px' }"
          show-search
          :filter-option="filterPlugin"
          :render="renderPlugin"
          @change="(keys: string[]) => bruteKeys = keys"
        />

        <a-form-item style="margin-top: 24px">
          <a-space>
            <a-button type="primary" :loading="saving" @click="save">{{ translate('ui.m_a3030bf8f16d') }}</a-button>
            <a-button @click="router.push('/policy')">{{ translate('ui.m_572cf45ba436') }}</a-button>
            <span v-if="dirty" style="color:#d48806;font-size:12px;font-weight:600">{{ translate('ui.m_e08bdc3722e2') }}</span>
          </a-space>
        </a-form-item>
      </a-form>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { policyApi, defaultPolicyConfig, type PolicyConfig } from '../../api/policy'
import { useUnsavedGuard } from '../../composables/useUnsavedGuard'
import { PENTEST_MODES } from '../../api/pentest'
import { pocApi } from '../../api/poc'
import { assetScopeApi } from '../../api/scope'
import { getSetupStatus, type SetupStatusResult } from '../../api/meta'
import { apiKeysApi, type ApiKeyItem } from '../../api/apiKeys'
import type { SelectOption } from '../../api/types'

interface TransferItem { key: string; title: string; description: string }

const route = useRoute()
const router = useRouter()
const id = computed(() => String(route.params.id || 'new'))
const isNew = computed(() => id.value === 'new')

const loading = ref(false)
const saving = ref(false)
const name = ref('')
const desc = ref('')
const cfg = reactive<PolicyConfig>(defaultPolicyConfig())
const currentModeWarn = computed(() => PENTEST_MODES.find(m => m.value === cfg.pentest_mode)?.warn)

// #3：单会话上下文上限 UI 已移到「新建任务」。此处不再提供三态控件；cfg.max_context_tokens 仍随
// 策略 load/save 原样保留（后端兜底：任务未传上下文上限时用策略值），只是策略页不再编辑它。
const setupStatus = ref<SetupStatusResult | null>(null)

interface CollectionSource { id: string; label: string; available: boolean }
const collectionSources = ref<CollectionSource[]>([])

async function loadCollectionSources() {
  try {
    const data = await apiKeysApi.options()
    collectionSources.value = (data.items || [])
      .filter((item: ApiKeyItem) => item.group === '资产测绘/情报')
      .map((item: ApiKeyItem) => ({
        id: item.id,
        label: item.label,
        // 资产测绘组的字段均是运行所需凭据；PassiveTotal 等复合凭据必须全部配置才可选。
        available: !!item.enabled && item.fields.every(f => !!item[`${f}_set`]),
      }))
  } catch {
    collectionSources.value = []
  }
}

// 代理模式：全局代理是否开启（用于直连标签提示）
const globalOn = ref(false)
async function loadProxyRules() {
  try {
    const { proxyApi } = await import('../../api/proxy')
    const st = await proxyApi.status()
    globalOn.value = !!(st.config as any)?.global_mode_enabled
  } catch { /* 代理服务不可用不阻断策略编辑 */ }
}

const bruteTypeOptions = [{ get label() { return translate('ui.m_e9d4525846e3') }, value: 'none' }, { get label() { return translate('ui.m_54d477436531') }, value: 'test' }, { get label() { return translate('ui.m_fbb7cf602234') }, value: 'big' }]
const portTypeOptions = [
  { get label() { return translate('ui.m_8f1cf22aa183') }, value: 'none' }, { get label() { return translate('ui.m_e136fb559b1e') }, value: 'test' }, { label: 'TOP100', value: 'top100' },
  { label: 'TOP1000', value: 'top1000' }, { get label() { return translate('ui.m_5c55a67935af') }, value: 'all' }, { get label() { return translate('ui.m_4eafa9e925b3') }, value: 'custom' }
]

/* PoC / 爆破插件穿梭框 */
const pocPlugins = ref<TransferItem[]>([])
const brutePlugins = ref<TransferItem[]>([])
const pocKeys = ref<string[]>([])
const bruteKeys = ref<string[]>([])

// 未保存提示（问题4）：策略编辑改了没点保存就切走会丢失。序列化覆盖名称/描述/配置/插件选择。
const { dirty, markSaved } = useUnsavedGuard(
  () => JSON.stringify({ name: name.value, desc: desc.value, cfg, pocKeys: pocKeys.value, bruteKeys: bruteKeys.value }),
  { get content() { return translate('ui.m_2c5966258581') } })
function filterPlugin(input: string, option: TransferItem) {
  return (option.title + option.description).toLowerCase().includes(input.toLowerCase())
}
function renderPlugin(item: TransferItem) { return item.title }

/* 资产组下拉 */
const scopeOptions = ref<SelectOption[]>([])
function filterScope(input: string, option: SelectOption) { return String(option.label).toLowerCase().includes(input.toLowerCase()) }
async function loadScopes() {
  try {
    const data = await assetScopeApi.list({ page: 1, size: 1000 })
    scopeOptions.value = (data.items || []).map(s => ({ label: String(s.name), value: String(s._id) }))
  } catch { /* 资产组可空，忽略加载失败 */ }
}
async function loadPlugins() {
  try {
    const data = await pocApi.list({ page: 1, size: 100000 })
    const all = (data.items || []) as Record<string, unknown>[]
    const toItem = (p: Record<string, unknown>): TransferItem => ({
      key: String(p.plugin_name),
      title: `${p.plugin_name}${p.vul_name ? ' / ' + p.vul_name : ''}`,
      description: String(p.app_name || '')
    })
    pocPlugins.value = all.filter(p => p.plugin_type !== 'brute').map(toItem)
    brutePlugins.value = all.filter(p => p.plugin_type === 'brute').map(toItem)
  } catch (error) {
    message.error(translate('ui.m_06522a53a770') + (error instanceof Error ? error.message : String(error)))
  }
}

async function loadOne() {
  await Promise.all([loadPlugins(), loadScopes(), loadProxyRules(), loadCollectionSources()])
  const availableSourceIds = collectionSources.value.filter(s => s.available).map(s => s.id)
  if (isNew.value) {
    cfg.collect_sources = availableSourceIds
    markSaved()   // 新建策略：以默认配置为基线，之后编辑才算「未保存」
    return
  }
  loading.value = true
  try {
    const data = await policyApi.list({ _id: id.value, page: 1, size: 1 })
    const item = (data.items || [])[0] as Record<string, unknown> | undefined
    if (item) {
      name.value = String(item.name || '')
      desc.value = String(item.desc || '')
      const storedPolicy = (item.policy || {}) as PolicyConfig
      Object.assign(cfg, { ...defaultPolicyConfig(), ...storedPolicy })
      // 存量策略无 collect_sources：按原有“全部可用源”语义迁移；显式数组则保留选择，
      // 但剔除当前未配置来源，保证界面灰态与后端真实可用性一致。
      cfg.collect_sources = Array.isArray(storedPolicy.collect_sources)
        ? storedPolicy.collect_sources.filter(s => availableSourceIds.includes(s))
        : availableSourceIds
      // 代理出口 4模式（2026-08 重构）：优先新 scan_egress/pentest_egress；旧字段迁移。
      const anyCfg = cfg as any
      if (!anyCfg.scan_egress || !anyCfg.scan_egress.mode) {
        anyCfg.scan_egress = { mode: String(anyCfg.scan_proxy) === 'proxy' ? 'global' : 'direct', rule_id: '' }
      }
      if (!anyCfg.pentest_egress || !anyCfg.pentest_egress.mode) {
        const _pp = String(anyCfg.pentest_proxy || '')
        const m = ['off', 'direct'].includes(_pp) ? 'direct' : (['on', 'proxy'].includes(_pp) ? 'global' : 'smart')
        anyCfg.pentest_egress = { mode: m, rule_id: '' }
      }
      // 规则代理已下线：存量 mode='rule' 降级为 smart（语义最近：走代理不通降级），清 rule_id
      if (anyCfg.scan_egress.mode === 'rule') { anyCfg.scan_egress = { mode: 'smart', rule_id: '' } }
      if (anyCfg.pentest_egress.mode === 'rule') { anyCfg.pentest_egress = { mode: 'smart', rule_id: '' } }
      // 资产收集模式:旧策略无此字段 → defaultPolicyConfig 已给 multi_brute;非法值回落 multi_brute
      cfg.collect_mode = ['single', 'multi_brute', 'multi_passive'].includes(String(cfg.collect_mode)) ? cfg.collect_mode : 'multi_brute'
      // 去重/范围偏移级别:旧策略无此字段 → 回落默认 2;情报开关无字段 → 默认启用
      cfg.dedup_level = [1, 2, 3].includes(Number(cfg.dedup_level)) ? Number(cfg.dedup_level) : 2
      cfg.scope_drift_level = [1, 2, 3].includes(Number(cfg.scope_drift_level)) ? Number(cfg.scope_drift_level) : 2
      cfg.intel_enabled = cfg.intel_enabled !== false
      // 从已有 poc_config/brute_config 还原已启用的插件
      pocKeys.value = (cfg.poc_config || []).filter(p => p.enable !== false).map(p => p.plugin_name)
      bruteKeys.value = (cfg.brute_config || []).filter(p => p.enable !== false).map(p => p.plugin_name)
    }
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
  markSaved()   // 载入 + 各字段迁移落定后设为基线，避免迁移写入被误判为「未保存修改」
}
async function save() {
  if (!name.value) return message.warning(translate('ui.m_083703c7d853'))
  // 启用 AI 渗透需有 AI 配置
  if (cfg.auto_pentest && setupStatus.value && !setupStatus.value.ai_configured) {
    Modal.confirm({
      get title() { return translate('ui.m_28e05ee6fe53') },
      get content() { return translate('ui.m_3e37535190af') },
      get okText() { return translate('ui.m_a34d0b8031af') },
      get cancelText() { return translate('ui.m_97fb4813eb17') },
      onOk: () => router.push('/ai-config'),
    })
    return
  }
  // 多域名+被动(FOFA) 模式需要 FOFA key
  if (cfg.collect_mode === 'multi_passive' && setupStatus.value && !setupStatus.value.fofa_configured) {
    Modal.confirm({
      get title() { return translate('ui.m_851bd5445889') },
      get content() { return translate('ui.m_b9c95d4c1e69') },
      get okText() { return translate('ui.m_a34d0b8031af') },
      get cancelText() { return translate('ui.m_97fb4813eb17') },
      onOk: () => router.push('/api-keys'),
    })
    return
  }
  saving.value = true
  const availableSourceIds = new Set(collectionSources.value.filter(s => s.available).map(s => s.id))
  cfg.collect_sources = (cfg.collect_sources || []).filter(s => availableSourceIds.has(s))
  // 组装 poc_config / brute_config（后端要求 {plugin_name, enable}）
  cfg.poc_config = pocKeys.value.map(plugin_name => ({ plugin_name, enable: true }))
  cfg.brute_config = bruteKeys.value.map(plugin_name => ({ plugin_name, enable: true }))
  try {
    if (isNew.value) await policyApi.add({ name: name.value, desc: desc.value, policy: cfg })
    else await policyApi.edit(id.value, { name: name.value, desc: desc.value, policy: cfg })
    markSaved()   // 保存成功后重置基线，随后 router.push 离开不再误弹未保存提示
    message.success(translate('ui.m_1bd91a7d0c53')); router.push('/policy')
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { saving.value = false }
}
onMounted(() => {
  loadOne()
  getSetupStatus().then(r => { setupStatus.value = r }).catch(() => {})
})
</script>

<style scoped>
/* 资产收集模式三按钮等宽，文字长短不一也整齐对称 */
.collect-mode-group {
  display: flex;
  width: 100%;
  max-width: 480px;
}
.collect-mode-group :deep(.ant-radio-button-wrapper) {
  flex: 1 1 0;
  text-align: center;
  padding-inline: 8px;
}
.collect-source-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px 16px;
  width: 100%;
}
.source-ready, .source-missing { margin-left: 4px; font-size: 11px; }
.source-ready { color: #52c41a; }
.source-missing { color: #999; }
.source-empty { margin-top: 6px; color: #d46b08; font-size: 12px; }
@media (max-width: 900px) {
  .collect-source-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
