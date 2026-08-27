<template>
  <PageContainer :title="isNew ? '新建策略' : '编辑策略'" kicker="Policy" description="配置扫描策略，字段与任务选项一致。">
    <a-card :bordered="false" :loading="loading">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12"><a-form-item label="策略名称" required><a-input v-model:value="name" placeholder="策略名称" /></a-form-item></a-col>
          <a-col :xs="24" :md="12"><a-form-item label="描述"><a-input v-model:value="desc" placeholder="策略描述" /></a-form-item></a-col>
        </a-row>

        <a-divider orientation="left">域名配置</a-divider>
        <a-form-item label="资产收集模式">
          <a-radio-group v-model:value="cfg.collect_mode" button-style="solid" size="small" class="collect-mode-group">
            <a-radio-button value="single">单点目标</a-radio-button>
            <a-radio-button value="multi_brute">广域目标</a-radio-button>
          </a-radio-group>
          <div style="margin-top:4px;color:#888;font-size:12px">
            <span v-if="cfg.collect_mode === 'single'">只解析下发目标本身,不做任何子域扩散(爆破/历史/智能/FOFA 全禁),去重按 IP+port/hostname。</span>
            <span v-else>subfinder 被动枚举(证书透明日志/DNS 聚合/搜索引擎等多源) + 子域名字典爆破(按上方选项),尽可能收全资产。</span>
          </div>
        </a-form-item>
        <a-space wrap>
          <span style="color:#888">域名爆破</span>
          <a-select v-model:value="cfg.domain_config.domain_brute_type" style="width: 120px" :options="bruteTypeOptions" :disabled="cfg.collect_mode === 'single'" />
        </a-space>
        <div style="margin-top:4px;color:#888;font-size:12px">
          子域名爆破字典（单点目标不爆破，已禁用）。选「不爆破」则只被动收集（subfinder 从证书透明日志/DNS 聚合/搜索引擎等被动源枚举子域名），不跑字典爆破。
        </div>
        <a-collapse ghost style="margin-top:8px">
          <a-collapse-panel key="dict" header="自定义爆破字典 / DNS Resolver（可选，留空用内置默认）">
            <a-row :gutter="16">
              <a-col :xs="24" :md="12">
                <a-form-item label="子域名爆破字典">
                  <a-textarea v-model:value="cfg.domain_config.subdomain_dict" :rows="4" placeholder="每行一个子域名前缀，留空用内置 domain_2w(约2万词)。" />
                </a-form-item>
              </a-col>
              <a-col :xs="24" :md="12">
                <a-form-item label="DNS Resolver">
                  <a-textarea v-model:value="cfg.domain_config.resolvers_custom" :rows="4" placeholder="每行一个 DNS 服务器 IP，留空用内置公共 DNS。" />
                </a-form-item>
              </a-col>
            </a-row>
          </a-collapse-panel>
        </a-collapse>

        <a-divider orientation="left">IP / 端口配置</a-divider>
        <a-space wrap>
          <span style="color:#888">端口扫描</span>
          <a-select v-model:value="cfg.ip_config.port_scan_type" style="width: 130px" :options="portTypeOptions" />
          <a-checkbox v-model:checked="cfg.ip_config.service_detection">服务识别</a-checkbox>
          <a-checkbox v-model:checked="cfg.ip_config.os_detection">操作系统识别</a-checkbox>
          <a-checkbox v-model:checked="cfg.ip_config.ssl_cert">SSL证书</a-checkbox>
          <a-checkbox v-model:checked="cfg.ip_config.skip_scan_cdn_ip">跳过CDN</a-checkbox>
        </a-space>
        <div style="margin-top:4px;color:#888;font-size:12px">
          端口扫描范围。选「不扫描」则不做端口扫描（服务识别/操作系统识别等依赖端口的项也不生效）。
        </div>
        <a-row :gutter="16" style="margin-top: 12px">
          <a-col :xs="24" :md="8" v-if="cfg.ip_config.port_scan_type === 'custom'"><a-form-item label="自定义端口"><a-input v-model:value="cfg.ip_config.port_custom" placeholder="80,443" /></a-form-item></a-col>
          <a-col :xs="24" :md="8"><a-form-item label="排除端口"><a-input v-model:value="cfg.ip_config.exclude_ports" placeholder="留空不排除" /></a-form-item></a-col>
          <a-col :xs="12" :md="4"><a-form-item label="主机超时(s)"><a-input-number v-model:value="cfg.ip_config.host_timeout" style="width: 100%" /></a-form-item></a-col>
          <a-col :xs="12" :md="4"><a-form-item label="并行度"><a-input-number v-model:value="cfg.ip_config.port_parallelism" style="width: 100%" /></a-form-item></a-col>
          <a-col :xs="12" :md="4"><a-form-item label="最小发包率"><a-input-number v-model:value="cfg.ip_config.port_min_rate" style="width: 100%" /></a-form-item></a-col>
        </a-row>

        <a-divider orientation="left">站点配置</a-divider>
        <a-space wrap>
          <a-checkbox v-model:checked="cfg.site_config.site_identify">站点识别</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.site_capture">站点截图</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.search_engines">搜索引擎</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.site_spider">站点爬虫</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.nuclei_scan">nuclei扫描</a-checkbox>
          <a-checkbox v-model:checked="cfg.site_config.web_info_hunter">WIH</a-checkbox>
        </a-space>

        <a-divider orientation="left">其他</a-divider>
        <a-space wrap>
          <a-checkbox v-model:checked="cfg.file_leak">文件泄露</a-checkbox>
          <a-checkbox v-model:checked="cfg.npoc_service_detection">服务识别(python)</a-checkbox>
          <a-checkbox v-model:checked="cfg.auto_pentest">扫描完成后自动 AI 渗透</a-checkbox>
        </a-space>
        <a-collapse v-if="cfg.file_leak" ghost style="margin-top:8px">
          <a-collapse-panel key="fileleak" header="自定义文件泄露字典（可选，留空用内置默认）">
            <a-form-item>
              <a-textarea v-model:value="cfg.fileleak_dict" :rows="4" placeholder="每行一个探测路径(如 .git/config、backup.zip)，留空用内置 file_top_2000(约1300词)。" />
            </a-form-item>
          </a-collapse-panel>
        </a-collapse>
        <div style="margin-top:10px">
          <span style="margin-right:8px">内核扫描出口</span>
          <a-radio-group v-model:value="cfg.scan_egress.mode" button-style="solid" size="small">
            <a-radio-button value="direct">直连</a-radio-button>
            <a-radio-button value="global">全局</a-radio-button>
            <a-radio-button value="smart">智能</a-radio-button>
          </a-radio-group>
          <div style="margin-top:6px;color:#888;font-size:12px">
            内核扫描(端口/站点/泄漏探测)出口。直连=快(默认);全局=走代理中心「平台代理模式」选定的源;智能=代理不通自动直连。
            <span v-if="cfg.scan_egress.mode === 'direct' && globalOn" style="color:#d46b08">（注：直连仅本策略此项，第三方情报仍走智能）</span>
          </div>
        </div>
        <div v-if="cfg.auto_pentest" style="margin-top:8px;color:#888;font-size:12px">用此策略下发的任务扫描完成后,会自动按独立站点(非泄露URL)创建 AI 渗透会话,优先级按 recon 价值排序,并发受全局上限闸控。</div>
        <div v-if="cfg.auto_pentest" style="margin-top:10px">
          <span style="margin-right:8px">AI 渗透模式</span>
          <a-radio-group v-model:value="cfg.pentest_mode" button-style="solid" size="small">
            <a-radio-button v-for="m in PENTEST_MODES" :key="m.value" :value="m.value">{{ m.label }}</a-radio-button>
          </a-radio-group>
          <div style="margin-top:6px;color:#d46b08;font-size:12px" v-if="currentModeWarn">⚠ {{ currentModeWarn }}</div>
          <!-- AI 攻击出口已移到「新建任务」页选择（cfg.pentest_egress 仍作策略默认兜底，任务传了则覆盖）。 -->
          <div style="margin-top:10px;color:#888;font-size:12px">
            AI 攻击出口（直连/全局/智能）改在<b>新建任务</b>时按任务选择，未绑定代理源的模式会置灰。本策略默认：{{ cfg.pentest_egress?.mode === 'global' ? '全局' : cfg.pentest_egress?.mode === 'smart' ? '智能' : '直连' }}。
          </div>
          <div style="margin-top:10px">
            <span style="margin-right:8px">派发去重</span>
            <a-radio-group v-model:value="cfg.dedup_level" button-style="solid" size="small">
              <a-radio-button :value="1">不去重</a-radio-button>
              <a-radio-button :value="2">保守</a-radio-button>
              <a-radio-button :value="3">激进</a-radio-button>
            </a-radio-group>
            <div style="margin-top:6px;color:#888;font-size:12px">1不去重=全量目标逐个渗透(红队全覆盖);2保守(默认)=非CDN按ip+port合并、CDN加hostname,同IP同端口视为同站;3激进=再按2xx+同指纹跨子域合并,省预算但可能漏挖。</div>
          </div>
          <div style="margin-top:10px">
            <span style="margin-right:8px">范围偏移</span>
            <a-radio-group v-model:value="cfg.scope_drift_level" button-style="solid" size="small">
              <a-radio-button :value="1">零偏移</a-radio-button>
              <a-radio-button :value="2">轻度</a-radio-button>
              <a-radio-button :value="3">中度</a-radio-button>
            </a-radio-group>
            <div style="margin-top:6px;color:#888;font-size:12px">1零偏移=严格锁定下发目标,连引用的子域名API也不碰;2轻度(默认)=允许调用目标引用的子域名API做功能验证,不独立渗透;3中度=允许对引用子域名快速信息收集,不深入,必须回归主目标。</div>
          </div>
          <div style="margin-top:10px">
            <a-checkbox v-model:checked="cfg.intel_enabled">启用情报体系</a-checkbox>
            <div style="margin-top:6px;color:#888;font-size:12px">启用(默认)=AI 中期可查历史打法/单位画像/凭证等情报辅助渗透;关闭=不查情报(靠自身探测打),但渗透报告/打法/凭证等成果照常回写沉淀。</div>
          </div>
        </div>
        <a-form-item label="关联资产组" style="margin-top: 12px; max-width: 420px">
          <a-select v-model:value="cfg.scope_config.scope_id" allow-clear placeholder="不关联" :options="scopeOptions" show-search :filter-option="filterScope" />
        </a-form-item>

        <a-divider orientation="left">PoC 插件 <a-tag color="blue">{{ pocKeys.length }} 已选</a-tag></a-divider>
        <a-transfer
          :data-source="pocPlugins"
          :target-keys="pocKeys"
          :titles="['可选 PoC', '已启用']"
          :list-style="{ width: '46%', height: '260px' }"
          show-search
          :filter-option="filterPlugin"
          :render="renderPlugin"
          @change="(keys: string[]) => pocKeys = keys"
        />

        <a-divider orientation="left">弱口令爆破插件 <a-tag color="orange">{{ bruteKeys.length }} 已选</a-tag></a-divider>
        <a-transfer
          :data-source="brutePlugins"
          :target-keys="bruteKeys"
          :titles="['可选爆破', '已启用']"
          :list-style="{ width: '46%', height: '260px' }"
          show-search
          :filter-option="filterPlugin"
          :render="renderPlugin"
          @change="(keys: string[]) => bruteKeys = keys"
        />

        <a-form-item style="margin-top: 24px">
          <a-space>
            <a-button type="primary" :loading="saving" @click="save">保存</a-button>
            <a-button @click="router.push('/policy')">返回</a-button>
          </a-space>
        </a-form-item>
      </a-form>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { policyApi, defaultPolicyConfig, type PolicyConfig } from '../../api/policy'
import { PENTEST_MODES } from '../../api/pentest'
import { pocApi } from '../../api/poc'
import { assetScopeApi } from '../../api/scope'
import { getSetupStatus, type SetupStatusResult } from '../../api/meta'
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
const setupStatus = ref<SetupStatusResult | null>(null)

// 代理模式：全局代理是否开启（用于直连标签提示）
const globalOn = ref(false)
async function loadProxyRules() {
  try {
    const { proxyApi } = await import('../../api/proxy')
    const st = await proxyApi.status()
    globalOn.value = !!(st.config as any)?.global_mode_enabled
  } catch { /* 代理服务不可用不阻断策略编辑 */ }
}

const bruteTypeOptions = [{ label: '不爆破', value: 'none' }, { label: '测试字典', value: 'test' }, { label: '大字典', value: 'big' }]
const portTypeOptions = [
  { label: '不扫描', value: 'none' }, { label: '测试端口', value: 'test' }, { label: 'TOP100', value: 'top100' },
  { label: 'TOP1000', value: 'top1000' }, { label: '全部', value: 'all' }, { label: '自定义', value: 'custom' }
]

/* PoC / 爆破插件穿梭框 */
const pocPlugins = ref<TransferItem[]>([])
const brutePlugins = ref<TransferItem[]>([])
const pocKeys = ref<string[]>([])
const bruteKeys = ref<string[]>([])
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
    message.error('加载插件列表失败：' + (error instanceof Error ? error.message : String(error)))
  }
}

async function loadOne() {
  await loadPlugins()
  await loadScopes()
  await loadProxyRules()
  if (isNew.value) return
  loading.value = true
  try {
    const data = await policyApi.list({ _id: id.value, page: 1, size: 1 })
    const item = (data.items || [])[0] as Record<string, unknown> | undefined
    if (item) {
      name.value = String(item.name || '')
      desc.value = String(item.desc || '')
      Object.assign(cfg, { ...defaultPolicyConfig(), ...(item.policy as PolicyConfig) })
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
}
async function save() {
  if (!name.value) return message.warning('请填写策略名称')
  // 启用 AI 渗透需有 AI 配置
  if (cfg.auto_pentest && setupStatus.value && !setupStatus.value.ai_configured) {
    Modal.confirm({
      title: 'AI 模型未配置',
      content: '当前未配置任何 AI 模型提供商，勾选的「自动 AI 渗透」将无法执行。',
      okText: '前往配置',
      cancelText: '暂时忽略',
      onOk: () => router.push('/ai-config'),
    })
    return
  }
  // 多域名+被动(FOFA) 模式需要 FOFA key
  if (cfg.collect_mode === 'multi_passive' && setupStatus.value && !setupStatus.value.fofa_configured) {
    Modal.confirm({
      title: 'FOFA 未配置',
      content: '当前未配置 FOFA API 密钥，「多域名+被动(FOFA)」模式将无法收集子域名资产。',
      okText: '前往配置',
      cancelText: '暂时忽略',
      onOk: () => router.push('/api-keys'),
    })
    return
  }
  saving.value = true
  // 组装 poc_config / brute_config（后端要求 {plugin_name, enable}）
  cfg.poc_config = pocKeys.value.map(plugin_name => ({ plugin_name, enable: true }))
  cfg.brute_config = bruteKeys.value.map(plugin_name => ({ plugin_name, enable: true }))
  try {
    if (isNew.value) await policyApi.add({ name: name.value, desc: desc.value, policy: cfg })
    else await policyApi.edit(id.value, { name: name.value, desc: desc.value, policy: cfg })
    message.success('已保存'); router.push('/policy')
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
</style>
