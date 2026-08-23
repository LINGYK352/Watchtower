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
            <a-radio-button value="fofa">FOFA 查询</a-radio-button>
            <a-radio-button value="unit">单位名</a-radio-button>
          </a-radio-group>
          <span v-if="form.target_type === 'fofa'" class="muted" style="margin-left:8px">FOFA:用语句导入资产(host 自动剥协议、域名+IP 都收、next 游标拉更全)</span>
          <span v-else-if="form.target_type === 'unit'" class="muted" style="margin-left:8px">单位名:填单位全称(一行一个,可多单位),自动按 ICP 备案反查资产(鹰图 icp.name 主力 + FOFA 兜底)→ 每单位建一个任务</span>
        </a-form-item>
        <a-form-item :label="form.target_type === 'fofa' ? 'FOFA 查询语句' : (form.target_type === 'unit' ? '单位全称(一行一个)' : '任务目标')" required>
          <a-textarea v-model:value="form.target" :rows="3"
            :placeholder="form.target_type === 'fofa' ? '如 domain=&quot;example.com&quot; && port=&quot;443&quot;(注意授权范围,语句太宽会捞到无关资产)' : (form.target_type === 'unit' ? '单位 ICP 备案全称,一行一个(带「有限公司」等全称命中率高)。如:\n北京某某科技有限公司\n某某市人民政府' : '支持域名、IP、IP段；多目标换行')" />
          <div v-if="form.target_type === 'fofa'" style="margin-top:4px">
            <a-button type="link" size="small" :loading="fofaTesting" @click="testFofa">测试查询(预估数量)</a-button>
            <span v-if="fofaSize !== null" class="muted">预估 {{ fofaSize }} 条(受 FOFA 会员单查询上限约束,超量需拆分查询)</span>
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

          <a-form-item label="指定 AI 模型">
            <a-select v-model:value="form.pentest_provider_id" :options="providerOptions" allow-clear
              style="max-width:360px" :placeholder="`跟随全局默认：${globalDefaultName}`" />
            <div v-if="!form.pentest_provider_id" class="default-hint">
              <BulbOutlined /> 留空将跟随全局默认 AI：<b>{{ globalDefaultName }}</b>
            </div>
            <div class="muted">锁定本任务派发的渗透会话所用 AI 模型，全程不受后续全局默认切换影响。留空=跟随全局默认（如上）。切换限同协议（OpenAI 系互切 / Claude 系互切），跨协议需新开会话。</div>
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
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { DownloadOutlined, UploadOutlined, PlusOutlined, DeleteOutlined, BulbOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { taskApi, taskFofaApi } from '../../api/task'
import { policyApi } from '../../api/policy'
import { aiConfigApi, type AIProvider } from '../../api/aiConfig'
import { getSetupStatus, type SetupStatusResult } from '../../api/meta'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const policyLoading = ref(false)
type PolicyOption = { label: string; value: string }
const policyOptions = ref<PolicyOption[]>([])
const policyRaw = ref<RowRecord[]>([])          // 完整策略对象，用于读 auto_pentest 做分步显示
const providers = ref<AIProvider[]>([])         // 可选 AI 模型（渗透会话锁定用）
const globalDefaultId = ref('')                  // AI 配置页的全局默认 provider（active_provider_id），用于"留空=跟随全局默认"显示具体模型名
const setupStatus = ref<SetupStatusResult | null>(null)

const form = reactive({
  name: '',
  target: '',
  target_type: 'normal' as 'normal' | 'fofa' | 'unit',
  policy_id: undefined as string | undefined,
  priority: 2,
  pentest_whitelist: '',
  pentest_provider_id: '',                       // 指定 AI 模型（空=跟随全局默认）
  'source.unit': ''
})

// 当前所选策略的完整对象 + 是否启用扫描后 AI 渗透（决定渗透相关选项是否显示）
const selectedPolicy = computed(() => policyRaw.value.find(p => String(p._id) === String(form.policy_id)))
const pentestEnabled = computed(() => !!(selectedPolicy.value?.policy as RowRecord | undefined)?.auto_pentest)
// 可选模型选项：仅已启用 provider（带协议标注，便于识别）
const providerOptions = computed(() => providers.value.filter(p => p.enabled).map(p => ({
  label: `${p.name}（${p.protocol === 'claude' ? 'Claude' : 'OpenAI'}协议）`, value: p._id,
})))
// 全局默认 AI 的展示名（留空时告诉用户实际会跟随哪个模型）；取不到默认配置时退化提示
const globalDefaultName = computed(() => {
  const p = providers.value.find(x => String(x._id) === String(globalDefaultId.value))
  return p ? `${p.name}（${p.protocol === 'claude' ? 'Claude' : 'OpenAI'}协议）` : '未设置全局默认 AI（请先到「AI 配置」设置）'
})
const fofaTesting = ref(false)
const fofaSize = ref<number | null>(null)

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
    const data = await aiConfigApi.providers()
    providers.value = data.items || []
  } catch { /* 取不到不阻断，模型下拉留空=跟随全局默认 */ }
  // 拉全局配置的默认 AI（active_provider_id），供"留空=跟随全局默认"显示出具体是哪个模型
  try {
    const cfg = await aiConfigApi.getConfig()
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
        policy_id: form.policy_id as string, priority: Number.isNaN(it.priority) ? form.priority : it.priority
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
  try {
    const res = await taskFofaApi.test(form.target)
    fofaSize.value = res.size
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    fofaTesting.value = false
  }
}

async function submit() {
  // unit 模式:任务名(第一级)+ 单位全称(第二级,多行)都要;其余模式需任务名+目标
  if (form.target_type === 'unit') {
    if (!form.name) return message.warning('请填写任务名称')
    if (!form.target) return message.warning('请填写单位全称(一行一个)')
  } else if (!form.name || !form.target) {
    return message.warning('请填写任务名称和目标')
  }
  if (!form.policy_id) return message.warning('请选择扫描策略')
  // FOFA 目标需要 FOFA 密钥已配置且启用
  if (form.target_type === 'fofa' && setupStatus.value && !setupStatus.value.fofa_configured) {
    return message.warning('FOFA API 密钥未配置或未启用，请先到「系统设置 → API 密钥」配置并启用')
  }
  loading.value = true
  const missionIntelJson = buildMissionIntel()
  try {
    if (form.target_type === 'unit') {
      // 单位名建任务:一个任务装多个单位,worker 异步反查种子→流式渗透
      const res = await taskFofaApi.submitByUnit({
        name: form.name,
        units: form.target,
        policy_id: form.policy_id,
        priority: form.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: missionIntelJson,
        pentest_provider_id: form.pentest_provider_id || '',
      })
      message.success(`任务「${form.name}」已建(${res.unit_count} 个单位,后台反查中)`)
      router.push('/tasks')
      return
    }
    if (form.target_type === 'fofa') {
      // FOFA 目标:语句导入,带上优先级/白名单/来源(与普通任务一致)
      await taskFofaApi.submit({
        name: form.name,
        query: form.target,
        policy_id: form.policy_id,
        priority: form.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: missionIntelJson,
        pentest_provider_id: form.pentest_provider_id || '',
        'source.unit': form['source.unit'],
      })
    } else {
      await taskApi.policy({
        name: form.name,
        task_tag: 'task',
        target: form.target,
        policy_id: form.policy_id,
        priority: form.priority,
        pentest_whitelist: form.pentest_whitelist || '',
        mission_intel: missionIntelJson,
        pentest_provider_id: form.pentest_provider_id || '',
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
  getSetupStatus().then(r => { setupStatus.value = r }).catch(() => {})
})
</script>

<style scoped>
.muted { color: #999; font-size: 12px; margin-top: 4px; }
.default-hint { color: #1677ff; font-size: 12px; margin-top: 6px; display: flex; align-items: center; gap: 4px; }
.default-hint b { font-weight: 600; }
.mi-row { display: flex; gap: 8px; align-items: flex-start; margin-bottom: 6px; }
</style>
