<template>
  <PageContainer title="系统扩展" kicker="System Extensions"
    description="扩展平台能力。「工具扩展」下分：AI 工具扩展=AI 渗透可主动调用的工具（据此生成 AI 工具表）；内核工具扩展=内核扫描时使用的工具（不进 AI 工具表）。">
    <a-alert type="warning" show-icon class="risk"
      message="本地 Python/二进制扩展等价于授予主机代码执行能力"
      description="仅上传可信扩展。平台以子进程、目标 scope、资源限制与审计降低风险，但无法证明黑盒程序不会自行越界。" />

    <a-card class="page-card">
      <a-tabs v-model:activeKey="tab" @change="onTab">
        <!-- 固定在 Tab 栏右上角：上传/商店/刷新，切 Tab 常驻可见（运行日志 Tab 隐藏上传/商店） -->
        <template #rightExtra>
          <a-space>
            <template v-if="tab !== 'logs'">
              <a-upload :show-upload-list="false" accept=".tar.gz,.tgz,.zip" :before-upload="(f: File) => pickFile(f)">
                <a-button type="primary"><template #icon><UploadOutlined /></template>上传扩展</a-button>
              </a-upload>
              <a-button @click="openStore"><template #icon><AppstoreOutlined /></template>扩展商店</a-button>
            </template>
            <a-button @click="refreshCurrent"><template #icon><ReloadOutlined /></template>刷新</a-button>
          </a-space>
        </template>

        <!-- 工具扩展（原「AI 扩展」子页改名）：内含 AI 工具扩展 / 内核工具扩展 两个子 Tab -->
        <a-tab-pane key="tools" tab="工具扩展">
          <a-tabs v-model:activeKey="subTab" @change="onSubTab" size="small">
            <!-- AI 工具扩展：AI 可调用的工具，据此生成 AI 工具表（内置工具 + 已装 AI 扩展，统一按功能分类展示，不再分隔） -->
            <a-tab-pane key="ai" tab="AI 工具扩展">
              <div class="hint">AI 渗透会话可主动调用的工具，平台据此生成 AI 工具表。内置工具随平台发布不可移除；已装 AI 扩展可启停，仅启用后 AI 才能看到并调用。上传的 .tar.gz 按其 manifest 的 ext_type 自动归入 AI 工具扩展或内核工具扩展。</div>
              <div class="toolbar">
                <span class="muted">共 {{ builtin.length + aiExts.length }} 个 AI 工具（内置 {{ builtin.length }} · 已装扩展 {{ aiExts.length }}），按功能分 {{ aiGroups.length }} 类</span>
              </div>
              <!-- 内置工具 + 已装 AI 扩展 合并按功能分类，去掉「内置能力/已装扩展」两段分隔 -->
              <div v-for="g in aiGroups" :key="g.name" class="cat-block">
                <a-divider orientation="left" class="cat-title">
                  {{ g.name }}<a-tag color="blue" style="margin-left:6px">{{ g.builtin.length + g.exts.length }}</a-tag>
                </a-divider>
                <div class="grid">
                  <!-- 内置工具卡（只读） -->
                  <div v-for="t in g.builtin" :key="t.name" class="ext-card readonly">
                    <div class="c-head">
                      <code class="c-name">{{ t.name }}</code>
                      <a-tag :color="t.available ? 'green' : 'default'" size="small">{{ t.available ? '可调用' : '未接入' }}</a-tag>
                    </div>
                    <div class="c-cat">
                      <a-tag :color="t.origin === 'third_party' ? 'orange' : 'cyan'" size="small">
                        {{ t.origin === 'third_party' ? '第三方' : '自研' }}
                      </a-tag>
                      <span class="c-tag builtin">内置</span>
                    </div>
                    <div class="c-sum">{{ t.summary || t.description }}</div>
                    <div v-if="t.params && t.params.length" class="c-params">
                      <span class="c-params-label">参数</span>
                      <span v-for="p in t.params" :key="p.name" class="param">{{ p.name }}<i v-if="p.required">*</i></span>
                    </div>
                  </div>
                  <!-- 已装 AI 扩展卡（可启停/删除，同分类内并列） -->
                  <ExtCard v-for="e in g.exts" :key="e.extension_id" :ext="e"
                    @toggle="toggle" @detail="showDetail" @remove="remove" @check="check" />
                </div>
              </div>
            </a-tab-pane>

            <!-- 内核工具扩展（原「功能扩展」，ext_type=feature/both）：内核扫描时使用的工具，不进 AI 工具表 -->
            <a-tab-pane key="feature" tab="内核工具扩展">
              <div class="hint">内核扫描时使用的工具（内置扫描器/弱口令爆破/JS 挖掘 + 已装内核扩展）。内核内置工具全局禁用于 AI（易触发 WAF/封 IP）、由侦察/扫描 pipeline 调用、不可移除；公共扩展两边都注册。</div>
              <div class="toolbar">
                <span class="muted">共 {{ kernelBuiltin.length + featureExts.length }} 个内核工具（内置 {{ kernelBuiltin.length }} · 已装扩展 {{ featureExts.length }}）</span>
              </div>
              <!-- 内核内置工具（只读） + 已装内核扩展 合并为一个连续列表，去掉两段分隔 -->
              <a-empty v-if="!kernelBuiltin.length && !featureExts.length" description="暂无内核工具，点右上角「上传扩展」或「扩展商店」添加" />
              <div v-else class="grid">
                <!-- 内核内置工具卡（只读，AI 禁用，不可移除） -->
                <div v-for="t in kernelBuiltin" :key="t.name" class="ext-card readonly">
                  <div class="c-head">
                    <code class="c-name">{{ t.name }}</code>
                    <a-tag :color="t.available ? 'green' : 'default'" size="small">{{ t.available ? '内核已接入' : '未接入' }}</a-tag>
                  </div>
                  <div class="c-cat">
                    <a-tag :color="t.origin === 'third_party' ? 'orange' : 'cyan'" size="small">
                      {{ t.origin === 'third_party' ? '第三方' : '自研' }}
                    </a-tag>
                    <span class="c-tag builtin">内置</span>
                    <a-tag color="red" size="small">AI 禁用</a-tag>
                  </div>
                  <div class="c-sum">{{ t.summary || t.description }}</div>
                  <div v-if="t.params && t.params.length" class="c-params">
                    <span class="c-params-label">参数</span>
                    <span v-for="p in t.params" :key="p.name" class="param">{{ p.name }}<i v-if="p.required">*</i></span>
                  </div>
                </div>
                <!-- 已装内核扩展卡（含公共扩展，可启停/删除） -->
                <ExtCard v-for="e in featureExts" :key="e.extension_id" :ext="e"
                  @toggle="toggle" @detail="showDetail" @remove="remove" @check="check" />
              </div>
            </a-tab-pane>
          </a-tabs>
        </a-tab-pane>

        <!-- 运行日志 -->
        <a-tab-pane key="logs" tab="运行日志">
          <div class="toolbar">
            <a-input v-model:value="logFilter" placeholder="扩展 ID" style="width:220px" allow-clear />
            <a-button @click="loadLogs">查询</a-button>
          </div>
          <a-table :data-source="logs" :columns="logColumns" row-key="_id" size="small" />
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 扩展商店抽屉 -->
    <a-drawer v-model:open="storeOpen" title="扩展商店" width="640" @open="loadStore">
      <a-alert v-if="storeError && storeAuthState !== 'ok'" type="warning" show-icon style="margin-bottom:12px">
        <template #message>
          {{ storeError }}
          <a-button type="link" size="small" @click="$router.push('/about/activation')" style="padding:0 4px">前往激活</a-button>
        </template>
      </a-alert>
      <a-alert v-else-if="storeError" type="info" :message="storeError" show-icon style="margin-bottom:12px" />
      <div class="toolbar"><span class="muted">使用统一 JWT 激活凭证访问扩展商店</span><a-button size="small" @click="loadStore">刷新</a-button></div>
      <a-empty v-if="!store.length && !storeError" description="商店暂无可用扩展" />
      <div class="grid">
        <div v-for="e in store" :key="e.extension_id" class="ext-card">
          <div class="c-head"><code class="c-name">{{ e.name || e.extension_id }}</code>
            <a-tag :color="e.ext_type === 'both' ? 'purple' : e.ext_type === 'feature' ? 'cyan' : 'geekblue'" size="small">{{ e.ext_type === 'both' ? '公共扩展' : e.ext_type === 'feature' ? '内核工具扩展' : 'AI 工具扩展' }}</a-tag>
          </div>
          <div class="c-cat"><a-tag color="blue" size="small">{{ e.category }}</a-tag><a-tag :color="e.origin === 'third_party' ? 'orange' : 'cyan'" size="small">{{ e.origin === 'third_party' ? '第三方' : '自研' }}</a-tag><span class="muted">v{{ e.version }}</span></div>
          <div class="c-sum">{{ e.summary }}</div>
          <div class="c-actions"><a-button type="primary" size="small" @click="install(e)">下载安装</a-button></div>
        </div>
      </div>
    </a-drawer>

    <!-- 扩展详情抽屉 -->
    <a-drawer v-model:open="detailOpen" :title="detail?.name || detail?.extension_id" width="560">
      <template v-if="detail">
        <a-descriptions :column="1" size="small" bordered>
          <a-descriptions-item label="扩展 ID"><code>{{ detail.extension_id }}</code></a-descriptions-item>
          <a-descriptions-item label="类型">{{ detail.ext_type === 'both' ? '公共扩展（AI + 内核两边都注册）' : detail.ext_type === 'feature' ? '内核工具扩展（内核扫描工具）' : 'AI 工具扩展（AI 可调用工具）' }}</a-descriptions-item>
          <a-descriptions-item label="版本">{{ detail.version }}</a-descriptions-item>
          <a-descriptions-item label="分类">{{ detail.category }}</a-descriptions-item>
          <a-descriptions-item label="来源">{{ detail.source === 'store' ? '扩展商店' : '本地上传' }}（{{ detail.trust }}）</a-descriptions-item>
          <a-descriptions-item label="自研/第三方">
            <a-tag :color="detail.origin === 'third_party' ? 'orange' : 'cyan'">{{ detail.origin === 'third_party' ? '第三方' : '自研' }}</a-tag>
            <span v-if="detail.origin === 'third_party'" class="muted">{{ detail.vendor }} · {{ detail.license }} · 上游 {{ detail.upstream_version }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="兼容性">
            <a-tag :color="detail.available ? 'green' : 'red'">{{ detail.available ? '兼容' : detail.unavailable_reason || '不可用' }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="启用状态">{{ detail.enabled ? '已启用' : '已停用' }}</a-descriptions-item>
        </a-descriptions>
        <div class="d-block"><b>摘要</b><p>{{ detail.summary }}</p></div>
        <div class="d-block"><b>说明</b><p>{{ detail.description }}</p></div>
        <div class="d-block" v-if="detail.ext_type !== 'feature' && detail.ai_instruction"><b>给 AI 的调用说明</b><p>{{ detail.ai_instruction }}</p></div>
        <div class="d-block" v-if="detailParams.length"><b>参数</b>
          <ul><li v-for="p in detailParams" :key="p.name"><code>{{ p.name }}</code><i v-if="p.required" class="req">*必填</i> — {{ p.desc || '—' }}</li></ul>
        </div>
      </template>
    </a-drawer>

    <!-- 上传目标选择：本地安装运行 / 提交云端商店审核 -->
    <a-modal v-model:open="uploadOpen" title="上传扩展" :confirm-loading="uploading"
      :ok-text="uploadTarget === 'cloud' ? '提交云端审核' : '安装到本地'" @ok="doUpload" @cancel="pendingFile = null">
      <p class="up-file">扩展包：<code>{{ pendingFile?.name }}</code>（支持 .tar.gz / .tgz / .zip）</p>
      <a-radio-group v-model:value="uploadTarget" class="up-target">
        <a-radio value="local">本地安装运行</a-radio>
        <a-radio value="cloud">提交云端商店审核</a-radio>
      </a-radio-group>
      <a-alert v-if="uploadTarget === 'local'" type="warning" show-icon
        message="本地安装等价于授予主机代码执行能力，仅安装你完全信任的代码。安装后需手动启用；manifest 的 ext_type 决定归入 AI / 内核 / 公共扩展。" />
      <a-alert v-else type="info" show-icon
        message="提交到云端商店：平台先校验清单，再转发到分发端排队。运营方在管理后台审核通过后，才会出现在扩展商店供各实例安装（凭激活凭证鉴权下发）。不在本机安装。" />
    </a-modal>
  </PageContainer>
</template>
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import { UploadOutlined, AppstoreOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import ExtCard from './ExtCard.vue'
import { aiExtensionApi, type ExtensionItem, type BuiltinTool, type ExtParam } from '../../api/aiExtension'

const tab = ref('tools')       // 顶层：tools 工具扩展 / logs 运行日志
const subTab = ref('ai')       // 工具扩展内子 Tab：ai AI工具扩展 / feature 内核工具扩展
const builtin = ref<BuiltinTool[]>([])
const aiExts = ref<ExtensionItem[]>([])
const featureExts = ref<ExtensionItem[]>([])
const kernelBuiltin = ref<BuiltinTool[]>([])   // 内核内置工具（只读，AI 禁用）
const store = ref<ExtensionItem[]>([])
const logs = ref<Record<string, unknown>[]>([])
const storeError = ref('')
const storeAuthState = ref<'ok' | 'unauthorized' | 'no_key'>('ok')
const storeOpen = ref(false)
const detailOpen = ref(false)
const detail = ref<ExtensionItem | null>(null)
const logFilter = ref('')
const uploadOpen = ref(false)
const pendingFile = ref<File | null>(null)
const uploadTarget = ref<'local' | 'cloud'>('local')
const uploading = ref(false)

// AI 扩展统一按功能分类展示（内置工具 + 已装 AI 扩展合并，去掉「内置能力/已装扩展」两段分隔）。
// 与「AI 工具」页 CAT_ORDER 一致；未登记的新分类排最后不丢。每类含 builtin(内置只读) + exts(已装可管)。
const CAT_ORDER = ['资产收集', '漏洞验证', '情报查询', '情报回写', '带外通道', '浏览器', '内网后渗透']
const aiGroups = computed(() => {
  const map = new Map<string, { builtin: BuiltinTool[]; exts: ExtensionItem[] }>()
  const ensure = (cat: string) => {
    const k = cat || '其他'
    if (!map.has(k)) map.set(k, { builtin: [], exts: [] })
    return map.get(k)!
  }
  for (const t of builtin.value) ensure(t.category).builtin.push(t)
  for (const e of aiExts.value) ensure(e.category).exts.push(e)
  return Array.from(map.entries())
    .map(([name, g]) => ({ name, builtin: g.builtin, exts: g.exts }))
    .sort((a, b) => {
      const ia = CAT_ORDER.indexOf(a.name), ib = CAT_ORDER.indexOf(b.name)
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib)
    })
})
const detailParams = computed<ExtParam[]>(() => {
  const d = detail.value
  if (!d) return []
  if (d.params && d.params.length) return d.params
  const s = d.parameters
  if (!s || !s.properties) return []
  const req = s.required || []
  return Object.entries(s.properties).map(([name, item]) => ({ name, desc: item?.description || '', required: req.includes(name) }))
})

const logColumns = [
  { title: '时间', dataIndex: 'save_date' }, { title: '事件', dataIndex: 'event' },
  { title: '扩展', dataIndex: 'extension_id' }, { title: '会话', dataIndex: 'session_id' },
  { title: '状态', dataIndex: 'status' }, { title: '耗时(ms)', dataIndex: 'duration_ms' }, { title: '错误', dataIndex: 'error' }
]

async function loadBuiltin() { try { builtin.value = (await aiExtensionApi.builtin()).tools || [] } catch (e) { message.error(String(e)) } }
async function loadAi() { try { aiExts.value = (await aiExtensionApi.list({ ext_type: 'ai' })).items || [] } catch (e) { message.error(String(e)) } }
async function loadKernelBuiltin() { try { kernelBuiltin.value = (await aiExtensionApi.builtinKernel()).tools || [] } catch (e) { message.error(String(e)) } }
async function loadFeature() { try { featureExts.value = (await aiExtensionApi.list({ ext_type: 'feature' })).items || [] } catch (e) { message.error(String(e)) } }
async function loadLogs() { try { logs.value = (await aiExtensionApi.logs({ extension_id: logFilter.value, size: 50 })).items || [] } catch (e) { message.error(String(e)) } }
async function loadStore() { storeError.value = ''; storeAuthState.value = 'ok'; try { const r = await aiExtensionApi.store(); store.value = r.items || []; storeError.value = r.error || ''; storeAuthState.value = r.auth_state || 'ok' } catch (e) { storeError.value = e instanceof Error ? e.message : String(e); storeAuthState.value = 'ok' } }
function openStore() { storeOpen.value = true; loadStore() }

// 顶层 Tab：tools 进入时按当前子 Tab 载数据；logs 载日志
function onTab(k: string) { if (k === 'tools') onSubTab(subTab.value); else loadLogs() }
// 子 Tab：ai 载内置+已装AI扩展；feature 载内核工具扩展
function onSubTab(k: string) { if (k === 'feature') { loadKernelBuiltin(); loadFeature() } else { loadBuiltin(); loadAi() } }
function refreshCurrent() { tab.value === 'logs' ? loadLogs() : onSubTab(subTab.value) }

function pickFile(file: File) { pendingFile.value = file; uploadTarget.value = 'local'; uploadOpen.value = true; return false }
async function doUpload() {
  const file = pendingFile.value
  if (!file) { uploadOpen.value = false; return }
  uploading.value = true
  try {
    if (uploadTarget.value === 'cloud') {
      const r = await aiExtensionApi.submit(file)
      if (r && r.ok) { message.success('已提交云端商店，等待运营方审核'); uploadOpen.value = false; pendingFile.value = null }
      else message.error((r && r.error) || '提交失败')
    } else {
      await aiExtensionApi.upload(file); message.success('扩展已安装，兼容后可手工启用'); loadAi(); loadFeature()
      uploadOpen.value = false; pendingFile.value = null
    }
  } catch (e) { message.error(String(e)) }
  finally { uploading.value = false }
}
async function toggle(r: ExtensionItem, v: boolean) {
  try { v ? await aiExtensionApi.enable(r.extension_id) : await aiExtensionApi.disable(r.extension_id); r.enabled = v; message.success(v ? '已启用' : '已停用') }
  catch (e) { message.error(String(e)) }
}
async function check(r: ExtensionItem) { try { await aiExtensionApi.check(r.extension_id); message.success('检测完成'); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } }
async function remove(r: ExtensionItem) { try { await aiExtensionApi.remove(r.extension_id); message.success('已删除'); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } }
async function install(r: ExtensionItem) { try { await aiExtensionApi.install(r); message.success('已安装，请到对应分类启用'); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } }
function showDetail(r: ExtensionItem) { detail.value = r; detailOpen.value = true }

onMounted(() => { loadBuiltin(); loadAi() })
</script>
<style scoped>
.risk { margin-bottom: 16px }
.hint { color: var(--dt-muted, #888); font-size: 13px; margin-bottom: 8px }
.sec { font-size: 13px; font-weight: 600 }
.toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 12px }
.muted { color: var(--dt-muted, #888); font-size: 13px }
.cat-block { margin-bottom: 8px }
.cat-title { font-size: 13px; font-weight: 600; margin: 6px 0 10px }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px }
.ext-card { border: 1px solid var(--dt-border, #f0f0f0); border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px }
.ext-card.readonly { background: var(--dt-fill, #fafafa) }
.c-head { display: flex; align-items: center; justify-content: space-between; gap: 8px }
.c-name { font-weight: 600; color: #1677ff; font-size: 13px; word-break: break-all }
.c-cat { display: flex; align-items: center; gap: 8px }
.c-tag.builtin { font-size: 11px; color: var(--dt-muted, #888) }
.c-sum { font-size: 12px; line-height: 1.6; color: var(--dt-text, #333); min-height: 32px;
  word-break: break-word; overflow-wrap: anywhere }
/* 参数区：flex-wrap 换行 + chip 样式，参数多/名长也整齐不溢出卡片 */
.c-params { font-size: 12px; color: var(--dt-muted, #888); display: flex; flex-wrap: wrap; align-items: center; gap: 6px; min-width: 0 }
.c-params-label { flex: 0 0 auto; color: var(--dt-muted, #888) }
.c-params .param { display: inline-flex; align-items: center; max-width: 100%;
  padding: 1px 7px; background: var(--dt-fill, #f0f2f5); border-radius: 4px;
  font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; color: var(--dt-text, #555);
  word-break: break-all; overflow-wrap: anywhere }
.c-params .param i { color: #ff4d4f; font-style: normal }
.c-actions { display: flex; align-items: center; justify-content: flex-end; margin-top: 4px }
.d-block { margin-top: 14px; font-size: 13px }
.d-block p { margin: 6px 0 0; line-height: 1.7; color: var(--dt-text, #333); white-space: pre-wrap }
.d-block ul { margin: 6px 0 0; padding-left: 18px }
.d-block .req { color: #ff4d4f; margin: 0 4px; font-style: normal }
.up-file { font-size: 13px; margin-bottom: 12px }
.up-target { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px }
</style>
