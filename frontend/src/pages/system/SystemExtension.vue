<template>
  <PageContainer :title="translate('ui.m_f6c93a56a62a')" kicker="System Extensions"
    :description="translate('ui.m_1a88601a1e86')">
    <a-alert type="warning" show-icon class="risk"
      :message="translate('ui.m_c1a8ad460d7c')"
      :description="translate('ui.m_c18d7385929b')" />

    <a-card class="page-card">
      <a-tabs v-model:activeKey="tab" @change="onTab">
        <!-- 固定在 Tab 栏右上角：上传/商店/刷新，切 Tab 常驻可见（运行日志 Tab 隐藏上传/商店） -->
        <template #rightExtra>
          <a-space>
            <template v-if="tab !== 'logs'">
              <a-upload :show-upload-list="false" accept=".tar.gz,.tgz,.zip" :before-upload="(f: File) => pickFile(f)">
                <a-button type="primary"><template #icon><UploadOutlined /></template>{{ translate('ui.m_0aa0d37f58c4') }}</a-button>
              </a-upload>
              <a-button @click="openStore"><template #icon><AppstoreOutlined /></template>{{ translate('ui.m_9449fa923c64') }}</a-button>
            </template>
            <a-button @click="refreshCurrent"><template #icon><ReloadOutlined /></template>{{ translate('ui.m_aee887434131') }}</a-button>
          </a-space>
        </template>

        <!-- 工具扩展（原「AI 扩展」子页改名）：内含 AI 工具扩展 / 内核工具扩展 两个子 Tab -->
        <a-tab-pane key="tools" tab="工具扩展">
          <a-tabs v-model:activeKey="subTab" @change="onSubTab" size="small">
            <!-- AI 工具扩展：AI 可调用的工具，据此生成 AI 工具表（内置工具 + 已装 AI 扩展，统一按功能分类展示，不再分隔） -->
            <a-tab-pane key="ai" tab="AI 工具扩展">
              <div class="hint">{{ translate('ui.m_46614e71e8dc') }}</div>
              <div class="toolbar">
                <span class="muted">{{ translate('ui.m_76e547a8fa54') }} {{ builtin.length + aiExts.length }} {{ translate('ui.m_b6c44909348b') }} {{ builtin.length }} {{ translate('ui.m_c5ec89befba3') }} {{ aiExts.length }}{{ translate('ui.m_961bc8bf4f92') }} {{ aiGroups.length }} {{ translate('ui.m_4fb249b9d7ac') }}</span>
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
                      <a-tag :color="t.available ? 'green' : 'default'" size="small">{{ t.available ? translate('ui.m_d59e47070f7f') : translate('ui.m_af33de3507b4') }}</a-tag>
                    </div>
                    <div class="c-cat">
                      <a-tag :color="t.origin === 'third_party' ? 'orange' : 'cyan'" size="small">
                        {{ t.origin === 'third_party' ? translate('ui.m_376cbd8cfc85') : translate('ui.m_4e88cd310f2c') }}
                      </a-tag>
                      <span class="c-tag builtin">{{ translate('ui.m_95e35aabd9a9') }}</span>
                    </div>
                    <div class="c-sum">{{ t.summary || t.description }}</div>
                    <div v-if="t.params && t.params.length" class="c-params">
                      <span class="c-params-label">{{ translate('ui.m_9634fb0832be') }}</span>
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
              <div class="hint">{{ translate('ui.m_ca1c159f4c13') }}</div>
              <div class="toolbar">
                <span class="muted">{{ translate('ui.m_76e547a8fa54') }} {{ kernelBuiltin.length + featureExts.length }} {{ translate('ui.m_13457a509db5') }} {{ kernelBuiltin.length }} {{ translate('ui.m_c5ec89befba3') }} {{ featureExts.length }}）</span>
              </div>
              <!-- 内核内置工具（只读） + 已装内核扩展 合并为一个连续列表，去掉两段分隔 -->
              <a-empty v-if="!kernelBuiltin.length && !featureExts.length" :description="translate('ui.m_1e13ffda90aa')" />
              <div v-else class="grid">
                <!-- 内核内置工具卡（只读，AI 禁用，不可移除） -->
                <div v-for="t in kernelBuiltin" :key="t.name" class="ext-card readonly">
                  <div class="c-head">
                    <code class="c-name">{{ t.name }}</code>
                    <a-tag :color="t.available ? 'green' : 'default'" size="small">{{ t.available ? translate('ui.m_952e164dd982') : translate('ui.m_af33de3507b4') }}</a-tag>
                  </div>
                  <div class="c-cat">
                    <a-tag :color="t.origin === 'third_party' ? 'orange' : 'cyan'" size="small">
                      {{ t.origin === 'third_party' ? translate('ui.m_376cbd8cfc85') : translate('ui.m_4e88cd310f2c') }}
                    </a-tag>
                    <span class="c-tag builtin">{{ translate('ui.m_95e35aabd9a9') }}</span>
                    <a-tag color="red" size="small">{{ translate('ui.m_9e6d81f58f0c') }}</a-tag>
                  </div>
                  <div class="c-sum">{{ t.summary || t.description }}</div>
                  <div v-if="t.params && t.params.length" class="c-params">
                    <span class="c-params-label">{{ translate('ui.m_9634fb0832be') }}</span>
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
            <a-input v-model:value="logFilter" :placeholder="translate('ui.m_82420d52a5cc')" style="width:220px" allow-clear />
            <a-button @click="loadLogs">{{ translate('ui.m_bcd6771e08ec') }}</a-button>
          </div>
          <a-table :data-source="logs" :columns="logColumns" row-key="_id" size="small" />
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 扩展商店抽屉 -->
    <a-drawer v-model:open="storeOpen" :title="translate('ui.m_9449fa923c64')" width="640" @open="loadStore">
      <a-alert v-if="storeError && storeAuthState !== 'ok'" type="warning" show-icon style="margin-bottom:12px">
        <template #message>
          {{ storeError }}
          <a-button type="link" size="small" @click="$router.push('/about/activation')" style="padding:0 4px">{{ translate('ui.m_e12cdebb88f8') }}</a-button>
        </template>
      </a-alert>
      <a-alert v-else-if="storeError" type="info" :message="storeError" show-icon style="margin-bottom:12px" />
      <div class="toolbar"><span class="muted">{{ translate('ui.m_9c1c75322816') }}</span><a-button size="small" @click="loadStore">{{ translate('ui.m_aee887434131') }}</a-button></div>
      <a-empty v-if="!store.length && !storeError" :description="translate('ui.m_e88e38f1a957')" />
      <div class="grid">
        <div v-for="e in store" :key="e.extension_id" class="ext-card">
          <div class="c-head"><code class="c-name">{{ e.name || e.extension_id }}</code>
            <a-tag :color="e.ext_type === 'both' ? 'purple' : e.ext_type === 'feature' ? 'cyan' : 'geekblue'" size="small">{{ e.ext_type === 'both' ? translate('ui.m_4e7009404af9') : e.ext_type === 'feature' ? translate('ui.m_9699be65e632') : translate('ui.m_061afd55163f') }}</a-tag>
          </div>
          <div class="c-cat"><a-tag color="blue" size="small">{{ e.category }}</a-tag><a-tag :color="e.origin === 'third_party' ? 'orange' : 'cyan'" size="small">{{ e.origin === 'third_party' ? translate('ui.m_376cbd8cfc85') : translate('ui.m_4e88cd310f2c') }}</a-tag><span class="muted">v{{ e.version }}</span></div>
          <div class="c-sum">{{ e.summary }}</div>
          <div class="c-actions"><a-button type="primary" size="small" @click="install(e)">{{ translate('ui.m_9b393d495f23') }}</a-button></div>
        </div>
      </div>
    </a-drawer>

    <!-- 扩展详情抽屉 -->
    <a-drawer v-model:open="detailOpen" :title="detail?.name || detail?.extension_id" width="560">
      <template v-if="detail">
        <a-descriptions :column="1" size="small" bordered>
          <a-descriptions-item :label="translate('ui.m_82420d52a5cc')"><code>{{ detail.extension_id }}</code></a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_ba40014ff496')">{{ detail.ext_type === 'both' ? translate('ui.m_7ff66f176951') : detail.ext_type === 'feature' ? translate('ui.m_fc8728557ff8') : translate('ui.m_c3b69dcbda21') }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_5f76b2bf82dd')">{{ detail.version }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_515559957fd3')">{{ detail.category }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_a488e93d69cc')">{{ detail.source === 'store' ? translate('ui.m_9449fa923c64') : translate('ui.m_02413a69d5ca') }}（{{ detail.trust }}）</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_21275af720b3')">
            <a-tag :color="detail.origin === 'third_party' ? 'orange' : 'cyan'">{{ detail.origin === 'third_party' ? translate('ui.m_376cbd8cfc85') : translate('ui.m_4e88cd310f2c') }}</a-tag>
            <span v-if="detail.origin === 'third_party'" class="muted">{{ detail.vendor }} · {{ detail.license }} {{ translate('ui.m_a419fd912fa2') }} {{ detail.upstream_version }}</span>
          </a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_174df048bacb')">
            <a-tag :color="detail.available ? 'green' : 'red'">{{ detail.available ? translate('ui.m_e1ba8151b252') : detail.unavailable_reason || translate('ui.m_460b3574e4bd') }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_d334c402ead1')">{{ detail.enabled ? translate('ui.m_dfb802238b38') : translate('ui.m_a8c3698b5b8c') }}</a-descriptions-item>
        </a-descriptions>
        <div class="d-block"><b>{{ translate('ui.m_21c04b2eeeb4') }}</b><p>{{ detail.summary }}</p></div>
        <div class="d-block"><b>{{ translate('ui.m_4262c45dc797') }}</b><p>{{ detail.description }}</p></div>
        <div class="d-block" v-if="detail.ext_type !== 'feature' && detail.ai_instruction"><b>{{ translate('ui.m_2fb90c162c46') }}</b><p>{{ detail.ai_instruction }}</p></div>
        <div class="d-block" v-if="detailParams.length"><b>{{ translate('ui.m_9634fb0832be') }}</b>
          <ul><li v-for="p in detailParams" :key="p.name"><code>{{ p.name }}</code><i v-if="p.required" class="req">{{ translate('ui.m_7aa0babac834') }}</i> — {{ p.desc || '—' }}</li></ul>
        </div>
      </template>
    </a-drawer>

    <!-- 上传目标选择：本地安装运行 / 提交云端商店审核 -->
    <a-modal v-model:open="uploadOpen" :title="translate('ui.m_0aa0d37f58c4')" :confirm-loading="uploading"
      :ok-text="uploadTarget === 'cloud' ? translate('ui.m_ba2120c98884') : translate('ui.m_ada9c55359d7')" @ok="doUpload" @cancel="pendingFile = null">
      <p class="up-file">{{ translate('ui.m_f34fa313b2d3') }}<code>{{ pendingFile?.name }}</code>{{ translate('ui.m_92c87e695608') }}</p>
      <a-radio-group v-model:value="uploadTarget" class="up-target">
        <a-radio value="local">{{ translate('ui.m_04b1c39196ac') }}</a-radio>
        <a-radio value="cloud">{{ translate('ui.m_a5a3f7fcf05e') }}</a-radio>
      </a-radio-group>
      <a-alert v-if="uploadTarget === 'local'" type="warning" show-icon
        :message="translate('ui.m_6cffb138e983')" />
      <a-alert v-else type="info" show-icon
        :message="translate('ui.m_de42954e4d13')" />
    </a-modal>
  </PageContainer>
</template>
<script setup lang="ts">
import { t as translate } from '../../i18n'

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
    const k = cat || translate('ui.m_d2909f1647e7')
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
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date' }, { get title() { return translate('ui.m_c560201b331c') }, dataIndex: 'event' },
  { get title() { return translate('ui.m_99a4e1e59743') }, dataIndex: 'extension_id' }, { get title() { return translate('ui.m_a63280253f17') }, dataIndex: 'session_id' },
  { get title() { return translate('ui.m_6320b4a8722a') }, dataIndex: 'status' }, { get title() { return translate('ui.m_105bab45479c') }, dataIndex: 'duration_ms' }, { get title() { return translate('ui.m_0bc1fb72ae1b') }, dataIndex: 'error' }
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
      if (r && r.ok) { message.success(translate('ui.m_d596e522e35c')); uploadOpen.value = false; pendingFile.value = null }
      else message.error((r && r.error) || translate('ui.m_1440c7e23865'))
    } else {
      await aiExtensionApi.upload(file); message.success(translate('ui.m_d044be36c4fa')); loadAi(); loadFeature()
      uploadOpen.value = false; pendingFile.value = null
    }
  } catch (e) { message.error(String(e)) }
  finally { uploading.value = false }
}
async function toggle(r: ExtensionItem, v: boolean) {
  try { v ? await aiExtensionApi.enable(r.extension_id) : await aiExtensionApi.disable(r.extension_id); r.enabled = v; message.success(v ? translate('ui.m_dfb802238b38') : translate('ui.m_a8c3698b5b8c')) }
  catch (e) { message.error(String(e)) }
}
async function check(r: ExtensionItem) { try { await aiExtensionApi.check(r.extension_id); message.success(translate('ui.m_37888055c912')); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } }
async function remove(r: ExtensionItem) { try { await aiExtensionApi.remove(r.extension_id); message.success(translate('ui.m_077a6d37719a')); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } }
async function install(r: ExtensionItem) { try { await aiExtensionApi.install(r); message.success(translate('ui.m_a98e6c2031e5')); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } }
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
