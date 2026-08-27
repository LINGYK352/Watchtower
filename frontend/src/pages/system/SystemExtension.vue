<template>
  <PageContainer title="系统扩展" kicker="System Extensions"
    description="扩展平台能力。AI 扩展是 AI 渗透可主动调用的工具；功能扩展是面向平台/人工使用的功能模块。">
    <a-alert type="warning" show-icon class="risk"
      message="本地 Python/二进制扩展等价于授予主机代码执行能力"
      description="仅上传可信扩展。平台以子进程、目标 scope、资源限制与审计降低风险，但无法证明黑盒程序不会自行越界。" />

    <a-card class="page-card">
      <a-tabs v-model:activeKey="tab" @change="onTab">
        <!-- 固定在 Tab 栏右上角：上传/商店/刷新，切 Tab 常驻可见（运行日志 Tab 隐藏上传/商店） -->
        <template #rightExtra>
          <a-space>
            <template v-if="tab !== 'logs'">
              <a-upload :show-upload-list="false" accept=".tar.gz,.tgz" :before-upload="(f: File) => upload(f)">
                <a-button type="primary"><template #icon><UploadOutlined /></template>上传扩展</a-button>
              </a-upload>
              <a-button @click="openStore"><template #icon><AppstoreOutlined /></template>扩展商店</a-button>
            </template>
            <a-button @click="refreshCurrent"><template #icon><ReloadOutlined /></template>刷新</a-button>
          </a-space>
        </template>

        <!-- AI 扩展 -->
        <a-tab-pane key="ai" tab="AI 扩展">
          <div class="hint">AI 渗透会话可主动调用的工具。内置能力随平台发布不可移除；已装 AI 工具扩展可启停，仅启用后 AI 才能看到并调用。上传的 .tar.gz 扩展包按其 manifest 的 ext_type 自动归入本类或功能扩展。</div>

          <a-divider orientation="left" class="sec">内置能力（{{ builtin.length }}）</a-divider>
          <div class="toolbar">
            <span class="muted">共 {{ builtin.length }} 个内置工具，按功能分 {{ builtinGroups.length }} 类（随平台发布，不可移除）</span>
          </div>
          <!-- 按 7 类功能维度分组展示（与「AI 工具」页一致） -->
          <div v-for="g in builtinGroups" :key="g.name" class="cat-block">
            <a-divider orientation="left" class="cat-title">
              {{ g.name }}<a-tag color="blue" style="margin-left:6px">{{ g.tools.length }}</a-tag>
            </a-divider>
            <div class="grid">
              <div v-for="t in g.tools" :key="t.name" class="ext-card readonly">
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
            </div>
          </div>

          <a-divider orientation="left" class="sec">已装 AI 工具扩展（{{ aiExts.length }}）</a-divider>
          <a-empty v-if="!aiExts.length" description="暂无已安装的 AI 工具扩展，点右上角「上传扩展」或「扩展商店」添加" />
          <div v-else class="grid">
            <ExtCard v-for="e in aiExts" :key="e.extension_id" :ext="e"
              @toggle="toggle" @detail="showDetail" @remove="remove" @check="check" />
          </div>
        </a-tab-pane>

        <!-- 功能扩展 -->
        <a-tab-pane key="feature" tab="功能扩展">
          <div class="hint">面向平台与人工使用的功能模块（如新数据源、报告格式、面板等）。功能扩展不进入 AI 工具表，AI 不会自动调用。</div>
          <a-divider orientation="left" class="sec">已装功能扩展（{{ featureExts.length }}）</a-divider>
          <a-empty v-if="!featureExts.length" description="暂无已安装的功能扩展，点右上角「上传扩展」或「扩展商店」添加" />
          <div v-else class="grid">
            <ExtCard v-for="e in featureExts" :key="e.extension_id" :ext="e"
              @toggle="toggle" @detail="showDetail" @remove="remove" @check="check" />
          </div>
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
      <a-alert v-if="storeError" type="info" :message="storeError" show-icon style="margin-bottom:12px" />
      <div class="toolbar"><span class="muted">使用统一 JWT 激活凭证访问扩展商店</span><a-button size="small" @click="loadStore">刷新</a-button></div>
      <a-empty v-if="!store.length && !storeError" description="商店暂无可用扩展" />
      <div class="grid">
        <div v-for="e in store" :key="e.extension_id" class="ext-card">
          <div class="c-head"><code class="c-name">{{ e.name || e.extension_id }}</code>
            <a-tag :color="e.ext_type === 'feature' ? 'purple' : 'geekblue'" size="small">{{ e.ext_type === 'feature' ? '功能扩展' : 'AI 扩展' }}</a-tag>
          </div>
          <div class="c-cat"><a-tag color="blue" size="small">{{ e.category }}</a-tag><span class="muted">v{{ e.version }}</span></div>
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
          <a-descriptions-item label="类型">{{ detail.ext_type === 'feature' ? '功能扩展（平台功能）' : 'AI 扩展（AI 可调用工具）' }}</a-descriptions-item>
          <a-descriptions-item label="版本">{{ detail.version }}</a-descriptions-item>
          <a-descriptions-item label="分类">{{ detail.category }}</a-descriptions-item>
          <a-descriptions-item label="来源">{{ detail.source === 'store' ? '扩展商店' : '本地上传' }}（{{ detail.trust }}）</a-descriptions-item>
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
  </PageContainer>
</template>
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { message, Modal } from 'ant-design-vue'
import { UploadOutlined, AppstoreOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import ExtCard from './ExtCard.vue'
import { aiExtensionApi, type ExtensionItem, type BuiltinTool, type ExtParam } from '../../api/aiExtension'

const tab = ref('ai')
const builtin = ref<BuiltinTool[]>([])
const aiExts = ref<ExtensionItem[]>([])
const featureExts = ref<ExtensionItem[]>([])
const store = ref<ExtensionItem[]>([])
const logs = ref<Record<string, unknown>[]>([])
const storeError = ref('')
const storeOpen = ref(false)
const detailOpen = ref(false)
const detail = ref<ExtensionItem | null>(null)
const logFilter = ref('')

// 内置能力按 7 类功能维度分组展示（与「AI 工具」页 CAT_ORDER 一致；未登记的新分类排最后不丢）
const CAT_ORDER = ['资产收集', '漏洞验证', '情报查询', '情报回写', '带外通道', '浏览器', '内网后渗透']
const builtinGroups = computed(() => {
  const map = new Map<string, BuiltinTool[]>()
  for (const t of builtin.value) {
    if (!map.has(t.category)) map.set(t.category, [])
    map.get(t.category)!.push(t)
  }
  return Array.from(map.entries())
    .map(([name, tools]) => ({ name, tools }))
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
async function loadFeature() { try { featureExts.value = (await aiExtensionApi.list({ ext_type: 'feature' })).items || [] } catch (e) { message.error(String(e)) } }
async function loadLogs() { try { logs.value = (await aiExtensionApi.logs({ extension_id: logFilter.value, size: 50 })).items || [] } catch (e) { message.error(String(e)) } }
async function loadStore() { storeError.value = ''; try { const r = await aiExtensionApi.store(); store.value = r.items || []; storeError.value = r.error || '' } catch (e) { storeError.value = e instanceof Error ? e.message : String(e) } }
function openStore() { storeOpen.value = true; loadStore() }

function onTab(k: string) { if (k === 'ai') { loadBuiltin(); loadAi() } else if (k === 'feature') loadFeature(); else loadLogs() }
function refreshCurrent() { onTab(tab.value) }

function upload(file: File) {
  Modal.confirm({ title: '确认授予扩展执行权限？', content: `将安装 ${file.name}。仅上传你完全信任的代码。扩展 manifest 的 ext_type 决定归入 AI 扩展或功能扩展。`, okType: 'danger',
    async onOk() { try { await aiExtensionApi.upload(file); message.success('扩展已安装，兼容后可手工启用'); loadAi(); loadFeature() } catch (e) { message.error(String(e)) } } })
  return false
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
</style>
