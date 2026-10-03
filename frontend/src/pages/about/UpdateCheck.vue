<template>
  <PageContainer :title="translate('ui.m_db216ba9c123')" kicker="Update" :description="translate('ui.m_117fd8da5685')">
    <a-card class="page-card">
      <div class="ver-hero">
        <div class="ver-badge"><CloudSyncOutlined /></div>
        <div>
          <div class="ver-label">{{ translate('ui.m_837bc9576721') }}</div>
          <div class="ver-num">{{ version }}</div>
        </div>
      </div>

      <a-divider style="margin:18px 0" />

      <a-space direction="vertical" size="middle" style="width:100%">
        <a-button type="primary" :loading="checking" @click="doCheck">
          <template #icon><CloudSyncOutlined /></template>{{ translate('ui.m_7f68ebad19ba') }}
        </a-button>

        <!-- 发现新版本 -->
        <div v-if="checked && hasUpdate && !updating && !updateDone && !updateError" class="update-found">
          <a-alert type="success" show-icon>
            <template #message>{{ translate('ui.m_ac217e4d1ca4') }} <a-tag color="blue">{{ latest }}</a-tag></template>
            <template #description>
              <a-tag color="green" style="margin-bottom:12px">{{ translate('ui.m_432bb30c280d') }}</a-tag>
              <div v-if="changelogs.length" class="changelog-box">
                <div class="changelog-title">
                  {{ translate('ui.m_00d640b1490e') }} {{ latest }}<span v-if="changelogs.length > 1">{{ translate('ui.m_7d2ea55dbbc5') }} {{ changelogs.length }} {{ translate('ui.m_3961b2e3b43d') }}</span>
                </div>
                <div class="changelog-item" v-for="item in changelogs" :key="item.ver">
                  <span class="changelog-ver">{{ item.ver }}</span>
                  <span class="changelog-text">{{ item.summary }}</span>
                </div>
              </div>
            </template>
          </a-alert>
          <a-button type="primary" size="large" @click="startUpdate" style="margin-top:12px">
            {{ translate('ui.m_12487befb4ba') }}
          </a-button>
        </div>

        <!-- 更新进度 -->
        <div v-if="updating" style="margin-top:8px">
          <a-progress :percent="percent" :status="progressStatus" size="small" />
          <p style="font-size:12px;color:#8b949e;margin-top:6px">{{ progressMsg }}</p>
        </div>

        <!-- 更新完成（自动刷新） -->
        <a-alert v-if="updateDone" type="success" show-icon
          :message="translate('ui.m_d5e461beff13')" :description="translate('ui.m_af52baea4d35')" />

        <!-- 更新失败 -->
        <a-alert v-if="updateError" type="error" show-icon
          :message="translate('ui.m_ec99e5c45d64')" :description="updateError" />
        <a-button v-if="updateError" @click="resetUpdateState">{{ translate('ui.m_b8784c8dd563') }}</a-button>

        <!-- 已是最新 -->
        <a-alert v-if="checked && !hasUpdate && !networkError && !authError" type="success" show-icon
          :message="translate('ui.m_bc310480b4ce')"
          :description="serverMessage || (translate('ui.m_cb62ebd689ee') + version + translate('ui.m_b4f9b5812821'))" />

        <!-- 网络不可达 -->
        <a-alert v-if="checked && networkError" type="error" show-icon
          :message="translate('ui.m_3cbf99883cfd')"
          :description="translate('ui.m_ad6d34674b16')" />

        <!-- 凭证无效 -->
        <a-alert v-if="checked && authError" type="warning" show-icon
          :message="translate('ui.m_dc1508425319')"
          :description="translate('ui.m_56f1a94d9a35')" />

        <a-alert type="info" show-icon :message="translate('ui.m_6dc946916d90')"
          :description="translate('ui.m_b261f12d9e1b')" />
      </a-space>
    </a-card>

    <!-- 历史版本与回退（版本仓） -->
    <a-card class="page-card" style="margin-top:16px" v-if="canRollback">
      <template #title>
        <span><HistoryOutlined /> {{ translate('ui.m_6fd29579ab66') }}</span>
        <a-button type="link" size="small" :loading="loadingVersions" @click="loadVersions">{{ translate('ui.m_aee887434131') }}</a-button>
      </template>
      <a-alert type="warning" show-icon style="margin-bottom:12px"
        :message="translate('ui.m_cc52738ba3c0')"
        :description="translate('ui.m_49d414078aa2')" />
      <a-checkbox v-model:checked="fullRollback" style="margin-bottom:12px" :disabled="updating">
        {{ translate('ui.m_3ef7e543fc93') }}
      </a-checkbox>
      <a-alert v-if="versionsHint" type="info" show-icon style="margin-bottom:12px" :message="versionsHint" />
      <a-table :columns="versionColumns" :data-source="versions" :loading="loadingVersions"
        row-key="version" size="middle" :pagination="{ pageSize: 10 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'version'">
            <a-tag :color="record.version === version ? 'green' : 'blue'">{{ record.version }}</a-tag>
            <a-tag v-if="record.version === version" color="green">{{ translate('ui.m_cb62ebd689ee') }}</a-tag>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-button type="link" size="small" @click="viewChanges(record.version)">{{ translate('ui.m_582a8e42e44e') }}</a-button>
            <!-- 仅对“严格低于当前版本”的历史版本显示回退：等于当前=显示“当前”标签，
                 高于当前=前滚/升级（应走上方“检查更新→立即更新”），不在回退入口出现，避免误导。 -->
            <a-popconfirm
              v-if="isOlderThanCurrent(record.version)"
              :title="translate('ui.m_885df13560e0', { p0: (record.version) })"
              :ok-text="translate('ui.m_8771e3682df1')" :cancel-text="translate('ui.m_2cd0f3be8738')" @confirm="doRollback(record.version)">
              <a-button type="link" danger size="small">{{ translate('ui.m_8771e3682df1') }}</a-button>
            </a-popconfirm>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 改动详情抽屉 -->
    <a-drawer v-model:open="changesOpen" :title="translate('ui.m_7b421c218686', { p0: (changesVersion) })" width="520">
      <a-spin :spinning="loadingChanges">
        <template v-if="changes">
          <a-descriptions size="small" :column="1" bordered style="margin-bottom:12px">
            <a-descriptions-item :label="translate('ui.m_e8ff4d335dee')">{{ changes.published_at || '-' }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_c3066077e363')">{{ changes.from || translate('ui.m_f8605f479658') }} → {{ changes.to }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_a8bab354dba5')">{{ changes.total }}</a-descriptions-item>
          </a-descriptions>
          <a-collapse>
            <a-collapse-panel key="added" :header="translate('ui.m_56c7b458ec2b', { p0: (changes.added.length) })">
              <div v-for="f in changes.added" :key="f" class="change-file added">+ {{ f }}</div>
              <a-empty v-if="!changes.added.length" :image="false" :description="translate('ui.m_484d55613910')" />
            </a-collapse-panel>
            <a-collapse-panel key="changed" :header="translate('ui.m_6d0479a97f14', { p0: (changes.changed.length) })">
              <div v-for="f in changes.changed" :key="f" class="change-file changed">~ {{ f }}</div>
              <a-empty v-if="!changes.changed.length" :image="false" :description="translate('ui.m_484d55613910')" />
            </a-collapse-panel>
            <a-collapse-panel key="removed" :header="translate('ui.m_5218bb5b6d7d', { p0: (changes.removed.length) })">
              <div v-for="f in changes.removed" :key="f" class="change-file removed">- {{ f }}</div>
              <a-empty v-if="!changes.removed.length" :image="false" :description="translate('ui.m_484d55613910')" />
            </a-collapse-panel>
          </a-collapse>
        </template>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { message } from 'ant-design-vue'
import { CloudSyncOutlined, HistoryOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { APP_VERSION } from '../../config/brand'
import { checkUpdate, applyUpdate, getProgress, getChangelog,
  getVersions, getVersionChanges, rollbackTo, type VersionItem, type ChangesResult } from '../../api/about'
import { hasPerm } from '../../api/request'
import { useServerVersion } from '../../composables/useServerVersion'

// 「当前版本」显示/版本表比对/回退资格/changelog 过滤都用**后端真实版本**（version.txt），
// 非编译进包的 APP_VERSION——跳板逐级更新时前端产物 brand 标签可能滞后/错配。
const { serverVersion: version } = useServerVersion()
const canRollback = computed(() => hasPerm('system:update') || getRoleIsAdmin())
function getRoleIsAdmin() { return (localStorage.getItem('arl_role') || '') === 'admin' }

// 版本号数值比较（与后端 update_check._cmp 同逻辑）：剥 v 前缀，逐段按数值比，补齐位数。
// 修复原字符串比较 bug：'v1.21.65' > 'v1.21.131' 字符串比会误判为 true（'6'>'1'），
// 导致 v1.21.6x 等旧版被当成“比当前新”混进更新内容列表（看似反向更新）。
function _parseVer(v: string): number[] {
  return String(v || '').trim().replace(/^v/i, '').split(/[.\-_]/).map(s => {
    const m = /^\d+/.exec(s); return m ? parseInt(m[0], 10) : 0
  })
}
function _cmpVer(a: string, b: string): number {
  const ta = _parseVer(a), tb = _parseVer(b)
  const n = Math.max(ta.length, tb.length)
  for (let i = 0; i < n; i++) {
    const x = ta[i] || 0, y = tb[i] || 0
    if (x !== y) return x > y ? 1 : -1
  }
  return 0
}
// 模板可用包装：仅“严格低于当前版本”才是可回退目标（等于=当前，高于=前滚/升级不在此入口）。
// 注：<script setup> 中以 _ 开头的绑定不暴露给模板，故用不带下划线的名字包一层给 v-if 用。
function isOlderThanCurrent(v: string): boolean {
  return _cmpVer(v, version.value) < 0
}

// —— 历史版本与回退 ——
const versions = ref<VersionItem[]>([])
const loadingVersions = ref(false)
const versionsHint = ref('')   // 空列表/不支持时的友好提示（不再弹 error）
const fullRollback = ref(false)
const versionColumns = [
  { get title() { return translate('ui.m_5f76b2bf82dd') }, key: 'version', dataIndex: 'version' },
  { get title() { return translate('ui.m_e8ff4d335dee') }, dataIndex: 'published_at', key: 'published_at' },
  { get title() { return translate('ui.m_b3fa95f830ed') }, dataIndex: 'files', key: 'files', width: 90 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 140 },
]
async function loadVersions() {
  loadingVersions.value = true
  versionsHint.value = ''
  try {
    const r = await getVersions()
    versions.value = r.versions || []
    // 空列表分三种语义，别混为一谈（治"暂无历史版本"闪烁：其实是拿取失败非真没有）：
    //   unsupported  = 分发源尚不支持版本仓端点（确定性，升级分发端才有）
    //   fetch_failed = 转发层重试 N 次仍超时/失败（偶发，重试即可，不是真没历史）
    //   都不是       = 分发源确实还没归档历史版本
    if (!versions.value.length) {
      if (r.fetch_failed) {
        versionsHint.value = '暂时获取历史版本失败（网络波动），请点“刷新”重试。'
      } else if (r.unsupported) {
        versionsHint.value = '当前分发源暂不支持历史版本仓，升级分发端后可用。'
      } else {
        versionsHint.value = '暂无历史版本记录。'
      }
    }
  } catch (e) {
    // 真·异常（网络中断等）才提示，且降级为温和 warning，不用刺眼的 error。
    versionsHint.value = '获取历史版本失败：' + (e instanceof Error ? e.message : String(e))
  }
  loadingVersions.value = false
}

const changesOpen = ref(false)
const changesVersion = ref('')
const changes = ref<ChangesResult | null>(null)
const loadingChanges = ref(false)
async function viewChanges(v: string) {
  changesVersion.value = v
  changesOpen.value = true
  changes.value = null
  loadingChanges.value = true
  try {
    changes.value = await getVersionChanges(v)
  } catch (e) {
    message.error(e instanceof Error ? e.message : translate('ui.m_604c41b3aa28'))
  }
  loadingChanges.value = false
}

async function doRollback(v: string) {
  try {
    await rollbackTo(v, fullRollback.value)
    message.info(translate('ui.m_db42c90f4a60', { p0: (v) }))
    updating.value = true
    updateError.value = ''
    pollProgress()
  } catch (e) {
    message.error(e instanceof Error ? e.message : translate('ui.m_577da48e1938'))
  }
}

onMounted(async () => {
  if (canRollback.value) loadVersions()
  // v1.21.159-x 后台更新：更新器是独立进程、进度落服务端文件——切菜单/刷新返回后，
  // 若后台仍在更新，重新挂上进度轮询（不丢进度、不用重新点更新）。
  try {
    const p = await getProgress()
    if (p && ['downloading', 'compiling', 'applying', 'checking'].includes(p.phase)) {
      progress.value = p
      updating.value = true
      updateError.value = ''
      pollProgress()
    }
  } catch { /* 取不到进度=没有在跑，忽略 */ }
})
const checking = ref(false)
const checked = ref(false)
const hasUpdate = ref(false)
const networkError = ref(false)
const authError = ref(false)
const latest = ref('')
const serverMessage = ref('')
const changelogs = ref<{ver: string, date: string, summary: string}[]>([])

const updating = ref(false)
const updateDone = ref(false)
const updateError = ref('')
const progress = ref<{phase: string, total: number, done: number, msg: string, ts?: number, error?: string}>({phase: 'idle', total: 0, done: 0, msg: ''})
let pollTimer: ReturnType<typeof setInterval> | null = null
// 链式更新 stale 检测：跟踪后端 progress 最近一次「有推进」的本地墙钟（用前端本地时钟，免前后端时钟不同步）。
// 非终结相位(applying/checking/downloading)持续 STALE_MS 无推进 → 判链断，给重试（不再死等）。
const _CHAIN_STALE_MS = 200000   // 200s：略大于后端 watchdog 兜底窗口(180s)，让自动续跑先兜底、仍不动才提示用户
let _lastProgKey = ''
let _lastProgWall = 0

const percent = computed(() => {
  if (!progress.value.total) return _prevPct.value
  const cur = Math.round((progress.value.done / progress.value.total) * 100)
  // 一级一级更新：每跳都从 done=0 重新计数。新跳开始（done 归 0）时重置棘轮，
  // 否则进度条会被上一跳的 100% 钉死、后续跳看不到进度。跳内仍单调递增（不回跳抖动）。
  if (progress.value.done === 0) _prevPct.value = 0
  if (cur > _prevPct.value) _prevPct.value = cur
  return _prevPct.value
})
const _prevPct = ref(0)
const progressStatus = computed(() => progress.value.phase === 'error' ? 'exception' as const : 'active' as const)
const progressMsg = computed(() => {
  const msg = progress.value.msg
  if (msg) { _prevMsgVal.value = msg; return msg }
  return _prevMsgVal.value || translate('ui.m_c68d88d6f41e')
})
const _prevMsgVal = ref('')

async function doCheck() {
  checking.value = true
  checked.value = false
  networkError.value = false
  authError.value = false
  changelogs.value = []
  try {
    // check?client= 上报**前端构建版本**(APP_VERSION)：后端据此判断「是否提示刷新拿新构建」，与后端 version 比对
    const r = await checkUpdate(APP_VERSION)
    if (r.error_type === 'unauthorized') {
      authError.value = true
    } else if (r.error_type === 'network') {
      networkError.value = true
      serverMessage.value = r.message || ''
    } else {
      hasUpdate.value = r.has_update
      latest.value = r.latest_version || r.server_version || version.value
      serverMessage.value = r.message || ''
      // Fetch changelog if update available
      if (r.has_update) {
        try {
          const logs = await getChangelog()
          changelogs.value = (logs || [])
            .filter((l: any) => _cmpVer(l.ver, version.value) > 0)   // 数值比较：只留真正比当前(后端真实版本)新的
            .sort((a: any, b: any) => _cmpVer(b.ver, a.ver))   // 新→旧排序
            .slice(0, 10)
        } catch { /* ignore */ }
      }
    }
  } catch {
    networkError.value = true
    serverMessage.value = ''
  }
  checked.value = true
  checking.value = false
}

async function startUpdate() {
  updating.value = true
  updateError.value = ''
  try {
    await applyUpdate()
    pollProgress()
  } catch (e) {
    updateError.value = e instanceof Error ? e.message : String(e)
    updating.value = false
  }
}

function pollProgress() {
  _lastProgKey = ''; _lastProgWall = Date.now()   // 每次挂轮询重置 stale 基准
  pollTimer = setInterval(async () => {
    try {
      const p = await getProgress()
      progress.value = p
      if (p.phase === 'done') {
        if (pollTimer) clearInterval(pollTimer)
        updating.value = false
        updateDone.value = true
        // 自动刷新
        setTimeout(() => window.location.reload(), 2000)
      } else if (p.phase === 'error') {
        if (pollTimer) clearInterval(pollTimer)
        updating.value = false
        updateError.value = p.error || '未知错误'
      } else {
        // 非终结相位：靠后端 ts + done/msg 组合判「是否有推进」。有变化则刷新墙钟；
        // 持续 _CHAIN_STALE_MS 无任何推进 → 判链式续跑中断，停轮询给重试（后端 watchdog 已先兜底重派）。
        const key = `${p.ts || 0}|${p.phase}|${p.done}|${p.msg}`
        if (key !== _lastProgKey) { _lastProgKey = key; _lastProgWall = Date.now() }
        else if (Date.now() - _lastProgWall > _CHAIN_STALE_MS) {
          if (pollTimer) clearInterval(pollTimer)
          updating.value = false
          updateError.value = '更新似乎已中断（续跑未推进）。系统会自动尝试续跑，可点「重试」立即从当前版本继续，或稍后刷新页面查看。'
        }
      }
    } catch { /* continue polling */ }
  }, 1000)
}

function resetUpdateState() { updating.value = false; updateError.value = ''; updateDone.value = false }

// 切菜单/卸载只停本地轮询（后台更新进程照跑，进度落服务端文件）；返回时 onMounted 重新挂轮询。
onUnmounted(() => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null } })
</script>

<style scoped>
.ver-hero { display: flex; align-items: center; gap: 18px; }
.ver-badge { width: 60px; height: 60px; border-radius: 16px; background: #eef3f9; color: var(--dt-primary); font-size: 28px; display: flex; align-items: center; justify-content: center; flex: none; }
.ver-label { color: var(--dt-muted); font-size: 13px; }
.ver-num { font-size: 30px; font-weight: 750; letter-spacing: -.01em; margin-top: 2px; }
.changelog-box { background: #f6f8fa; border-radius: 8px; padding: 12px; margin-top: 8px; max-height: 200px; overflow-y: auto; }
.changelog-title { font-size: 13px; font-weight: 600; color: #1f2328; margin-bottom: 8px; }
.changelog-item { padding: 5px 0; border-bottom: 1px solid #e1e4e8; font-size: 12px; display: flex; gap: 8px; }
.changelog-item:last-child { border-bottom: none; }
.changelog-ver { color: #0969da; font-weight: 600; flex-shrink: 0; }
.changelog-text { color: #656d76; }
.change-file { font-family: 'JetBrains Mono', monospace; font-size: 12px; padding: 2px 0; word-break: break-all; }
.change-file.added { color: #1a7f37; }
.change-file.changed { color: #9a6700; }
.change-file.removed { color: #cf222e; }
</style>
