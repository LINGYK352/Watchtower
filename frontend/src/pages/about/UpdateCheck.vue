<template>
  <PageContainer title="更新检测" kicker="Update" description="查看当前版本并检测是否有可用更新。">
    <a-card class="page-card">
      <div class="ver-hero">
        <div class="ver-badge"><CloudSyncOutlined /></div>
        <div>
          <div class="ver-label">当前版本</div>
          <div class="ver-num">{{ version }}</div>
        </div>
      </div>

      <a-divider style="margin:18px 0" />

      <a-space direction="vertical" size="middle" style="width:100%">
        <a-button type="primary" :loading="checking" @click="doCheck">
          <template #icon><CloudSyncOutlined /></template>检查更新
        </a-button>

        <!-- 发现新版本 -->
        <div v-if="checked && hasUpdate && !updating && !updateDone && !updateError" class="update-found">
          <a-alert type="success" show-icon>
            <template #message>发现新版本 <a-tag color="blue">{{ latest }}</a-tag></template>
            <template #description>
              <a-tag color="green" style="margin-bottom:12px">热更新 · 不影响现有业务</a-tag>
              <div v-if="changelogs.length" class="changelog-box">
                <div class="changelog-title">更新内容</div>
                <div class="changelog-item" v-for="item in changelogs" :key="item.ver">
                  <span class="changelog-ver">{{ item.ver }}</span>
                  <span class="changelog-text">{{ item.summary }}</span>
                </div>
              </div>
            </template>
          </a-alert>
          <a-button type="primary" size="large" @click="startUpdate" style="margin-top:12px">
            立即更新
          </a-button>
        </div>

        <!-- 更新进度 -->
        <div v-if="updating" style="margin-top:8px">
          <a-progress :percent="percent" :status="progressStatus" size="small" />
          <p style="font-size:12px;color:#8b949e;margin-top:6px">{{ progressMsg }}</p>
        </div>

        <!-- 更新完成（自动刷新） -->
        <a-alert v-if="updateDone" type="success" show-icon
          message="更新完成" description="更新已成功应用，正在刷新页面..." />

        <!-- 更新失败 -->
        <a-alert v-if="updateError" type="error" show-icon
          message="更新失败" :description="updateError" />
        <a-button v-if="updateError" @click="resetUpdateState">重试</a-button>

        <!-- 已是最新 -->
        <a-alert v-if="checked && !hasUpdate && !networkError && !authError" type="success" show-icon
          message="已是最新版本"
          :description="serverMessage || ('当前 ' + version + ' 已是最新版本。')" />

        <!-- 网络不可达 -->
        <a-alert v-if="checked && networkError" type="error" show-icon
          message="无法连接到更新服务器"
          description="请检查设备是否能够连接到网络。" />

        <!-- 凭证无效 -->
        <a-alert v-if="checked && authError" type="warning" show-icon
          message="授权凭证无效或已过期"
          description="无法检测更新，请前往「激活设置」重新激活系统。" />

        <a-alert type="info" show-icon message="更新机制说明"
          description="支持一键热更新，更新过程不影响现有业务。新版本发布后可手动触发或等待系统每小时自动检测。" />
      </a-space>
    </a-card>

    <!-- 历史版本与回退（版本仓） -->
    <a-card class="page-card" style="margin-top:16px" v-if="canRollback">
      <template #title>
        <span><HistoryOutlined /> 历史版本</span>
        <a-button type="link" size="small" :loading="loadingVersions" @click="loadVersions">刷新</a-button>
      </template>
      <a-alert type="warning" show-icon style="margin-bottom:12px"
        message="回退是高危操作"
        description="回退会把全站运行代码对齐到所选版本（含删除新版新增文件），并重启 worker/scheduler。仅在新版本出现严重问题时使用。" />
      <a-alert v-if="versionsHint" type="info" show-icon style="margin-bottom:12px" :message="versionsHint" />
      <a-table :columns="versionColumns" :data-source="versions" :loading="loadingVersions"
        row-key="version" size="middle" :pagination="{ pageSize: 10 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'version'">
            <a-tag :color="record.version === version ? 'green' : 'blue'">{{ record.version }}</a-tag>
            <a-tag v-if="record.version === version" color="green">当前</a-tag>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-button type="link" size="small" @click="viewChanges(record.version)">改动</a-button>
            <!-- 仅对“严格低于当前版本”的历史版本显示回退：等于当前=显示“当前”标签，
                 高于当前=前滚/升级（应走上方“检查更新→立即更新”），不在回退入口出现，避免误导。 -->
            <a-popconfirm
              v-if="isOlderThanCurrent(record.version)"
              :title="`确认回退到 ${record.version}？此操作影响全站运行代码。`"
              ok-text="回退" cancel-text="取消" @confirm="doRollback(record.version)">
              <a-button type="link" danger size="small">回退</a-button>
            </a-popconfirm>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 改动详情抽屉 -->
    <a-drawer v-model:open="changesOpen" :title="`版本改动 · ${changesVersion}`" width="520">
      <a-spin :spinning="loadingChanges">
        <template v-if="changes">
          <a-descriptions size="small" :column="1" bordered style="margin-bottom:12px">
            <a-descriptions-item label="发布时间">{{ changes.published_at || '-' }}</a-descriptions-item>
            <a-descriptions-item label="较上版">{{ changes.from || '（首版）' }} → {{ changes.to }}</a-descriptions-item>
            <a-descriptions-item label="变更总数">{{ changes.total }}</a-descriptions-item>
          </a-descriptions>
          <a-collapse>
            <a-collapse-panel key="added" :header="`新增 (${changes.added.length})`">
              <div v-for="f in changes.added" :key="f" class="change-file added">+ {{ f }}</div>
              <a-empty v-if="!changes.added.length" :image="false" description="无" />
            </a-collapse-panel>
            <a-collapse-panel key="changed" :header="`修改 (${changes.changed.length})`">
              <div v-for="f in changes.changed" :key="f" class="change-file changed">~ {{ f }}</div>
              <a-empty v-if="!changes.changed.length" :image="false" description="无" />
            </a-collapse-panel>
            <a-collapse-panel key="removed" :header="`删除 (${changes.removed.length})`">
              <div v-for="f in changes.removed" :key="f" class="change-file removed">- {{ f }}</div>
              <a-empty v-if="!changes.removed.length" :image="false" description="无" />
            </a-collapse-panel>
          </a-collapse>
        </template>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { CloudSyncOutlined, HistoryOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { APP_VERSION } from '../../config/brand'
import { checkUpdate, applyUpdate, getProgress, getChangelog,
  getVersions, getVersionChanges, rollbackTo, type VersionItem, type ChangesResult } from '../../api/about'
import { hasPerm } from '../../api/request'

const version = APP_VERSION
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
  return _cmpVer(v, version) < 0
}

// —— 历史版本与回退 ——
const versions = ref<VersionItem[]>([])
const loadingVersions = ref(false)
const versionsHint = ref('')   // 空列表/不支持时的友好提示（不再弹 error）
const versionColumns = [
  { title: '版本', key: 'version', dataIndex: 'version' },
  { title: '发布时间', dataIndex: 'published_at', key: 'published_at' },
  { title: '文件数', dataIndex: 'files', key: 'files', width: 90 },
  { title: '操作', key: 'action', width: 140 },
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
    message.error(e instanceof Error ? e.message : '获取改动失败')
  }
  loadingChanges.value = false
}

async function doRollback(v: string) {
  try {
    await rollbackTo(v)
    message.info(`已开始回退到 ${v}，正在应用…`)
    updating.value = true
    updateError.value = ''
    pollProgress()
  } catch (e) {
    message.error(e instanceof Error ? e.message : '回退失败')
  }
}

onMounted(() => { if (canRollback.value) loadVersions() })
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
const progress = ref<{phase: string, total: number, done: number, msg: string}>({phase: 'idle', total: 0, done: 0, msg: ''})
let pollTimer: ReturnType<typeof setInterval> | null = null

const percent = computed(() => {
  if (!progress.value.total) return _prevPct.value
  const cur = Math.round((progress.value.done / progress.value.total) * 100)
  if (cur > _prevPct.value) _prevPct.value = cur
  return _prevPct.value
})
const _prevPct = ref(0)
const progressStatus = computed(() => progress.value.phase === 'error' ? 'exception' as const : 'active' as const)
const progressMsg = computed(() => {
  const msg = progress.value.msg
  if (msg) { _prevMsgVal.value = msg; return msg }
  return _prevMsgVal.value || '准备中...'
})
const _prevMsgVal = ref('')

async function doCheck() {
  checking.value = true
  checked.value = false
  networkError.value = false
  authError.value = false
  changelogs.value = []
  try {
    const r = await checkUpdate(version)
    if (r.error_type === 'unauthorized') {
      authError.value = true
    } else if (r.error_type === 'network') {
      networkError.value = true
      serverMessage.value = r.message || ''
    } else {
      hasUpdate.value = r.has_update
      latest.value = r.latest_version || r.server_version || version
      serverMessage.value = r.message || ''
      // Fetch changelog if update available
      if (r.has_update) {
        try {
          const logs = await getChangelog()
          changelogs.value = (logs || [])
            .filter((l: any) => _cmpVer(l.ver, version) > 0)   // 数值比较：只留真正比当前新的版本
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
      }
    } catch { /* continue polling */ }
  }, 1000)
}

function resetUpdateState() { updating.value = false; updateError.value = ''; updateDone.value = false }
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
