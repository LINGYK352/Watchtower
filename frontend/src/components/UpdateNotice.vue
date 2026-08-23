<template>
  <a-modal :open="showModal" :closable="true" :maskClosable="false" :footer="null" centered width="500px" @cancel="dismiss">
    <div class="update-wrap">
      <div class="update-header">
        <h2>发现新版本</h2>
        <a-tag color="blue" class="update-ver">{{ latestVersion }}</a-tag>
      </div>
      <a-tag color="green" class="update-badge">热更新 · 不影响现有业务</a-tag>

      <div class="update-changelog" v-if="changelogs.length">
        <div class="changelog-title">更新内容</div>
        <div class="changelog-item" v-for="item in changelogs" :key="item.ver">
          <span class="changelog-ver">{{ item.ver }}</span>
          <span class="changelog-text">{{ item.summary }}</span>
        </div>
      </div>

      <!-- Progress -->
      <div v-if="updating" class="update-progress">
        <a-progress :percent="percent" :status="progressStatus" size="small" />
        <p class="progress-msg">{{ progressMsg }}</p>
      </div>

      <!-- Actions -->
      <div class="update-actions" v-if="!updating && !updateDone && !updateError">
        <a-button type="primary" block size="large" @click="startUpdate">立即更新</a-button>
        <a-button block size="large" class="btn-later" @click="dismiss">稍后提醒</a-button>
      </div>
      <div v-if="updateDone" class="update-done">
        <p style="color:#3fb950;font-weight:600;margin-bottom:12px">更新完成</p>
        <a-button type="primary" block @click="reload">刷新页面</a-button>
      </div>
      <div v-if="updateError" class="update-error">
        <p style="color:#f85149;margin-bottom:8px">更新失败：{{ updateError }}</p>
        <a-button block @click="resetState">重试</a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { APP_VERSION } from '../config/brand'
import { request } from '../api/request'

const showModal = ref(false)
const latestVersion = ref('')
const changelogs = ref<{ver: string, date: string, summary: string}[]>([])
const updating = ref(false)
const updateDone = ref(false)
const updateError = ref('')
const progress = ref<{phase: string, total: number, done: number, msg: string}>({phase: 'idle', total: 0, done: 0, msg: ''})

const percent = computed(() => {
  if (!progress.value.total) return prevPercent.value  // total=0 时保持上次进度，不回退到 0
  const cur = Math.round((progress.value.done / progress.value.total) * 100)
  if (cur > prevPercent.value) prevPercent.value = cur
  return prevPercent.value
})
const prevPercent = ref(0)
const progressStatus = computed(() => progress.value.phase === 'error' ? 'exception' as const : 'active' as const)
const progressMsg = computed(() => {
  const msg = progress.value.msg
  if (msg) { prevMsg.value = msg; return msg }
  // msg 为空时不回退到"准备中"，保持上一条有效消息
  return prevMsg.value || '准备中...'
})
const prevMsg = ref('')

const DISMISS_KEY = 'update_dismissed_ver'
const CHECK_INTERVAL = 1 * 3600 * 1000 // 1 hour (also serves as activation heartbeat)
let timer: ReturnType<typeof setInterval> | null = null
let pollTimer: ReturnType<typeof setInterval> | null = null
let _unauthorizedConfirmed = false  // 防激活后竞态误弹：首次 unauthorized 延迟重试确认

const emit = defineEmits<{ (e: 'unauthorized'): void }>()

// 版本号数值比较（与后端 update_check._cmp 同逻辑）：剥 v 前缀，逐段按数值比。
// 修复字符串比较 bug：'v1.21.65' > 'v1.21.131' 字符串比会误判为 true（'6'>'1'），
// 导致旧版被当成新版误弹/混进更新内容（看似反向更新）。
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

async function checkUpdate() {
  try {
    const res = await request<any>('/api/about/check?client=' + APP_VERSION)
    // If server explicitly says unauthorized → 延迟重试一次确认（排除激活后竞态：多 worker 间 key 同步需要时间）
    if (res.error_type === 'unauthorized') {
      if (!_unauthorizedConfirmed) {
        _unauthorizedConfirmed = true
        setTimeout(checkUpdate, 10000)  // 10 秒后再确认一次
        return
      }
      emit('unauthorized')
      return
    }
    _unauthorizedConfirmed = false  // 成功时重置
    if (res.has_update && res.latest_version) {
      // 前端侧保险：latest_version 必须真的 > APP_VERSION 才弹（数值比较，防字符串误判）
      if (_cmpVer(res.latest_version, APP_VERSION) <= 0) return
      const dismissed = localStorage.getItem(DISMISS_KEY)
      if (dismissed === res.latest_version) return
      // 已有更新在进行（用户在更新检测页手动更新中 / 另一实例在更新）→ 不弹自动提醒，避免撞车
      if (updating.value) return
      try {
        const prog = await request<any>('/api/about/progress')
        if (prog && ['checking', 'downloading', 'validating', 'applying'].includes(prog.phase)) return
      } catch { /* progress 查不到不阻断，继续按需弹 */ }
      latestVersion.value = res.latest_version
      try {
        const logs = await request<any[]>('/api/about/changelog')
        changelogs.value = (logs || [])
          .filter((l: any) => _cmpVer(l.ver, APP_VERSION) > 0)   // 数值比较：只留真正比当前新的版本
          .sort((a: any, b: any) => _cmpVer(b.ver, a.ver))       // 新→旧排序
          .slice(0, 10)
      } catch { changelogs.value = [] }
      showModal.value = true
    }
  } catch { /* network error, keep current state */ }
}

function dismiss() {
  showModal.value = false
  if (latestVersion.value) localStorage.setItem(DISMISS_KEY, latestVersion.value)
}

async function startUpdate() {
  updating.value = true
  updateError.value = ''
  prevPercent.value = 0
  prevMsg.value = '准备中...'
  progress.value = {phase: 'checking', total: 0, done: 0, msg: '准备中...'}
  try {
    await request('/api/about/apply', { method: 'POST' })
    pollProgress()
  } catch (e) {
    updateError.value = e instanceof Error ? e.message : String(e)
    updating.value = false
  }
}

function pollProgress() {
  pollTimer = setInterval(async () => {
    try {
      const p = await request<any>('/api/about/progress')
      progress.value = p
      if (p.phase === 'done') {
        if (pollTimer) clearInterval(pollTimer)
        updating.value = false
        updateDone.value = true
        setTimeout(() => window.location.reload(), 2000)
      } else if (p.phase === 'error') {
        if (pollTimer) clearInterval(pollTimer)
        updating.value = false
        updateError.value = p.error || '未知错误'
      }
    } catch { /* continue polling */ }
  }, 1000)
}

function reload() { window.location.reload() }
function resetState() { updating.value = false; updateError.value = ''; updateDone.value = false }

onMounted(() => {
  setTimeout(checkUpdate, 15000)  // 首次心跳延迟 15 秒（给激活流程写入 key 的时间窗口）
  timer = setInterval(checkUpdate, CHECK_INTERVAL)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
  if (pollTimer) clearInterval(pollTimer)
})

defineExpose({ checkUpdate })
</script>

<style scoped>
.update-wrap { padding: 8px 0; }
.update-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px }
.update-header h2 { font-size: 18px; font-weight: 700; margin: 0 }
.update-ver { font-size: 14px }
.update-badge { margin-bottom: 16px }
.update-changelog { background: #f6f8fa; border-radius: 8px; padding: 14px; margin-bottom: 20px; max-height: 200px; overflow-y: auto }
.changelog-title { font-size: 13px; font-weight: 600; color: #1f2328; margin-bottom: 8px }
.changelog-item { padding: 6px 0; border-bottom: 1px solid #e1e4e8; font-size: 13px; display: flex; gap: 8px }
.changelog-item:last-child { border-bottom: none }
.changelog-ver { color: #0969da; font-weight: 600; flex-shrink: 0; font-size: 12px }
.changelog-text { color: #656d76 }
.update-progress { margin: 16px 0 }
.progress-msg { font-size: 12px; color: #656d76; margin-top: 6px }
.update-actions { display: flex; flex-direction: column; gap: 8px }
.btn-later { color: #656d76 }
.update-done { text-align: center; padding: 12px 0 }
.update-error { text-align: center; padding: 12px 0 }
</style>
