<!--
  资源水位告警弹窗：定时轮询 /api/console/resource_alert，当综合水位达 critical（内存/CPU/磁盘任一 ≥ 危险阈值）
  时弹窗，列出超标维度当前使用率 + 针对性排查建议。
  去重不打扰：localStorage 记 last_alerted_ts（上次已弹过的那次判定 ts），同一次判定不重复弹；用户关掉后
  只有当水位「回落后再次恶化」（新的一轮判定 ts 更新且仍 critical）才再弹。
  与推送告警解耦：推送侧在 tight+ 就发（scheduler check_and_alert_resource），弹窗只在 critical 弹（少打扰）。
  纯前端消费既有端点，数据源：resourceAlert() 的 {level,mem,cpu,disk,dims[],ts}。
-->
<template>
  <a-modal v-model:open="open" title="⚠ 系统资源告警" :footer="null" :width="600" :mask-closable="false" wrap-class-name="res-alert">
    <a-alert type="error" show-icon style="margin-bottom:14px"
      :message="`系统资源水位已达「严重」，可能导致任务卡死或服务中断`"
      :description="summary" />
    <div class="res-dims" v-if="dims.length">
      <div class="res-sub">超标资源项：</div>
      <a-tag v-for="d in dims" :key="d.key" :color="d.level==='critical' ? 'red' : 'orange'">
        {{ d.label }}：{{ d.value }}%（{{ d.level==='critical' ? '严重' : '偏高' }}）
      </a-tag>
    </div>
    <div class="res-snapshot">
      <span>内存 {{ fmt(mem) }}</span>
      <a-divider type="vertical" />
      <span>CPU {{ fmt(cpu) }}</span>
      <a-divider type="vertical" />
      <span>磁盘 {{ fmt(disk) }}</span>
    </div>
    <div class="res-time" v-if="alertTime">告警时间：{{ alertTime }}</div>
    <div class="res-sub" style="margin-top:14px">建议排查：</div>
    <ul class="res-tips">
      <li v-for="(t,i) in tips" :key="i">{{ t }}</li>
    </ul>
    <div style="text-align:right;margin-top:18px">
      <a-space>
        <a-button type="primary" @click="goDashboard">去态势总览</a-button>
        <a-button @click="dismiss">稍后处理</a-button>
      </a-space>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { consoleApi, type ResourceAlertDim } from '../api/console'

const SEEN_KEY = 'res_alert_last_ts'    // localStorage：上次已弹过告警的那次判定 ts
const POLL_MS = 60000                    // 1 分钟轮询一次（scheduler 每 tick ~30s 采样，够抓到恶化）

const router = useRouter()
const open = ref(false)
const mem = ref<number | null>(null)
const cpu = ref<number | null>(null)
const disk = ref<number | null>(null)
const dims = ref<ResourceAlertDim[]>([])
const alertTs = ref<number>(0)          // 本次告警的判定时间戳（秒），来自后端 resource_alert.ts
let timer: number | null = null

function fmt(v: number | null): string { return v == null ? 'N/A' : `${v}%` }

// 秒级 Unix 时间戳 → 本地可读时间（Date 需毫秒，故 *1000）
const alertTime = computed(() => {
  if (!alertTs.value) return ''
  const d = new Date(alertTs.value * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
})

const summary = computed(() => {
  const parts = dims.value.map(d => `${d.label} ${d.value}%`)
  return parts.length ? `当前 ${parts.join('、')}，已超过危险阈值。持续高水位可能触发内核 OOM，导致中间件/任务进程被杀。` : '系统资源紧张。'
})

// 按超标维度给针对性排查建议（哪项高给哪项的建议，无明确短板给通用建议）
const tips = computed<string[]>(() => {
  const keys = dims.value.map(d => d.key)
  const out: string[] = []
  if (keys.includes('memory')) out.push('内存偏高：暂停或减少并发的 AI 渗透会话/扫描任务；若为小内存机器，避免同时开启浏览器渲染工具（Chromium 内存消耗大）。')
  if (keys.includes('cpu')) out.push('CPU 偏高：降低扫描并发（策略侧 io_concurrency/scan_parallelism），或错峰运行大批量任务。')
  if (keys.includes('disk')) out.push('磁盘偏高：清理旧扫描结果/日志/镜像缓存，检查 resource_history、日志集合的 TTL 保留天数是否过长。')
  if (!out.length) out.push('系统综合资源紧张：到「态势总览」查看资源趋势图，定位是内存、CPU 还是磁盘瓶颈。')
  out.push('调度器已对高水位自动降级（暂停低优先级会话、收窄并发）；若持续告警，建议扩容或减负。')
  return out
})

async function poll() {
  try {
    const r = await consoleApi.resourceAlert()
    if (!r) return
    const ts = Number(r.ts || 0)
    // 弹窗只在 critical 触发（推送侧在 tight 就发，弹窗少打扰）
    if (r.level === 'critical' && ts > 0) {
      const lastTs = Number(localStorage.getItem(SEEN_KEY) || 0)
      if (ts > lastTs) {
        mem.value = r.mem
        cpu.value = r.cpu
        disk.value = r.disk
        dims.value = Array.isArray(r.dims) ? r.dims : []
        alertTs.value = ts
        open.value = true
        try { localStorage.setItem(SEEN_KEY, String(ts)) } catch { /* ignore */ }
      }
    }
  } catch { /* 取不到不打扰，下轮再试 */ }
}

function dismiss() { open.value = false }
function goDashboard() { open.value = false; router.push('/') }

onMounted(() => { poll(); timer = window.setInterval(poll, POLL_MS) })
onUnmounted(() => { if (timer) { clearInterval(timer); timer = null } })
</script>

<style scoped>
.res-sub { font-weight: 600; color: #333; margin-bottom: 6px; }
.res-dims { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 12px; }
.res-snapshot { color: #666; font-size: 13px; margin-top: 4px; }
.res-time { color: #999; font-size: 12px; margin-top: 6px; }
.res-tips { margin: 6px 0 0; padding-left: 20px; }
.res-tips li { line-height: 1.8; color: #444; }
</style>
