<!--
  资源水位告警弹窗：定时轮询 /api/console/resource_alert，当综合水位达 critical（内存/CPU/磁盘任一 ≥ 危险阈值）
  时弹窗，列出超标维度当前使用率 + 针对性排查建议。
  去重不打扰：localStorage 记 last_alerted_ts（上次已弹过的那次判定 ts），同一次判定不重复弹；用户关掉后
  只有当水位「回落后再次恶化」（新的一轮判定 ts 更新且仍 critical）才再弹。
  与推送告警解耦：推送侧在 tight+ 就发（scheduler check_and_alert_resource），弹窗只在 critical 弹（少打扰）。
  纯前端消费既有端点，数据源：resourceAlert() 的 {level,mem,cpu,disk,dims[],ts}。
-->
<template>
  <a-modal v-model:open="open" :title="translate('ui.m_78ba00a8c645')" :footer="null" :width="600" :mask-closable="false" wrap-class-name="res-alert">
    <a-alert type="error" show-icon style="margin-bottom:14px"
      :message="translate('ui.m_c3333ed59191')"
      :description="summary" />
    <div class="res-dims" v-if="dims.length">
      <div class="res-sub">{{ translate('ui.m_8bfdf37f6584') }}</div>
      <a-tag v-for="d in dims" :key="d.key" :color="d.level==='critical' ? 'red' : 'orange'">
        {{ d.label }}：{{ d.value }}%（{{ d.level==='critical' ? translate('ui.m_73eb0e14e307') : translate('ui.m_cde6311d914f') }}）
      </a-tag>
    </div>
    <div class="res-snapshot">
      <span>{{ translate('ui.m_7d8f8c37ec78') }} {{ fmt(mem) }}</span>
      <a-divider type="vertical" />
      <span>CPU {{ fmt(cpu) }}</span>
      <a-divider type="vertical" />
      <span>{{ translate('ui.m_de7b72a3f852') }} {{ fmt(disk) }}</span>
    </div>
    <div class="res-time" v-if="alertTime">{{ translate('ui.m_292332a83aa4') }}{{ alertTime }}</div>
    <div class="res-sub" style="margin-top:14px">{{ translate('ui.m_399fced38fdf') }}</div>
    <ul class="res-tips">
      <li v-for="(t,i) in tips" :key="i">{{ t }}</li>
    </ul>
    <div style="text-align:right;margin-top:18px">
      <a-space>
        <a-button type="primary" @click="goDashboard">{{ translate('ui.m_fe9fcaad7fd9') }}</a-button>
        <a-button @click="dismiss">{{ translate('ui.m_bf639a51feec') }}</a-button>
      </a-space>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

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
  return parts.length ? translate('ui.m_18fb9c27da34', { p0: (parts.join('、')) }) : translate('ui.m_75a68fff0afc')
})

// 按超标维度给针对性排查建议（哪项高给哪项的建议，无明确短板给通用建议）
const tips = computed<string[]>(() => {
  const keys = dims.value.map(d => d.key)
  const out: string[] = []
  if (keys.includes('memory')) out.push(translate('ui.m_f3881d85bf55'))
  if (keys.includes('cpu')) out.push(translate('ui.m_1752e233bb2c'))
  if (keys.includes('disk')) out.push(translate('ui.m_0481f3a69254'))
  if (!out.length) out.push(translate('ui.m_a638ce44ae11'))
  out.push(translate('ui.m_970339be3afb'))
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
