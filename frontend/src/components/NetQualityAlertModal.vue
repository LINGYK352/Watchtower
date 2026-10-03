<!--
  网络质量告警弹窗：定时轮询 /api/network/quality/latest，当综合体检分数 < 40（严重/差的下沿）时弹窗，
  提示当前网络问题 + 按失败维度列举排查选项。**每次新的自检若仍 <40 就再弹一次**：
  用 localStorage 记 last_alerted_ts（上次已弹过的那次体检的 checked_ts），只有当 latest 的 checked_ts
  比它新（=跑了新一轮自检）且分数仍 <40 时才再弹——同一次体检不重复弹，用户关掉后不打扰，直到下一轮自检。
  纯前端消费既有端点，无后端改动。数据源：overall_assessment 的 assess{score,dims,summary}。
-->
<template>
  <a-modal v-model:open="open" :title="translate('ui.m_3c7627582daa')" :footer="null" :width="600" :mask-closable="false" wrap-class-name="netq-alert">
    <a-alert type="error" show-icon style="margin-bottom:14px"
      :message="translate('ui.m_48b7ca863037', { p0: (score), p1: (levelText) })"
      :description="summary" />
    <div class="netq-dims" v-if="weakDims.length">
      <div class="netq-sub">{{ translate('ui.m_d0c165a344df') }}</div>
      <a-tag v-for="d in weakDims" :key="d.key" :color="d.grade==='dead' ? 'red' : 'orange'">
        {{ d.label }}：{{ d.grade==='dead' ? translate('ui.m_8d7c03019f1d') : translate('ui.m_7fe1099fbfc0') }}
      </a-tag>
    </div>
    <div class="netq-time" v-if="alertTime">{{ translate('ui.m_292332a83aa4') }}{{ alertTime }}</div>
    <div class="netq-sub" style="margin-top:14px">{{ translate('ui.m_399fced38fdf') }}</div>
    <ul class="netq-tips">
      <li v-for="(t,i) in tips" :key="i">{{ t }}</li>
    </ul>
    <div style="text-align:right;margin-top:18px">
      <a-space>
        <a-button @click="goProxy">{{ translate('ui.m_f0be8afa2783') }}</a-button>
        <a-button type="primary" @click="goNetCheck">{{ translate('ui.m_c953f314de71') }}</a-button>
        <a-button @click="dismiss">{{ translate('ui.m_bf639a51feec') }}</a-button>
      </a-space>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { request } from '../api/request'

const THRESHOLD = 40                              // 分数 < 40 触发告警
const SEEN_KEY = 'netq_alert_last_ts'             // localStorage：上次已弹过告警的那次体检 checked_ts
const POLL_MS = 120000                            // 2 分钟轮询一次 latest（服务端 30min 自检一次，够抓到新一轮）

const router = useRouter()
const open = ref(false)
const score = ref(0)
const levelText = ref('')
const summary = ref('')
const weakDims = ref<Array<{ key: string; label: string; grade: string }>>([])
const alertTs = ref<number>(0)                   // 本次告警对应体检的 checked_ts（秒）
let timer: number | null = null

const DIM_LABEL: Record<string, string> = { get deps() { return translate('ui.m_0f1f1fa959ed') }, get stability() { return translate('ui.m_21be9efba97f') }, get ping() { return translate('ui.m_76f89bc31422') }, get dns() { return translate('ui.m_a6739d3803ef') }, get proxy() { return translate('ui.m_3632d795122a') } }

// 秒级 Unix 时间戳 → 本地可读时间（Date 需毫秒，故 *1000）
const alertTime = computed(() => {
  if (!alertTs.value) return ''
  const d = new Date(alertTs.value * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
})

// 按失败维度给针对性排查建议（哪项坏给哪项的建议，无短板给通用建议）
const tips = computed<string[]>(() => {
  const keys = weakDims.value.map(d => d.key)
  const out: string[] = []
  if (keys.includes('dns')) out.push(translate('ui.m_8614dac2bce6'))
  if (keys.includes('stability') || keys.includes('deps')) out.push(translate('ui.m_4428a7b6d1e7'))
  if (keys.includes('ping')) out.push(translate('ui.m_87b9e774031c'))
  if (keys.includes('proxy')) out.push(translate('ui.m_f3b8877dae10'))
  if (!out.length) out.push(translate('ui.m_cf26eed0f82f'))
  out.push(translate('ui.m_69fa47f250d3'))
  return out
})

async function poll() {
  try {
    const r = await request<any>('/api/network/quality/latest')
    if (!r || !r.has_data || !r.assess) return
    const a = r.assess
    const s = typeof a.score === 'number' ? a.score : null
    const ts = Number(r.checked_ts || 0)
    if (s == null || ts <= 0) return
    // 只在"新一轮自检"且分数 <阈值 时弹：checked_ts 比上次已弹的新，才认为是新一轮体检
    const lastTs = Number(localStorage.getItem(SEEN_KEY) || 0)
    if (s < THRESHOLD && ts > lastTs) {
      score.value = s
      levelText.value = a.level_text || '差'
      summary.value = a.summary || '网络质量偏低'
      const dims = a.dims || {}
      weakDims.value = Object.keys(dims)
        .filter(k => dims[k] === 'dead' || dims[k] === 'poor')
        .map(k => ({ key: k, label: DIM_LABEL[k] || k, grade: dims[k] }))
      alertTs.value = ts
      open.value = true
      try { localStorage.setItem(SEEN_KEY, String(ts)) } catch { /* ignore */ }
    }
  } catch { /* 取不到不打扰，下轮再试 */ }
}

function dismiss() { open.value = false }
function goProxy() { open.value = false; router.push('/proxy') }
function goNetCheck() { open.value = false; router.push('/network-check') }

onMounted(() => { poll(); timer = window.setInterval(poll, POLL_MS) })
onUnmounted(() => { if (timer) { clearInterval(timer); timer = null } })
</script>

<style scoped>
.netq-time { color: #999; font-size: 12px; margin-top: 10px; }
.netq-sub { font-weight: 600; color: #333; margin-bottom: 6px; }
.netq-dims { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.netq-tips { margin: 6px 0 0; padding-left: 20px; }
.netq-tips li { line-height: 1.8; color: #444; }
</style>
