<!--
  激活到期提醒弹窗：剩余天数 ≤ 阈值(5天)时提醒续期。
  节流不打扰：localStorage 记 last_shown_ts（上次弹窗的墙钟毫秒），距上次 ≥ 24h 才再弹。
  「几天才访问一次只弹一次」：检查只在挂载时(进入系统)触发一次 + 可选低频复查；靠 24h 时间戳节流，
  故用户隔几天来一次也最多弹一次（除非跨过 24h）。数据源：checkActivation() 的 {activated, remaining_days, expires_at, tz_label}。
-->
<template>
  <a-modal v-model:open="open" :title="translate('ui.m_c6406a3b9f13')" :footer="null" :width="520" :mask-closable="true" wrap-class-name="lic-expiry">
    <a-alert :type="days <= 1 ? 'error' : 'warning'" show-icon style="margin-bottom:14px"
      :message="days <= 0 ? translate('ui.m_29317e52918d') : translate('ui.m_cd26df64a1db', { p0: (days) })"
      :description="desc" />
    <div class="lic-info" v-if="expiresAt">
      <span>{{ translate('ui.m_2ca0ed59cad1') }}{{ expiresAt }}</span>
      <template v-if="tzLabel"><a-divider type="vertical" /><span>（{{ tzLabel }}）</span></template>
    </div>
    <div style="text-align:right;margin-top:18px">
      <a-space>
        <a-button type="primary" @click="goActivation">{{ translate('ui.m_d23ab2a84908') }}</a-button>
        <a-button @click="dismiss">{{ translate('ui.m_bf639a51feec') }}</a-button>
      </a-space>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { checkActivation } from '../api/meta'

const SEEN_KEY = 'license_expiry_last_shown_ts'   // localStorage：上次弹窗的墙钟毫秒
const THRESHOLD_DAYS = 5                            // 剩余 ≤ 此天数开始提醒
const RECHECK_MS = 6 * 60 * 60 * 1000              // 长挂机场景每 6h 复查一次（配合分级节流）
const H = 60 * 60 * 1000

/** 分级节流：越临近到期提醒越频繁（治"弹过一次后 24h 内再不弹"，紧急状态该多提醒）。
 *  剩余 >2 天：24h 一次(不打扰)；1-2 天：12h 一次；≤0(已到期)：每次进系统必弹(0 节流)。 */
function throttleMs(rd: number): number {
  if (rd <= 0) return 0            // 已到期：每次进系统都提醒
  if (rd <= 2) return 12 * H       // 剩 1-2 天：12h 一次
  return 24 * H                    // 剩 3-5 天：24h 一次
}

const router = useRouter()
const open = ref(false)
const days = ref<number>(0)
const expiresAt = ref('')
const tzLabel = ref('')
let timer: number | null = null

// 内存兜底：localStorage 失败时用内存变量保证本会话内节流（隐私模式/存储满）
let memoryLastShown = 0

const desc = computed(() => days.value <= 0
  ? translate('ui.m_e7ba934abe27')
  : translate('ui.m_f2c9262423dd', { p0: (days.value) }))

/** 读取上次弹窗时间（localStorage 优先，失败降级内存变量） */
function getLastShown(): number {
  try {
    return Number(localStorage.getItem(SEEN_KEY) || 0) || memoryLastShown
  } catch {
    return memoryLastShown
  }
}

/** 记录本次弹窗时间（localStorage 优先，失败降级内存变量） */
function recordShown(timestamp: number) {
  try {
    localStorage.setItem(SEEN_KEY, String(timestamp))
  } catch {
    // localStorage 不可用（隐私模式/配额满），用内存兜底，至少本会话内不重复弹
    memoryLastShown = timestamp
  }
}

async function checkAndAlert() {
  try {
    const res = await checkActivation()
    // 已激活且剩余天数在阈值内（含 0）才提醒；未激活/过期/吊销有独立的激活向导阻断，不在此弹
    if (!res.activated || res.revoked) return
    // 计算剩余天数：优先用后端返回值；兜底计算时防止 Invalid Date，且与后端一致用 ceil
    const rd = res.remaining_days ?? (() => {
      const expTime = new Date(res.expires_at || 0).getTime()
      return expTime > 0 ? Math.max(1, Math.ceil((expTime - Date.now()) / 86400000)) : -1
    })()
    if (rd > THRESHOLD_DAYS || rd < 0) return
    // 分级节流：越临近到期提醒越频繁（剩余越少节流窗口越短，已到期不节流）
    const last = getLastShown()
    const now = Date.now()
    if (now - last < throttleMs(rd)) return
    days.value = rd
    expiresAt.value = res.expires_at || ''
    tzLabel.value = res.tz_label || ''
    open.value = true
    recordShown(now)
  } catch { /* 取不到不打扰 */ }
}

function dismiss() { open.value = false }
function goActivation() { open.value = false; router.push('/about/activation') }

onMounted(() => {
  checkAndAlert()                                  // 进入系统即检查一次（满足「访问才提醒、隔几天来只弹一次」）
  timer = window.setInterval(checkAndAlert, RECHECK_MS)  // 长挂机复查（24h 时间戳节流保证不多弹）
})
onUnmounted(() => { if (timer) { clearInterval(timer); timer = null } })
</script>

<style scoped>
.lic-info { color: #666; font-size: 13px; margin-top: 4px; }
</style>
