<template>
  <!-- 顶部通告条：默认展示，不弹出；多条时轮流/堆叠展示当前未关闭的最高优先级一条 -->
  <div v-if="barItem" class="ann-bar" :class="'ann-' + barItem.level">
    <component :is="levelIcon(barItem.level)" class="ann-bar-ico" />
    <span class="ann-bar-title" :title="barItem.title">{{ translate(barItem.scope==='version' ? 'ann.version' : 'ann.system') }} · {{ barItem.title }}</span>
    <span class="ann-bar-content" :title="barItem.content">{{ barItem.content }}</span>
    <button type="button" class="ann-bar-close" @click="closeBar(barItem.id)" :title="translate('ui.m_530475d69caa')" :aria-label="translate('ui.m_530475d69caa')">✕</button>
  </div>

  <!-- 强制弹窗：popup=true 的通告，每条按 id 记已读，不重复弹 -->
  <a-modal :open="popupOpen" :title="translate(popupItem?.scope==='version' ? 'ann.version' : 'ann.system') + ' · ' + (popupItem?.title || '')" :footer="null"
    :maskClosable="false" centered width="520px" @cancel="dismissPopup" wrap-class-name="ann-modal">
    <div v-if="popupItem" class="ann-pop">
      <a-alert :type="alertType(popupItem.level)" show-icon banner style="margin-bottom:14px"
        :message="popupItem.title" />
      <div class="ann-pop-body">{{ popupItem.content }}</div>
      <div class="ann-pop-meta" v-if="popupItem.ts">{{ popupItem.ts }}</div>
      <div class="ann-pop-actions">
        <a-button type="primary" @click="dismissPopup">{{ translate('ui.m_348f1cf1243e') }}</a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  InfoCircleOutlined, WarningOutlined, ExclamationCircleOutlined,
} from '@ant-design/icons-vue'
import { getAnnouncements, type Announcement } from '../api/about'
import { requestNotice, releaseNotice } from '../composables/noticeQueue'

const POLL_INTERVAL = 3600 * 1000   // 每 1 小时主动拉一次通告；内网断网时静默失败不报错
let pollTimer: ReturnType<typeof setInterval> | null = null
let retryTimer: ReturnType<typeof setTimeout> | null = null
let fetchController: AbortController | null = null
let stopped = false

// 已关闭/已读的通告 id（localStorage，跨刷新保留；换设备会重看，符合"每设备"语义）。
const CLOSED_BAR_KEY = 'ann_closed_bar_ids'      // 通告条被手动关闭的 id
const READ_POPUP_KEY = 'ann_read_popup_ids'      // 弹窗已读的 id

const items = ref<Announcement[]>([])
const closedBarIds = ref<number[]>(loadIds(CLOSED_BAR_KEY))
const readPopupIds = ref<number[]>(loadIds(READ_POPUP_KEY))
const popupOpen = ref(false)

function loadIds(key: string): number[] {
  try { return JSON.parse(localStorage.getItem(key) || '[]') } catch { return [] }
}
function saveIds(key: string, ids: number[]) {
  try { localStorage.setItem(key, JSON.stringify(ids)) } catch { /* ignore */ }
}

// 级别权重：danger > warning > info，通告条展示未关闭里最高优先级的一条。
const _weight: Record<string, number> = { critical: 4, danger: 4, warning: 2, info: 1 }

const barItem = computed<Announcement | null>(() => {
  const open = items.value.filter(a => !closedBarIds.value.includes(a.id))
  if (!open.length) return null
  return [...open].sort((a, b) => (_weight[b.level] || 0) - (_weight[a.level] || 0) || b.id - a.id)[0]
})

// 待弹窗队列：popup=true 且未读的，逐个弹（当前弹第一个）。
const pendingPopups = computed(() => items.value.filter(a => a.popup && !readPopupIds.value.includes(a.id)).sort((a,b)=>(_weight[b.level]||0)-(_weight[a.level]||0)||b.id-a.id))
const popupItem = ref<Announcement | null>(null)

function levelIcon(level: string) {
  if (level === 'danger' || level === 'critical') return ExclamationCircleOutlined
  if (level === 'warning') return WarningOutlined
  return InfoCircleOutlined
}
function alertType(level: string): 'info' | 'warning' | 'error' {
  if (level === 'danger' || level === 'critical') return 'error'
  if (level === 'warning') return 'warning'
  return 'info'
}

function closeBar(id: number) {
  if (!closedBarIds.value.includes(id)) {
    closedBarIds.value = [...closedBarIds.value, id]
    saveIds(CLOSED_BAR_KEY, closedBarIds.value)
  }
}

function dismissPopup() {
  const cur = popupItem.value
  if (cur && !readPopupIds.value.includes(cur.id)) {
    readPopupIds.value = [...readPopupIds.value, cur.id]
    saveIds(READ_POPUP_KEY, readPopupIds.value)
  }
  popupOpen.value = false
  releaseNotice('announcement')
  // 还有下一条待弹的，继续弹
  setTimeout(showNextPopup, 300)
}

function showNextPopup() {
  if (stopped) return
  const next = pendingPopups.value[0]
  if (next) requestNotice('announcement',(_weight[next.level]||1)*10,()=>{popupItem.value=next;popupOpen.value=true})
}

async function load() {
  if (stopped || fetchController) return
  const controller = new AbortController()
  fetchController = controller
  const timeout = setTimeout(()=>controller.abort(),5000)
  let retry = false
  try {
    const res = await getAnnouncements(controller.signal)
    if (stopped) return
    if (res?.fetch_failed) { retry = !res.unsupported; return }
    items.value = (res?.announcements || []).filter(a => a.enabled !== false)
    showNextPopup()
  } catch { retry = !stopped }
  finally {
    clearTimeout(timeout)
    if (fetchController === controller) fetchController = null
    if (retry && !stopped) { if (retryTimer) clearTimeout(retryTimer); retryTimer = setTimeout(load,15000) }
  }
}

onMounted(() => {
  load()                                       // 登录进入即拉一次
  pollTimer = setInterval(load, POLL_INTERVAL) // 之后每 1 小时主动拉一次
})
onUnmounted(() => { stopped=true;fetchController?.abort();if(pollTimer)clearInterval(pollTimer);if(retryTimer)clearTimeout(retryTimer);releaseNotice('announcement') })
</script>

<style scoped>
.ann-bar { display: flex; align-items: center; gap: 10px; padding: 8px 20px; font-size: 13px;
  background: var(--ann-bg); border-bottom: 1px solid var(--ann-border); color: var(--ann-tone); }
.ann-bar-ico { font-size: 15px; flex: none; }
.ann-bar-title { font-weight: 650; flex: 0 1 auto; max-width: 48%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ann-bar-ico, .ann-bar-title { color: var(--ann-tone); }
.ann-bar-content { color: var(--ann-text); flex: 1; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ann-bar-close { flex: none; color: var(--ann-tone); cursor: pointer; padding: 3px 6px;
  font-size: 12px; line-height: 1; min-width: 32px; min-height: 32px; border: 0; border-radius: 6px; background: transparent; }
.ann-bar-close:hover { background: var(--ann-border); }
.ann-bar-close:focus-visible { outline: 2px solid var(--ann-tone); outline-offset: 2px; }
/* Keep the full selector inside :global: a trailing descendant is discarded by scoped CSS. */
:global(.ann-bar) { --ann-text: #334155; --ann-bg: #eef5fc; --ann-border: #cbdbea; --ann-tone: #315b7b; }
:global(.ann-bar.ann-warning) { --ann-bg: #fff8e7; --ann-border: #ead7a4; --ann-tone: #795d24; }
:global(.ann-bar.ann-critical), :global(.ann-bar.ann-danger) { --ann-bg: #fff1ef; --ann-border: #edc6bf; --ann-tone: #873f37; }
:global(html[data-theme="dark"] .ann-bar) { --ann-text: #d6e2ef; --ann-bg: #192a38; --ann-border: #324a5e; --ann-tone: #a3c9e8; }
:global(html[data-theme="dark"] .ann-bar.ann-warning) { --ann-bg: #302a1d; --ann-border: #594a2b; --ann-tone: #e0c48a; }
:global(html[data-theme="dark"] .ann-bar.ann-critical), :global(html[data-theme="dark"] .ann-bar.ann-danger) { --ann-bg: #352325; --ann-border: #68413d; --ann-tone: #ecb6ad; }
.ann-pop-body { font-size: 14px; line-height: 1.8; color: var(--dt-text, #333); white-space: pre-wrap; }
.ann-pop-meta { color: var(--dt-muted, #999); font-size: 12px; margin-top: 12px; }
.ann-pop-actions { display: flex; justify-content: flex-end; margin-top: 16px; }
</style>
