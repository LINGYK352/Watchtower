<template>
  <a-modal
    :open="visible"
    :title="title"
    :closable="false"
    :maskClosable="false"
    :keyboard="false"
    :footer="null"
    width="640px"
    wrap-class-name="disclaimer-modal"
    :z-index="2000">
    <div class="dc-body" data-testid="disclaimer-terms">
      <a-alert type="warning" show-icon banner style="margin-bottom:14px"
        :message="translate('ui.m_8eaf04cf69bb')" />
      <div class="dc-scroll">
        <div v-for="sec in sections" :key="sec.h" class="dc-sec">
          <h4 class="dc-h">{{ sec.h }}</h4>
          <ul class="dc-list">
            <li v-for="(it, i) in sec.items" :key="i">{{ it }}</li>
          </ul>
        </div>
      </div>
      <a-checkbox v-model:checked="agreed" class="dc-check">{{ agreeText }}</a-checkbox>
      <div class="dc-actions">
        <a-button danger @click="onReject">{{ translate('ui.m_40b0aade58d7') }}</a-button>
        <a-button type="primary" :disabled="!agreed || countdown > 0" :loading="submitting" @click="onAgree">
          {{ countdown > 0 ? translate('ui.m_e5c44f9be14d', { p0: (countdown) }) : translate('ui.m_81c92013219d') }}
        </a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'
import { ref, onMounted, onUnmounted } from 'vue'
import { message } from 'ant-design-vue'
import { clearToken } from '../api/request'
import { getDisclaimerStatus, acceptDisclaimer, hasPersistedAssent } from '../api/meta'
import { DISCLAIMER_SECTIONS, DISCLAIMER_TITLE, DISCLAIMER_AGREE_TEXT, DISCLAIMER_VERSION } from '../config/disclaimer'

const sections = DISCLAIMER_SECTIONS
const title = DISCLAIMER_TITLE
const agreeText = DISCLAIMER_AGREE_TEXT
// Signed status is checked silently; only a confirmed missing record opens terms.
const visible = ref(false)
const agreed = ref(false)
const submitting = ref(false)
const countdown = ref(5)
let cdTimer: number | null = null
let retryTimer: number | null = null
let controller: AbortController | null = null
let disposed = false
let generation = 0
function startCountdown() {
  if (cdTimer !== null) clearInterval(cdTimer)
  countdown.value = 5
  cdTimer = window.setInterval(() => {
    if (--countdown.value <= 0 && cdTimer !== null) { clearInterval(cdTimer); cdTimer = null }
  }, 1000)
}
async function checkStatus() {
  if (retryTimer !== null) { clearTimeout(retryTimer); retryTimer = null }
  controller?.abort()
  controller = new AbortController()
  const current = ++generation
  visible.value = false
  try {
    const status = await getDisclaimerStatus(controller.signal)
    if (disposed || current !== generation) return
    if (status.status === 'unavailable' || (status.accepted && status.persisted === false)) throw new Error('Assent storage unavailable')
    if (hasPersistedAssent(status)) {
      visible.value = false
      return
    }
    // Only a successfully verified missing assent opens the terms.
    visible.value = true
    startCountdown()
  } catch {
    if (disposed || current !== generation) return
    retryTimer = window.setTimeout(checkStatus, 5000)
  }
}
onMounted(checkStatus)
onUnmounted(() => {
  disposed = true; generation++; controller?.abort()
  if (cdTimer !== null) clearInterval(cdTimer)
  if (retryTimer !== null) clearTimeout(retryTimer)
})
async function onAgree() {
  if (!agreed.value || countdown.value > 0 || submitting.value) return
  submitting.value = true
  try {
    const status = await acceptDisclaimer(DISCLAIMER_VERSION)
    if (!hasPersistedAssent(status)) {
      throw new Error(translate('disclaimerStatus.saveFailed'))
    }
    if (!disposed) visible.value = false
  } catch (e) {
    if (!disposed) message.error(translate('ui.m_60b699584716') + (e instanceof Error ? e.message : String(e)))
  } finally {
    submitting.value = false
  }
}
function onReject() {
  controller?.abort(); generation++
  clearToken()
  visible.value = false
  location.href = '/login'
}
</script>

<style scoped>
.dc-scroll { max-height: 46vh; overflow-y: auto; padding: 4px 12px; border: 1px solid var(--dt-border, #e8e8e8); border-radius: 8px; background: var(--dt-hover, #fafafa); }
.dc-sec { margin-bottom: 14px; }
.dc-h { font-size: 14px; font-weight: 700; margin: 6px 0; color: var(--dt-text, #1f2328); }
.dc-list { padding-left: 20px; margin: 0; }
.dc-list li { font-size: 13px; line-height: 1.9; color: var(--dt-text, #333); }
.dc-check { margin: 16px 0 4px; font-size: 13px; font-weight: 600; }
.dc-actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 12px; }
</style>

