<template>
  <a-modal :open="!!cur" :title="translate('ui.m_1379c8cc47ff')" :mask-closable="false" :closable="false"
    :ok-text="translate('ui.m_036a0e4228fc')" :cancel-text="translate('ui.m_6e90ac940752')" :confirm-loading="uploading"
    @ok="submit" @cancel="ignore">
    <a-alert type="warning" show-icon style="margin-bottom:12px"
      :message="translate('ui.m_f2e2fb365696')"
      :description="translate('ui.m_495c16f97a72')" />
    <div class="er-box" v-if="cur">
      <div class="er-row"><span class="er-k">{{ translate('ui.m_c80d519245a7') }}</span><span class="er-v">{{ cur.method }} {{ cur.path }}</span></div>
      <div class="er-row"><span class="er-k">{{ translate('ui.m_6320b4a8722a') }}</span><span class="er-v">{{ cur.status || translate('ui.m_d536d47bd3da') }}</span></div>
      <div class="er-row"><span class="er-k">{{ translate('ui.m_0bc1fb72ae1b') }}</span><span class="er-v er-msg">{{ cur.message }}</span></div>
      <div class="er-row"><span class="er-k">{{ translate('ui.m_5f76b2bf82dd') }}</span><span class="er-v">{{ cur.version }}</span></div>
      <div class="er-row"><span class="er-k">{{ translate('ui.m_8b6ff498515b') }}</span><span class="er-v">{{ cur.ts }}</span></div>
    </div>
    <a-textarea v-model:value="note" :rows="3" style="margin-top:10px"
      :placeholder="translate('ui.m_95a20700ed81')" />
    <div class="er-hint">{{ translate('ui.m_c997bd57a488') }}</div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { ref, computed } from 'vue'
import { message } from 'ant-design-vue'
import { usePendingError, clearPending, dismissError } from '../composables/useErrorReport'
import { reportError } from '../api/about'

const state = usePendingError()
const cur = computed(() => state.pending)
const note = ref('')
const uploading = ref(false)

async function submit() {
  if (!state.pending) return
  uploading.value = true
  try {
    const e = state.pending
    const logContent = [
      `接口: ${e.method} ${e.path}`,
      `状态: ${e.status}`,
      `错误: ${e.message}`,
      `版本: ${e.version}`,
      `时间: ${e.ts}`,
    ].join('\n')
    await reportError({
      description: note.value.trim() || translate('ui.m_c39e232e0de7'),
      log_content: logContent,
      version: e.version,
      meta: JSON.stringify({ path: e.path, method: e.method, status: e.status }),
    })
    message.success(translate('ui.m_91b12d58fe16'))
    note.value = ''
    clearPending()
  } catch (err) {
    message.error((err as Error).message || translate('ui.m_219481a6dde7'))
  } finally {
    uploading.value = false
  }
}

function ignore() {
  note.value = ''
  dismissError()
}
</script>

<style scoped>
/* 用已定义的 --dt-card/--dt-border（theme-dark.css 有），不再用从未定义的 --dt-panel/--dt-line
   （那俩恒 fallback 浅色 → 夜间白盒黑字看不清，同 -48 网络横幅坑）。日间 fallback 保持浅色。 */
.er-box { background: var(--dt-card, #f6f8fa); border: 1px solid var(--dt-border, #e5e7eb); border-radius: 8px; padding: 10px 12px; font-size: 13px }
.er-row { display: flex; gap: 8px; padding: 2px 0 }
.er-k { color: var(--dt-muted, #8a94a6); width: 40px; flex: none }
.er-v { color: var(--dt-text, #1f2430); word-break: break-all }
.er-msg { color: #ff6b6b }
.er-hint { margin-top: 8px; font-size: 12px; color: var(--dt-muted, #8a94a6) }
</style>
