<template>
  <a-modal :open="!!cur" title="业务出现异常" :mask-closable="false" :closable="false"
    ok-text="上传给开发者" cancel-text="忽略" :confirm-loading="uploading"
    @ok="submit" @cancel="ignore">
    <a-alert type="warning" show-icon style="margin-bottom:12px"
      message="操作过程中出现异常"
      description="是否将本次错误日志上传给开发者以便定位修复？仅上传错误摘要（类型/消息/接口/版本），不含你的请求数据、目标信息或密钥。" />
    <div class="er-box" v-if="cur">
      <div class="er-row"><span class="er-k">接口</span><span class="er-v">{{ cur.method }} {{ cur.path }}</span></div>
      <div class="er-row"><span class="er-k">状态</span><span class="er-v">{{ cur.status || '网络异常' }}</span></div>
      <div class="er-row"><span class="er-k">错误</span><span class="er-v er-msg">{{ cur.message }}</span></div>
      <div class="er-row"><span class="er-k">版本</span><span class="er-v">{{ cur.version }}</span></div>
      <div class="er-row"><span class="er-k">时间</span><span class="er-v">{{ cur.ts }}</span></div>
    </div>
    <a-textarea v-model:value="note" :rows="3" style="margin-top:10px"
      placeholder="补充说明（可选）：你当时在做什么操作？" />
    <div class="er-hint">上传后可在「日志监测 → 我的上报」查看开发者的回复与修复进展。</div>
  </a-modal>
</template>

<script setup lang="ts">
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
      description: note.value.trim() || '(用户未填写补充说明)',
      log_content: logContent,
      version: e.version,
      meta: JSON.stringify({ path: e.path, method: e.method, status: e.status }),
    })
    message.success('已上传给开发者，可在「日志监测 → 我的上报」查看回复')
    note.value = ''
    clearPending()
  } catch (err) {
    message.error((err as Error).message || '上传失败')
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
