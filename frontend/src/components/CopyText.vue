<template>
  <a-tooltip :title="translate('ui.m_876a1818bf94')">
    <a-typography-text class="copy-text" code @click="copy">{{ text || '-' }}</a-typography-text>
  </a-tooltip>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { message } from 'ant-design-vue'
const props = defineProps<{ text?: string | number }>()
async function copy() {
  if (props.text === undefined || props.text === null || props.text === '') return
  const val = String(props.text)
  try {
    // 优先 clipboard API（HTTPS 环境）
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(val)
    } else {
      // HTTP 降级：用隐藏 textarea + execCommand
      const ta = document.createElement('textarea')
      ta.value = val
      ta.style.position = 'fixed'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    message.success(translate('ui.m_8f6f8d979c98'))
  } catch {
    message.error(translate('ui.m_753d8bb0da99'))
  }
}
</script>
