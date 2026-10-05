<template>
  <!-- 降级模式红标签：仅在 broker 降级为线程模式时显示，位于时区标签前。点击可切回 rabbitmq 模式 -->
  <a-tooltip v-if="degraded" :title="reason || translate('ui.m_8b524ed6a323')">
    <a-tag color="red" style="cursor:pointer;margin:0" @click="onSwitchBack">
      {{ translate('ui.m_2e4a666802e6') }}
    </a-tag>
  </a-tooltip>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { ref, onMounted, onUnmounted } from 'vue'
import { Modal, message } from 'ant-design-vue'
import { getBrokerStatus, switchBackBroker } from '../api/broker'

const degraded = ref(false)
const reason = ref('')
const switching = ref(false)
let timer: number | undefined
let notifiedDegrade = false   // 本会话内只弹一次降级提示

async function poll() {
  try {
    const s = await getBrokerStatus()
    const wasDegraded = degraded.value
    degraded.value = !!s.degraded
    reason.value = s.reason || ''
    // 首次检测到降级（本会话未提示过）→ 弹窗告知
    if (degraded.value && !wasDegraded && !notifiedDegrade) {
      notifiedDegrade = true
      Modal.warning({
        get title() { return translate('ui.m_05bf6f6c7b77') },
        content: (reason.value || translate('ui.m_c843c97a0d99'))
          + translate('ui.m_80f570f55ba9'),
      })
    }
    if (!degraded.value) notifiedDegrade = false   // 已恢复，允许下次再提示
  } catch { /* 查询失败不打扰，下次再试 */ }
}

function onSwitchBack() {
  if (switching.value) return
  Modal.confirm({
    get title() { return translate('ui.m_3ac83d0e5714') },
    get content() { return translate('ui.m_0c66d8b061fd') },
    get okText() { return translate('ui.m_f356ea527e1f') },
    get cancelText() { return translate('ui.m_2cd0f3be8738') },
    onOk: async () => {
      switching.value = true
      try {
        const r = await switchBackBroker(false)
        if (r.ok) {
          degraded.value = false
          message.success(r.message || translate('ui.m_0e4ed671bbda'))
        } else {
          message.warning(r.message || translate('ui.m_69f752fdf9e3'))
        }
      } catch (e: any) {
        message.error(e?.message || translate('ui.m_ac7c926ededa'))
      } finally {
        switching.value = false
        poll()
      }
    },
  })
}

onMounted(() => {
  poll()
  timer = window.setInterval(poll, 30000)   // 30s 轮询
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>
