<template>
  <!-- 降级模式红标签：仅在 broker 降级为线程模式时显示，位于时区标签前。点击可切回 rabbitmq 模式 -->
  <a-tooltip v-if="degraded" :title="reason || 'rabbitmq 不可用，已降级为应用进程线程执行模式，功能不受影响。点击尝试切回 rabbitmq 模式'">
    <a-tag color="red" style="cursor:pointer;margin:0" @click="onSwitchBack">
      ⚠ 降级模式 · 点击切回
    </a-tag>
  </a-tooltip>
</template>

<script setup lang="ts">
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
        title: '调度已降级为线程模式',
        content: (reason.value || 'rabbitmq 不可用，系统已自动降级为应用进程线程执行模式。')
          + ' AI 会话与任务照常运行，功能不受影响。待 rabbitmq 恢复后，可点击顶栏「降级模式」红标签手动切回。',
      })
    }
    if (!degraded.value) notifiedDegrade = false   // 已恢复，允许下次再提示
  } catch { /* 查询失败不打扰，下次再试 */ }
}

function onSwitchBack() {
  if (switching.value) return
  Modal.confirm({
    title: '切回 rabbitmq(celery) 模式？',
    content: '将先检测 rabbitmq 是否恢复：连通才切回并恢复分布式投递；仍不可用则保持当前线程模式。',
    okText: '检测并切回',
    cancelText: '取消',
    onOk: async () => {
      switching.value = true
      try {
        const r = await switchBackBroker(false)
        if (r.ok) {
          degraded.value = false
          message.success(r.message || '已切回 rabbitmq 模式')
        } else {
          message.warning(r.message || 'rabbitmq 仍不可用，保持线程模式')
        }
      } catch (e: any) {
        message.error(e?.message || '切回失败')
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
