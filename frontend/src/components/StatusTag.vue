<template>
  <a-tag :color="color">{{ label }}</a-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ value?: string | number | boolean }>()

const map: Record<string, { label: string; color: string }> = {
  done: { label: '已完成', color: 'success' },
  stop: { label: '已停止', color: 'default' },
  error: { label: '异常', color: 'error' },
  running: { label: '运行中', color: 'processing' },
  waiting: { label: '等待中', color: 'warning' },
  proxy_paused: { label: '代理暂停', color: 'orange' },
  scheduled: { label: '已计划', color: 'blue' },
  true: { label: '启用', color: 'success' },
  false: { label: '关闭', color: 'default' }
}

const key = computed(() => String(props.value ?? '').toLowerCase())
const label = computed(() => map[key.value]?.label || String(props.value ?? '-'))
const color = computed(() => map[key.value]?.color || 'blue')
</script>
