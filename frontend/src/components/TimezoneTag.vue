<!--
  服务器时区标签（态势总览刷新按钮左侧 + 全局顶栏激活徽标左侧共用）。
  平台所有时间戳都是服务器操作系统时区的本地时间、且无时区标注——本标签显示该时区，
  悬停解释：要更改时间显示只能改操作系统/容器时区（平台不改时间存储，见项目说明 §7.8）。
-->
<template>
  <a-tooltip placement="bottom">
    <template #title>
      <div style="max-width:260px;line-height:1.6">
        平台所有时间戳（检测时间、任务时间、日志等）均为<b>服务器操作系统时区</b>的本地时间。<br />
        当前服务器时区：<b>{{ tzLabel || tzName }}</b>（{{ tzName }} · {{ offsetText }}）。<br />
        如需改变时间显示，请调整服务器 / 容器的操作系统时区（平台不单独存储或转换时区）。
      </div>
    </template>
    <a-tag :color="color" style="cursor:help;margin:0">🕓 当前时区：{{ label }}</a-tag>
  </a-tooltip>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { getVersion } from '../api/meta'

const props = defineProps<{ color?: string }>()
const color = computed(() => props.color || 'default')

const tzName = ref('')      // IANA/缩写（tooltip 里展示）
const tzLabel = ref('')     // 中文地理名（协调世界时/美国东部时间…）
const offsetMin = ref<number | null>(null)

const offsetText = computed(() => {
  if (offsetMin.value == null) return 'UTC'
  const m = offsetMin.value
  const sign = m >= 0 ? '+' : '-'
  const abs = Math.abs(m)
  const h = Math.floor(abs / 60)
  const mm = abs % 60
  return `UTC${sign}${h}${mm ? ':' + String(mm).padStart(2, '0') : ''}`
})

// 标签：中文地理名 + UTC 偏移，如"协调世界时（UTC+0）"、"美国东部时间（UTC-5）"；无中文名则只显 UTC 偏移
const label = computed(() => tzLabel.value ? `${tzLabel.value}（${offsetText.value}）` : offsetText.value)

onMounted(async () => {
  try {
    const v = await getVersion()
    tzName.value = v.tz_name || v.tz_abbr || ''
    tzLabel.value = v.tz_label || ''
    offsetMin.value = typeof v.utc_offset_min === 'number' ? v.utc_offset_min : null
  } catch { /* 时区可选，取不到不显异常 */ }
})
</script>
