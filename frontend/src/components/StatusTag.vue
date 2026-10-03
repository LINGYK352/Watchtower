<template>
  <a-tag :color="color">{{ label }}</a-tag>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { computed } from 'vue'

const props = defineProps<{ value?: string | number | boolean }>()

const map: Record<string, { label: string; color: string }> = {
  done: { get label() { return translate('ui.m_f28461bb49c8') }, color: 'success' },
  stop: { get label() { return translate('ui.m_f006455e3baf') }, color: 'default' },
  error: { get label() { return translate('ui.m_428fb8bfeecf') }, color: 'error' },
  running: { get label() { return translate('ui.m_1f0eb99b7ed0') }, color: 'processing' },
  waiting: { get label() { return translate('ui.m_26c8cfcbf763') }, color: 'warning' },
  proxy_paused: { get label() { return translate('ui.m_49d5a8fb9591') }, color: 'orange' },
  scheduled: { get label() { return translate('ui.m_c543d8e1dd10') }, color: 'blue' },
  true: { get label() { return translate('ui.m_f4f0ead1116b') }, color: 'success' },
  false: { get label() { return translate('ui.m_3fd47edce45b') }, color: 'default' }
}

const key = computed(() => String(props.value ?? '').toLowerCase())
const label = computed(() => map[key.value]?.label || String(props.value ?? '-'))
const color = computed(() => map[key.value]?.color || 'blue')
</script>
