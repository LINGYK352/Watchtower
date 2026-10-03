<template>
  <a-modal :open="open" :title="translate('ui.m_2a50a4d4efa3')" width="760px" @cancel="$emit('update:open', false)" :footer="null">
    <pre class="json-preview">{{ formatted }}</pre>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { computed } from 'vue'
const props = defineProps<{ open: boolean; data?: unknown }>()
defineEmits<{ 'update:open': [value: boolean] }>()
const formatted = computed(() => JSON.stringify(props.data || {}, null, 2))
</script>
