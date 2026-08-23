<template>
  <a-modal :open="open" title="数据详情" width="760px" @cancel="$emit('update:open', false)" :footer="null">
    <pre class="json-preview">{{ formatted }}</pre>
  </a-modal>
</template>

<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ open: boolean; data?: unknown }>()
defineEmits<{ 'update:open': [value: boolean] }>()
const formatted = computed(() => JSON.stringify(props.data || {}, null, 2))
</script>
