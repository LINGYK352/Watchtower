<template>
  <a-textarea v-model:value="value" :rows="rows" placeholder="请输入目标，多个目标换行" />
</template>

<script setup lang="ts">
withDefaults(defineProps<{ rows?: number }>(), { rows: 4 })
const value = defineModel<string>({ required: true })
</script>
