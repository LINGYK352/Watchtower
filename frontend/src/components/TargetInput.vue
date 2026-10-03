<template>
  <a-textarea v-model:value="value" :rows="rows" :placeholder="translate('ui.m_2478c1c90055')" />
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

withDefaults(defineProps<{ rows?: number }>(), { rows: 4 })
const value = defineModel<string>({ required: true })
</script>
