<template>
  <a-card class="search-card" :bordered="false">
    <a-form layout="inline" :model="model" class="search-form">
      <slot />
      <a-form-item>
        <a-space>
          <a-button type="primary" @click="$emit('search')">{{ translate('ui.m_bcd6771e08ec') }}</a-button>
          <a-button @click="$emit('reset')">{{ translate('ui.m_cb5d682bac3d') }}</a-button>
        </a-space>
      </a-form-item>
    </a-form>
  </a-card>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

defineProps<{ model: Record<string, unknown> }>()
defineEmits<{ search: []; reset: [] }>()
</script>
