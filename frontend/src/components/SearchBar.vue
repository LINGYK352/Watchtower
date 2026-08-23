<template>
  <a-card class="search-card" :bordered="false">
    <a-form layout="inline" :model="model" class="search-form">
      <slot />
      <a-form-item>
        <a-space>
          <a-button type="primary" @click="$emit('search')">查询</a-button>
          <a-button @click="$emit('reset')">重置</a-button>
        </a-space>
      </a-form-item>
    </a-form>
  </a-card>
</template>

<script setup lang="ts">
defineProps<{ model: Record<string, unknown> }>()
defineEmits<{ search: []; reset: [] }>()
</script>
