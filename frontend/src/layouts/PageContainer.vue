<template>
  <div class="page-container">
    <div class="page-heading">
      <div class="page-heading-main">
        <div class="page-kicker" v-if="kicker">{{ kicker }}</div>
        <h1>{{ title }}</h1>
        <p v-if="description" :title="description" class="page-description">{{ description }}</p>
      </div>
      <div class="page-extra"><slot name="extra" /></div>
    </div>
    <slot />
  </div>
</template>

<script setup lang="ts">
defineProps<{ title: string; description?: string; kicker?: string }>()
</script>
