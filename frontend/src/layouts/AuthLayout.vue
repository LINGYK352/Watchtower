<template>
  <div class="auth-shell">
    <div class="auth-card">
      <div class="auth-brand">
        <div class="auth-logo"><BrandLogo :size="42" /></div>
        <div>
          <h1>{{ APP_NAME }}</h1>
          <p>{{ APP_SUBTITLE }}</p>
        </div>
      </div>
      <router-view />
    </div>
  </div>
</template>

<script setup lang="ts">
import BrandLogo from '../components/BrandLogo.vue'
import { APP_NAME, APP_SUBTITLE } from '../config/brand'
</script>
