<template>
  <button class="language-switch" type="button" :title="hint" :aria-label="hint" data-testid="language-switch" @click="toggle">
    <TranslationOutlined /><span>{{ t('language.short') }}</span>
  </button>
</template>
<script setup lang="ts">
import { TranslationOutlined } from '@ant-design/icons-vue'
import { computed } from 'vue'
import { appLocale, setLocale, t } from '../i18n'
const hint = computed(() => t(appLocale.value === 'en-US' ? 'language.toChinese' : 'language.toEnglish'))
function toggle() { setLocale(appLocale.value === 'en-US' ? 'zh-CN' : 'en-US') }
</script>
<style scoped>
.language-switch { display:flex;align-items:center;gap:5px;border:1px solid var(--border-color,#334155);background:transparent;color:inherit;border-radius:6px;padding:4px 8px;cursor:pointer;white-space:nowrap }
.language-switch:focus-visible { outline:2px solid #00c4d4;outline-offset:2px }
</style>
