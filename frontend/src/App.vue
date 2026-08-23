<template>
  <a-config-provider :theme="antdTheme">
    <router-view />
  </a-config-provider>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { theme } from 'ant-design-vue'
import { useTheme } from './composables/useTheme'

const { isDark } = useTheme()

// 暗色时启用 Ant darkAlgorithm（让 table/input/select/modal/dropdown 等组件原生变暗），
// 并把主色切成霓虹青，与会话台赛博风一致；浅色沿用默认算法 + 品牌蓝。
const antdTheme = computed(() => ({
  algorithm: isDark.value ? theme.darkAlgorithm : theme.defaultAlgorithm,
  token: isDark.value
    ? { colorPrimary: '#00e5ff', colorBgBase: '#0a0e17', colorInfo: '#00e5ff', borderRadius: 8 }
    : { colorPrimary: '#1677ff' },
}))
</script>
