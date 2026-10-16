<template>
  <a-config-provider :theme="antdTheme" :locale="componentLocale">
    <router-view />
    <ErrorReportModal />
  </a-config-provider>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { theme } from 'ant-design-vue'
import { useTheme } from './composables/useTheme'
import ErrorReportModal from './components/ErrorReportModal.vue'
import { componentLocale } from './i18n'
const { isDark } = useTheme()
// Both algorithms retain native component states; daylight surfaces share the
// same palette as CSS tokens so tables, portals and controls stay consistent.
const antdTheme = computed(() => ({
  algorithm: isDark.value ? theme.darkAlgorithm : theme.defaultAlgorithm,
  token: isDark.value ? {
    colorPrimary:'#3b82f6', colorInfo:'#3b82f6', colorBgBase:'#0b1220', colorBgLayout:'#0b1220',
    colorBgContainer:'#111d30', colorBgElevated:'#1b2b42', colorText:'#e6edf3',
    colorTextSecondary:'#9aaec5', colorTextPlaceholder:'#9aaec5', colorBorder:'#475569',
    colorBorderSecondary:'#334155', colorFillAlter:'#1b2b42', borderRadius:8, controlHeight:32, fontSize:14,
  } : { colorPrimary:'#3865c9', colorInfo:'#3865c9', colorBgLayout:'#eaf0f8', colorBgContainer:'#fcfdff', colorBgElevated:'#fcfdff', colorText:'#20324d', colorTextSecondary:'#5e708c', colorBorder:'#ccd8ea', colorBorderSecondary:'#dbe4f1', colorFillAlter:'#eef3fa', borderRadius:8, controlHeight:32, fontSize:14 },
  components: {
    Card:{headerFontSize:15,headerHeight:44},
    Table:{headerBg:isDark.value?'#1b2b42':'#e9eff9',cellPaddingBlockMD:8,cellPaddingInlineMD:12},
    ...(isDark.value ? {Button:{primaryColor:'#ffffff',colorPrimary:'#2563eb',colorPrimaryHover:'#1d4ed8',colorPrimaryActive:'#174793'}} : {}),
  },
}))
</script>
