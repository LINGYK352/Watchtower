import { ref } from 'vue'

// 全局主题：light（浅色科技风，默认）/ dark（赛博作战室风，与会话台一致）。
// 单例 ref 跨组件共享；持久化 localStorage 'theme'；通过 <html data-theme> 驱动 CSS 变量，
// 同时供 App.vue 的 a-config-provider 切 Ant darkAlgorithm。
export type ThemeMode = 'light' | 'dark'

function read(): ThemeMode {
  try {
    return localStorage.getItem('theme') === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

const isDark = ref(read() === 'dark')

function apply(mode: ThemeMode) {
  try { document.documentElement.dataset.theme = mode } catch { /* SSR/无 document 忽略 */ }
}

export function setTheme(mode: ThemeMode) {
  isDark.value = mode === 'dark'
  try { localStorage.setItem('theme', mode) } catch { /* 隐私模式忽略 */ }
  apply(mode)
}

export function toggleTheme() {
  setTheme(isDark.value ? 'light' : 'dark')
}

// 模块加载即应用一次（与 index.html 内联脚本一致，双保险）
apply(isDark.value ? 'dark' : 'light')

export function useTheme() {
  return { isDark, setTheme, toggleTheme }
}
