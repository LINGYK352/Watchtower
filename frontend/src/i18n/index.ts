import { computed, watch } from 'vue'
import { createI18n } from 'vue-i18n'
import zhCN from '../locales/zh-CN.json'
import enUS from '../locales/en-US.json'
import antZhCN from 'ant-design-vue/es/locale/zh_CN'
import antEnUS from 'ant-design-vue/es/locale/en_US'

export type AppLocale = 'zh-CN' | 'en-US'
export const localeOptions = [{ value: 'zh-CN', label: '简体中文' }, { value: 'en-US', label: 'English' }] as const
const STORAGE_KEY = 'watchtower.locale'
const supported = (value: unknown): value is AppLocale => value === 'zh-CN' || value === 'en-US'
function storedLocale(): AppLocale {
  try { const value = localStorage.getItem(STORAGE_KEY); if (supported(value)) return value } catch { /* private browser storage may be disabled */ }
  return 'zh-CN'
}
// UI help contains literal JSON, e-mail addresses and code. Interpret only named
// parameters; do not treat those literal characters as message-format syntax.
export const i18n = createI18n({ legacy: false, globalInjection: true, locale: storedLocale(), fallbackLocale: 'zh-CN',
  messageCompiler: message => (context: { named(name: string): unknown }) => {
    if (typeof message !== 'string') return ''
    return message.replace(/\{([A-Za-z_]\w*)\}/g, (original, name: string) => {
      const value = context.named(name)
      return value === undefined ? original : String(value)
    })
  }, messages: { 'zh-CN': zhCN, 'en-US': enUS } })
export const appLocale = i18n.global.locale
export const componentLocale = computed(() => appLocale.value === 'en-US' ? antEnUS : antZhCN)
export function setLocale(value: AppLocale) {
  if (supported(value)) appLocale.value = value
}
watch(appLocale, value => {
  document.documentElement.lang = value
  try { localStorage.setItem(STORAGE_KEY, value) } catch { /* switching still works */ }
}, { immediate: true })
window.addEventListener('storage', event => { if (event.key === STORAGE_KEY && supported(event.newValue)) setLocale(event.newValue) })
export function t(key: string, parameters?: Record<string, unknown>) {
  const named = parameters && Object.fromEntries(Object.entries(parameters).map(([name, value]) => [name, value == null ? '' : value]))
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}
export function hasMessage(key: string) { return i18n.global.te(key) }
