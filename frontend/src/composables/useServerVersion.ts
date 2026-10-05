/**
 * 运行时服务端版本源 —— UI「当前版本」的单一事实源。
 *
 * **为何需要**：前端 `brand.ts:APP_VERSION` 是**编译进包的静态常量**，与后端 `version.txt` 不同源。
 * 跳板逐级更新时，某一级的前端产物 brand 标签可能滞后/错配（如落地 157 却标着 159），
 * 直接显示 APP_VERSION 会让「当前版本」显示假版本号，进而误导更新检测。
 * 本 composable 运行时从后端 `/api/about/version`（读 version.txt）拉真实版本，显示与比对都用它，
 * APP_VERSION 仅作后端不可达时的兜底。一次拉取全局缓存，多处共享同一 ref。
 */
import { ref } from 'vue'
import { APP_VERSION } from '../config/brand'
import { request } from '../api/request'

// 全局单例：真实后端版本（初始为编译版本作占位，拉到后覆盖）
const serverVersion = ref<string>(APP_VERSION)
let _fetched = false
let _inflight: Promise<string> | null = null

/** 拉后端真实版本（version.txt）。失败保持当前值（兜底 APP_VERSION）。幂等：并发只发一次。 */
export async function fetchServerVersion(force = false): Promise<string> {
  if (_fetched && !force) return serverVersion.value
  if (_inflight) return _inflight
  _inflight = (async () => {
    try {
      const res = await request<{ version: string }>('/api/about/version')
      const v = (res && res.version) ? String(res.version).trim() : ''
      if (v) serverVersion.value = v
      _fetched = true
    } catch {
      /* 后端不可达：保持当前值（APP_VERSION 兜底），不抛错 */
    } finally {
      _inflight = null
    }
    return serverVersion.value
  })()
  return _inflight
}

/** 供组件绑定的响应式版本 ref + 主动刷新方法。 */
export function useServerVersion() {
  if (!_fetched) fetchServerVersion()   // 首次使用即懒加载
  return { serverVersion, refresh: () => fetchServerVersion(true) }
}
