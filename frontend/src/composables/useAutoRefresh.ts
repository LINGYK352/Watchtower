import { ref, watch, onMounted, onBeforeUnmount, type Ref } from 'vue'

/**
 * 定时自动刷新 composable。
 *
 * - 组件挂载后按 intervalMs 周期调用 fn;
 * - 页面切到后台(visibilitychange hidden)时暂停,切回时立即刷新一次再继续(省请求、保新鲜);
 * - 组件卸载自动清理定时器;
 * - 返回 enabled(开关) + 手动 trigger,UI 可挂个"自动刷新"开关。
 *
 * 不负责首次加载(由调用方 onMounted 自行 load),只管"周期性再刷"。
 */
export function useAutoRefresh(fn: () => void | Promise<unknown>, intervalMs = 30000, defaultOn = true): {
  enabled: Ref<boolean>
  trigger: () => void
} {
  const enabled = ref(defaultOn)
  let timer: ReturnType<typeof setInterval> | null = null
  let running = false
  let disposed = false

  async function tick() {
    if (disposed || running || !enabled.value || document.visibilityState !== 'visible') return
    running = true
    try { await fn() } catch { /* 单次刷新失败不影响后续 */ }
    finally { running = false }
  }

  function start() {
    stop()
    if (!disposed && enabled.value && document.visibilityState === 'visible') {
      timer = setInterval(tick, intervalMs)
    }
  }

  function stop() {
    if (timer) { clearInterval(timer); timer = null }
  }

  function onVisible() {
    // 切回前台立即刷新一次,避免等满一个周期才更新
    if (document.visibilityState === 'visible' && enabled.value) {
      void tick()
      start()
    } else {
      stop()
    }
  }

  onMounted(() => {
    start()
    document.addEventListener('visibilitychange', onVisible)
  })

  watch(enabled, () => enabled.value ? start() : stop())

  onBeforeUnmount(() => {
    disposed = true
    stop()
    document.removeEventListener('visibilitychange', onVisible)
  })

  return { enabled, trigger: tick }
}
