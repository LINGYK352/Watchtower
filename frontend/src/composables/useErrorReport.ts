import { t as translate } from '../i18n'
import { reactive } from 'vue'
import { APP_VERSION } from '../config/brand'

/**
 * 全局业务异常捕获 + 上报弹窗状态（需求：用户操作出错时弹窗问是否上传日志给开发者）。
 *
 * 由 request.ts 在请求失败(服务端 5xx / 业务异常)时调 captureError() 投递；
 * App.vue 挂的 ErrorReportModal 消费 pending 展示弹窗，用户确认后调 /api/about/report_error。
 *
 * 防刷屏（去重+冷却）：同一 (path+message) 指纹在 COOLDOWN_MS 内只弹一次；用户「忽略」后该指纹静默更久。
 * 安全边界：只收错误类型/消息/路径/状态码/版本 —— 绝不含请求体/响应体/Token/目标数据。
 */

const COOLDOWN_MS = 60_000        // 同类错误弹窗冷却：60s 内不重复弹
const DISMISS_MS = 10 * 60_000    // 用户「忽略」后该类错误静默 10 分钟

export interface CapturedError {
  path: string
  method: string
  status: number
  message: string
  version: string
  ts: string
}

// 最近一次待处理的错误（供弹窗展示，null=无）
const state = reactive<{ pending: CapturedError | null }>({ pending: null })

// 指纹 → 上次弹窗时间戳，用于去重+冷却
const _lastShown: Record<string, number> = {}

function _fingerprint(path: string, message: string): string {
  // 归一：去掉 path 里的 query 和数字 id 段，避免 /x/1 /x/2 被当不同错误
  const p = (path || '').split('?')[0].replace(/\/\d+/g, '/:id')
  return p + '|' + (message || '').slice(0, 80)
}

/** request.ts 调：捕获一条业务异常。会做去重+冷却，命中冷却则静默不弹。 */
export function captureError(info: { path: string; method?: string; status?: number; message: string }) {
  const fp = _fingerprint(info.path, info.message)
  const now = Date.now()
  const last = _lastShown[fp] || 0
  if (now - last < COOLDOWN_MS) return        // 冷却中：静默
  _lastShown[fp] = now
  state.pending = {
    path: (info.path || '').split('?')[0],
    method: info.method || 'GET',
    status: info.status || 0,
    message: info.message || translate('ui.m_13a46616e16f'),
    version: APP_VERSION,
    ts: new Date().toLocaleString(),
  }
}

/** 弹窗组件用：读当前待处理错误 */
export function usePendingError() {
  return state
}

/** 用户关闭/上传后清空 pending */
export function clearPending() {
  state.pending = null
}

/** 用户点「忽略」：该类错误延长静默期，避免连环弹 */
export function dismissError() {
  if (state.pending) {
    const fp = _fingerprint(state.pending.path, state.pending.message)
    _lastShown[fp] = Date.now() + (DISMISS_MS - COOLDOWN_MS)   // 推远冷却起点 → 静默更久
  }
  state.pending = null
}
