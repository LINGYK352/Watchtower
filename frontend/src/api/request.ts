import { t as translate } from '../i18n'
import type { ApiEnvelope } from './types'
import { captureError } from '../composables/useErrorReport'

export function getToken(): string {
  return localStorage.getItem('Token') || localStorage.getItem('token') || sessionStorage.getItem('Token') || sessionStorage.getItem('token') || ''
}

export function setToken(token: string) {
  localStorage.setItem('Token', token)
}

export function getUser(): string {
  return localStorage.getItem('arl_user') || ''
}

export function setUser(username: string) {
  if (username) localStorage.setItem('arl_user', username)
}

// 当前用户权限/角色(登录时存,前端菜单过滤用;后端网关仍独立校验)
export function setPerms(role: string, permissions: string[]) {
  if (role) localStorage.setItem('arl_role', role)
  localStorage.setItem('arl_perms', JSON.stringify(permissions || []))
}

export function getRole(): string {
  return localStorage.getItem('arl_role') || ''
}

export function getPerms(): string[] {
  try {
    return JSON.parse(localStorage.getItem('arl_perms') || '[]')
  } catch {
    return []
  }
}

export function hasPerm(perm: string): boolean {
  const perms = getPerms()
  return perms.includes(perm)
}

export function clearToken() {
  localStorage.removeItem('Token')
  localStorage.removeItem('token')
  localStorage.removeItem('arl_user')
  localStorage.removeItem('arl_role')
  localStorage.removeItem('arl_perms')
  sessionStorage.removeItem('Token')
  sessionStorage.removeItem('token')
}

export function toQueryString(query: Record<string, unknown> = {}) {
  const params = new URLSearchParams()
  Object.entries(query).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    params.set(key, String(value))
  })
  const raw = params.toString()
  return raw ? `?${raw}` : ''
}

function normalizeError(data: ApiEnvelope, status: number) {
  const detail = data?.data && typeof data.data === 'object' ? JSON.stringify(data.data) : ''
  return data.message || detail || translate('ui.m_47245f9bc28a', { p0: (status) })
}

// 上报接口自身/鉴权类不触发捕获（防环、防噪声）
function _isReportPath(path: string): boolean {
  return path.includes('/about/report_error') || path.includes('/about/my_reports')
}
function _method(options: RequestInit): string {
  return (options.method || 'GET').toUpperCase()
}
// 仅"服务端故障"触发上报弹窗：HTTP 5xx，或业务信封 code>=500。4xx/普通业务码(校验失败等)不弹。
function _maybeCapture(path: string, options: RequestInit, httpStatus: number, code: number | undefined, msg: string) {
  if (_isReportPath(path)) return
  const serverFault = httpStatus >= 500 || (typeof code === 'number' && code >= 500)
  if (!serverFault) return
  captureError({ path, method: _method(options), status: httpStatus || code || 0, message: msg })
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {})
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json')
  }
  const token = getToken()
  if (token) {
    headers.set('Token', token)
  }

  // API 数据不走浏览器 HTTP 缓存：否则 GET(如 console/info 设备状态、exit_ip)会命中缓存返回旧数据，
  // 自动刷新(30s)拉不到新数据(表现为"显示旧数据、不更新")。API 响应本就不该被浏览器缓存。
  // 网络层失败自愈（铁律 [[feedback-retry-not-cache-for-flaky-probe]]）：gunicorn --reload 重启的几百毫秒、
  // 或偶发网络抖动会让在途请求（尤其 30s 轮询的 GET 如 console/resource_alert）吃一次 "Failed to fetch"。
  // 单次波动不该立刻弹错误上报打扰用户。对**幂等请求(GET/HEAD)**先静默重试几次+退避再上报；
  // 写请求(POST/PUT/DELETE/PATCH)不盲重试（防重复提交），保持快速失败。
  const method = _method(options)
  const idempotent = method === 'GET' || method === 'HEAD'
  const maxAttempts = idempotent ? 3 : 1
  let response: Response | null = null
  let lastErr: Error | null = null
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      response = await fetch(path, { ...options, headers, cache: 'no-store' })
      break
    } catch (e) {
      lastErr = e as Error
      if (attempt < maxAttempts) {
        await new Promise(r => setTimeout(r, 400 * attempt))   // 退避 400ms/800ms，等 reload 恢复
        continue
      }
    }
  }
  if (!response) {
    // 幂等请求重试仍失败 / 写请求单次失败：判定为真实网络故障，捕获供上报（排除上报接口本身防环）
    const msg = `网络请求失败：${lastErr?.message || '连接异常'}`
    if (!_isReportPath(path)) captureError({ path, method, status: 0, message: msg })
    throw new Error(msg)
  }
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) {
    if (!response.ok) {
      _maybeCapture(path, options, response.status, undefined, `请求失败：${response.status}`)
      throw new Error(translate('ui.m_47245f9bc28a', { p0: (response.status) }))
    }
    return response as unknown as T
  }

  const data = await response.json().catch(() => ({})) as ApiEnvelope<T>
  if (response.status === 401 || data.code === 401) {
    clearToken()
    if (!location.pathname.startsWith('/login')) {
      location.href = `/login?redirect=${encodeURIComponent(location.pathname + location.search)}`
    }
    throw new Error(data.message || translate('ui.m_0759032719bf'))
  }
  if (response.status === 402 || data.code === 402) {
    // 系统未激活/激活过期:核心业务端点被网关硬拦。不跳登录(登录态正常),抛错让页面提示去激活。
    // 触发全局事件,由 AppLayout 弹激活向导(与首登弹窗同一入口)。
    try { window.dispatchEvent(new CustomEvent('sentinel:activation-required', { detail: { path } })) } catch { /* SSR/无 window 降级 */ }
    throw new Error(data.message || translate('ui.m_ec42ebd430df'))
  }
  if (data.code === 403) {
    // 无权限:不跳登录,只抛错让页面提示(后端网关拦截)
    throw new Error(data.message || translate('ui.m_ae9422ab59f6'))
  }
  if (!response.ok || data.code !== 200) {
    const msg = normalizeError(data, response.status)
    // 业务异常上报捕获：仅服务端故障(HTTP 5xx / 业务 code 5xx)触发弹窗,不含校验类(4xx/普通业务码);
    // 排除上报接口本身防环。用户操作出错→弹窗问是否上传日志给开发者(useErrorReport 去重+冷却)。
    _maybeCapture(path, options, response.status, data.code, msg)
    throw new Error(msg)
  }

  if (data.data !== undefined) return data.data as T
  return data as unknown as T
}
