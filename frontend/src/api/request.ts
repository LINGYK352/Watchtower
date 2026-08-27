import type { ApiEnvelope } from './types'

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
  return data.message || detail || `请求失败：${status}`
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
  const response = await fetch(path, { ...options, headers, cache: 'no-store' })
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) {
    if (!response.ok) throw new Error(`请求失败：${response.status}`)
    return response as unknown as T
  }

  const data = await response.json().catch(() => ({})) as ApiEnvelope<T>
  if (response.status === 401 || data.code === 401) {
    clearToken()
    if (!location.pathname.startsWith('/login')) {
      location.href = `/login?redirect=${encodeURIComponent(location.pathname + location.search)}`
    }
    throw new Error(data.message || '登录已失效')
  }
  if (data.code === 403) {
    // 无权限:不跳登录,只抛错让页面提示(后端网关拦截)
    throw new Error(data.message || '无权限执行此操作')
  }
  if (!response.ok || data.code !== 200) {
    throw new Error(normalizeError(data, response.status))
  }

  if (data.data !== undefined) return data.data as T
  return data as unknown as T
}
