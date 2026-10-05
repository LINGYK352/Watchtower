import { request } from './request'

export interface LoginResult {
  token?: string
  username?: string
  role?: string
  permissions?: string[]
  [key: string]: unknown
}

export interface ProfileResult {
  username: string
  role: string
  permissions: string[]
  type: string
}

export interface UserItem {
  username: string
  role: string
  disabled: boolean
  is_manager: boolean
  created_by?: string
  create_date?: string
}

export interface RoleItem {
  name: string
  title: string
  permissions: string[]
  builtin: boolean
  desc?: string
}

export interface PermItem {
  key: string
  desc: string
}

export const userApi = {
  login: (username: string, password: string) => request<LoginResult>('/api/user/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  }),
  logout: () => request<Record<string, never>>('/api/user/logout'),
  changePassword: (old_password: string, new_password: string, check_password: string) => request<Record<string, never>>('/api/user/change_pass', {
    method: 'POST',
    body: JSON.stringify({ old_password, new_password, check_password })
  }),

  // 自身权限(菜单过滤用)
  profile: () => request<ProfileResult>('/api/user_manage/profile'),

  // 用户管理(需 user:manage)
  listUsers: () => request<{ items: UserItem[] }>('/api/user_manage/manage/users'),
  createUser: (username: string, password: string, role: string) =>
    request<{ username: string }>('/api/user_manage/manage/users', {
      method: 'POST', body: JSON.stringify({ username, password, role })
    }),
  updateUser: (payload: { username: string; role?: string; password?: string; disabled?: boolean }) =>
    request<{ username: string }>('/api/user_manage/manage/user/update', {
      method: 'POST', body: JSON.stringify(payload)
    }),
  deleteUser: (username: string) =>
    request<{ username: string }>('/api/user_manage/manage/user/delete', {
      method: 'POST', body: JSON.stringify({ username })
    }),

  // 角色管理
  listRoles: () => request<{ items: RoleItem[] }>('/api/user_manage/manage/roles'),
  upsertRole: (payload: { name: string; title?: string; permissions: string[]; desc?: string }) =>
    request<{ name: string }>('/api/user_manage/manage/roles', {
      method: 'POST', body: JSON.stringify(payload)
    }),
  deleteRole: (name: string) =>
    request<{ name: string }>('/api/user_manage/manage/role/delete', {
      method: 'POST', body: JSON.stringify({ name })
    }),

  // 权限点清单(建角色勾选用)
  listPermissions: () => request<{ items: PermItem[] }>('/api/user_manage/manage/permissions'),
}
