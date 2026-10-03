import { t as translate } from '../i18n'
import { request, getToken } from './request'

export interface MiniAppResult {
  ok?: boolean
  wxid: string
  name?: string
  unpacked_at?: string
  unpacked_ts?: number
  wxapkg_count?: number
  packages?: string[]         // 包文件名列表（主包+子包）
  source_file_count?: number
  out_dir?: string            // 解包源码目录（后端注入 AI 上下文用，前端不展示明文）
  error?: string
}

export interface MiniAppHistoryItem {
  wxid: string; name?: string; unpacked_at?: string; unpacked_ts?: number
  wxapkg_count?: number; packages?: string[]; source_file_count?: number
}

export const miniappApi = {
  // 解包工具(KillWxapkg)是否就绪
  status: () => request<{ available: boolean; binary: string }>('/api/miniapp/status'),

  // 已处理小程序历史（AppID 倒序）
  history: () => request<{ items: MiniAppHistoryItem[] }>('/api/miniapp/history'),

  // 读某 AppID 完整解包结果（回看）
  result: (wxid: string) => request<MiniAppResult>(`/api/miniapp/result/${encodeURIComponent(wxid)}`),

  // 删除某 AppID 记录 + 工作区
  remove: (wxid: string) =>
    request<{ ok: boolean; wxid: string }>(`/api/miniapp/${encodeURIComponent(wxid)}`, { method: 'DELETE' }),

  // 对勾选的小程序包发起 AI 渗透（一包一会话，选模式+模型；provider_id 空=全局默认模型）
  launch: (wxids: string[], mode: string, providerId = '') =>
    request<{ ok: boolean; created: number; session_ids: string[]; mode: string }>('/api/miniapp/launch', {
      method: 'POST',
      body: JSON.stringify({ wxids, mode, provider_id: providerId }),
    }),

  // 解包上传：FormData 多文件（webkitdirectory 选中的整个文件夹）。
  // 用原生 fetch 走 multipart（request 封装会强设 application/json，破坏 boundary），手动带 Token。
  unpack: async (wxid: string, files: File[], name = ''): Promise<MiniAppResult> => {
    const fd = new FormData()
    fd.append('wxid', wxid)
    if (name) fd.append('name', name)
    for (const f of files) {
      // 带上相对路径（webkitRelativePath），后端可从首段推断 AppID
      fd.append('files', f, (f as any).webkitRelativePath || f.name)
    }
    const headers = new Headers()
    const token = getToken()
    if (token) headers.set('Token', token)
    const resp = await fetch('/api/miniapp/unpack', { method: 'POST', body: fd, headers, cache: 'no-store' })
    const data = await resp.json().catch(() => ({}))
    if (!resp.ok || (data && data.code && data.code !== 200)) {
      throw new Error((data && data.message) || translate('ui.m_92be8cee0164', { p0: (resp.status) }))
    }
    return (data && data.data) as MiniAppResult
  },
}
