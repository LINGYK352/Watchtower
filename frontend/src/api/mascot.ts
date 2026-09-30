import { request } from './request'

export interface MascotMsg {
  role: 'user' | 'assistant'
  content: string
}

// 桌宠 AI 对话：复用平台已配置的 AI provider（后端 /api/mascot/chat）。
// history 为最近数轮上下文，由前端携带（无服务端会话态）。
export function mascotChat(message: string, history: MascotMsg[] = []) {
  return request<{ reply: string }>('/api/mascot/chat', {
    method: 'POST',
    body: JSON.stringify({ message, history }),
  })
}
