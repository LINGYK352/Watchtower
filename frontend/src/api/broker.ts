import { request } from './request'

export interface BrokerStatus {
  mode: 'celery' | 'thread'
  degraded: boolean
  reason: string
  degraded_at: number
  recovered_at: number
}

// 查调度 broker 降级状态（顶栏红标签轮询）
export function getBrokerStatus() {
  return request<BrokerStatus>('/api/system/broker/status')
}

// 手动切回 rabbitmq(celery) 模式：后端先 ping broker，通了才切
export function switchBackBroker(force = false) {
  return request<{ ok: boolean; mode: string; message: string }>(
    '/api/system/broker/switch_back',
    { method: 'POST', body: JSON.stringify({ force }) },
  )
}
