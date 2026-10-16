import { shallowRef, onMounted, onUnmounted } from 'vue'
import { request, getToken } from '../api/request'

type Unread = {unread_total:number;unread_groups:Record<string,number>;unread_rooms:Record<string,Record<string,number>>}
type Summary = { total: number; groups: Record<string, number> } & Unread
const emptyUnread:Unread={unread_total:0,unread_groups:{},unread_rooms:{}}
const summary = shallowRef<Summary>({ total: 0, groups: {},...emptyUnread })
export const groupNotificationState=summary
let revision = 0

function publish(value: {total:number;groups:Record<string,number>} & Partial<Unread>) {
  const groups: Record<string, number> = {}
  for (const [id, count] of Object.entries(value.groups || {})) groups[id] = Math.max(0, Number(count) || 0)
  summary.value = { ...summary.value,...value,total: Object.values(groups).reduce((a, b) => a + b, 0), groups }
  revision++
}

export function updateGroupNotifications(groups: any[],unread?:Unread) {
  const counts: Record<string, number> = {}
  for (const group of groups) if (group.enabled !== false) counts[group._id] = Number(group.pending_count || 0)
  publish({ total: 0, groups: counts,...unread })
}

export function updateTeamUnread(value:Unread){publish({...summary.value,...value})}

export function useGroupNotifications(enabled: () => boolean) {
  let stopped = false, busy = false
  let generation = 0
  let controller: AbortController | null = null
  let timer: ReturnType<typeof setInterval> | undefined
  async function refresh() {
    if (stopped || busy) return
    const token = getToken()
    if (!token || !enabled()) { publish({ total: 0, groups: {},...emptyUnread }); return }
    busy = true
    const current = ++generation
    controller = new AbortController()
    const before = revision
    try {
      const result = await request<Summary>('/api/collaboration/pending', { silent: true, signal: controller.signal })
      if (!stopped && current === generation && before === revision && token === getToken()) publish(result)
    } catch { /* Keep last valid counts through transient update/network outages. */ }
    finally { if (current === generation) busy = false }
  }
  function changed() { controller?.abort(); generation++; busy = false; void refresh() }
  onMounted(() => {
    void refresh()
    timer = setInterval(() => { if (!document.hidden) void refresh() }, 6000)
    window.addEventListener('focus', changed)
    window.addEventListener('watchtower:collaboration-changed', changed)
  })
  onUnmounted(() => {
    stopped = true; controller?.abort()
    if (timer) clearInterval(timer)
    window.removeEventListener('focus', changed)
    window.removeEventListener('watchtower:collaboration-changed', changed)
  })
  return summary
}
