// Credentials stay in the URL fragment; parsing never contacts the supplied host.
export type InvitationKind = 'group' | 'sync'
export function invitationTarget(value: string): string {
  value = value.trim()
  if (!value || value.length > 300 || /[\s\\]/.test(value)) throw new Error('invitationLink.invalidTarget')
  const authority=value.replace(/^https?:\/\//i,'').split('/')[0]
  const bare=authority.split(':')[0]
  if(/^[0-9.]+$/.test(bare)&&(!/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)||bare.split('.').some(n=>Number(n)>255)))throw new Error('invitationLink.invalidTarget')
  if(authority.endsWith(':'))throw new Error('invitationLink.invalidTarget')
  let url: URL
  try { url = new URL(value.includes('://') ? value : 'http://' + value) } catch { throw new Error('invitationLink.invalidTarget') }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.pathname !== '/' || url.search || url.hash || url.port === '0') throw new Error('invitationLink.invalidTarget')
  return url.origin
}
export function syncReceiverTarget(value:string,port:number|null):string {
  if(!Number.isInteger(port)||!port||port<1||port>65535)throw new Error('revision17.invalidReceiver')
  value=value.trim()
  if(!value)throw new Error('revision17.invalidReceiver')
  // A bare IPv6 address denotes the host; an explicit port uses [host]:port.
  if(!value.includes('://')&&!value.startsWith('[')&&(value.match(/:/g)||[]).length>1)value='['+value+']'
  const raw=value.includes('://')?value:'http://'+value
  const match=/^(https?):\/\/(\[[^\]]+\]|[^:/?#]+)(?::([0-9]+))?\/?$/.exec(raw)
  if(!match)throw new Error('revision17.invalidReceiver')
  const host=match[2]
  if(/^[0-9.]+$/.test(host)&&(!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)||host.split('.').some(n=>Number(n)>255)))throw new Error('revision17.invalidReceiver')
  return invitationTarget(match[1]+'://'+host+':'+(match[3]||port))
}
export function makeInvitationLink(kind: InvitationKind, target: string, key: string, node?: Record<string,unknown> | null): string {
  const direct = invitationTarget(target || String(node?.url || '')), origin = node?invitationTarget(String(node.url)):direct
  const path = kind === 'group' ? '/collaboration' : '/control-sync'
  const fragment = new URLSearchParams({ 'wt-invite': kind, target: direct, key })
  if(node)fragment.set('node',JSON.stringify(node))
  return origin + path + '#' + fragment.toString()
}
export function parseInvitationLink(value: string, kind: InvitationKind): { target: string; key: string; node_descriptor?: Record<string,unknown> } {
  if (value.length > 4096) throw new Error('invitationLink.invalidLink')
  let url: URL
  try { url = new URL(value.trim()) } catch { throw new Error('invitationLink.invalidLink') }
  const fragment = new URLSearchParams(url.hash.slice(1)), target = fragment.get('target') || '', key = fragment.get('key') || ''
  const pattern = kind === 'group' ? /^wt_group\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/ : /^wt_pair\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/
  if (fragment.get('wt-invite') !== kind || !pattern.test(key)) throw new Error('invitationLink.invalidLink')
  const normalized = invitationTarget(target)
  let node_descriptor:Record<string,unknown>|undefined
  if(fragment.has('node')){try{node_descriptor=JSON.parse(fragment.get('node') || '')}catch{throw new Error('invitationLink.invalidLink')};if(!node_descriptor || typeof node_descriptor!=='object' || Array.isArray(node_descriptor) || node_descriptor.realm!==key.split('.')[1])throw new Error('invitationLink.invalidLink')}
  const origin=node_descriptor?invitationTarget(String(node_descriptor.url)):normalized
  if (url.origin !== origin || url.pathname !== (kind === 'group' ? '/collaboration' : '/control-sync') || url.search || url.username || url.password) throw new Error('invitationLink.invalidLink')
  return { target: normalized, key, ...(node_descriptor?{node_descriptor}:{}) }
}
export function pendingInvitation(kind: InvitationKind): string {
  let saved=''
  try { saved=sessionStorage.getItem('watchtower.pendingInvitation') || '' } catch { /* private browser storage */ }
  if (location.hash.startsWith('#wt-invite='+kind)) return location.href
  return saved.includes('#wt-invite='+kind) ? saved : ''
}
export function clearPendingInvitation() {
  try { sessionStorage.removeItem('watchtower.pendingInvitation') } catch { /* private browser storage */ }
}
