import { t as translate } from '../../i18n'
/** Keep authentication success separate from completing navigation. */
interface LoginRouter {
  replace(to: string): Promise<unknown>
  currentRoute: { value: { path: string } }
  resolve(to: string): { matched: unknown[] }
}

export function loginDestination(redirect: unknown, origin: string, router: LoginRouter): string {
  if (typeof redirect !== 'string' || !redirect.startsWith('/') || redirect.startsWith('//') || /[\\\x00-\x20]/.test(redirect)) return '/dashboard'
  try {
    const url = new URL(redirect, origin)
    if (url.origin !== origin || /^\/login(?:\/|$)/.test(url.pathname)) return '/dashboard'
    const target = url.pathname + url.search + url.hash
    return router.resolve(target).matched.length ? target : '/dashboard'
  } catch { return '/dashboard' }
}

export async function navigateAfterLogin(router: LoginRouter, target: string, reload: (target: string) => void, timeoutMs = 10000): Promise<'spa' | 'reload'> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      router.replace(target),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(translate('ui.m_295440f81347'))), timeoutMs) }),
    ])
    if (!/^\/login(?:\/|$)/.test(router.currentRoute.value.path)) return 'spa'
  } catch (error) {
    // Failed module loads are cached by the JS module loader. Retrying the same
    // import in this document does not repair it; use one fresh same-origin document.
    console.warn('Login page navigation did not complete', error)
    if (!/^\/login(?:\/|$)/.test(router.currentRoute.value.path)) return 'spa'
  } finally { if (timer) clearTimeout(timer) }
  reload(target)
  return 'reload'
}
