/** One shared-revision reader per visible finding page. No overlapping loops. */
export type FindingFeedState = 'live' | 'reconnecting'
export function createFindingFeed(options: {
  revision: (signal: AbortSignal) => Promise<string>
  refresh: (signal: AbortSignal) => Promise<boolean>
  state: (state: FindingFeedState) => void
  interval?: number
  reconcile?: number
  timeout?: number
}) {
  let paused = true, running = false, requested = false
  let seen: string | undefined, lastRefresh = 0, failures = 0
  let timer: ReturnType<typeof setTimeout> | undefined
  let controller: AbortController | undefined
  const interval = options.interval ?? 1000
  async function tick(force = false) {
    if (paused) return
    if (running) { requested = true; return }
    running = true
    const current = new AbortController(); controller = current
    const deadline = setTimeout(() => current.abort(), options.timeout ?? 12000)
    try {
      const revision = await options.revision(current.signal)
      if (current.signal.aborted || paused) return
      if (force || requested || revision !== seen || Date.now() - lastRefresh >= (options.reconcile ?? 30000)) {
        requested = false
        const committed = await options.refresh(current.signal)
        if (paused) return
        if (current.signal.aborted) throw new Error('Finding data read timed out')
        if (!committed) return
        // Only acknowledge the revision read BEFORE the successful data read.
        // A concurrent write during that read is detected by the next tick.
        seen = revision; lastRefresh = Date.now()
      }
      failures = 0; options.state('live')
    } catch {
      if (!paused) { failures++; options.state('reconnecting') }
    } finally {
      clearTimeout(deadline); running = false
      if (controller === current) controller = undefined
      if (!paused) timer = setTimeout(() => tick(requested), requested ? 0 : Math.min(8000, interval * 2 ** failures))
    }
  }
  return {
    start() { paused = false; clearTimeout(timer); void tick(true) },
    pause() { paused = true; requested = false; clearTimeout(timer); controller?.abort() },
  }
}
