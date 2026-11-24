type Clock = { now: () => number; later: (run: () => void, delay: number) => number; cancel: (timer: number) => void }

/** A slow node occupies one slot, without delaying another node's next read. */
export function resourcePoll(read: (id: string, signal: AbortSignal) => Promise<number>, visible: () => boolean,
  clock: Clock = { now: () => performance.now(), later: (run, delay) => window.setTimeout(run, delay), cancel: timer => clearTimeout(timer) }, limit = 4) {
  const due = new Map<string, number>(), active = new Map<string, AbortController>()
  let timer: number | undefined, closed = false
  function pump() {
    if (timer !== undefined) clock.cancel(timer)
    timer = undefined
    if (closed || !visible()) return
    while (active.size < limit) {
      const next = [...due].filter(([id, at]) => !active.has(id) && at <= clock.now()).sort((a, b) => a[1] - b[1])[0]
      if (!next) break
      const [id] = next, controller = new AbortController()
      active.set(id, controller)
      void Promise.resolve().then(() => read(id, controller.signal)).then(delay => {
        if (active.get(id) === controller && due.has(id)) due.set(id, clock.now() + Math.max(100, delay))
      }, () => {
        if (active.get(id) === controller && due.has(id)) due.set(id, clock.now() + 15000)
      }).finally(() => {
        if (active.get(id) === controller) active.delete(id)
        pump()
      })
    }
    if (active.size < limit) {
      const next = Math.min(...[...due].filter(([id]) => !active.has(id)).map(([, at]) => at))
      if (Number.isFinite(next)) timer = clock.later(pump, Math.max(0, next - clock.now()))
    }
  }
  return {
    setTargets(ids: readonly string[]) {
      const current = new Set(ids)
      for (const id of due.keys()) if (!current.has(id)) {
        due.delete(id); active.get(id)?.abort()
      }
      for (const id of ids) if (!due.has(id)) due.set(id, 0)
      pump()
    },
    resume: pump,
    close() { closed = true; if (timer !== undefined) clock.cancel(timer); for (const controller of active.values()) controller.abort(); active.clear(); due.clear() },
  }
}
