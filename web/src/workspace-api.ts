import { ApiError, api, type Session } from './api'
import { useCallback, useEffect, useRef, useState } from 'react'

export function workspace<T>(target: string, session: Session, action: string, body: object = {}, signal?: AbortSignal) {
  return api<T>(`/peers/${target}/workspace/${action}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body),
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(25_000)]) : AbortSignal.timeout(25_000) })
}
export function workspaceError(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === 'NOT_FOUND') return '目标节点或服务已不在当前目录，请刷新后核对。'
    if (error.code === 'UNSUPPORTED_METHOD' || error.status === 404) return '目标节点需要通过 Grove 群组更新升级后使用此功能。'
    if (['OFFLINE', 'NO_ROUTE', 'ROUTE_LOST', 'TIMEOUT'].includes(error.code || '')) return '到目标节点的 Mesh 路径暂时不可用，请稍后刷新。'
    if (error.code === 'DENIED') return '请核对 Grove 登录状态和成员目录同步情况。'
    if (error.code === 'CONFLICT') return '服务或运行状态已变化，请刷新后核对。正在运行的程序需要先停止再取消登记。'
    return error.message
  }
  return '暂未收到目标节点回执，请检查连接后重试。'
}
export function useWorkspace<T>(target: string, session: Session, action: string, body: object,
  onUnauthorized: () => void, interval = 5000) {
  const [sample, setSample] = useState<{ value: T; scope: string }>()
  const [failure, setFailure] = useState<{ text: string; scope: string }>()
  const encoded = JSON.stringify(body), scope = `${target}/${action}/${encoded}`
  const [revision, refresh] = useState(0)
  const reload = useCallback(() => refresh(value => value + 1), [])
  useEffect(() => {
    const controller = new AbortController()
    let timer: number
    async function read() {
      try {
        const value = await workspace<T>(target, session, action, JSON.parse(encoded), controller.signal)
        if (!controller.signal.aborted) { setSample({ value, scope }); setFailure(undefined) }
      } catch (error) {
        if (!controller.signal.aborted) {
          if (error instanceof ApiError && error.status === 401) onUnauthorized()
          setFailure({ text: workspaceError(error), scope })
        }
      } finally { if (!controller.signal.aborted) timer = window.setTimeout(() => void read(), interval) }
    }
    void read()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [target, session, action, encoded, scope, revision, onUnauthorized, interval])
  return { data: sample?.scope === scope ? sample.value : undefined, error: failure?.scope === scope ? failure.text : '', reload }
}
export function returnRoute(fallback = '#/services') {
  const from = new URLSearchParams(location.hash.split('?')[1]).get('from')
  return from?.startsWith('#/') && !from.startsWith('#//') ? from : fallback
}
export function withReturn(route: string, from = location.hash || '#/services') {
  return route + (route.includes('?') ? '&' : '?') + 'from=' + encodeURIComponent(from)
}

type Result = { status: string; id?: string; message?: string | null; updated_at?: number; reason?: string }
type Intent = { key: string; action: string; operation?: Result; request_id?: string; error?: string }
const finished = (intent?: Intent) => !!intent?.operation && ['succeeded', 'failed'].includes(intent.operation.status)

export function useServiceOperation(path: string, session: Session, version: number, changed: () => void) {
  const storage = `spearmint-workspace/${session.csrf_token}/${path}`
  const [intent, setIntent] = useState<Intent | undefined>(() => {
    try { return JSON.parse(sessionStorage.getItem(storage) || 'null') ?? undefined } catch { return undefined }
  })
  const intentRef = useRef(intent), busy = useRef(false), mounted = useRef(true)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  function remember(next?: Intent) {
    intentRef.current = next
    try { if (next) sessionStorage.setItem(storage, JSON.stringify(next)); else sessionStorage.removeItem(storage) } catch { /* The request still has an idempotency key. */ }
    if (mounted.current) setIntent(next)
  }
  function accept(previous: Intent, data: any) {
    if (!data) return
    remember({ ...previous, ...(data.request_id ? { request_id: data.request_id, operation: data.operation ?? { status: 'queued' } }
      : { operation: data }), error: undefined })
    changed()
  }
  async function query() {
    const current = intentRef.current
    if (!current || busy.current) return
    busy.current = true
    try {
      const saved = await api<any>(`${path}/actions/request`, { headers: { 'Idempotency-Key': current.key }, signal: AbortSignal.timeout(25_000) })
      if (saved?.request_id && !saved.pending) {
        const receipt = await api<any>(`${path}/operations/${saved.request_id}`, { signal: AbortSignal.timeout(25_000) })
        accept(current, receipt)
      } else if (saved && !saved.pending) accept(current, saved)
      else remember({ ...current, error: '尚未查到执行回执，已保留原请求。查询不会重新执行操作。' })
    } catch (error) { remember({ ...current, error: workspaceError(error) }) }
    finally { busy.current = false }
  }
  async function submit(action: string) {
    if (busy.current || intentRef.current && !finished(intentRef.current)) return
    const next: Intent = { key: crypto.randomUUID().replaceAll('-', ''), action, operation: { status: 'queued' } }
    remember(next); busy.current = true
    try {
      const result = await api<any>(`${path}/actions?service_version=${version}`, { method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token, 'Idempotency-Key': next.key }, body: JSON.stringify(path.startsWith('/services/') ? { action } : { action, service_version: version }),
        signal: AbortSignal.timeout(50_000) })
      accept(next, result)
    } catch (error) { remember({ ...next, operation: { status: error instanceof ApiError && error.status >= 400 && error.status < 500 ? 'failed' : 'uncertain' }, error: workspaceError(error) }) }
    finally { busy.current = false }
  }
  useEffect(() => {
    if (!intent || finished(intent) || intent.operation?.status === 'uncertain') return
    const timer = window.setInterval(() => void query(), 1800)
    return () => window.clearInterval(timer)
  }, [intent?.key, intent?.operation?.status, path])
  return { intent, submit, query, tracking: !!intent && !finished(intent), clear: () => remember(undefined) }
}
