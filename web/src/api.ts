export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly code?: string, readonly serviceId?: string) {
    super(message)
  }
}

export type Session = { username: string; csrf_token: string; role?: 'node_admin' | 'remote_operator'; grove?: boolean; display_name?: string }

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { ...init, credentials: 'same-origin', cache: 'no-store' })
  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    throw new ApiError(response.status, typeof payload?.detail === 'string' ? payload.detail : '请求失败', payload?.code,
      typeof payload?.service_id === 'string' ? payload.service_id : undefined)
  }
  return response.status === 204 ? (undefined as T) : response.json()
}
import { useEffect, useState } from 'react'

export const READ_TIMEOUT_MS = 25_000

export function timestamp(value: number | null) {
  return value === null ? '等待采样' : new Date(value * 1000).toLocaleString()
}

type PollOptions = { foregroundOnly?: boolean; busyRetryMs?: number }

export function usePoll<T>(path: string | null, onUnauthorized: () => void, interval = 3000, headers?: HeadersInit, scope?: string,
  { foregroundOnly = false, busyRetryMs }: PollOptions = {}) {
  const [sample, setSample] = useState<{ data: T; requestedAt: number; path: string; headers?: HeadersInit; scope?: string }>()
  const [failure, setFailure] = useState<{ message: string; code?: string; status?: number; path: string; headers?: HeadersInit; scope?: string }>()
  useEffect(() => {
    setSample(undefined)
    setFailure(undefined)
    if (path === null) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let running = false
    let refreshPending = false
    let nextPollAt = 0

    function canPoll() {
      return !running && !controller.signal.aborted && (!foregroundOnly || document.visibilityState === 'visible')
    }

    function schedule() {
      clearTimeout(timer)
      if (!canPoll()) return
      const remaining = nextPollAt - performance.now()
      if (remaining > 0) timer = setTimeout(schedule, remaining)
      else void poll()
    }

    async function poll() {
      if (!canPoll()) return
      running = true
      clearTimeout(timer)
      let delay = interval
      const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
      try {
        const requestedAt = performance.now()
        const value = await api<T>(path!, { signal: AbortSignal.any([controller.signal, deadline]), headers })
        if (!controller.signal.aborted) {
          setSample({ data: value, requestedAt, path: path!, headers, scope })
          setFailure(undefined)
        }
      } catch (error) {
        if (controller.signal.aborted) return
        if (error instanceof ApiError && error.status === 401) onUnauthorized()
        else {
          const busy = error instanceof ApiError && error.status === 429 && busyRetryMs !== undefined
          if (busy) delay = Math.max(interval, busyRetryMs)
          const message = busy ? '请求暂时繁忙，稍后自动重试。'
            : deadline.aborted ? '读取超时，稍后自动重试。' : error instanceof Error ? error.message : '读取失败'
          const failedResponse = error instanceof ApiError ? error : undefined
          setFailure({ message, code: failedResponse?.code, status: failedResponse?.status, path: path!, headers, scope })
        }
      } finally {
        running = false
        if (!controller.signal.aborted) {
          // A refresh requested during this read may follow a change the response did not include.
          nextPollAt = performance.now() + (refreshPending ? 0 : delay)
          refreshPending = false
          schedule()
        }
      }
    }
    const refresh = () => {
      if (foregroundOnly || busyRetryMs !== undefined) schedule()
      else if (running) refreshPending = true
      else void poll()
    }
    window.addEventListener('spearmint:refresh', refresh)
    if (foregroundOnly) document.addEventListener('visibilitychange', schedule)
    refresh()
    return () => {
      controller.abort()
      clearTimeout(timer)
      window.removeEventListener('spearmint:refresh', refresh)
      if (foregroundOnly) document.removeEventListener('visibilitychange', schedule)
    }
  }, [path, onUnauthorized, interval, headers, scope, foregroundOnly, busyRetryMs])
  const current = sample && sample.path === path && sample.headers === headers && sample.scope === scope ? sample : undefined
  const currentFailure = failure && failure.path === path && failure.headers === headers && failure.scope === scope ? failure : undefined
  return { data: current?.data, requestedAt: current?.requestedAt, error: currentFailure?.message ?? '',
    errorCode: currentFailure?.code, errorStatus: currentFailure?.status }
}
