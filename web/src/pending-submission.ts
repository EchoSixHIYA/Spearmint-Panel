import { useCallback, useEffect, useState } from 'react'
import { ApiError } from './api'

type Submission = { key: string }
type Decoder<T> = (value: Record<string, unknown> & Submission) => T | undefined
const eventName = 'spearmint:pending-submission'

async function sessionKey(prefix: string, path: string, csrfToken: string) {
  try {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(csrfToken))
    const session = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
    return `${prefix}:${session}:${path}`
  } catch {
    return null
  }
}

function read<T extends Submission>(key: string, decode: Decoder<T>): T | undefined {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) ?? 'null')
    if (typeof value?.key === 'string' && /^[a-f0-9-]{36}$/.test(value.key)) return decode(value)
  } catch {
    // A disabled or invalid store leaves the current view usable.
  }
}

function save<T extends Submission>(key: string, request?: T) {
  try {
    if (request) sessionStorage.setItem(key, JSON.stringify(request))
    else sessionStorage.removeItem(key)
    window.dispatchEvent(new CustomEvent(eventName, { detail: key }))
  } catch {
    // The mounted view can still keep the request in memory.
  }
}

export function usePendingSubmission<T extends Submission>(prefix: string, path: string, csrfToken: string, decode: Decoder<T>) {
  const [pending, setPending] = useState<T>()
  const [storageKey, setStorageKey] = useState<string | null>()
  useEffect(() => {
    let disposed = false
    let key: string | null = null
    function update(event: Event) {
      if (key && (event as CustomEvent<string>).detail === key) setPending(read(key, decode))
    }
    setStorageKey(undefined)
    setPending(undefined)
    void sessionKey(prefix, path, csrfToken).then((value) => {
      if (disposed) return
      key = value
      if (key) setPending(read(key, decode))
      setStorageKey(key)
    })
    window.addEventListener(eventName, update)
    return () => {
      disposed = true
      window.removeEventListener(eventName, update)
    }
  }, [prefix, path, csrfToken, decode])

  function remember(request: T) {
    if (storageKey === undefined) return
    const existing = (storageKey ? read(storageKey, decode) : undefined) ?? pending
    if (existing && existing.key !== request.key) {
      setPending(existing)
      return
    }
    const current = existing ?? request
    setPending(current)
    if (storageKey) save(storageKey, current)
    return current
  }

  const update = useCallback((request: T) => {
    setPending((current) => current?.key === request.key ? request : current)
    if (storageKey && read(storageKey, decode)?.key === request.key) save(storageKey, request)
  }, [storageKey, decode])

  const clear = useCallback((key: string) => {
    setPending((current) => current?.key === key ? undefined : current)
    if (storageKey && read(storageKey, decode)?.key === key) save(storageKey)
  }, [storageKey, decode])

  return { pending, ready: storageKey !== undefined, remember, update, clear }
}

export function uncertainSubmission(error: unknown) {
  return !(error instanceof ApiError) || error.status >= 500 || [408, 425, 429].includes(error.status)
}
