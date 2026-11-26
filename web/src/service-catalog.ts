import { useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError, type Session } from './api'
import type { Peer } from './console-data'
import type { NodeDirectory } from './remote-catalog'
import { remoteDirectoryCurrent } from './remote-directory'
import { resourcePoll } from './node-resource-poll'

export function useRemoteDirectoryReads(peers: Peer[] | undefined, session: Session, onUnauthorized: () => void, scope: string) {
  const targets = JSON.stringify((peers ?? []).filter(peer => peer.node_id && peer.enabled && peer.status === 'online'
    && peer.directory_ready !== false).map(peer => peer.node_id!))
  const ids = useRef<string[]>([]), polling = useRef<ReturnType<typeof resourcePoll> | null>(null)
  ids.current = JSON.parse(targets)
  const [snapshot, setSnapshot] = useState<{ scope: string; data: NodeDirectory[]; requestedAt: number }>()
  useEffect(() => {
    let stopped = false
    const poll = resourcePoll(async (id, signal) => {
      const requestedAt = performance.now()
      let directory: NodeDirectory
      try {
        directory = await api<NodeDirectory>(`/peers/${id}/services`, { signal: AbortSignal.any([signal, AbortSignal.timeout(25_000)]) })
        if (directory.node_id !== id) throw new Error('No matching service directory')
      } catch (error) {
        if (stopped || signal.aborted) return 5000
        if (error instanceof ApiError && error.status === 401) onUnauthorized()
        setSnapshot(previous => previous?.scope === scope ? { ...previous, data: previous.data.map(entry =>
          entry.node_id === id ? { ...entry, stale: true, catalog_complete: false } : entry) } : previous)
        return 5000
      }
      if (!stopped && !signal.aborted) setSnapshot(previous => {
        const entries = new Map((previous?.scope === scope ? previous.data : []).map(entry => [entry.node_id, entry]))
        entries.set(id, directory)
        return { scope, data: [...entries.values()], requestedAt }
      })
      return 5000
    }, () => document.visibilityState === 'visible', undefined, 2)
    polling.current = poll; poll.setTargets(ids.current)
    document.addEventListener('visibilitychange', poll.resume)
    return () => { stopped = true; poll.close(); polling.current = null; document.removeEventListener('visibilitychange', poll.resume) }
  }, [scope, session, onUnauthorized])
  useEffect(() => { polling.current?.setTargets(ids.current) }, [targets])
  return { data: snapshot?.scope === scope ? snapshot.data : undefined,
    requestedAt: snapshot?.scope === scope ? snapshot.requestedAt : undefined, error: '' }
}

// Keep display rows across path changes. Only a complete, current directory may
// remove services; retained rows never certify a new session's control rights.
export function retainServiceCatalog(previous: readonly NodeDirectory[], incoming: readonly NodeDirectory[], peers: readonly Peer[]) {
  const before = new Map(previous.map(directory => [directory.node_id, directory]))
  const next = new Map(incoming.map(directory => [directory.node_id, directory]))
  return peers.flatMap(peer => {
    if (!peer.node_id || !peer.enabled || ['quarantined', 'disabled'].includes(peer.status)) return []
    const directory = next.get(peer.node_id)
    if (directory && remoteDirectoryCurrent({ status: peer.status, peer }, directory)) return [directory]
    const cached = before.get(peer.node_id)
    if (!directory && !cached) return []
    const services = new Map(cached?.services.map(service => [service.id, service]))
    for (const service of directory?.services ?? []) services.set(service.id, service)
    return [{ ...(directory ?? cached!), node_id: peer.node_id, stale: true, catalog_complete: false,
      catalog_read_only: directory?.catalog_read_only ?? cached?.catalog_read_only,
      services: [...services.values()], service_groups: directory?.service_groups ?? cached?.service_groups }]
  })
}

export function useServiceCatalog(data: NodeDirectory[] | undefined, peers: Peer[] | undefined, scope?: string) {
  const [retained, setRetained] = useState<{ scope?: string; data: NodeDirectory[] }>({ scope, data: [] })
  const catalog = useMemo(() => retainServiceCatalog(retained.scope === scope ? retained.data : [], data ?? [], peers ?? []),
    [data, peers, scope, retained])
  useEffect(() => {
    setRetained(previous => ({ scope, data: retainServiceCatalog(previous.scope === scope ? previous.data : [], data ?? [], peers ?? []) }))
  }, [data, peers, scope])
  return data === undefined && !catalog.length ? undefined : catalog
}
