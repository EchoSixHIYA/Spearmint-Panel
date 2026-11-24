import { useEffect, useMemo, useState } from 'react'
import type { Peer } from './console-data'
import type { NodeDirectory } from './remote-catalog'
import { remoteDirectoryCurrent } from './remote-directory'

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
      services: [...services.values()] }]
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
