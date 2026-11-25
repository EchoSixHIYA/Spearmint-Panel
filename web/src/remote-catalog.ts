import { useEffect, useState } from 'react'
import { useConsole } from './console-data'
import type { RemoteObservation } from './remote-observation'
import type { Action } from './services'
import type { ServiceGroup } from './service-groups'
import { remoteDirectoryCurrent } from './remote-directory'

export { remoteDirectoryCurrent } from './remote-directory'

export type RemoteService = {
  id: string
  name: string
  driver: 'process' | 'docker'
  version: number
  status: boolean
  logs: boolean
  actions: Action[]
  observation: RemoteObservation | null
}

export type RemoteDirectory = { stale: boolean; catalog_complete?: boolean; connection_id?: string | null; directory_generation?: number | null;
  services: RemoteService[]; service_groups?: ServiceGroup[] }
export type NodeDirectory = RemoteDirectory & { node_id: string }

export function useRemoteObservationTime(observations: readonly (RemoteObservation | null | undefined)[]) {
  const [, refresh] = useState(0)
  const now = Date.now()
  let nextExpiry = Infinity
  for (const observation of observations) {
    if (observation?.stale !== false || observation.valid_until == null) continue
    const expiry = observation.valid_until * 1000
    if (expiry > now) nextExpiry = Math.min(nextExpiry, expiry)
  }
  useEffect(() => {
    if (!Number.isFinite(nextExpiry)) return
    const timer = setTimeout(() => refresh((value) => value + 1),
      Math.min(2_147_483_647, Math.max(0, nextExpiry - Date.now())))
    return () => clearTimeout(timer)
  }, [nextExpiry, now])
  return now
}

export function useRemoteCatalog() {
  const { nodes, remoteCatalog: { data, error } } = useConsole()
  const directories = new Map(data?.map((directory) => [directory.node_id, directory]))
  const entries = nodes.filter((node) => !node.local).flatMap((node) => {
    const directory = directories.get(node.id)
    if (!directory || !node.peer?.enabled || node.status === 'quarantined' || node.status === 'disabled') return []
    const stale = !remoteDirectoryCurrent(node, directory) || !!error
    return directory.services.map((service) => ({ node, service, stale }))
  })
  return { data, error, entries, directories }
}
