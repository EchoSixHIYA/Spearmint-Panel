import { serviceHealthState, type ServiceHealth } from './service-status.ts'

export type RemoteObservation = {
  status: string
  source: 'process' | 'docker'
  last_status: string | null
  checked_at: number | null
  last_seen_at: number | null
  valid_until: number | null
  stale: boolean
  health?: ServiceHealth
}

export function remoteObservationState(observation: RemoteObservation, directoryStale: boolean, now: number) {
  const stale = directoryStale || observation.stale || observation.valid_until == null
    || observation.valid_until * 1000 <= now
  const health = serviceHealthState(observation.health, stale)
  return { stale, status: stale ? observation.last_status : observation.status, ...(health && { health }) }
}
