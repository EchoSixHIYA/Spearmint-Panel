import type { NodeView } from './console-data'

export function directoryScope(connectionId?: string, generation?: number) {
  return generation === undefined ? connectionId : `${connectionId ?? ''}/${generation}`
}

export function directoryQuery(connectionId?: string, generation?: number) {
  if (!connectionId) return ''
  const query = new URLSearchParams({ connection_id: connectionId })
  if (generation !== undefined) query.set('directory_generation', String(generation))
  return query.toString()
}

export function remoteDirectoryCurrent(node: Pick<NodeView, 'status' | 'peer'>,
  directory?: { stale: boolean; catalog_complete?: boolean; connection_id?: string | null; directory_generation?: number | null }) {
  return node.status === 'online' && node.peer?.directory_ready !== false && directory?.stale === false && directory.catalog_complete !== false
    && node.peer?.connection_id === (directory.connection_id ?? undefined)
    && node.peer?.directory_generation === (directory.directory_generation ?? undefined)
}
