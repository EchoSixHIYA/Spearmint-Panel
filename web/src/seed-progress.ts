import type { NodeView } from './console-data'
import type { GroveInfo } from './grove-auth'
import { memberPanelOrigin } from './grove-directory.ts'
import { remoteDirectoryCurrent } from './remote-directory.ts'

type SeedNode = Pick<NodeView, 'id' | 'local' | 'activePath' | 'status' | 'peer'>
type SeedRoster = { directoryCurrent: boolean; members?: GroveInfo['members'] }

export function seedMembership(origin: string, roster: SeedRoster, expectedNodeId?: string) {
  if (!roster.directoryCurrent || !roster.members) return { status: 'directory-unavailable' } as const
  const matches = roster.members.filter((member) => memberPanelOrigin(member.origin) === origin)
  if (expectedNodeId) {
    const expected = roster.members.find((member) => member.node_id === expectedNodeId)
    if (expected && memberPanelOrigin(expected.origin) === origin) {
      return expected.enabled ? { status: 'approved', id: expectedNodeId } as const : { status: 'member-disabled' } as const
    }
    if (expected || matches.length) {
      return { status: 'identity-mismatch' } as const
    }
  } else {
    const active = matches.filter((member) => member.enabled)
    if (active.length > 1) return { status: 'ambiguous-origin' } as const
    if (active.length === 1) return { status: 'approved', id: active[0].node_id } as const
    if (matches.length) return { status: 'member-disabled' } as const
  }
  return { status: 'awaiting-member' } as const
}

export function seedProgress(origin: string, roster: SeedRoster, nodes: readonly SeedNode[],
  directories: ReadonlyMap<string, { stale: boolean; connection_id?: string | null; directory_generation?: number | null;
    services: readonly unknown[] }>,
  catalogError: boolean, expectedNodeId?: string) {
  const membership = seedMembership(origin, roster, expectedNodeId)
  if (membership.status !== 'approved') return membership
  const { id } = membership
  const node = nodes.find((item) => item.id === id)
  if (node?.local) return { status: 'local', id } as const
  if (!node || node.status === 'unknown') return { status: 'mesh-unavailable', id } as const
  if (node.status === 'unconfigured') return { status: 'mesh-unconfigured', id } as const
  if (node.status === 'disabled' || node.status === 'quarantined') return { status: 'mesh-restricted', id } as const
  if (node.status === 'idle') return { status: 'mesh-idle', id } as const
  if (node.status !== 'online' || !node.activePath) return { status: 'awaiting-path', id } as const

  const hops = node.activePath.length - 1
  const directory = directories.get(id)
  if (catalogError || !directory || !remoteDirectoryCurrent(node, directory)) return { status: 'awaiting-catalog', id, hops } as const
  return { status: 'ready', id, hops, services: directory.services.length } as const
}
