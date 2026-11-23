import { useLayoutEffect, useRef } from 'react'
import { useConsole, type NodeView } from './console-data'
import { shortId } from './ui'
import { isNodeIcon, isNodeType, type NodeIcon, type NodeType } from './node-types'

export type RememberedEdge = { from: string; to: string; owners: string[] }
type SavedNode = { id: string; name: string; depth: number; path?: string[]; relay?: true; nodeType?: NodeType; icon?: NodeIcon }
type Snapshot = { version: 1; current: string; realm: string | null; realmKnown?: boolean; nodes: SavedNode[]; edges?: RememberedEdge[] }
const nodeId = /^spm1-[a-f0-9]{64}$/

function read(key: string): Snapshot | undefined {
  try {
    const raw = localStorage.getItem(key)
    if (!raw || raw.length > 2_000_000) return
    const value = JSON.parse(raw) as Snapshot
    if (value.version !== 1 || !nodeId.test(value.current) || !(value.realm === null || typeof value.realm === 'string')
      || !Array.isArray(value.nodes) || value.nodes.length > 4096) return
    const seen = new Set<string>()
    for (const node of value.nodes) {
      if (!nodeId.test(node.id) || seen.has(node.id) || typeof node.name !== 'string' || node.name.length > 160
        || !Number.isInteger(node.depth) || node.depth < 0 || node.depth > 512 || (node.relay !== undefined && node.relay !== true)) return
      if (node.nodeType !== undefined && !isNodeType(node.nodeType) || node.icon !== undefined && !isNodeIcon(node.icon)) return
      seen.add(node.id)
      if (node.path && (!Array.isArray(node.path) || node.path.length < 2 || node.path.length > 512
        || node.path[0] !== value.current || node.path.at(-1) !== node.id
        || node.path.some(id => !nodeId.test(id)) || new Set(node.path).size !== node.path.length)) return
    }
    if (value.realmKnown !== undefined && typeof value.realmKnown !== 'boolean') return
    if (value.edges !== undefined && (!Array.isArray(value.edges) || value.edges.length > 65536 || value.edges.some(edge =>
      !nodeId.test(edge.from) || !nodeId.test(edge.to) || edge.from === edge.to || !Array.isArray(edge.owners)
      || edge.owners.length > 4096 || edge.owners.some(id => !seen.has(id))))) return
    if (seen.has(value.current)) return value
  } catch { /* A missing or unavailable display cache must not block the live graph. */ }
}

/** A display-only snapshot. Cached nodes never carry live status, peer configuration, or permissions. */
export function useNetworkMemory() {
  const { listedNodes, local, grove, directoryCurrent, meshCurrent, session, nodeNotesCurrent } = useConsole()
  const key = `spearmint-network-v1:${JSON.stringify([session.username, session.role ?? 'node_admin'])}`
  const memory = useRef<{ key: string; snapshot?: Snapshot; raw?: string } | null>(null)
  if (!memory.current) memory.current = { key, snapshot: read(key) }
  let previous = memory.current.key === key ? memory.current.snapshot : read(key)
  const realmKnown = !!grove.data && !grove.error
  const realm = grove.data?.realm?.id ?? null
  const previousRealmKnown = previous?.realmKnown ?? previous?.realm != null
  if ((local.data && previous?.current !== local.data.node_id) || (realmKnown && previousRealmKnown && previous?.realm !== realm)) previous = undefined
  const current = local.data?.node_id ?? previous?.current
  const authoritative = directoryCurrent || (grove.data?.configured === false && !grove.error && meshCurrent)
  const live = new Map(listedNodes.map(node => [node.id, node]))
  const allowed = new Set(live.keys())
  const removed = new Set((previous?.nodes ?? []).filter(node => authoritative && !node.relay && !allowed.has(node.id)).map(node => node.id))
  const saved = new Map((previous?.nodes ?? []).filter(node => !removed.has(node.id)).map(node => [node.id, node]))
  const ids = [...new Set([...saved.keys(), ...live.keys()])]
  let nodes: NodeView[] = ids.map(id => {
    const cached = saved.get(id), actual = live.get(id)
    if (actual) return { ...actual, name: nodeNotesCurrent ? actual.name : cached?.name ?? actual.name,
      nodeType: nodeNotesCurrent ? actual.nodeType : cached?.nodeType ?? actual.nodeType,
      icon: nodeNotesCurrent ? actual.icon : cached?.icon ?? actual.icon }
    return { id, name: cached!.name, nodeType: cached?.nodeType, icon: cached?.icon, local: id === current, status: 'unknown', observations: [] }
  })
  const paths = new Map<string, string[]>()
  const depths = new Map<string, number>()
  for (const node of nodes) {
    const cached = saved.get(node.id)
    const path = node.activePath ?? (cached?.path && !cached.path.some(id => removed.has(id)) ? cached.path : undefined)
    const depth = node.local ? 0 : path ? path.length - 1 : cached?.depth ?? 1
    if (path) paths.set(node.id, path)
    depths.set(node.id, depth)
  }
  const edges = new Map<string, RememberedEdge>()
  function remember(from: string, to: string, owners: string[]) {
    if (removed.has(from) || removed.has(to) || !owners.length) return
    const key = [from, to].sort().join('/')
    const old = edges.get(key)
    edges.set(key, { from: old?.from ?? from, to: old?.to ?? to, owners: [...new Set([...(old?.owners ?? []), ...owners])] })
  }
  for (const edge of previous?.edges ?? []) {
    remember(edge.from, edge.to, edge.owners.filter(id => saved.has(id) && !live.get(id)?.activePath))
  }
  for (const [owner, path] of paths) for (let depth = 1; depth < path.length; depth++) {
    remember(path[depth - 1], path[depth], [owner])
    if (!depths.has(path[depth])) depths.set(path[depth], saved.get(path[depth])?.depth ?? depth)
  }
  const endpoints = new Set([...edges.values()].flatMap(edge => [edge.from, edge.to]))
  nodes = nodes.filter(node => !saved.get(node.id)?.relay || live.has(node.id) || endpoints.has(node.id))
  const plotted = new Set(nodes.map(node => node.id))
  for (const id of endpoints) if (!plotted.has(id)) {
    nodes.push({ id, name: saved.get(id)?.name ?? shortId(id), local: id === current, status: 'unknown', observations: [] })
    if (!depths.has(id)) depths.set(id, saved.get(id)?.depth ?? 1)
  }
  const stored: SavedNode[] = nodes.map(node => {
    const path = paths.get(node.id)
    return { id: node.id, name: node.name, nodeType: node.nodeType, icon: node.icon, depth: depths.get(node.id) ?? 1, ...(path && { path }), ...(!live.has(node.id) && (saved.get(node.id)?.relay || !saved.has(node.id)) && { relay: true as const }) }
  })
  const snapshot: Snapshot | undefined = current && nodes.some(node => node.id === current)
    ? { version: 1, current, realm: realmKnown ? realm : previous?.realm ?? realm, realmKnown: realmKnown || (previous?.realmKnown ?? previous?.realm != null), nodes: stored, edges: [...edges.values()] } : undefined
  const raw = snapshot && JSON.stringify(snapshot)
  useLayoutEffect(() => {
    if (!snapshot || !raw) return
    const changed = memory.current?.key !== key || memory.current?.raw !== raw
    memory.current = { key, snapshot, raw }
    if (changed && raw.length <= 2_000_000) {
      try { localStorage.setItem(key, raw) } catch { /* The live graph also works without browser storage. */ }
    }
  }, [key, raw])
  return { nodes, current: nodes.find(node => node.local), paths, depths, edges: [...edges.values()] }
}
