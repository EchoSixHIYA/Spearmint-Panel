import { useLayoutEffect, useRef } from 'react'
import { useConsole, type NodeView } from './console-data'

type SavedNode = { id: string; name: string; depth: number; path?: string[] }
type Snapshot = { version: 1; current: string; realm: string | null; nodes: SavedNode[] }
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
        || !Number.isInteger(node.depth) || node.depth < 0 || node.depth > 512) return
      seen.add(node.id)
      if (node.path && (!Array.isArray(node.path) || node.path.length < 2 || node.path.length > 512
        || node.path[0] !== value.current || node.path.at(-1) !== node.id
        || node.path.some(id => !nodeId.test(id)) || new Set(node.path).size !== node.path.length)) return
    }
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
  if ((local.data && previous?.current !== local.data.node_id) || (realmKnown && previous?.realm !== realm)) previous = undefined
  const current = local.data?.node_id ?? previous?.current
  const authoritative = directoryCurrent || (grove.data?.configured === false && !grove.error && meshCurrent)
  const live = new Map(listedNodes.map(node => [node.id, node]))
  const allowed = new Set(live.keys())
  const saved = new Map((previous?.nodes ?? []).filter(node => !authoritative || allowed.has(node.id)).map(node => [node.id, node]))
  const ids = [...new Set([...saved.keys(), ...live.keys()])]
  const nodes: NodeView[] = ids.map(id => {
    const cached = saved.get(id), actual = live.get(id)
    if (actual) return { ...actual, name: nodeNotesCurrent ? actual.name : cached?.name ?? actual.name }
    return { id, name: cached!.name, local: id === current, status: 'unknown', observations: [] }
  })
  const paths = new Map<string, string[]>()
  const depths = new Map<string, number>()
  const stored: SavedNode[] = nodes.map(node => {
    const cached = saved.get(node.id)
    const path = node.activePath ?? (cached?.path && (!authoritative || cached.path.every(id => allowed.has(id))) ? cached.path : undefined)
    const depth = node.local ? 0 : path ? path.length - 1 : cached?.depth ?? 1
    if (path) paths.set(node.id, path)
    depths.set(node.id, depth)
    return { id: node.id, name: node.name, depth, ...(path && { path }) }
  })
  const snapshot: Snapshot | undefined = current && nodes.some(node => node.id === current)
    ? { version: 1, current, realm: realmKnown ? realm : previous?.realm ?? realm, nodes: stored } : undefined
  const raw = snapshot && JSON.stringify(snapshot)
  useLayoutEffect(() => {
    if (!snapshot || !raw) return
    const changed = memory.current?.key !== key || memory.current?.raw !== raw
    memory.current = { key, snapshot, raw }
    if (changed && raw.length <= 2_000_000) {
      try { localStorage.setItem(key, raw) } catch { /* The live graph also works without browser storage. */ }
    }
  }, [key, raw])
  return { nodes, current: nodes.find(node => node.local), paths, depths }
}
