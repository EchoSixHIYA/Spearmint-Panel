export const connectionLabels = {
  connected: '已连接',
  idle: '按需连接',
  pending: '等待连接',
  unconfigured: '未配置互联',
  observed: '邻居近期可达',
  unreachable: '本机未连通',
  restricted: '停用或隔离',
  unknown: '状态未知',
}

export type ConnectionGroup = keyof typeof connectionLabels

export function connectionGroup(status: string): ConnectionGroup {
  switch (status) {
    case 'online': return 'connected'
    case 'idle': return 'idle'
    case 'connecting':
    case 'reconnecting':
    case 'backoff':
    case 'listening':
    case 'probing': return 'pending'
    case 'unconfigured': return 'unconfigured'
    case 'error':
    case 'offline':
    case 'unreachable': return 'unreachable'
    case 'disabled':
    case 'quarantined': return 'restricted'
    default: return 'unknown'
  }
}

export function reportedPath(currentId: string | undefined, peer: {
  node_id?: string; status: string; direct?: boolean; path?: string[]
}) {
  const { node_id: target, status, path, direct } = peer
  if (!currentId || !target || currentId === target || status !== 'online') return
  if (path === undefined) return direct === true ? [currentId, target] : undefined
  if (Array.isArray(path) && path.length >= 2 && path[0] === currentId && path.at(-1) === target
    && path.every((id) => typeof id === 'string' && id.length > 0) && new Set(path).size === path.length) return path
}

export function pathLabel(path?: readonly string[]) {
  if (path) return path.length === 2 ? '直连' : `${path.length - 1} 跳`
}

export function meshEndpointLabel(address?: string | null, port?: number | null) {
  if (!address) return undefined
  if (!port) return address
  return `${address.includes(':') ? `[${address}]` : address}:${port}`
}

type ConnectionEvidence = {
  status: string
  observations?: readonly { observer_node_id: string }[]
}

export function reachabilityReports({ status, observations }: ConnectionEvidence) {
  const group = connectionGroup(status)
  if (group === 'connected' || group === 'restricted' || group === 'unconfigured' || group === 'unknown') return 0
  return new Set(observations?.map((observation) => observation.observer_node_id)).size
}

export function nodeConnectionGroup(node: ConnectionEvidence): ConnectionGroup {
  const group = connectionGroup(node.status)
  return group === 'unreachable' && reachabilityReports(node) ? 'observed' : group
}

export function countConnections(nodes: readonly ConnectionEvidence[]) {
  const counts = { connected: 0, idle: 0, pending: 0, unconfigured: 0, observed: 0, unreachable: 0, restricted: 0, unknown: 0 }
  for (const node of nodes) counts[nodeConnectionGroup(node)]++
  return counts
}

export function reachabilityLabel(node: ConnectionEvidence) {
  const reports = reachabilityReports(node)
  return reports ? `${reports} 个邻居报告近期可达` : undefined
}
