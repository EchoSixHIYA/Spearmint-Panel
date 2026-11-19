import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { type Session, usePoll } from './api'
import type { Service } from './services'
import type { NodeDirectory } from './remote-catalog'
import { shortId } from './ui'
import type { GroveInfo } from './grove-auth'
import { connectionGroup, countConnections, reachabilityLabel, reportedPath } from './connection-status'
import { groveDirectory } from './grove-directory'
import type { DeploymentHost } from './release-compatibility'
import { localServiceAlerts, remoteServiceAlerts, type ConsoleAlert } from './service-alerts'
import { hostResourceAlerts } from './host-resources'

export type Platform = { os: string; architecture: string; process_backend: string; docker: string; file_security: string }
export type NodeInfo = { node_id: string; platform?: Platform; deployment_host?: DeploymentHost; package_checksums_sha256?: string; build?: {
  version: string | null; commit: string | null; runtime: 'native' | 'python'
} }
export type LocalQuarantine = { recorded_at: number; reason: string }
export type PeerReputation = {
  state: 'normal' | 'suspected'; invalid_requests: number; limited_requests: number; in_flight: number
  restriction_seconds: number; last_invalid_method: string | null
  quotas: Record<'logs' | 'evidence', { limit: number; remaining: number }>
}
export type RouteObservation = {
  observer_node_id: string; method: 'local' | 'direct'; age_seconds: number; remaining_seconds: number
}
export type IdlePath = { path: string[]; age_seconds: number; remaining_seconds: number }
type RouteSession = {
  path: string[]; role: string; connection_generation: string; cost_ms: number | null
  directory_prepared?: boolean
  directory_prepared_remaining_seconds?: number
  rtt_ewma_ms?: number | null; rtt_sample_count?: number; rtt_sample_age_seconds?: number | null; rtt_fresh?: boolean
  rtt_remaining_seconds?: number
  handshake_ms?: number | null
}
export type RouteDiagnostics = {
  selected_path: string[] | null; switch_reason: string | null; switches: number
  backup_sessions: number; candidate_sessions: RouteSession[]
  comparison?: { path: string[]; completed: number; required: number; dwell_remaining_seconds: number; remaining_seconds?: number } | null
  best_alternative?: { path: string[]; saving_ms: number; required_saving_ms: number; meets_threshold: boolean; remaining_seconds?: number } | null
  preparing_switch?: boolean; last_path_error?: string | null
  deferred_switch?: { reason: string; remaining_seconds: number } | null
  opening_trial?: boolean
  waiting_for_trial?: boolean
  last_idle_path?: IdlePath | null
  pending_requests?: number; observations?: RouteObservation[]
}
export type NeighborUse = {
  role: 'fixed' | 'trial' | 'automatic' | 'candidate'; connected: boolean; qualified: boolean
  protected_by: string[]; retry_seconds: number
}
export type Peer = {
  node_id?: string; status: string; host?: string; display_host?: string; source_ip?: string | null; enabled?: boolean; mesh_id?: string; direct?: boolean; hops?: number
  path?: string[]; next_hop?: string; tls?: string; rtt_ms?: number | null; connected_at?: number; connected_ip?: string
  automatic_endpoint?: [string, number] | null
  fingerprint?: string; legacy?: boolean; routed?: boolean; port?: number; reconnects?: number; detail?: string
  local_quarantine?: LocalQuarantine | null
  local_reputation?: PeerReputation
  route_diagnostics?: RouteDiagnostics; observations?: RouteObservation[]; directory_ready?: boolean; connection_id?: string;
  directory_generation?: number; neighbor_use?: NeighborUse
}
export type Metrics = {
  sampled_at: number | null; valid_until: number | null; stale: boolean; cpu_percent: number | null
  memory: { total: number; available: number } | null
  root_disk: { total: number; used: number; free: number; percent: number } | null
  state_disk: { total: number; used: number; free: number; percent: number } | null
  state_disk_is_root?: boolean | null
  gpu?: { sampled_at: number | null; valid_until: number | null; status: 'available' | 'unavailable'; stale?: boolean;
    devices: { id: string; name: string; utilization_percent: number | null; memory_used_bytes: number | null; memory_total_bytes: number | null }[] }
  network: { received_per_second: number; sent_per_second: number } | null; uptime_seconds: number | null
}
export type AuditEntry = { id: number; recorded_at: number; actor: string; source: string; event: string; target: string | null; reason?: string | null; count?: number }
export type NodeView = {
  id: string; name: string; local: boolean; status: string; observations: RouteObservation[]
  activePath?: string[]; idlePath?: IdlePath; peer?: Peer; memberOrigin?: string
}

function usePeerEvidence(peers: Pick<ReturnType<typeof usePoll<Peer[]>>, 'data' | 'requestedAt' | 'error'>) {
  const [, expire] = useState(0)
  const evidence = new Map<string, Pick<NodeView, 'observations' | 'idlePath' | 'peer'>>()
  const now = performance.now()
  let expiresAt = Infinity
  if (!peers.error && peers.requestedAt !== undefined) {
    const requestedAt = peers.requestedAt
    function remaining(seconds: number) {
      const deadline = requestedAt + seconds * 1000
      if (!Number.isFinite(deadline) || deadline <= now) return 0
      expiresAt = Math.min(expiresAt, deadline)
      return (deadline - now) / 1000
    }
    function live<T extends { remaining_seconds?: number }>(record?: T | null) {
      return record?.remaining_seconds !== undefined && !remaining(record.remaining_seconds) ? null : record
    }
    function current<T extends { age_seconds: number; remaining_seconds: number }>(record: T): T | undefined {
      const seconds = remaining(record.remaining_seconds)
      if (!seconds) return
      return { ...record, age_seconds: record.age_seconds + (now - requestedAt) / 1000,
        remaining_seconds: seconds }
    }
    for (const peer of peers.data || []) {
      if (!peer.node_id || ['unknown', 'disabled', 'quarantined'].includes(peer.status)) continue
      const records: RouteObservation[] = []
      for (const observation of peer.observations ?? peer.route_diagnostics?.observations ?? []) {
        const report = current(observation)
        if (report) records.push(report)
      }
      const diagnostics = peer.route_diagnostics
      const lastPath = diagnostics?.last_idle_path
      const sessions = diagnostics?.candidate_sessions?.map(route => {
        const directorySeconds = route.directory_prepared === true && route.directory_prepared_remaining_seconds !== undefined
          ? remaining(route.directory_prepared_remaining_seconds) : undefined
        const rttExpired = route.rtt_fresh === true && route.rtt_remaining_seconds !== undefined && !remaining(route.rtt_remaining_seconds)
        return { ...route, ...(directorySeconds !== undefined && { directory_prepared: directorySeconds > 0,
          directory_prepared_remaining_seconds: directorySeconds }), ...(rttExpired && { rtt_fresh: false, cost_ms: null }) }
      })
      const currentPeer = diagnostics && sessions ? { ...peer, route_diagnostics: { ...diagnostics, candidate_sessions: sessions,
        comparison: live(diagnostics.comparison), best_alternative: live(diagnostics.best_alternative),
        deferred_switch: live(diagnostics.deferred_switch) } } : peer
      evidence.set(peer.node_id, { observations: records, idlePath: lastPath ? current(lastPath) : undefined, peer: currentPeer })
    }
  }
  useEffect(() => {
    if (!Number.isFinite(expiresAt)) return
    const timer = setTimeout(() => expire((count) => count + 1), Math.max(0, Math.ceil(expiresAt - performance.now())))
    return () => clearTimeout(timer)
  }, [expiresAt])
  return evidence
}

export type Preferences = { grove: string; localName: string; compact: boolean; nodeNotes: Record<string, string> }
export const defaultPreferences: Preferences = { grove: '我的 Grove', localName: '本机节点', compact: false, nodeNotes: {} }

export function usePreferences() {
  const [preferences, setPreferences] = useState<Preferences>(() => {
    try {
      const value = JSON.parse(localStorage.getItem('spearmint-display') || '{}')
      const notes = value.nodeNotes && typeof value.nodeNotes === 'object' ? Object.entries(value.nodeNotes) : []
      const nodeNotes = Object.fromEntries(notes.flatMap(([id, note]) =>
        /^spm1-[a-f0-9]{64}$/.test(id) && typeof note === 'string' && note.trim() ? [[id, note.trim().slice(0, 80)]] : []))
      return { grove: typeof value.grove === 'string' && value.grove.trim() ? value.grove.slice(0, 40) : defaultPreferences.grove,
        localName: typeof value.localName === 'string' && value.localName.trim() ? value.localName.slice(0, 40) : defaultPreferences.localName,
        compact: value.compact === true, nodeNotes }
    } catch { return defaultPreferences }
  })
  function save(value: Preferences) {
    localStorage.setItem('spearmint-display', JSON.stringify(value))
    setPreferences(value)
  }
  return { preferences, save }
}

function useConsoleData(session: Session, onUnauthorized: () => void, preferences: Preferences) {
  const admin = session.role !== 'remote_operator'
  const local = usePoll<NodeInfo>('/node', onUnauthorized)
  const grove = usePoll<GroveInfo>('/auth/grove/info', onUnauthorized)
  const realmId = grove.data?.realm?.id
  const sharedNotes = usePoll<Record<string, string>>(realmId ? '/grove/node-notes' : null, onUnauthorized, 3000, undefined, realmId)
  const nodeNotes = realmId ? sharedNotes.data ?? {} : preferences.nodeNotes
  const roster = usePoll<GroveInfo>(admin && grove.data?.configured ? '/grove' : null, onUnauthorized, 15000, undefined, realmId)
  const directory = groveDirectory(grove, roster, admin)
  const [, refreshDirectory] = useState(0)
  useEffect(() => {
    if (directory.directoryExpiresAt === undefined) return
    const timer = setTimeout(() => refreshDirectory((value) => value + 1), Math.max(0, directory.directoryExpiresAt - Date.now()))
    return () => clearTimeout(timer)
  }, [directory.directoryExpiresAt])
  const mesh = usePoll<{ peers: Peer[]; directories: NodeDirectory[] }>(admin ? '/mesh/overview' : null, onUnauthorized)
  const peers = { data: mesh.data?.peers, requestedAt: mesh.requestedAt, error: mesh.error }
  const remoteCatalog = { data: mesh.data?.directories, requestedAt: mesh.requestedAt, error: mesh.error }
  const peerEvidence = usePeerEvidence(peers)
  const services = usePoll<Service[]>(admin ? '/services' : null, onUnauthorized)
  const metrics = usePoll<Metrics>(admin ? '/metrics' : null, onUnauthorized)
  const audit = usePoll<AuditEntry[]>(admin ? '/audit?limit=100' : null, onUnauthorized)
  const meshFailure = peers.data?.find((peer) => !peer.node_id && peer.status === 'error')
  const peerError = peers.error || (meshFailure ? meshFailure.detail || 'Mesh 状态暂时不可用。' : '')
  const meshError = local.error || peerError
  const meshCurrent = !meshError && !!local.data && !!peers.data
  const meshLoading = !meshError && (!local.data || !peers.data)
  const inventory = new Map<string, NodeView>()
  if (local.data) inventory.set(local.data.node_id, { id: local.data.node_id,
    name: nodeNotes[local.data.node_id] || (realmId ? shortId(local.data.node_id) : preferences.localName), local: true,
    status: local.error ? 'unknown' : 'online', observations: [] })
  for (const peer of peers.data || []) if (peer.node_id) inventory.set(peer.node_id, { id: peer.node_id,
    name: nodeNotes[peer.node_id] || shortId(peer.node_id), local: false, status: meshCurrent ? peer.status : 'unknown',
    activePath: meshCurrent ? reportedPath(local.data?.node_id, peer) : undefined,
    peer, ...((meshCurrent ? peerEvidence.get(peer.node_id) : undefined) ?? { observations: [] }) })
  const memberNodes: NodeView[] = []
  for (const member of directory.members || []) {
    if (!member.enabled) continue
    const existing = inventory.get(member.node_id)
    const name = existing?.name || nodeNotes[member.node_id] || shortId(member.node_id)
    const node: NodeView = existing ? { ...existing, name, memberOrigin: member.origin } : {
      id: member.node_id, name, local: false, status: directory.directoryCurrent && meshCurrent ? 'unconfigured' : 'unknown',
      observations: [], memberOrigin: member.origin,
    }
    inventory.set(node.id, node)
    memberNodes.push(node)
  }
  const listedNodes = [...inventory.values()]
  const localName = local.data ? inventory.get(local.data.node_id)?.name ?? preferences.localName : preferences.localName
  const nodes = listedNodes.filter((node) => node.local || node.peer)
  const [, expireAlerts] = useState(0)
  const now = Date.now()
  const remoteAlerts = meshCurrent ? remoteServiceAlerts(inventory, remoteCatalog.data ?? [], now) : []
  const resourceAlerts = local.data && !local.error && !metrics.error
    ? hostResourceAlerts(metrics.data, local.data.node_id, localName, now) : []
  const metricsExpiry = (metrics.data?.valid_until ?? 0) * 1000
  const nextAlertExpiry = remoteAlerts.reduce((next, alert) => Math.min(next, (alert.validUntil ?? Infinity) * 1000),
    metricsExpiry > now && !metrics.error ? metricsExpiry : Infinity)
  useEffect(() => {
    if (!Number.isFinite(nextAlertExpiry)) return
    const timer = setTimeout(() => expireAlerts((count) => count + 1),
      Math.min(2_147_483_647, Math.max(1, nextAlertExpiry - Date.now())))
    return () => clearTimeout(timer)
  }, [nextAlertExpiry])
  const alerts: ConsoleAlert[] = [
    ...nodes.filter((n) => !n.local && n.peer?.enabled && (connectionGroup(n.status) === 'unreachable' || n.status === 'quarantined')).map((n): ConsoleAlert => ({
      id: n.id,
      title: n.status === 'quarantined' ? `当前节点已隔离 ${n.name}` : `当前节点尚未连通 ${n.name}`,
      detail: [reachabilityLabel(n), n.peer?.detail || '检查节点连接与已配置的网络路径。'].filter(Boolean).join('。'),
      href: `#/nodes/${n.id}`, kind: 'node', tone: 'amber',
    })),
    ...(!services.error ? localServiceAlerts(services.data ?? [], localName) : []),
    ...resourceAlerts,
    ...remoteAlerts,
    ...[['node', local.error], ['peers', peerError], ['services', services.error], ['metrics', metrics.error]]
      .flatMap(([kind, error]): ConsoleAlert[] => error ? [{ id: `connection/${kind}`, title: '部分状态暂时无法更新',
        detail: error, href: '#/overview', kind: 'connection', tone: 'amber' }] : []),
  ]
  const remoteNodes = listedNodes.filter((node) => !node.local)
  return { local, localName, peers, services, metrics, audit, nodes, listedNodes, memberNodes: directory.members ? memberNodes : undefined,
    remoteNodes, connections: countConnections(remoteNodes),
    meshCurrent, meshLoading, meshError, remoteCatalog, alerts,
    admin, session, preferences, nodeNotes, nodeNotesCurrent: !!grove.data && !grove.error && (!realmId || (!!sharedNotes.data && !sharedNotes.error)),
    grove, groveError: grove.error || roster.error, ...directory, onUnauthorized }
}

type Data = ReturnType<typeof useConsoleData> & { webBuild?: string }
const Context = createContext<Data | null>(null)
export function ConsoleData({ session, onUnauthorized, preferences, webBuild, children }: {
  session: Session; onUnauthorized: () => void; preferences: Preferences; webBuild?: string; children: ReactNode
}) {
  const value = { ...useConsoleData(session, onUnauthorized, preferences), webBuild }
  return <Context.Provider value={value}>{children}</Context.Provider>
}
export function useConsole() {
  const value = useContext(Context)
  if (!value) throw new Error('Console context is unavailable')
  return value
}
export function refreshConsole() { window.dispatchEvent(new Event('spearmint:refresh')) }

const events: Record<string, string> = {
  'grove.update.started': '发起 Grove 更新',
  'grove.update.accepted': '接收 Grove 更新',
  'grove.update.succeeded': 'Grove 节点已更新',
  'grove.update.failed': 'Grove 节点更新失败',
  'node.initialized': '节点已初始化', 'session.login': '账户登录成功', 'session.logout': '账户已退出',
  'session.revoked': '登录会话已撤销', 'service.registered': '服务已登记', 'service.unregistered': '服务已移除',
  'service.details.updated': '服务信息已更新',
  'administrator.password_reset': '管理员密码已重置', 'administrator.factor_recovery': '已执行本机账户恢复',
  'peer.added': '新节点已登记', 'peer.enabled': '节点互联已启用', 'peer.disabled': '节点互联已停用',
  'mesh.quarantine.applied': '已隔离节点', 'mesh.quarantine.released': '已解除本机隔离',
  'mesh.evidence.shared': '已共享冲突证据', 'mesh.evidence.unshared': '已停止共享证据',
  'mesh.evidence.received': '已核验并接收证据',
  'state.restored': '已从备份恢复节点',
  'grove.member_joined': '已批准 Grove 成员',
  'grove.member_departed': 'Grove 成员已退出',
  'grove.node_note_changed': '已更新节点备注',
  'grove.member_approved': '已批准 Grove 成员',
  'grove.member_directory_requested': '收到 Grove 成员的 HTTPS 身份目录请求',
  'grove.member_directory_requested_mesh': '收到 Grove 成员的 Mesh 身份目录请求',
  'seed.ssh.running': '已发起 SSH 播种', 'seed.ssh.started': 'SSH 播种已启动面板',
  'seed.ssh.failed': 'SSH 播种未能发起', 'seed.ssh.checksum': 'SSH 播种归档摘要不符',
  'seed.ssh.uncertain': 'SSH 播种结果待确认',
  'seed.preflight.passed': 'SSH 播种预检通过', 'seed.preflight.failed': 'SSH 播种预检未通过',
  'seed.destination.started': '已记录部署目标的 Node ID',
}
export function eventLabel(event: string) {
  if (events[event]) return events[event]
  const seed = /^(seed\.ssh\.(?:started|failed|uncertain)|seed\.preflight\.(?:passed|failed)|seed\.destination\.started)\./.exec(event)
  if (seed) return events[seed[1]]
  const operation = /^operation\.(start|stop|restart)\.(.+)$/.exec(event)
  if (operation) return `${{ start: '启动', stop: '停止', restart: '重启' }[operation[1]]}操作 · ${{ queued: '已排队', running: '执行中', succeeded: '已完成', failed: '失败', uncertain: '结果待确认' }[operation[2]] || operation[2]}`
  return event.replaceAll('.', ' · ')
}
