import { actions, demoNodes, initialState, metrics, nodeId, now, observation, originFor, sourceCommit } from './data'
import { terminalRequest } from './terminal'
import type { Session } from '../src/api'

const key = 'spearmint-offline-demo-v1'
export let state: any = initialState()
try { const saved = JSON.parse(localStorage.getItem(key) || 'null'); if (saved?.version === 1) state = saved } catch { /* In-memory mode is also supported. */ }
export const save = () => { try { localStorage.setItem(key, JSON.stringify(state)) } catch { /* In-memory demo. */ } }
export function resetDemo() {
  try { localStorage.removeItem(key); sessionStorage.clear(); localStorage.removeItem('spearmint-display') } catch { /* In-memory demo. */ }
  location.hash = '#/overview'; location.reload()
}
export function event(message: string) { window.dispatchEvent(new CustomEvent('spearmint-demo:message', { detail: message })) }
function audit(name: string, target: string | null = null) {
  state.audits.unshift({ id: Date.now(), recorded_at: now(), actor: 'demo-admin', source: '演示工作站', event: name, target })
  state.audits = state.audits.slice(0, 100); save()
}
const currentSession: Session = { username: 'demo-admin', display_name: '演示管理员', csrf_token: 'demo-offline-session', role: 'node_admin', grove: true }
export const demoSession = currentSession
const realm = { version: 1, id: 'grv1-' + '0'.repeat(32), name: 'Spearmint 示例花园', public_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  issuer_node: nodeId(2), issuer_origin: originFor(nodeId(2)) }
const memberDirectory = () => ({ sequence: '42', members_sha256: 'a'.repeat(64), valid_until: now() + 3600 })
const grove = () => ({ configured: true, realm, local_issuer: false, frozen: '', issuer_paused: false, member_login: true,
  continuity_configured: true, issuer_retired: true, operator_revocation: 'available', identity_voter: false, sequence: 42, valid_until: now() + 3600,
  member_directory: memberDirectory(), members: demoNodes.map(node => ({ node_id: node.id, origin: originFor(node.id), enabled: 1 })), users: state.users })
const targetFor = (id: string) => { const node = demoNodes.find(item => item.id === id) || demoNodes[0]; return `${node.os}-${node.arch}` }
const build = { version: '0.4.0', commit: sourceCommit, runtime: 'native' }
const deployment = (id = nodeId(1)) => ({ node_id: id, origin: originFor(id), build, host: { target: targetFor(id), schema: 30 },
  package_checksums_sha256: 'b'.repeat(64), web: { status: 'ready', build: 'preview.17 / mock', package_match: true, package_web_sha256: 'c'.repeat(64) },
  connection_id: 'demo-link-' + id.slice(-1), member_directory: memberDirectory() })
function serviceView(service: any) { return { ...service, actions, version: service.version || 1, approval_required: false,
  logs_available: true, observation: { ...observation(service.status), source: service.driver }, operations: state.operations.filter((item: any) => item.service_id === service.id),
  can_unregister: true, can_edit_details: true } }
function directory(id: string) { return { node_id: id, stale: false, connection_id: 'demo-link-' + id.slice(-1), directory_generation: 1,
  services: state.services.filter((service: any) => service.node_id === id).map((service: any) => ({ ...serviceView(service), status: true, logs: true })) } }
function peers() { return demoNodes.slice(1).map(node => {
  const online = node.path.length > 0 || state.seeded && node.id === nodeId(6)
  const path = node.path.length ? node.path.map(nodeId) : [nodeId(1), node.id]
  return { node_id: node.id, enabled: true, status: online ? 'online' : 'offline', mesh_id: '0'.repeat(32),
    direct: path.length === 2, routed: true, legacy: false, hops: path.length - 1, path: online ? path : [],
    next_hop: path[1], host: `node-${node.id.slice(-6)}.mesh`, source_ip: node.ip || null, port: node.ip ? 8766 : null,
    connected_ip: path.length === 2 && node.ip ? node.ip : undefined, tls: 'TLSv1.3',
    connected_at: now() - 4200, rtt_ms: online ? node.latency || 8.2 : null,
    fingerprint: 'd'.repeat(64), directory_ready: true, connection_id: 'demo-link-' + node.id.slice(-1), directory_generation: 1,
    observations: online ? [{ observer_node_id: path.at(-2), method: 'direct', age_seconds: 1.1, remaining_seconds: 19 }] : [],
    route_diagnostics: { selected_path: online ? path : null, switches: 0, switch_reason: 'latency', backup_sessions: 0,
      candidate_sessions: online ? [{ path, role: 'active', connection_generation: 'demo', cost_ms: node.latency,
        directory_prepared: true, directory_prepared_remaining_seconds: 90, rtt_fresh: true, rtt_ewma_ms: node.latency, rtt_sample_count: 12 }] : [] } }
}) }
const seedJobs = new Map<string, any>()
const mappings: any[] = state.mappings
const release = { tag: 'v0.4.0-preview.17', commit: sourceCommit }
let updateStarted = 0

function seed(action: string, id: string, body: any) {
  let job = seedJobs.get(id)
  if (action === 'start') { job = { status: 'verify-host', fingerprint: 'SHA256:SpearmintDemoKey0123456789', platform: body.connection?.host?.toLowerCase().includes('win') ? 'windows-amd64' : 'linux-arm64' }; seedJobs.set(id, job) }
  if (!job) throw new Error('请先测试示例 SSH 连接。')
  if (action === 'verify') job.status = 'choose'
  if (action === 'directory') { job.status = 'choose'; job.path = body.path || '/home/demo' }
  if (action === 'install') { job.status = 'installing'; job.started = Date.now() }
  if (action === 'status' && job.status === 'installing' && Date.now() - job.started > 3000) job.status = 'admitting'
  if (action === 'status' && job.status === 'admitting' && Date.now() - job.started > 6000) { job.status = 'joined'; state.seeded = true; audit('grove.member_joined', '家庭 NAS') }
  job.path ||= '/home/demo'
  job.package = { name: `spearmint-0.4.0-${job.platform}-${sourceCommit.slice(0, 8)}.tar.gz`, commit: sourceCommit, size: 25393918 }
  job.directory = { parent: job.path === '/' ? null : '/', writable: true, free: 100 * 1024 ** 3, truncated: false,
    items: ['spearmint', 'projects', 'backups'].map(name => ({ name, path: job.path.replace(/\/$/, '') + '/' + name })) }
  job.origin = originFor(nodeId(6)); job.node_id = nodeId(6)
  job.install = job.path + '/spearmint'; job.state = job.path + '/spearmint-data'
  return job
}
export async function respond(path: string, method: string, body: any): Promise<any> {
  const [route, search] = path.split('?'), query = new URLSearchParams(search)
  if (route === '/setup') return { required: false, link_expired: false }
  if (route === '/session') return currentSession
  if (route === '/node') return { node_id: nodeId(1), build, deployment_host: { target: 'windows-amd64', schema: 30 },
    package_checksums_sha256: 'b'.repeat(64),
    platform: { os: 'windows', architecture: 'amd64', process_backend: 'windows-job', docker: 'available', file_security: 'acl' } }
  if (route === '/metrics') return metrics()
  if (route === '/metrics/trend') return { sampled_at: now(), window_seconds: 300, points: Array.from({ length: 151 }, (_, i) => ({
    sampled_at: now() - 300 + i * 2, cpu_percent: 20 + Math.sin(i / 7) * 8, memory_percent: 34 + Math.sin(i / 20) * 3, root_disk_percent: 35, state_disk_percent: 21 })) }
  if (route === '/auth/grove/info' || route === '/grove') return grove()
  if (route === '/grove/node-notes') return state.notes
  if (route.startsWith('/grove/node-notes/')) { const id = route.split('/').at(-1)!; state.notes[id] = body.note ?? body.name ?? body.text; audit('grove.node_note_changed', state.notes[id]); return { note: state.notes[id] } }
  if (route === '/grove/sync-directory') return { realm_id: realm.id, previous_sequence: '42', member_directory: memberDirectory(), source: 'member-quorum' }
  if (route === '/grove/browser-invitation') return { code: 'spmt-demo-invitation:grove-example:preview17' }
  if (route === '/mesh/overview') return { peers: peers(), directories: demoNodes.slice(1).map(node => directory(node.id)) }
  if (route === '/peers') return peers()
  if (route === '/audit') return state.audits
  if (route === '/sessions') return state.sessions
  if (route.startsWith('/sessions/')) { state.sessions = state.sessions.filter((item: any) => item.id !== route.split('/').at(-1)); audit('session.revoked'); return null }
  if (route === '/auth/first-factor') return { eligible: false, grove_totp: true, totp: true, passkeys: [] }
  if (route === '/auth/grove/password') return { available: true, changed: method !== 'GET' }
  if (route === '/mesh/services') return state.services.map((item: any) => ({ node_id: item.node_id, service_id: item.id, name: item.name, version: 1, actions, key_ids: [], stale: false }))
  if (route === '/operations/local') return state.operations.filter((item: any) => item.node_id === nodeId(1)).map((item: any) => ({ ...item, service_name: item.name, operation_id: item.id, recorded_at: item.updated_at }))
  if (route === '/operations/remote') return query.has('pending') ? [] : state.operations.filter((item: any) => item.node_id !== nodeId(1))
    .map((item: any) => ({ ...item, service_name: item.name, request_id: item.id }))
  if (route.startsWith('/operations/remote/') && route !== '/operations/remote/review') {
    const item = state.operations.find((entry: any) => entry.id === route.split('/').at(-1))
    return item ? { ...item, request_id: item.id, service_name: item.name } : null
  }
  if (route === '/security/evidence') return { conflicts: [], next_before: null, can_share: true }
  if (route === '/security/evidence/inbox') return []
  if (/^\/peers\/[^/]+\/evidence$/.test(route)) return { reports: [], next_before: null }
  if (route === '/frp/exposures') return mappings
  if (route === '/node/web-bundle') return { ...deployment().web, deployment: deployment() }
  const deploy = /^\/grove\/deployments\/([^/]+)(\/member-directory)?$/.exec(route)
  if (deploy) return deploy[2] ? { ...memberDirectory(), ...deployment(deploy[1]), members: grove().members } : deployment(deploy[1])
  if (route === '/grove/updates/release') return { release }
  if (route === '/grove/updates') {
    if (method === 'POST') { updateStarted = Date.now(); state.update = { job: crypto.randomUUID(), release, nodes: {}, expires: now() + 3600 }; audit('grove.update.started', release.tag) }
    if (state.update) {
      const elapsed = Date.now() - updateStarted
      state.update.nodes = Object.fromEntries(demoNodes.map((node, index) => [node.id, { status: elapsed > 6500 + index * 500 ? 'succeeded' : elapsed > 2500 ? 'installing' : 'downloading',
        ...(elapsed < 2500 && index === 5 ? { reason: 'fetching_from_grove' } : {}) }]))
    }
    return state.update || { job: null }
  }
  const wizard = /^\/grove\/seed-wizard\/([^/]+)\/([^/]+)\/([^/]+)$/.exec(route)
  if (wizard) return seed(wizard[3], wizard[2], body)
  const terminal = /^\/peers\/([^/]+)\/terminal\/([^/]+)\/([^/]+)$/.exec(route)
  if (terminal) return terminalRequest(terminal[1], terminal[2], terminal[3], body)
  const routeProbe = /^\/peers\/([^/]+)\/route$/.exec(route)
  if (routeProbe) { const node = demoNodes.find(item => item.id === routeProbe[1])!; return { path: node.path.map(nodeId), hops: node.path.length - 1, status: 'online', rtt_ms: node.latency } }
  const setup = /^\/peers\/([^/]+)\/service-setup\/([^/]+)$/.exec(route)
  if (setup) {
    const id = setup[1] === 'local' ? nodeId(1) : setup[1], kind = targetFor(id).startsWith('windows') ? 'windows' : 'systemd'
    if (setup[2] === 'kinds') return { kinds: kind === 'windows' ? ['windows'] : ['systemd', 'docker'], workflow: 2, checks: true, commands: true, scripts: true }
    if (setup[2] === 'running') return { candidates: body.kind === 'docker' ? [{ target: 'demo-redis', name: 'Redis 缓存' }, { target: 'demo-postgres', name: 'PostgreSQL' }]
      : kind === 'windows' ? [{ target: 'W32Time', name: 'Windows Time' }, { target: 'Spooler', name: 'Print Spooler' }]
        : [{ target: 'nginx.service', name: 'Nginx Web Server' }, { target: 'redis.service', name: 'Redis 缓存' }],
      registered: state.services.filter((item: any) => item.node_id === id).map((item: any) => ({ ...item, target: item.registered_target, managed: true, version: 1 })), truncated: false }
    if (setup[2] === 'inspect') return { ready: true, log_path: kind === 'windows' ? 'C:\\Demo\\logs\\application.log' : '/var/log/nginx/access.log' }
    if (['create', 'take-over', 'register'].includes(setup[2])) {
      const existing = body.target && state.services.find((entry: any) => entry.node_id === id && entry.registered_target === body.target)
      if (existing) return { service: { ...existing, target: body.target, managed: true, version: 1 } }
      const item: any = { id: crypto.randomUUID().replaceAll('-', ''), node_id: id, name: body.name || body.target, driver: body.kind === 'docker' ? 'docker' : 'process',
        registered_target: body.target, command: body.command, endpoint: null, status: setup[2] === 'create' ? 'stopped' : 'running' }
      if (setup[2] !== 'create' && body.kind !== 'docker') item.runtime = kind === 'windows' ? 'windows-service' : 'systemd-system'
      state.services.push(item); audit('service.registered', item.name); return { service: { ...item, target: body.target || item.id, managed: true, version: 1 } }
    }
    const item = state.services.find((entry: any) => entry.id === body.service_id)
    return { service: { ...item, version: 1, actions, managed: true } }
  }
  if (route === '/services') return state.services.filter((item: any) => item.node_id === nodeId(1)).map(serviceView)
  const nodeServices = /^\/peers\/([^/]+)\/services$/.exec(route)
  if (nodeServices) return directory(nodeServices[1])
  const servicePath = /^(?:\/peers\/([^/]+))?\/services\/([^/]+)(?:\/(.*))?$/.exec(route)
  if (servicePath) {
    const item = state.services.find((entry: any) => entry.id === servicePath[2])
    if (!item) throw new Error('示例服务不存在，可能已被移除。')
    const action = servicePath[3] || ''
    if (action === 'status') return { ...observation(item.status), source: item.driver }
    if (action === 'logs') return { text: `${new Date().toISOString()} INFO ${item.name} initialized\n${new Date().toISOString()} INFO Configuration loaded\n${new Date().toISOString()} INFO GET /healthz 200 2ms\n${new Date().toISOString()} INFO Grove heartbeat acknowledged\n`, source: item.driver, checked_at: now(), truncated: false }
    if (action === 'actions' && method === 'GET') return { actions }
    if (action === 'operations' && method === 'GET') return state.operations.filter((entry: any) => entry.service_id === item.id).map((entry: any) => ({ ...entry, request_id: entry.id, receipt: entry.receipt }))
    if (action.startsWith('operations/') || action.startsWith('actions/')) return state.operations.find((entry: any) => entry.id === action.split('/').at(-1))?.receipt || null
    if (action === 'actions' && method === 'POST' || actions.includes(action) && method === 'POST') {
      const command = body.action || action
      item.status = command === 'stop' ? 'stopped' : 'running'
      const operation: any = { id: crypto.randomUUID().replaceAll('-', ''), service_id: item.id, node_id: item.node_id, name: item.name,
        action: command, status: 'succeeded', message: '已完成', updated_at: now() }
      operation.receipt = { accepted: true, request_id: operation.id, operation_id: operation.id, operation: { status: 'succeeded', updated_at: now() } }
      state.operations.unshift(operation); audit('operation.' + command + '.succeeded', item.name)
      return servicePath[1] ? operation.receipt : operation
    }
    if (['management', 'management-check', 'systemd-management', 'windows-management'].includes(action)) return { ready: true, listed_actions: { start: true, stop: true, restart: true }, listed_logs: true }
    if (action === 'mode') return { version: 1, actions }
    if (action === 'details' && method !== 'GET') { Object.assign(item, { name: body.name || item.name, endpoint: body.endpoint ?? null }); audit('service.updated', item.name); return { ...item, version: 1, actions } }
    if (action === 'frp' && method === 'POST') {
      const mapping = { id: crypto.randomUUID().replaceAll('-', ''), service_id: item.id, service_name: item.name, provider: body.provider || 'demo-edge',
        protocol: body.protocol || 'https', public_address: 'https://' + (body.domain || 'service.demo.example'), expires_at: now() + (body.ttl || 3600), status: 'running', health: 'ready' }
      mappings.unshift(mapping); audit('frp.mapping.created', item.name); return { mapping }
    }
    if (action.startsWith('frp/')) {
      const mapping = mappings.find(entry => entry.id === action.split('/')[1]) || mappings.find(entry => entry.service_id === item.id)
      if (action.endsWith('/revoke') && mapping) { mapping.status = 'revoked'; mapping.health = null; audit('frp.mapping.revoked', item.name) }
      return { mapping }
    }
    if (action === 'frp') return { can_start: true, options: [{ provider: 'demo-edge', protocol: 'https', targets: [{ address: 'https://service.demo.example', domain: 'service.demo.example' }] }],
      mappings: mappings.filter(entry => entry.service_id === item.id) }
    if (method === 'DELETE' && !action) { state.services = state.services.filter((entry: any) => entry.id !== item.id); audit('service.unregistered', item.name); return null }
    return serviceView(item)
  }
  if (route.includes('/frp')) return { available: true, manageable: true, mappings, options: [] }
  if (route.includes('/quarantine')) return { local_quarantine: null }
  if (route.includes('/operations')) return []
  console.info('[demo] no sample handler:', method, route)
  throw new Error('此项示例记录暂未提供。请使用演示指南中的操作。')
}

// All API calls terminate in this browser. No real panel or SSH server is contacted.
window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  const index = raw.indexOf('/api/v1')
  if (index < 0) throw new TypeError('离线演示不发起外部请求。')
  let body: any = {}
  try { body = JSON.parse(String(init?.body || '{}')) } catch { /* Empty request. */ }
  try {
    const result = await respond(raw.slice(index + 7), init?.method || 'GET', body)
    if (init?.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
    return new Response(JSON.stringify(result ?? null), { status: 200, headers: { 'Content-Type': 'application/json' } })
  } catch (error) {
    return new Response(JSON.stringify({ detail: error instanceof Error ? error.message : String(error), code: 'DEMO_DATA' }), {
      status: 400, headers: { 'Content-Type': 'application/json' },
    })
  }
}
