export const sourceCommit = '8bb543fb457c5570277358f2b2412c540405d063'
export const nodeId = (value: number) => 'spm1-' + value.toString(16).repeat(64)
export const demoNodes = [
  { id: nodeId(1), name: '演示工作站', os: 'windows', arch: 'amd64', ip: '', latency: 0, path: [1] },
  { id: nodeId(2), name: '上海节点', os: 'linux', arch: 'amd64', ip: '192.0.2.12', latency: 18.6, path: [1, 2] },
  { id: nodeId(3), name: '香港节点', os: 'linux', arch: 'amd64', ip: '192.0.2.13', latency: 47.2, path: [1, 2, 3] },
  { id: nodeId(4), name: '美国节点', os: 'linux', arch: 'amd64', ip: '192.0.2.14', latency: 187.4, path: [1, 4] },
  { id: nodeId(5), name: 'Jetson Thor', os: 'linux', arch: 'arm64', ip: '', latency: 22.8, path: [1, 2, 5] },
  { id: nodeId(6), name: '家庭 NAS', os: 'windows', arch: 'amd64', ip: '', latency: 0, path: [] },
]
export const originFor = (id: string) => `https://${({ [nodeId(1)]: 'workstation.demo.example', [nodeId(2)]: 'shanghai.demo.example', [nodeId(3)]: 'hongkong.demo.example', [nodeId(4)]: 'us.demo.example' })[id] || '192.168.50.10'}:18443`
export const now = () => Math.floor(Date.now() / 1000)
export const initialServices = () => [
  { id: 'a'.repeat(32), node_id: nodeId(1), name: 'Demo API', driver: 'process', command: 'cd C:\\Demo\\api\r\npython app.py --port 8080', status: 'running', endpoint: 'http://127.0.0.1:8080' },
  { id: 'b'.repeat(32), node_id: nodeId(1), name: '定时备份', driver: 'process', command: 'cd C:\\Demo\\backup\r\npython backup.py', status: 'stopped', endpoint: null },
  { id: 'c'.repeat(32), node_id: nodeId(2), name: 'Nginx 网关', driver: 'process', runtime: 'systemd-system', registered_target: 'nginx.service', status: 'running', endpoint: 'https://gateway.example' },
  { id: 'd'.repeat(32), node_id: nodeId(3), name: 'PostgreSQL', driver: 'docker', registered_target: 'demo-postgres', status: 'running', endpoint: 'tcp://127.0.0.1:5432' },
  { id: 'e'.repeat(32), node_id: nodeId(4), name: '消息消费者', driver: 'process', status: 'running', endpoint: null },
  { id: 'f'.repeat(32), node_id: nodeId(5), name: '图像推理 API', driver: 'process', status: 'running', endpoint: 'http://127.0.0.1:8000' },
]
export function initialState() {
  return { version: 1, services: initialServices(), notes: Object.fromEntries(demoNodes.map(node => [node.id, node.name])),
    audits: [
      { id: 3, recorded_at: now() - 65, actor: 'demo-admin', source: '演示工作站', event: 'service.registered', target: 'Demo API' },
      { id: 2, recorded_at: now() - 230, actor: 'demo-admin', source: '上海节点', event: 'grove.member_joined', target: 'Jetson Thor' },
      { id: 1, recorded_at: now() - 360, actor: 'demo-admin', source: '演示工作站', event: 'session.login', target: null },
    ],
    sessions: [{ id: 'current', created_at: now() - 360, last_seen: now(), current: true },
      { id: 'other-browser', created_at: now() - 86400, last_seen: now() - 1800, current: false }],
    operations: [], mappings: [{ id: 'demo-mapping', service_id: 'a'.repeat(32), service_name: 'Demo API', provider: 'demo-edge',
      protocol: 'https', public_address: 'https://api.demo.example', expires_at: now() + 3600, status: 'running', health: 'ready' }],
    files: {}, seeded: false, update: null, users: [
      { id: 'usr1-demo-admin', name: 'demo-admin', role: 'node_admin', enabled: true, require_mfa: true },
      { id: 'usr1-demo-operator', name: 'demo-operator', role: 'remote_operator', enabled: true, require_mfa: true },
    ] }
}
export const actions = ['start', 'stop', 'restart']
export const observation = (status: string) => ({ status, message: null, health: status === 'running' ? 'healthy' : null,
  pid: status === 'running' ? 5024 : 0, source: 'process', checked_at: now(), last_seen_at: now(), last_status: status,
  stale: false, valid_until: now() + 90 })
export function metrics() {
  const gib = 1024 ** 3
  const cpu = 18 + Math.sin(Date.now() / 18000) * 7
  return { sampled_at: now(), valid_until: now() + 90, stale: false, cpu_percent: cpu,
    memory: { total: 32 * gib, available: 21 * gib },
    root_disk: { total: 512 * gib, used: 179 * gib, free: 333 * gib, percent: 35 },
    state_disk: { total: 1024 * gib, used: 215 * gib, free: 809 * gib, percent: 21 }, state_disk_is_root: false,
    network: { received_per_second: 1480000, sent_per_second: 256000 }, uptime_seconds: 186432 }
}
