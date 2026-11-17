import { compareMemberDirectories, memberDirectoryDifferences, memberPanelOrigin, type DirectoryMember, type MemberDirectoryVersion } from './grove-directory.ts'
import { deploymentWebDifference, rolloutLabels, type ReleaseCandidate } from './release-compatibility.ts'

export const MAX_DEPLOYMENT_REPORT_SIZE = 1024 * 1024
const nodeId = /^spm1-[a-f0-9]{64}$/
const groveId = /^grv1-[a-f0-9]{32}$/
const commit = /^[a-f0-9]{40}$/
const digest = /^[a-f0-9]{64}$/
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

type Evidence = {
  commit?: string
  schema?: number
  packageDigest?: string
  web?: { status: string; build: string | null; package_match?: boolean; package_web_sha256?: string }
  directory?: MemberDirectoryVersion
}
export const queryLabels = { 'no-mesh': '无可用 Mesh 配置', 'route-changed': 'Mesh 路径已变更',
  'connection-unconfirmed': 'Mesh 连接待确认', 'not-queried': '尚未查询', unsupported: '节点版本未提供状态', unavailable: '暂时无法读取' }
type ReportRow = { name?: string; observedAt?: string; evidence?: Evidence; query?: keyof typeof queryLabels;
  rollout?: keyof typeof rolloutLabels; path?: string[] }
type Candidate = Pick<ReleaseCandidate, 'version' | 'commit' | 'schema'> & { archives?: string; webSha256?: string }
type DeploymentReport = { grove?: string; source?: string; generatedAt: string; candidate?: Candidate; rows: ReadonlyMap<string, ReportRow>;
  directorySnapshot?: { members: DirectoryMember[]; status: 'unchecked' | 'verified' | 'unverified' } }

export function reportCandidate({ version, commit, schema, packages, webSha256 }: ReleaseCandidate) {
  return { version, commit, schema, web_sha256: webSha256,
    archives: Object.fromEntries(packages.map(({ target, sha256 }) => [target, sha256])) }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function matches(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && pattern.exec(value)?.[0] === value
}

function date(value: unknown): value is string {
  return matches(value, timestamp) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value
}

function schemaNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 && value < 2 ** 31
}

function candidateMetadata(value: unknown): Candidate | undefined {
  if (!record(value) || !matches(value.version, /^[a-zA-Z0-9][a-zA-Z0-9.+-]{0,63}$/)
      || !matches(value.commit, commit) || !schemaNumber(value.schema)) return
  const entries = record(value.archives) ? Object.entries(value.archives).sort(([a], [b]) => a.localeCompare(b)) : []
  const archives = entries.length && entries.every(([target, sha]) => ['linux-amd64', 'linux-arm64', 'windows-amd64'].includes(target)
    && matches(sha, digest)) ? JSON.stringify(entries) : undefined
  return { version: value.version, commit: value.commit, schema: value.schema, archives,
    webSha256: matches(value.web_sha256, digest) ? value.web_sha256 : undefined }
}

function knownLabel<T extends string>(labels: Record<T, string>, value: unknown): T | undefined {
  return typeof value === 'string' && Object.hasOwn(labels, value) ? value as T : undefined
}

function observationPath(value: unknown, source: string | undefined, target: string): string[] | undefined {
  if (!source || !Array.isArray(value) || value.length < 2 || value.length > 64
      || value[0] !== source || value.at(-1) !== target || new Set(value).size !== value.length
      || !value.every(id => matches(id, nodeId))) return
  return value
}

function evidence(value: Record<string, unknown>): Evidence {
  const { build, host, web, member_directory: directory, package_checksums_sha256: packageDigest } = value
  return {
    commit: record(build) && matches(build.commit, commit) ? build.commit : undefined,
    schema: record(host) && schemaNumber(host.schema) ? host.schema : undefined,
    packageDigest: matches(packageDigest, digest) ? packageDigest : undefined,
    web: record(web) && ['ready', 'missing-entry', 'unbuilt', 'missing-assets', 'unreadable'].some(status => status === web.status)
      && typeof web.status === 'string' && (web.build === null || matches(web.build, /^[\w-]+ \/ [\w-]+$/))
      ? { status: web.status, build: web.build, package_match: typeof web.package_match === 'boolean' ? web.package_match : undefined,
        package_web_sha256: matches(web.package_web_sha256, digest) ? web.package_web_sha256 : undefined } : undefined,
    directory: record(directory) && matches(directory.sequence, /^[1-9][0-9]{0,18}$/) && matches(directory.members_sha256, digest)
      && typeof directory.valid_until === 'number' && Number.isSafeInteger(directory.valid_until) && directory.valid_until > 0
      ? { sequence: directory.sequence, members_sha256: directory.members_sha256, valid_until: directory.valid_until } : undefined,
  }
}

export function parseDeploymentReport(text: string): DeploymentReport {
  if (text.length > MAX_DEPLOYMENT_REPORT_SIZE) throw new Error('核对报告超过 1 MiB。')
  const value: unknown = JSON.parse(text)
  if (!record(value) || value.version !== 1 || !date(value.generated_at) || !record(value.source) || !Array.isArray(value.nodes)
      || (value.grove_id !== undefined && !matches(value.grove_id, groveId))
      || (value.source.node_id !== undefined && !matches(value.source.node_id, nodeId))) throw new Error('版本核对报告格式无效。')
  const rows = new Map<string, ReportRow>()
  const candidate = candidateMetadata(value.candidate)
  const source = value.source.node_id
  if (source) rows.set(source, { observedAt: date(value.source.received_at) ? value.source.received_at : value.generated_at,
    evidence: evidence(value.source),
    rollout: candidate && knownLabel(rolloutLabels, value.source.candidate_status) })
  for (const row of value.nodes) {
    if (!record(row) || !matches(row.node_id, nodeId) || rows.has(row.node_id) || typeof row.status !== 'string') {
      throw new Error('节点标识无效或重复。')
    }
    const observation = row.status === 'reported' && record(row.observation) ? row.observation : undefined
    const observedAt = date(observation?.received_at) ? observation.received_at : undefined
    rows.set(row.node_id, {
      name: typeof row.name === 'string' && row.name.length <= 256 ? row.name : undefined,
      observedAt,
      evidence: observation && observedAt ? evidence(observation) : undefined,
      path: observedAt ? observationPath(observation?.path, source, row.node_id) : undefined,
      query: knownLabel(queryLabels, row.status),
      rollout: candidate && (observation && observedAt ? knownLabel(rolloutLabels, row.candidate_status) : 'unverified'),
    })
  }
  const members = value.source.directory_members
  let directorySnapshot: DeploymentReport['directorySnapshot']
  if (members !== undefined) {
    const directory = source ? rows.get(source)?.evidence?.directory : undefined
    if (!directory || !value.grove_id || !Array.isArray(members) || members.length > 64) throw new Error('成员目录快照格式无效。')
    const ids = new Set<string>()
    const entries = members.map((member: unknown): DirectoryMember => {
      if (!record(member) || !matches(member.node_id, nodeId) || ids.has(member.node_id)
          || typeof member.origin !== 'string' || memberPanelOrigin(member.origin) !== member.origin
          || (member.enabled !== 0 && member.enabled !== 1)) throw new Error('成员目录快照条目无效或重复。')
      ids.add(member.node_id)
      return { node_id: member.node_id, origin: member.origin, enabled: member.enabled }
    })
    directorySnapshot = { members: entries, status: 'unchecked' }
  }
  return { grove: value.grove_id, source, generatedAt: value.generated_at, candidate, rows, directorySnapshot }
}

export async function verifyReportDirectory(report: DeploymentReport): Promise<DeploymentReport> {
  const snapshot = report.directorySnapshot
  if (!snapshot || !report.source) return report
  const expected = report.rows.get(report.source)?.evidence?.directory?.members_sha256
  let status: 'verified' | 'unverified' = 'unverified'
  if (globalThis.crypto?.subtle && expected) {
    // Match grove.member_directory_version: sort by Node ID and hash the JSON tuples.
    const members = [...snapshot.members].sort((a, b) => a.node_id < b.node_id ? -1 : a.node_id > b.node_id ? 1 : 0)
      .map(({ node_id, origin, enabled }) => [node_id, origin, enabled])
    const bytes = new TextEncoder().encode(JSON.stringify({ members }))
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
      byte => byte.toString(16).padStart(2, '0')).join('')
    if (hash === expected) status = 'verified'
  }
  return { ...report, directorySnapshot: { ...snapshot, status } }
}

function compareCandidates(a?: Candidate, b?: Candidate) {
  if (!a || !b) return 'unverified'
  if (a.version !== b.version || a.commit !== b.commit || a.schema !== b.schema
      || (a.archives && b.archives && a.archives !== b.archives)
      || (a.webSha256 && b.webSha256 && a.webSha256 !== b.webSha256)) return 'different'
  return a.archives && b.archives ? 'matched' : 'unverified'
}

function compareWeb(left?: Evidence['web'], right?: Evidence['web']) {
  if (!left || !right) return 'unverified'
  if (deploymentWebDifference(left, right) || left.status !== right.status
      || (typeof left.package_match === 'boolean' && typeof right.package_match === 'boolean' && left.package_match !== right.package_match)) {
    return 'different'
  }
  if (left.status !== 'ready' || left.package_match === false || right.package_match === false) return 'unhealthy'
  return left.status === 'ready' && left.package_match === true && right.package_match === true
    && !!left.package_web_sha256 && left.package_web_sha256 === right.package_web_sha256 ? 'matched' : 'unverified'
}

function compareValue(left: string | number | undefined, right: string | number | undefined) {
  return left === undefined || right === undefined ? 'unverified' : left === right ? 'matched' : 'different'
}

export function compareDeploymentReports(left: DeploymentReport, right: DeploymentReport) {
  if (left.grove && right.grove && left.grove !== right.grove) return undefined
  const leftExport = Date.parse(left.generatedAt)
  const rightExport = Date.parse(right.generatedAt)
  const sameSource = !!left.source && left.source === right.source
  // Consecutive reports from the same panel can be compared as two historical snapshots.
  const directoryTime = sameSource ? Math.min(leftExport, rightExport) : Math.max(leftExport, rightExport)
  const compareDirectories = (a?: MemberDirectoryVersion, b?: MemberDirectoryVersion) =>
    a && b && a.valid_until * 1000 > leftExport && b.valid_until * 1000 > rightExport
      ? compareMemberDirectories(a, b, directoryTime) : 'unverified'
  const leftSnapshot = left.directorySnapshot
  const rightSnapshot = right.directorySnapshot
  const leftSourceDirectory = left.source ? left.rows.get(left.source)?.evidence?.directory : undefined
  const rightSourceDirectory = right.source ? right.rows.get(right.source)?.evidence?.directory : undefined
  const sourceComparison = compareDirectories(leftSourceDirectory, rightSourceDirectory)
  const roster = left.grove && left.grove === right.grove && leftSnapshot?.status === 'verified' && rightSnapshot?.status === 'verified'
    && leftSourceDirectory && rightSourceDirectory && sourceComparison !== 'unverified'
    ? { leftSequence: leftSourceDirectory.sequence, rightSequence: rightSourceDirectory.sequence,
      differences: memberDirectoryDifferences(leftSnapshot.members, rightSnapshot.members) } : undefined
  const rows = [...new Set([...left.rows.keys(), ...right.rows.keys()])].sort().map(id => {
    const a = left.rows.get(id)
    const b = right.rows.get(id)
    const leftEvidence = a?.evidence
    const rightEvidence = b?.evidence
    const earlierSample = a?.observedAt && b?.observedAt && a.observedAt !== b.observedAt
      ? (a.observedAt < b.observedAt ? 'left' : 'right') : undefined
    return { id, name: a?.name ?? b?.name, left: a, right: b,
      earlierSample,
      commit: compareValue(leftEvidence?.commit, rightEvidence?.commit),
      schema: compareValue(leftEvidence?.schema, rightEvidence?.schema),
      packageDigest: compareValue(leftEvidence?.packageDigest, rightEvidence?.packageDigest),
      web: compareWeb(leftEvidence?.web, rightEvidence?.web),
      directory: compareDirectories(leftEvidence?.directory, rightEvidence?.directory),
    } as const
  })
  return { sameGrove: !!left.grove && !!right.grove, sameSource,
    candidateComparison: compareCandidates(left.candidate, right.candidate), roster, rows }
}
