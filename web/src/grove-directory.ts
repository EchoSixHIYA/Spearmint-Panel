import type { GroveInfo } from './grove-auth'

type DirectoryResponse = { data?: GroveInfo; error: string }
export type MemberDirectoryVersion = { sequence: string; members_sha256: string; valid_until: number }
export type DirectoryMember = { node_id: string; origin: string; enabled: number }

export function compareMemberDirectories(local?: MemberDirectoryVersion, remote?: MemberDirectoryVersion | null, now = Date.now()) {
  if (!local || !remote || Math.min(local.valid_until, remote.valid_until) * 1000 <= now) return 'unverified'
  if (local.members_sha256 !== remote.members_sha256) return 'different'
  return local.sequence === remote.sequence ? 'matched' : 'same-members'
}

export function memberDirectoryDifferences(local: readonly DirectoryMember[], remote: readonly DirectoryMember[]) {
  const localById = new Map(local.map(member => [member.node_id, member]))
  const remoteById = new Map(remote.map(member => [member.node_id, member]))
  const ids = [...new Set([...localById.keys(), ...remoteById.keys()])].sort()
  return ids.flatMap(nodeId => {
    const here = localById.get(nodeId)
    const there = remoteById.get(nodeId)
    if (here && there && here.origin === there.origin && here.enabled === there.enabled) return []
    return [{ nodeId, here, there }]
  })
}

export function activeGroveDirectory(data: GroveInfo | undefined, now = Date.now()) {
  return !!(data?.configured && data.members && !data.frozen && !data.issuer_paused && (data.valid_until ?? 0) * 1000 > now)
}

function panelOrigin(value: string) {
  try {
    const url = new URL(value)
    if (url.protocol === 'https:' && url.port !== '0' && !url.username && !url.password
        && url.pathname === '/' && !url.search && !url.hash) return url
  } catch { return undefined }
}

export function memberPanelHost(value: string) {
  return panelOrigin(value)?.host
}

export function memberPanelOrigin(value: string) {
  return panelOrigin(value.trim())?.origin
}

export function publicPanelLabel(value: string | undefined) {
  if (!value) return '暂无面板地址'
  const url = panelOrigin(value)
  if (!url) return '暂无面板地址'
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  if (host.startsWith('[')) return /^\[[23][0-9a-f]{3}:/.test(host) ? url.host : '无公网 IP'
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const [a, b, c] = host.split('.').map(Number)
    const privateAddress = a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0)) || (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) ||
      (a === 203 && b === 0 && c === 113)
    return privateAddress ? '无公网 IP' : url.host
  }
  return host.includes('.') && !/\.(localhost|local|internal|lan|home\.arpa)$/.test(host) ? url.host : '无公网 IP'
}

export function groveDirectory(grove: DirectoryResponse, roster: DirectoryResponse, admin: boolean, now = Date.now()) {
  const realm = grove.data?.realm
  const directory = admin && grove.data?.configured && realm && roster.data?.realm?.id === realm.id ? roster.data : undefined
  const expiresAt = (directory?.valid_until ?? 0) * 1000
  const members = expiresAt > 0 ? directory?.members : undefined
  const directorySequence = members ? directory?.sequence : undefined
  const readable = !grove.error && !roster.error
  const directoryCurrent = readable && !grove.data?.frozen && !grove.data?.issuer_paused
    && activeGroveDirectory(directory || undefined, now)
  const directoryLoading = admin && readable && (!grove.data || (grove.data.configured && !directory))
  const directoryPending = readable && directory?.local_issuer === false
    && !directory.frozen && !directory.issuer_paused && expiresAt === 0
  const memberPanelOrigins = directoryCurrent ? groveMemberOrigins(directory || undefined, now) : new Map<string, string>()
  const directoryRequestedAt = directoryCurrent && directory?.local_issuer ? directory.directory_requested_at : undefined
  const directoryMeshRequestedAt = directoryCurrent && directory?.local_issuer ? directory.directory_mesh_requested_at : undefined
  return { members, directorySequence, directoryCurrent, directoryLoading, directoryPending, memberPanelOrigins,
    groveDetails: directory ?? grove.data,
    directoryExpiresAt: directoryCurrent ? expiresAt : undefined,
    directoryRequestedAt, directoryMeshRequestedAt }
}

export function groveMemberOrigins(data: GroveInfo | undefined, now = Date.now()) {
  const origins = new Map<string, string>()
  if (activeGroveDirectory(data, now)) for (const member of data?.members || []) {
    const origin = member.enabled ? panelOrigin(member.origin) : undefined
    const host = origin?.hostname.replace(/\.$/, '')
    if (origin && host && !/^(localhost$|.+\.localhost$|127\.|\[::1\]$|0\.0\.0\.0$)/.test(host))
      origins.set(member.node_id, origin.origin)
  }
  return origins
}
