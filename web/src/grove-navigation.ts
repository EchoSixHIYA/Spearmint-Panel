import { memberPanelOrigin } from './grove-directory.ts'

const nodeId = 'spm1-[a-f0-9]{64}'
const identifier = '[a-f0-9]{32}'
const validNodeId = new RegExp(`^${nodeId}$`)
export const localRegistrationRoute = '#/services/local/register'
const localRegistrationPattern = new RegExp(`^${localRegistrationRoute}(?:/(${nodeId}))?$`)
const groveRegistrationRoute = '#/services/register'
const groveRegistrationPattern = new RegExp(`^${groveRegistrationRoute}(?:/(${nodeId}))?$`)
export const remoteOperationHistoryRoutes = {
  recent: '#/operations', pending: '#/operations/pending', review: '#/operations/review',
} as const
export type RemoteOperationHistoryFilter = keyof typeof remoteOperationHistoryRoutes
const sharedSections = ['overview', 'nodes', 'topology', 'ssh', 'services', 'services/local', 'services/remote', 'operations',
  'operations/pending', 'operations/review', 'operations/local', 'exposures', 'alerts', 'access', 'audit', 'deployments', 'settings', 'sessions', 'seeds',
  'identity', 'maintenance', 'account', 'account/sessions', 'account/settings', 'pollen', 'federation']
const sharedRoutes = new Set(sharedSections.map((section) => `#/${section}`))
const seedProgressRoute = new RegExp(`^#/seeds/progress/([^/]+)(?:/(${nodeId}))?$`)
const nodeDetailRoute = new RegExp(`^#/nodes/(${nodeId})(?:/(resources))?$`)
const savedRemoteOperationRoute = new RegExp(`^#/operations/remote/(${nodeId})/(${identifier})/(${identifier})(?:/(pending|review))?$`)
const seedJoinRoute = new RegExp(`^#/access/join/(${nodeId})$`)
const topologyTargetRoute = new RegExp(`^#/topology/(${nodeId})$`)
const terminalTargetRoute = new RegExp(`^#/ssh/(${nodeId})$`)
const deploymentTargetRoute = new RegExp(`^#/(?:deployments|maintenance)/(${nodeId})$`)
const remoteServiceRoute = new RegExp(`^#/services/remote/(${nodeId})/(${identifier})(?:/(logs)(?:/(${identifier}))?|/(${identifier}))?$`)
const remoteServiceSyncRoute = new RegExp(`^#/services/remote/(${nodeId})/(${identifier})/sync$`)
const validIdentifier = new RegExp(`^${identifier}$`)
const remoteDirectoryRoute = new RegExp(`^#/services/remote/(${nodeId})$`)
const localServiceRoute = new RegExp(`^#/services/(${identifier})(?:/(logs|history|access(?:/${nodeId})?))?$`)

export type LocalServiceTab = 'overview' | 'logs' | 'history' | 'access'

export function nodeResourcesHref(id: string) {
  return `#/nodes/${encodeURIComponent(id)}/resources`
}

export function nodeResourcesTarget(hash: string) {
  const match = nodeDetailRoute.exec(hash)
  return match?.[0] === hash && match[2] ? match[1] : undefined
}

export function localServiceHref(serviceId: string, tab: LocalServiceTab = 'overview') {
  return `#/services/${encodeURIComponent(serviceId)}${tab === 'overview' ? '' : '/' + tab}`
}

export function remoteServiceHref(nodeId: string, serviceId: string, showLogs = false, requestId?: string) {
  const receipt = requestId?.length === 32 && validIdentifier.test(requestId) ? `/${requestId}` : ''
  return `#/services/remote/${encodeURIComponent(nodeId)}/${encodeURIComponent(serviceId)}${showLogs ? '/logs' : ''}${receipt}`
}

export function remoteServiceTarget(hash: string) {
  const sync = remoteServiceSyncRoute.exec(hash)
  if (sync?.[0] === hash) return { nodeId: sync[1], serviceId: sync[2], showLogs: false, syncOnOpen: true }
  const match = remoteServiceRoute.exec(hash)
  if (match?.[0] === hash) return { nodeId: match[1], serviceId: match[2], showLogs: !!match[3], requestId: match[4] ?? match[5] }
}

export function remoteServiceSyncHref(nodeId: string, serviceId: string) {
  return `${remoteServiceHref(nodeId, serviceId)}/sync`
}

export function savedRemoteOperationHref(nodeId: string, serviceId: string, requestId: string, filter: RemoteOperationHistoryFilter = 'recent') {
  return `#/operations/remote/${encodeURIComponent(nodeId)}/${encodeURIComponent(serviceId)}/${encodeURIComponent(requestId)}${filter === 'recent' ? '' : `/${filter}`}`
}

export function savedRemoteOperationTarget(hash: string) {
  const match = savedRemoteOperationRoute.exec(hash)
  if (match?.[0] === hash) return { nodeId: match[1], serviceId: match[2], requestId: match[3],
    filter: (match[4] ?? 'recent') as RemoteOperationHistoryFilter }
}

export function serviceAccessRoute(serviceId: string, sourceId?: string) {
  const path = `#/services/${encodeURIComponent(serviceId)}/access`
  return sourceId && validNodeId.test(sourceId) ? `${path}/${sourceId}` : path
}

export function serviceRegistrationRoute(sourceId?: string) {
  return sourceId && validNodeId.test(sourceId) ? `${localRegistrationRoute}/${sourceId}` : localRegistrationRoute
}

export function serviceRegistrationTarget(hash: string) {
  const match = localRegistrationPattern.exec(hash)
  if (match) return { sourceNodeId: match[1] || undefined }
}

export function groveServiceRegistrationHref(targetId?: string) {
  return targetId && validNodeId.test(targetId) ? `${groveRegistrationRoute}/${targetId}` : groveRegistrationRoute
}

export function groveServiceRegistrationTarget(hash: string) {
  const match = groveRegistrationPattern.exec(hash)
  if (match?.[0] === hash) return { targetId: match[1] || undefined }
}

export function seedJoinHref(expectedNodeId?: string) {
  return expectedNodeId?.length === 69 && validNodeId.test(expectedNodeId) ? `#/access/join/${expectedNodeId}` : '#/access'
}

export function seedJoinTarget(hash: string) {
  const match = seedJoinRoute.exec(hash)
  return match?.[0] === hash ? match[1] : undefined
}

export function deploymentTarget(hash: string) {
  const match = deploymentTargetRoute.exec(hash)
  return match?.[0] === hash ? match[1] : undefined
}

export function seedProgressHref(origin: string, expectedNodeId?: string) {
  const path = `#/seeds/progress/${encodeURIComponent(origin)}`
  return expectedNodeId && validNodeId.test(expectedNodeId) ? `${path}/${expectedNodeId}` : path
}

export function seedProgressTarget(hash: string) {
  const match = seedProgressRoute.exec(hash)
  if (!match) return undefined
  try {
    const origin = decodeURIComponent(match[1])
    return memberPanelOrigin(origin) === origin ? { origin, nodeId: match[2] || undefined } : undefined
  } catch {
    return undefined
  }
}

export function groveReturnRoute(hash: string): string {
  const base = hash.split('?')[0]
  if (base !== hash) return groveReturnRoute(base) === base ? hash : '#/services'
  if (hash.startsWith('#/seeds/')) return seedProgressTarget(hash) ? hash : '#/seeds'
  return sharedRoutes.has(hash) || serviceRegistrationTarget(hash) || groveServiceRegistrationTarget(hash) || seedJoinTarget(hash)
    || nodeDetailRoute.test(hash) || savedRemoteOperationTarget(hash) || topologyTargetRoute.test(hash) || terminalTargetRoute.test(hash) || deploymentTarget(hash)
    || localServiceRoute.test(hash) || remoteDirectoryRoute.test(hash) || remoteServiceTarget(hash) ? hash : '#/overview'
}

export function grovePanelRoute(hash: string, targetId: string, currentId?: string, memberOrigins?: ReadonlyMap<string, string>) {
  if (sharedRoutes.has(hash)) return hash
  if (terminalTargetRoute.test(hash)) return hash
  const setup = groveServiceRegistrationTarget(hash)
  if (setup) return setup.targetId === targetId ? localRegistrationRoute : hash
  const joining = seedJoinTarget(hash)
  if (joining) return joining === targetId ? hash : '#/access'
  if (hash.startsWith('#/seeds/')) return seedProgressTarget(hash) ? hash : '#/seeds'
  const deployment = deploymentTarget(hash)
  if (deployment) return deployment !== targetId && memberOrigins?.has(deployment) ? hash : '#/deployments'
  const topologyTarget = topologyTargetRoute.exec(hash)
  if (topologyTarget) {
    const node = topologyTarget[1]
    return node !== targetId && memberOrigins?.has(node) ? hash : '#/topology'
  }
  const selectedNode = nodeDetailRoute.exec(hash)
  if (selectedNode && memberOrigins?.has(selectedNode[1])) return hash
  const remote = remoteServiceTarget(hash)
  if (remote) return remote.nodeId === targetId ? localServiceHref(remote.serviceId, remote.showLogs ? 'logs' : 'overview')
    : remoteServiceHref(remote.nodeId, remote.serviceId, remote.showLogs)
  const directory = remoteDirectoryRoute.exec(hash)
  if (directory) return directory[1] === targetId ? '#/services/local' : hash
  const local = localServiceRoute.exec(hash)
  if (local && currentId && currentId !== targetId && validNodeId.test(currentId)) {
    return remoteServiceHref(currentId, local[1], local[2] === 'logs')
  }
  if (hash.startsWith('#/services/remote/')) return '#/services/remote'
  if (hash.startsWith('#/services/')) return '#/services'
  if (hash.startsWith('#/nodes/')) return '#/nodes'
  const savedOperation = savedRemoteOperationTarget(hash)
  if (savedOperation) return remoteOperationHistoryRoutes[savedOperation.filter]
  if (hash.startsWith('#/operations/remote/')) return '#/operations'
  return '#/overview'
}
