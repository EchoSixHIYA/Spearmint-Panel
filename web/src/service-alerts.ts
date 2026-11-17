import type { NodeView } from './console-data'
import { localServiceHref, remoteServiceHref } from './grove-navigation.ts'
import type { NodeDirectory } from './remote-catalog'
import { remoteDirectoryCurrent } from './remote-directory.ts'
import { remoteObservationState } from './remote-observation.ts'
import { serviceAttention, serviceHealthLabels } from './service-status.ts'
import type { Service } from './services'

export type ConsoleAlert = {
  id: string; title: string; detail: string; href: string
  kind: 'node' | 'service' | 'resource' | 'connection'; tone: 'red' | 'amber'
  source?: string; checkedAt?: number | null; validUntil?: number
}

const descriptions = {
  failed: '服务运行失败',
  missing: '所属节点未找到该服务',
  unknown: '所属节点无法确认运行状态',
  unhealthy: serviceHealthLabels.unhealthy,
  stale: '服务观测已过期',
}

export function localServiceAlerts(services: readonly Service[], source: string): ConsoleAlert[] {
  return services.flatMap(({ id, name, observation }) => {
    const issue = serviceAttention(observation)
    if (!issue) return []
    return [{ id: `service/local/${id}`, kind: 'service', title: `${name} 需要关注`, href: localServiceHref(id),
      detail: issue === 'stale' || issue === 'unhealthy' ? descriptions[issue] : observation.message || descriptions[issue],
      tone: issue === 'failed' || issue === 'unhealthy' ? 'red' : 'amber',
      source, checkedAt: observation.checked_at }]
  })
}

export function remoteServiceAlerts(nodes: ReadonlyMap<string, NodeView>, directories: readonly NodeDirectory[], now: number): ConsoleAlert[] {
  return directories.flatMap(directory => {
    const node = nodes.get(directory.node_id)
    if (!node || node.local || !node.peer?.enabled || !remoteDirectoryCurrent(node, directory)) return []
    return directory.services.flatMap(service => {
      const report = service.observation
      if (!service.status || !report || report.valid_until == null) return []
      const observed = remoteObservationState(report, false, now)
      if (observed.stale) return []
      const issue = serviceAttention(observed)
      if (!issue) return []
      return [{ id: `service/${node.id}/${service.id}`, kind: 'service', title: `${service.name} 需要关注`,
        href: remoteServiceHref(node.id, service.id), detail: descriptions[issue],
        tone: issue === 'failed' || issue === 'unhealthy' ? 'red' : 'amber',
        source: node.name, checkedAt: report.checked_at, validUntil: report.valid_until }]
    })
  })
}
