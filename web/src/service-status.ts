export const serviceFilters = {
  all: '全部',
  running: '运行中',
  attention: '需要关注',
  unhealthy: '健康检查异常',
  stopped: '已停止',
}

export type ServiceFilter = keyof typeof serviceFilters

export const serviceHealthLabels = {
  starting: '健康检查等待就绪',
  healthy: '健康检查通过',
  unhealthy: '健康检查异常',
}

export type ServiceHealth = keyof typeof serviceHealthLabels

export function serviceHealthState(health: string | null | undefined, stale: boolean): ServiceHealth | undefined {
  if (!stale && health && Object.hasOwn(serviceHealthLabels, health)) return health as ServiceHealth
}

type ServiceObservation = { status: string | null; stale: boolean; health?: string | null }

export function serviceAttention({ status, stale, health }: ServiceObservation) {
  if (stale) return 'stale'
  if (status === 'failed' || status === 'missing' || status === 'unknown') return status
  if (health === 'unhealthy') return 'unhealthy'
}

export function matchesServiceStatus(filter: ServiceFilter, observation: ServiceObservation | null) {
  if (filter === 'all') return true
  if (!observation) return false
  if (filter === 'attention') return serviceAttention(observation) !== undefined
  if (filter === 'unhealthy') return serviceHealthState(observation.health, observation.stale) === 'unhealthy'
  return !observation.stale && observation.status === filter
}
