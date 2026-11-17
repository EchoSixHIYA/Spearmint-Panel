import type { Metrics } from './console-data'
import type { ConsoleAlert } from './service-alerts'
import { nodeResourcesHref } from './grove-navigation.ts'

export const resourceWarningPercent = 90

export type HostResource = {
  id: string; label: string; icon: string; percent?: number | null; available?: number; total?: number
}

export type HostTrendPoint = {
  sampled_at: number
  cpu_percent: number | null
  memory_percent: number | null
  root_disk_percent: number | null
  state_disk_percent: number | null
}

export type HostTrend = {
  sampled_at: number; window_seconds: number; points: HostTrendPoint[]
}

const trendResources = {
  cpu_percent: 'CPU', memory_percent: '内存', root_disk_percent: '系统盘', state_disk_percent: '状态目录磁盘',
} satisfies Record<Exclude<keyof HostTrendPoint, 'sampled_at'>, string>

export function hostTrendSeries({ sampled_at, window_seconds, points }: HostTrend) {
  const start = sampled_at - window_seconds
  return (Object.keys(trendResources) as (keyof typeof trendResources)[]).map((key) => {
    const segments: { x: number; y: number }[][] = []
    let previousTime = -Infinity
    let peak: { value: number; time: number } | undefined
    for (const point of points) {
      const time = point.sampled_at
      const value = point[key]
      if (time < start || time > sampled_at) continue
      if (value == null || !Number.isFinite(value)) {
        previousTime = -Infinity
        continue
      }
      if (time - previousTime > 4) segments.push([])
      segments.at(-1)?.push({ x: (time - start) / window_seconds * 100, y: 100 - value })
      previousTime = time
      if (!peak || value >= peak.value) peak = { value, time }
    }
    return { label: trendResources[key], segments, peak }
  })
}

export function hostResources(sample?: Metrics): HostResource[] {
  const memory = sample?.memory
  const root = sample?.root_disk
  const sameDisk = sample?.state_disk_is_root === true && root != null
  return [
    { id: 'memory', label: '内存', icon: 'layers',
      percent: memory?.total ? (memory.total - memory.available) / memory.total * 100 : null,
      available: memory?.available, total: memory?.total },
    ...(sample?.state_disk_is_root !== undefined ? [
      { id: 'system-disk', label: sameDisk ? '系统盘（含状态目录）' : '系统盘', icon: 'hard-drive',
        percent: root?.percent, available: root?.free, total: root?.total },
    ] : []),
    ...(!sameDisk ? [
      { id: 'state-disk', label: '状态目录磁盘', icon: 'hard-drive',
        percent: sample?.state_disk?.percent, available: sample?.state_disk?.free, total: sample?.state_disk?.total },
    ] : []),
  ]
}

export function hostSampleCurrent(sample: Metrics | undefined, now: number): sample is Metrics & { valid_until: number } {
  return !!sample && !sample.stale && sample.valid_until != null && sample.valid_until * 1000 > now
}

export function hostResourceAlerts(sample: Metrics | undefined, nodeId: string, name: string, now: number): ConsoleAlert[] {
  if (!hostSampleCurrent(sample, now)) return []
  return hostResources(sample).flatMap(({ id, label, percent }) => {
    if (percent == null || percent < resourceWarningPercent) return []
    return [{ id: `resource/${id}`, kind: 'resource', title: `${label}使用率偏高`, tone: 'amber',
      detail: `当前使用率 ${percent.toFixed(1)}%`, href: nodeResourcesHref(nodeId),
      source: name, checkedAt: sample.sampled_at, validUntil: sample.valid_until }]
  })
}
