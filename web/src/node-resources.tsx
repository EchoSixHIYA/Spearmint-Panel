import { useEffect, useRef, useState } from 'react'
import { ApiError, timestamp } from './api'
import { useConsole, type Metrics, type NodeView } from './console-data'
import { hostSampleCurrent } from './host-resources'
import { workspace, workspaceError } from './workspace-api'
import { bytes } from './ui'
import { resourcePoll } from './node-resource-poll'

export type NodeResourceSample = { metrics?: Metrics; error?: string; receivedAt: number }

/** A single bounded read queue for the visible map; the small relationship map does not issue duplicate reads. */
export function useNodeResources(nodes: NodeView[], enabled: boolean) {
  const { session, onUnauthorized, local, metrics, admin, grove } = useConsole()
  const scope = `${local.data?.node_id}/${grove.data?.realm?.id}/${session.csrf_token}`
  const targets = JSON.stringify(enabled && admin && grove.data?.configured ? nodes.filter(node => !node.local && node.status === 'online').map(node => node.id).sort() : [])
  const targetIds = useRef<string[]>([])
  targetIds.current = JSON.parse(targets)
  const polling = useRef<ReturnType<typeof resourcePoll> | null>(null)
  const [collected, setCollected] = useState<{ scope: string; samples: Record<string, NodeResourceSample> }>({ scope: '', samples: {} })
  useEffect(() => {
    let flushTimer: number | undefined, stopped = false
    let pending: Record<string, NodeResourceSample> = {}
    function flush() {
      clearTimeout(flushTimer); flushTimer = undefined
      if (stopped || !Object.keys(pending).length) return
      const updates = pending; pending = {}
      setCollected(previous => {
        const samples = previous.scope === scope ? { ...previous.samples } : {}
        for (const [id, sample] of Object.entries(updates)) samples[id] = sample.error && samples[id]?.metrics
          ? { ...samples[id], error: sample.error } : sample
        return { scope, samples }
      })
    }
    const poll = resourcePoll(async (id, signal) => {
      let retry = 5000
      try {
        const host = await workspace<{ node_id: string; metrics: Metrics }>(id, session, 'host', {}, signal)
        if (signal.aborted || stopped) return retry
        if (host.node_id !== id || !host.metrics) throw new Error('No matching host sample')
        pending[id] = { metrics: host.metrics, receivedAt: Date.now() }
      } catch (error) {
        if (signal.aborted || stopped) return retry
        if (error instanceof ApiError && error.status === 401) onUnauthorized()
        pending[id] = { error: workspaceError(error), receivedAt: Date.now() }
        retry = 15000
      }
      flushTimer ??= window.setTimeout(flush, 100)
      return retry
    }, () => document.visibilityState === 'visible')
    polling.current = poll
    poll.setTargets(targetIds.current)
    document.addEventListener('visibilitychange', poll.resume)
    return () => { stopped = true; poll.close(); polling.current = null; clearTimeout(flushTimer); document.removeEventListener('visibilitychange', poll.resume) }
  }, [scope, session, onUnauthorized])
  useEffect(() => { polling.current?.setTargets(targetIds.current) }, [targets])
  const samples = new Map<string, NodeResourceSample>(collected.scope === scope ? Object.entries(collected.samples) : [])
  if (local.data) samples.set(local.data.node_id, { metrics: metrics.data, error: metrics.error || undefined, receivedAt: Date.now() })
  return samples
}

const percent = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null
const usage = (used?: number | null, total?: number | null) => total && used != null ? `${bytes(used)} / ${bytes(total)}` : '暂无数据'

export function NodeResourceStats({ sample, online }: { sample?: NodeResourceSample; online: boolean }) {
  const data = sample?.metrics
  const fresh = online && !sample?.error && hostSampleCurrent(data, Date.now())
  const memory = data?.memory, disk = data?.root_disk ?? data?.state_disk
  const gpu = data?.gpu
  const devices = gpu?.devices ?? []
  const loads = devices.map(device => percent(device.utilization_percent)).filter((value): value is number => value !== null)
  const gpuFresh = fresh && gpu?.status === 'available' && !gpu.stale && (gpu.valid_until ?? 0) * 1000 > Date.now()
  const gpuDetail = devices.length ? devices.map(device => `${device.name} · ${percent(device.utilization_percent) == null ? '利用率未上报' : device.utilization_percent + '%'} · 显存 ${usage(device.memory_used_bytes, device.memory_total_bytes)}`).join('\n') : '节点尚未上报 GPU 采样'
  const fields = [
    { label: 'CPU', value: percent(data?.cpu_percent), detail: 'CPU 使用率', fresh },
    { label: 'GPU', value: loads.length ? Math.max(...loads) : null, detail: `${devices.length > 1 ? '最忙的 GPU；' : ''}${gpuDetail}`, fresh: gpuFresh },
    { label: '内存', value: memory?.total ? percent((1 - memory.available / memory.total) * 100) : null, detail: `已用内存 ${usage(memory ? memory.total - memory.available : null, memory?.total)}`, fresh },
    { label: '磁盘', value: percent(disk?.percent), detail: `系统盘 ${usage(disk?.used, disk?.total)}`, fresh },
  ]
  return <span className="mesh-node-resources" aria-label="节点资源占用">{fields.map(field => <span key={field.label}
    className={`mesh-resource${field.value != null && !field.fresh ? ' is-stale' : ''}${field.fresh && field.value != null && field.value >= 90 ? ' is-high' : ''}`}
    title={`${field.detail}${field.value != null && !field.fresh ? `\n上次采样 ${timestamp((field.label === 'GPU' ? gpu?.sampled_at : data?.sampled_at) ?? null)}` : ''}${sample?.error ? `\n${sample.error}` : ''}`}>
    <span>{field.label}</span><b>{field.fresh && field.value != null ? `${Math.round(field.value)}%` : '—'}</b>
  </span>)}</span>
}
