import { useState } from 'react'
import { usePoll } from './api'
import { useConsole } from './console-data'
import { RemoteOperations } from './remote-operations'
import type { Action } from './services'
import { Badge, EmptyState, Icon, Loading, Notice, Panel, shortId } from './ui'

export type MeshService = { node_id: string; service_id: string; name: string; version: number; actions: Action[]; key_ids: string[]; stale: boolean }

export function MeshOperations() {
  const { session, onUnauthorized } = useConsole()
  const { data, error } = usePoll<MeshService[]>('/mesh/services', onUnauthorized)
  const [selected, setSelected] = useState('')
  const service = selected ? data?.find((entry) => `${entry.node_id}/${entry.service_id}` === selected) : data?.[0]
  return <div className={`approval-layout ${data?.length ? '' : 'empty-approval'}`}><Panel title="选择授权服务">
    {error && <Notice tone="amber">{error}</Notice>}{!data && !error ? <Loading /> : data?.length ? <div className="approval-services">{data.map((entry) => {
      const id = `${entry.node_id}/${entry.service_id}`
      const stale = entry.stale || !!error
      return <button key={id} className={`approval-service ${service === entry ? 'selected' : ''}`} aria-pressed={service === entry} onClick={() => setSelected(id)}><span className="service-symbol"><Icon name="layers" size={18} /></span><span><strong>{entry.name}</strong><small>{shortId(entry.node_id)}</small></span><Badge tone={stale ? 'amber' : 'sage'}>{stale ? '待同步' : entry.actions.length ? '可申请' : '历史'}</Badge></button>
    })}</div> : <EmptyState icon="shield-check" title="还没有可操作的远程服务">当前账户没有可用的远程操作授权。请联系独立授权方配置策略与账户映射。</EmptyState>}
  </Panel>{service && <Panel title={service.name} action={<Badge tone="sage">独立签名批准</Badge>}>
    {(service.stale || error) && <Notice tone="amber" title="当前服务状态尚未恢复">授权列表恢复后可发起新操作。已知回执仍可查看。</Notice>}
    <RemoteOperations key={`${service.node_id}/${service.service_id}`} path={`/mesh/peers/${service.node_id}/services/${service.service_id}`}
      actions={service.actions} keyIds={service.key_ids} version={service.version} stale={service.stale || !!error}
      session={session} onUnauthorized={onUnauthorized} />
  </Panel>}
  {selected && data?.length && !service ? <Panel><EmptyState title="所选服务暂时不在授权列表">可从列表选择其他服务。</EmptyState></Panel> : null}</div>
}
