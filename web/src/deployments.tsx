import { useConsole } from './console-data'
import { usePoll } from './api'
import { GroveUpdatePanel } from './grove-updates'
import { Icon, PageHeading, Panel } from './ui'

type NodeVersion = { node_id: string; build: { version: string | null } }

function TargetVersion({ id }: { id: string }) {
  const { local, listedNodes, onUnauthorized } = useConsole()
  const node = listedNodes.find(item => item.id === id)
  const isLocal = id === local.data?.node_id
  const version = usePoll<NodeVersion>(node && !isLocal ? `/grove/deployments/${id}` : null, onUnauthorized, 15_000)
  const value = isLocal ? local.data?.build?.version : version.data?.node_id === id ? version.data.build.version : undefined
  return <Panel className="maintenance-target">
    <Icon name="server" size={18} />
    <strong>{node?.name ?? '目标节点'}</strong>
    <span className="maintenance-target-version">Spearmint {value ? `v${value}` : '—'}</span>
    {(isLocal ? local.error : version.error) && <span className="muted tiny">版本暂时无法读取</span>}
    <a className="text-link" href="#/maintenance">查看全部更新<Icon name="arrow-right" size={14} /></a>
  </Panel>
}

export function DeploymentsPage({ targetId }: { targetId?: string }) {
  return <div className="maintenance-page">
    <PageHeading eyebrow="MANAGEMENT / PLATFORM" title="平台维护" description="更新 Spearmint，查看节点更新结果。" />
    {targetId && <TargetVersion key={targetId} id={targetId} />}
    <GroveUpdatePanel />
  </div>
}
