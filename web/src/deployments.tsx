import { useConsole } from './console-data'
import { usePoll } from './api'
import { GroveUpdatePanel } from './grove-updates'
import { Badge, Icon, PageHeading, Panel } from './ui'
import { updatePresentation, updateProgress, type GroveUpdate } from './grove-update-state'

type NodeVersion = { node_id: string; build: { version: string | null; commit?: string | null } }

function TargetVersion({ id }: { id: string }) {
  const { local, listedNodes, onUnauthorized, grove } = useConsole()
  const node = listedNodes.find(item => item.id === id)
  const isLocal = id === local.data?.node_id
  const version = usePoll<NodeVersion>(node && !isLocal ? `/grove/deployments/${id}` : null, onUnauthorized, 15_000)
  const status = usePoll<GroveUpdate>(grove.data?.realm ? '/grove/updates' : null, onUnauthorized, 4000, undefined, grove.data?.realm?.id)
  const batch = status.data?.job ? status.data : undefined
  const build = isLocal ? local.data?.build : version.data?.node_id === id ? version.data.build : undefined
  const value = build?.commit && build.commit === batch?.release.commit ? batch.release.tag : build?.version ? `v${build.version}` : '—'
  const result = batch?.nodes[id]
  const view = result && updatePresentation(updateProgress(result, batch.expires))
  return <Panel className="maintenance-node" title={<span className="maintenance-target-name"><Icon name="server" size={18} />{node?.name ?? '目标节点'}</span>}
    action={<a className="text-link" href="#/maintenance">前往群组更新<Icon name="arrow-right" size={14} /></a>}>
    <dl className="maintenance-node-facts"><div><dt>当前版本</dt><dd>{value}</dd></div>
      <div><dt>最近更新</dt><dd>{view ? <><span>{batch!.release.tag}</span><Badge tone={view.tone}>{view.label}</Badge></> : '—'}</dd></div></dl>
    {view?.detail && <p className="maintenance-feedback muted">{view.detail}</p>}
    {(isLocal ? local.error : version.error) && <p className="maintenance-feedback muted">版本暂时无法刷新，连接恢复后自动重试。</p>}
  </Panel>
}

export function DeploymentsPage({ targetId }: { targetId?: string }) {
  const { grove } = useConsole()
  return <div className="maintenance-page">
    {targetId && <a className="back-link" href="#/maintenance"><Icon name="arrow-left" size={15} />返回平台维护</a>}
    <PageHeading eyebrow="MANAGEMENT / PLATFORM" title={targetId ? '节点版本与更新' : '平台维护'}
      description={targetId ? '查看此节点的版本和最近更新结果。' : '更新 Spearmint，查看节点更新结果。'} />
    {targetId ? <TargetVersion key={`${grove.data?.realm?.id}/${targetId}`} id={targetId} /> : <GroveUpdatePanel key={grove.data?.realm?.id ?? 'unconfigured'} />}
  </div>
}
