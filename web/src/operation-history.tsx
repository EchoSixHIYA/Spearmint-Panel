import { timestamp, usePoll } from './api'
import { refreshConsole, useConsole } from './console-data'
import { receiptFinished, ReceiptBadge, ReceiptStatus, type History } from './remote-operations'
import { localServiceHref, remoteOperationHistoryRoutes, remoteServiceHref, savedRemoteOperationHref, type RemoteOperationHistoryFilter } from './grove-navigation'
import { actions, LocalOperationBadge, localOperationMessage, type Operation } from './services'
import { CopyValue, EmptyState, Icon, Loading, Notice, PageHeading, Panel, shortId } from './ui'

type RemoteHistory = History & { node_id: string; service_id: string; service_name: string | null }
type LocalHistory = Operation & { service_id: string; service_name: string | null }

const historyFilters = {
  recent: { label: '最近操作', path: '/operations/remote', description: '显示此节点保存的最近 50 笔普通远程服务操作。',
    empty: '此面板暂无远程操作记录' },
  pending: { label: '待跟踪', path: '/operations/remote?pending=true', description: '显示最近 50 笔等待回执、排队中或执行中的操作。',
    empty: '暂无待跟踪的远程操作' },
  review: { label: '需人工核对', path: '/operations/remote/review', description: '显示最近 50 笔目标已回报「结果待确认」的操作。打开回执可查看原因，并核对服务当前状态。',
    empty: '暂无需人工核对的远程操作' },
} satisfies Record<RemoteOperationHistoryFilter, { label: string; path: string; description: string; empty: string }>

export function LocalOperationHistory() {
  const { onUnauthorized } = useConsole()
  const { data, error } = usePoll<LocalHistory[]>('/operations/local', onUnauthorized)

  return <Panel title="本机操作记录" action={<button type="button" className="btn btn-secondary btn-small" onClick={refreshConsole}>
    <Icon name="refresh" size={14} />刷新记录</button>}>
    <p className="muted tiny">显示当前账号在此节点提交的最近 50 笔服务操作。</p>
    {error && <Notice tone="amber" title="暂时无法更新操作记录">{error}</Notice>}
    {!data && !error && <Loading label="正在读取操作记录…" />}
    {data?.length === 0 && !error && <EmptyState icon="activity" title="此账号暂无本机操作记录"
      action={<a className="btn btn-primary" href="#/services/local">打开本机服务</a>} />}
    {!!data?.length && <div className="table-wrap"><table className="data-table service-table">
      <thead><tr><th scope="col">服务</th><th scope="col">动作</th><th scope="col">结果</th>
        <th scope="col">最近更新</th><th scope="col">操作 ID</th></tr></thead>
      <tbody>{data.map((entry) => {
        const message = localOperationMessage(entry)
        return <tr key={entry.id}>
          <td>{entry.service_name ? <a className="text-link" href={localServiceHref(entry.service_id, 'history')}>
            {entry.service_name}<Icon name="arrow-up-right" size={13} />
          </a> : <><span>服务已移除</span><small className="table-secondary"><CopyValue value={entry.service_id} short /></small></>}</td>
          <td>{actions[entry.action]}</td><td><LocalOperationBadge operation={entry} />
            {message && <small className="table-secondary operation-message">{message}</small>}</td>
          <td className="time-cell">{timestamp(entry.updated_at)}</td><td><CopyValue value={entry.id} short /></td>
        </tr>
      })}</tbody>
    </table></div>}
  </Panel>
}

export function OperationHistory({ filter }: { filter: RemoteOperationHistoryFilter }) {
  const { nodes, onUnauthorized } = useConsole()
  const view = historyFilters[filter]
  const { data, error, errorStatus } = usePoll<RemoteHistory[]>(view.path, onUnauthorized)
  const rows = filter === 'pending' ? data?.filter(entry => !receiptFinished(entry.receipt ?? undefined)) : data
  const names = new Map(nodes.map(({ id, name }) => [id, name]))

  return <Panel title="此面板最近的远程操作" action={<button className="btn btn-secondary btn-small" onClick={refreshConsole}>
    <Icon name="refresh" size={14} />刷新记录</button>}>
    <div className="filter-pills" role="group" aria-label="筛选远程操作记录">
      {(Object.keys(historyFilters) as RemoteOperationHistoryFilter[]).map(id => <a key={id} href={remoteOperationHistoryRoutes[id]}
        className={`pill ${filter === id ? 'active' : ''}`} aria-current={filter === id ? 'page' : undefined}>{historyFilters[id].label}</a>)}
    </div>
    <p className="muted tiny">{view.description}</p>
    {error && (filter === 'review' && errorStatus === 404
      ? <Notice tone="amber">此节点版本尚未提供人工核对列表。<a className="text-link" href={remoteOperationHistoryRoutes.recent}>查看最近操作</a></Notice>
      : <Notice tone="amber" title="暂时无法更新操作记录">{error}</Notice>)}
    {!data && !error && <Loading label="正在读取操作记录…" />}
    {rows?.length === 0 && !error && <EmptyState icon="activity" title={view.empty}
      action={filter === 'recent' && <a className="btn btn-primary" href="#/services/remote">打开远程服务</a>} />}
    {!!rows?.length && <div className="table-wrap"><table className="data-table service-table">
      <thead><tr><th scope="col">服务</th><th scope="col">目标节点</th><th scope="col">动作</th>
        <th scope="col">回执状态</th><th scope="col">最近更新</th><th scope="col">请求 ID</th></tr></thead>
      <tbody>{rows.map((entry) => <tr key={`${entry.node_id}/${entry.request_id}`}>
        <td><a className="text-link" href={savedRemoteOperationHref(entry.node_id, entry.service_id, entry.request_id, filter)}>
          {entry.service_name || shortId(entry.service_id)}<Icon name="arrow-up-right" size={13} />
        </a></td>
        <td>{names.get(entry.node_id) || shortId(entry.node_id)}</td>
        <td>{actions[entry.action]}</td><td><ReceiptBadge receipt={entry.receipt} /></td>
        <td className="time-cell">{timestamp(entry.updated_at)}</td><td><CopyValue value={entry.request_id} short /></td>
      </tr>)}</tbody>
    </table></div>}
  </Panel>
}

export function SavedRemoteOperation({ nodeId, serviceId, requestId, filter }: {
  nodeId: string; serviceId: string; requestId: string; filter: RemoteOperationHistoryFilter
}) {
  const { listedNodes, meshCurrent, onUnauthorized } = useConsole()
  const node = listedNodes.find((item) => item.id === nodeId)
  const service = encodeURIComponent(serviceId)
  const target = encodeURIComponent(nodeId)
  const request = encodeURIComponent(requestId)
  const { data, error } = usePoll<RemoteHistory>(`/operations/remote/${target}/${service}/${request}`, onUnauthorized)
  const stale = !meshCurrent || !node?.peer?.enabled || node.status !== 'online'
  return <>
    <a className="back-link" href={remoteOperationHistoryRoutes[filter]}>
      <Icon name="arrow-left" size={15} />{filter === 'recent' ? '返回远程操作记录' : `返回${historyFilters[filter].label}操作`}
    </a>
    <PageHeading eyebrow="OPERATIONS" title={data ? `${actions[data.action]}回执` : '远程操作回执'}
      description="从发起节点读取已保存的记录。" />
    {error && <Notice tone="amber">暂时无法读取这条操作记录。{error}</Notice>}
    {!data && !error && <Loading label="正在读取已保存的操作记录…" />}
    {data && <Panel title={data.service_name || shortId(serviceId)} action={
      <button type="button" className="btn btn-secondary btn-small" onClick={refreshConsole}>
        <Icon name="refresh" size={14} />刷新回执
      </button>}>
      <dl className="facts"><div><dt>目标节点</dt><dd>{node?.name || shortId(nodeId)}</dd></div>
        <div><dt>请求 ID</dt><dd><CopyValue value={requestId} /></dd></div>
        <div><dt>最近更新</dt><dd>{timestamp(data.updated_at)}</dd></div></dl>
      <ReceiptStatus key={`${target}/${service}/${request}`} path={`/peers/${target}/services/${service}/operations/${request}`}
        onUnauthorized={onUnauthorized} initial={data.receipt ?? undefined} stale={stale} connectionId={node?.peer?.connection_id} />
      {node?.peer && <a className="text-link" href={remoteServiceHref(nodeId, serviceId, false, requestId)}>打开远程服务<Icon name="arrow-right" size={14} /></a>}
    </Panel>}
  </>
}
