import { useCallback, useEffect, useEffectEvent, useId, useRef, useState } from 'react'
import { ApiError, api, READ_TIMEOUT_MS, type Session, timestamp, usePoll } from './api'
import { drivers, serviceSearchText, ServiceState, statuses } from './services'
import { refreshConsole, useConsole, type NeighborUse, type NodeView, type RouteDiagnostics, type RouteObservation } from './console-data'
import { RemoteActions } from './remote-actions'
import { FrpMappings } from './frp-mappings'
import { ServiceLogs } from './service-logs'
import { Badge, CopyValue, EmptyState, Icon, Loading, NodeConnectionBadge, Notice, PageHeading, Panel, ServiceHealthBadge, ServiceStatusFilters, shortId } from './ui'
import { remoteDirectoryCurrent, useRemoteCatalog, useRemoteObservationTime, type NodeDirectory, type RemoteDirectory, type RemoteService } from './remote-catalog'
import { remoteObservationState, type RemoteObservation } from './remote-observation'
import { groveServiceRegistrationHref, localServiceHref, remoteServiceHref, savedRemoteOperationHref, serviceAccessRoute } from './grove-navigation'
import { matchesServiceStatus, type ServiceFilter } from './service-status'
import { pathLabel } from './connection-status'
import { directoryQuery, directoryScope } from './remote-directory'

function RemoteServiceState({ observation, directoryStale, now }: {
  observation: RemoteObservation | null; directoryStale: boolean; now: number
}) {
  if (!observation) return directoryStale ? '目录待同步' : '暂无状态'
  const { stale, status, health } = remoteObservationState(observation, directoryStale, now)
  const label = status && (statuses[status] || status)
  if (stale) return label ? `状态待更新 · 上次${label}` : '状态待更新'
  return <>{label}{health && <> <ServiceHealthBadge health={health} /></>}</>
}

export function RouteObservations({ observations, names }: {
  observations: RouteObservation[]; names?: ReadonlyMap<string, string>
}) {
  return <div className="route-observations">
    <ul>{observations.map((record) => <li key={record.observer_node_id}>
      {names?.get(record.observer_node_id) || <CopyValue value={record.observer_node_id} short />}
      <span>{record.method === 'local' ? '报告自身就绪' : '报告已直连目标'}
        {' · '}{record.age_seconds.toFixed(1)} 秒前 · {record.remaining_seconds.toFixed(1)} 秒内有效</span>
    </li>)}</ul>
  </div>
}

export function RouteSelectionStatus({ diagnostics }: { diagnostics: RouteDiagnostics }) {
  const reason = diagnostics.deferred_switch?.reason
  const reasons: Record<string, string> = {
    candidate_unavailable: '候选会话已不可用', samples_expired: '延迟样本已过期',
    saving_lost: '备选路径的成本优势已不足', better_candidate: '发现成本更低的备选路径',
  }
  return <>
    {reason && <p>最近一次换路已推迟 · {reasons[reason] ?? '路径条件已变化'}</p>}
    <RouteSelectionProgress diagnostics={diagnostics} />
  </>
}

function RouteSelectionProgress({ diagnostics }: { diagnostics: RouteDiagnostics }) {
  const { comparison, best_alternative: alternative, preparing_switch: preparing, opening_trial: opening, waiting_for_trial: waiting } = diagnostics
  if (preparing) return <p>正在同步备选路径的服务目录并核对操作回执，准备切换。</p>
  if (comparison) return <p>备选路径成本更低，正在比较 · {Math.min(comparison.completed, comparison.required)} / {comparison.required} 组样本
    {comparison.dwell_remaining_seconds > 0 && ` · 当前路径至少再保持 ${Math.ceil(comparison.dwell_remaining_seconds)} 秒`}</p>
  if (opening) return <p>正在建立备选会话。</p>
  if (waiting) return <p>已发现备选路径，正在等待试用名额。</p>
  if (alternative) {
    if (alternative.meets_threshold) return <p>最低成本备选路径已达到换路阈值，等待下一轮比较。</p>
    return <p>{alternative.saving_ms > 0
      ? `最低成本备选路径低 ${alternative.saving_ms.toFixed(1)} ms · 换路至少需低 ${alternative.required_saving_ms.toFixed(1)} ms`
      : '在已完成采样的路径中，当前路径成本最低或并列最低。'}</p>
  }
  if (diagnostics.backup_sessions > 0) return <p>已有备选会话，正在等待足够的有效延迟样本。</p>
  return <p>{diagnostics.selected_path ? '当前只有一条已验证的可用路径。' : '正在确认可用路径。'}</p>
}

const meshPathErrors: Record<string, string> = {
  no_route: '暂时找不到可用路径', route_lost: 'Mesh 路径已断开', offline: '目标会话离线',
  timeout: '响应超时', busy: '通道容量不足', unavailable: '目录暂时不可用',
  denied: 'Mesh 节点拒绝请求', protocol: 'Mesh 协议响应无效', conflict: 'Mesh 状态已变更',
}

export function meshPathError(code?: string, fallback = '暂时无法使用') {
  return meshPathErrors[code?.toLowerCase() ?? ''] ?? fallback
}

export function RouteDetails({ diagnostics, neighbor, names, showSelection = true }: {
  diagnostics: RouteDiagnostics; neighbor?: NeighborUse; names?: ReadonlyMap<string, string>; showSelection?: boolean
}) {
  const reasons: Record<string, string> = {
    initial: '首次连接', resumed: '恢复会话', idle: '按需连接', failure: '原路径失效，已接替', lower_cost: '新路径成本持续更低',
    route_lost: '路径已断开', offline: '会话已关闭', timeout: '通信超时', busy: '通道容量不足',
  }
  const failureStages: Record<string, string> = {
    prepare: '新路径准备失败', open: '中继建链失败', connect: '路径发现失败', trial: '最近一次备路异常',
  }
  const roles: Record<string, string> = { active: '当前使用', trial: '备路试用', direct: '直连备路', inbound: '对端建立的中继' }
  const neighborRoles = { fixed: '固定邻居', trial: '候补试连', automatic: '自动邻居', candidate: '待选邻居' }
  const protections: Record<string, string> = { fixed: '固定配置', in_flight_rpc: '正在传输请求',
    relay_circuit: '承载中继通道', sole_first_hop: '近期目的的唯一首跳', recent_business: '近期业务路径' }
  const { comparison } = diagnostics
  const standbys = diagnostics.candidate_sessions.filter(route => route.role !== 'active')
  const readyDirectories = standbys.filter(route => route.directory_prepared === true).length
  const directoryCountsKnown = standbys.length === diagnostics.backup_sessions && standbys.every(route => route.directory_prepared !== undefined)
  const activePath = diagnostics.selected_path
  const [errorStage, ...errorParts] = (diagnostics.last_path_error || '').split('_')
  const pathError = errorParts.join('_')
  return <details className="route-details">
    <summary>连接详情 · {diagnostics.backup_sessions} 条备选会话
      {standbys.length > 0 && directoryCountsKnown && ` · ${readyDirectories} 条已预同步目录`}</summary>
    <p>{reasons[diagnostics.switch_reason || ''] || '正在确认可用路径'} · 已换路 {diagnostics.switches} 次</p>
    {showSelection && (diagnostics.selected_path || diagnostics.opening_trial || diagnostics.preparing_switch) &&
      <RouteSelectionStatus diagnostics={diagnostics} />}
    {pathError && <p>{failureStages[errorStage] || '连接失败'} · {meshPathError(pathError)}</p>}
    {comparison && <div className="route-comparison">
      <strong>正在比较的路径</strong>
      <ol className="route-session-path" aria-label="正在比较的路径">{comparison.path.map((node) => <li key={node}>
        {names?.get(node) || <CopyValue value={node} short />}</li>)}</ol>
    </div>}
    {neighbor && <p>物理连接：{neighborRoles[neighbor.role]} · {neighbor.connected ? neighbor.qualified ? '心跳已稳定' : '正在采样' : '尚未连接'}
      {!!neighbor.protected_by.length && <> · 保留原因：{neighbor.protected_by.map((reason) => protections[reason] || reason).join('、')}</>}
      {!neighbor.connected && neighbor.retry_seconds > 0 && <> · 约 {Math.ceil(neighbor.retry_seconds)} 秒后重试</>}</p>}
    {!!diagnostics.pending_requests && <p>待确认操作：{diagnostics.pending_requests} 笔。</p>}
    {diagnostics.candidate_sessions.length === 0 && <p>尚无已验证的可用会话。</p>}
    {diagnostics.candidate_sessions.length > 0 && <div className="table-wrap"><table className="data-table route-table">
      <caption className="sr-only">本节点已验证的连接路径</caption>
      <thead><tr><th scope="col">用途与路径</th><th scope="col">估算成本</th><th scope="col">延迟样本</th></tr></thead>
      <tbody>{diagnostics.candidate_sessions.map((route) => <tr key={route.connection_generation}>
        <td><Badge tone={route.role === 'active' ? 'green' : 'outline'}>{roles[route.role] || route.role}</Badge>
          <ol className="route-session-path" aria-label="路径节点">{route.path.map((node) => <li key={node}>{names?.get(node) || <CopyValue value={node} short />}</li>)}</ol>
          {route.role !== 'active' && <>
            <small className="table-secondary">{route.directory_prepared === true ? '已预同步服务目录'
              : route.directory_prepared === false ? '服务目录待预同步' : '服务目录状态未报告'}</small>
            {activePath?.length === route.path.length && route.path.every((id, index) => id === activePath[index]) &&
              <small className="table-secondary">与活动会话经过相同的节点</small>}
          </>}
        </td>
        <td>{route.cost_ms == null ? route.rtt_sample_age_seconds != null && route.rtt_fresh === false ? '采样已过期' : '采样中'
          : `${route.cost_ms.toFixed(1)} ms`}
          <small className="table-secondary">{route.path.length - 1} 跳</small></td>
        <td>{route.rtt_sample_count ?? 0} 个
          {route.handshake_ms != null && <small className="table-secondary">建链 {route.handshake_ms.toFixed(1)} ms</small>}
          <small className="table-secondary">{route.rtt_sample_age_seconds == null ? '等待心跳'
            : `${route.rtt_sample_age_seconds.toFixed(1)} 秒前${route.rtt_fresh ? '' : ' · 已过期'}`}</small></td>
      </tr>)}</tbody>
    </table></div>}
  </details>
}

function OwnerServiceLink({ origin, serviceId, showLogs }: { origin: string; serviceId?: string; showLogs?: boolean }) {
  const destination = serviceId ? localServiceHref(serviceId, showLogs ? 'logs' : 'overview') : '#/services/local'
  return <a className="btn btn-secondary" href={`${origin}/${destination}`}>
    {serviceId ? '打开所属节点的服务页' : '打开所属节点的服务列表'}<Icon name="arrow-up-right" size={15} />
  </a>
}

export function OwnerRegistrationLink({ nodeId }: { nodeId: string }) {
  return <a className="btn btn-secondary" href={groveServiceRegistrationHref(nodeId)}>
    登记此节点的服务<Icon name="arrow-right" size={15} />
  </a>
}

function RemoteLogsLink({ nodeId, service }: { nodeId: string; service: RemoteService }) {
  return <a className="text-link" href={remoteServiceHref(nodeId, service.id, true)} aria-label={`查看 ${service.name} 的日志`}>
    <Icon name="file-text" size={15} />查看日志
  </a>
}

function RemoteDetail({ item, nodeId, path, stale, memberOrigin, showLogs, onUnauthorized, connectionId, directoryGeneration, requestId, completedRequest, onRouteLost }: {
  item: RemoteService; nodeId: string; path: string; stale: boolean; memberOrigin?: string; showLogs: boolean; onUnauthorized: () => void
  connectionId?: string; directoryGeneration?: number; requestId?: string; completedRequest?: string
  onRouteLost: (scope: string) => void
}) {
  const scope = directoryScope(connectionId, directoryGeneration)
  const [observed, setObserved] = useState<{ scope?: string; value: RemoteObservation }>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const request = useRef<AbortController>(null)
  const lastCompletionRead = useRef<{ requestId: string; scope?: string }>(undefined)
  const heading = useId()
  const fromDirectory = item.observation
  const liveObservation = !stale && item.status && observed && observed.scope === scope ? observed.value : undefined
  const current = liveObservation && (liveObservation.checked_at ?? 0) > (fromDirectory?.checked_at ?? 0) ? liveObservation : fromDirectory
  const now = useRemoteObservationTime(stale ? [] : [current])

  useEffect(() => {
    setObserved(undefined)
    setPending(false)
    setError('')
    return () => {
      request.current?.abort()
      request.current = null
    }
  }, [path, stale, scope, item.status])

  async function readStatus() {
    if (stale || request.current) return
    const controller = new AbortController()
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    request.current = controller
    setPending(true)
    setError('')
    try {
      const query = directoryQuery(connectionId, directoryGeneration)
      const result = await api<RemoteObservation>(`${path}/status${query ? '?' + query : ''}`, {
        signal: AbortSignal.any([controller.signal, deadline]),
      })
      if (!controller.signal.aborted) setObserved({ scope, value: result })
    } catch (failure) {
      if (controller.signal.aborted) return
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else if (failure instanceof ApiError && failure.code === 'ROUTE_LOST') {
        setObserved(undefined)
        setError('服务目录已变化，同步后可重新读取。')
        if (scope) onRouteLost(scope)
        else refreshConsole()
      }
      else setError(deadline.aborted ? '读取超时，请重试。' : failure instanceof Error ? failure.message : '读取失败')
    } finally {
      if (request.current === controller) {
        request.current = null
        setPending(false)
      }
    }
  }

  const readAfterOperation = useEffectEvent(() => {
    const previous = lastCompletionRead.current
    if (!completedRequest || request.current || (previous?.requestId === completedRequest && previous.scope === scope)) return
    lastCompletionRead.current = { requestId: completedRequest, scope }
    void readStatus()
  })
  useEffect(() => {
    if (!stale && item.status && !pending) readAfterOperation()
  }, [completedRequest, scope, item.status, pending, stale])

  return <article className="service-detail" aria-labelledby={heading}>
    <h3 id={heading}>{item.name}</h3>
    <p>{drivers[item.driver]} · <RemoteServiceState observation={item.status ? current : null} directoryStale={stale} now={now} /></p>
    {current && <p className="muted">由所属节点通过 {drivers[current.source] || drivers[item.driver]} 检查
      {current.checked_at != null && <> · 最近检查 {timestamp(current.checked_at)}</>}
      {current.valid_until != null && <> · 有效期至 {timestamp(current.valid_until)}</>}
      {current.last_seen_at != null && current.last_seen_at !== current.checked_at && <> · 上次有效观测 {timestamp(current.last_seen_at)}</>}
    </p>}
    <div className="button-row">
      {item.status && <button className="secondary" disabled={stale || pending} onClick={() => void readStatus()}>
        {pending ? '读取中…' : '刷新远程状态'}
      </button>}
      {(item.logs || showLogs) && <button className="secondary" disabled={!showLogs && stale} aria-expanded={item.logs && !stale && showLogs}
        onClick={() => { location.hash = remoteServiceHref(nodeId, item.id, !showLogs, requestId) }}>
        {showLogs ? '收起远程日志' : '读取远程日志'}
      </button>}
      <a className="btn btn-secondary" href={groveServiceRegistrationHref(nodeId)}>设置托管<Icon name="arrow-right" size={15} /></a>
      {memberOrigin && <OwnerServiceLink origin={memberOrigin} serviceId={item.id} showLogs={showLogs} />}
    </div>
    {error && <p className="error" role="alert">{error}</p>}
    {showLogs && !stale && !item.logs && <Notice>当前面板没有此服务的日志权限。</Notice>}
  </article>
}

export function PeerDirectory({ node, memberOrigin, session, onUnauthorized, serviceId, requestId, showLogs = false, syncOnOpen = false }: {
  node: NodeView; memberOrigin?: string; session: Session; onUnauthorized: () => void; serviceId?: string; requestId?: string; showLogs?: boolean
  syncOnOpen?: boolean
}) {
  const { listedNodes, local, remoteCatalog } = useConsole()
  const { id, peer, status, observations } = node
  const nodeId = encodeURIComponent(id)
  const path = `/peers/${nodeId}/services`
  const canRead = !!peer?.enabled && status !== 'quarantined' && status !== 'disabled'
  const [refreshing, setRefreshing] = useState(false)
  const [refreshReceipt, setRefreshReceipt] = useState<{ at: number; scope?: string; retried: boolean }>()
  const [refreshError, setRefreshError] = useState('')
  const [openSyncResult, setOpenSyncResult] = useState<'synced' | 'failed'>()
  const [completedRequest, setCompletedRequest] = useState<string>()
  const refreshRequest = useRef<AbortController>(null)
  const lastLostScope = useRef<string>(undefined)
  useEffect(() => {
    setRefreshing(false)
    setRefreshReceipt(undefined)
    setRefreshError('')
    setOpenSyncResult(undefined)
    lastLostScope.current = undefined
    return () => { refreshRequest.current?.abort(); refreshRequest.current = null }
  }, [path, canRead])
  // The on-demand read keeps the route in use. The shared snapshot determines directory freshness.
  const syncPending = syncOnOpen && canRead && openSyncResult === undefined
  const { error: demandError } = usePoll<RemoteDirectory>(canRead && !syncPending && !refreshing ? path : null, onUnauthorized)
  const data = remoteCatalog.data?.find((directory) => directory.node_id === id)
  const item = serviceId ? data?.services.find((service) => service.id === serviceId) : undefined
  const overviewAfterRefresh = !!refreshReceipt && (remoteCatalog.requestedAt ?? 0) >= refreshReceipt.at
    && !remoteCatalog.error && remoteDirectoryCurrent(node, data)
  const scope = directoryScope(peer?.connection_id, peer?.directory_generation)
  const refreshRouteChanged = overviewAfterRefresh && refreshReceipt?.scope !== undefined && scope !== refreshReceipt.scope
  const syncBusy = refreshing || refreshReceipt !== undefined
  const stale = syncPending || !!refreshError || syncBusy || !remoteDirectoryCurrent(node, data) || !!remoteCatalog.error
  const connectionId = peer?.connection_id
  const now = useRemoteObservationTime(!serviceId && !stale ? data?.services.map((service) => service.observation) ?? [] : [])
  const ownerAccess = !session.grove && serviceId && memberOrigin &&
    `${memberOrigin}/${serviceAccessRoute(serviceId, local.error ? undefined : local.data?.node_id)}`

  const refreshDirectory = useCallback(async (retried = false) => {
    if (!canRead || refreshing || refreshRequest.current || (!retried && refreshReceipt)) return
    const controller = new AbortController()
    refreshRequest.current = controller
    setRefreshing(true)
    setRefreshReceipt(undefined)
    setRefreshError('')
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      const result = await api<NodeDirectory>(`${path}?refresh=true`, {
        signal: AbortSignal.any([controller.signal, deadline]),
      })
      if (controller.signal.aborted) return
      if (result.node_id !== id || result.stale) {
        if (syncOnOpen) setOpenSyncResult('failed')
        setRefreshError('所属节点暂时未返回最新目录。')
      } else setRefreshReceipt({ at: performance.now(),
        scope: directoryScope(result.connection_id ?? undefined, result.directory_generation ?? undefined), retried })
      refreshConsole()
    } catch (failure) {
      if (controller.signal.aborted) return
      if (syncOnOpen) setOpenSyncResult('failed')
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setRefreshError(deadline.aborted ? '同步服务目录超时，请重试。' : failure instanceof Error ? failure.message : '同步服务目录失败。')
    } finally {
      if (refreshRequest.current === controller) {
        refreshRequest.current = null
        setRefreshing(false)
      }
    }
  }, [canRead, refreshing, refreshReceipt, path, id, syncOnOpen, onUnauthorized])

  const syncDirectoryOnOpen = useEffectEvent(() => refreshDirectory())
  const syncAfterRouteChange = useEffectEvent(() => refreshDirectory(true))

  const recoverLostConnection = useCallback((lostScope: string) => {
    if (!canRead || syncBusy || refreshRequest.current || lostScope !== scope || lastLostScope.current === lostScope) return
    lastLostScope.current = lostScope
    void refreshDirectory()
  }, [canRead, syncBusy, scope, refreshDirectory])

  useEffect(() => {
    if (!refreshReceipt) return
    if (overviewAfterRefresh) {
      if (refreshRouteChanged && !refreshReceipt.retried) {
        void syncAfterRouteChange()
        return
      }
      setRefreshReceipt(undefined)
      if (syncOnOpen) setOpenSyncResult(refreshRouteChanged ? 'failed' : 'synced')
      if (refreshRouteChanged) setRefreshError('同步期间服务目录再次变化，请重新同步。')
      return
    }
    const timer = setTimeout(() => {
      setRefreshReceipt(undefined)
      if (syncOnOpen) setOpenSyncResult('failed')
      setRefreshError('等待当前 Mesh 连接的目录超时，请重新同步。')
    }, Math.max(0, refreshReceipt.at + READ_TIMEOUT_MS - performance.now()))
    return () => clearTimeout(timer)
  }, [overviewAfterRefresh, refreshReceipt, refreshRouteChanged, syncOnOpen])

  useEffect(() => {
    if (!syncOnOpen) setOpenSyncResult(undefined)
    else if (syncPending) void syncDirectoryOnOpen()
  }, [path, syncOnOpen, syncPending])

  const operations = serviceId && <RemoteActions key={`operations-${nodeId}-${serviceId}`}
    path={`${path}/${encodeURIComponent(serviceId)}`}
    name={item?.name ?? serviceId} version={item?.version ?? 0} stale={stale || !item} advertised={item?.actions ?? []}
    receiptOffline={!peer?.enabled || status !== 'online'}
    visibleService={!!item} session={session} onUnauthorized={onUnauthorized} requestId={requestId} connectionId={connectionId}
    directoryGeneration={peer?.directory_generation}
    onSelectReceipt={selected => { location.hash = remoteServiceHref(id, serviceId, showLogs, selected) }}
    onOperationFinished={setCompletedRequest}
    onSyncDirectory={() => void refreshDirectory()}
    onRouteLost={recoverLostConnection}
    ownerAccess={ownerAccess || undefined} />
  const offline = ['idle', 'probing', 'connecting', 'reconnecting', 'listening'].includes(status)
    ? '正在从当前节点建立连接' : status === 'unknown' ? '连接状态暂时无法更新' : '当前节点暂未连通'
  return <>
    <div className="remote-node-heading"><span className="service-symbol"><Icon name="cloud" size={20} /></span>
      <strong>{node.name}</strong>
      <CopyValue value={id} short /><NodeConnectionBadge node={node} />{stale && <Badge tone="amber">目录待同步</Badge>}</div>
    {canRead && <div className="button-row">
      <button type="button" className="btn btn-secondary btn-small" disabled={syncBusy} onClick={() => void refreshDirectory()}>
        <Icon name="refresh" size={14} />{syncBusy ? '正在同步目录…' : refreshError ? '重新同步服务目录' : '同步服务目录'}
      </button>
    </div>}
    {stale && !refreshError && <Notice tone="amber">{refreshReceipt ? '已收到同步回执，正在核对当前 Mesh 连接上的目录。'
      : status === 'online' ? '正在同步目录，等待新的有效状态。' : `${offline}，暂时不能发起新的远程操作。`}</Notice>}
    {status === 'online' && peer && <p>{pathLabel(node.activePath) ?? '路径待报告'}
      {node.activePath && node.activePath.length > 2 && ' · 端到端 TLS'}
      {peer.rtt_ms != null && ` · RTT ${peer.rtt_ms.toFixed(1)} ms`}</p>}
    {!!observations.length && <details className="route-details"><summary>邻居的可达观测</summary>
      <RouteObservations observations={observations} names={new Map(listedNodes.map((node) => [node.id, node.name]))} />
    </details>}
    {status !== 'unknown' && peer?.route_diagnostics && <RouteDetails diagnostics={peer.route_diagnostics} neighbor={peer.neighbor_use} />}
    {stale && demandError && demandError !== remoteCatalog.error && <p className="error" role="alert">{demandError}</p>}
    {refreshError && <Notice tone="amber"><span role="alert">{refreshError} 同步成功后可继续远程操作。</span></Notice>}
    {(!serviceId || !item && memberOrigin) && <div className="button-row">
      {!serviceId && <OwnerRegistrationLink nodeId={id} />}
      {!item && memberOrigin && <OwnerServiceLink origin={memberOrigin} serviceId={serviceId} showLogs={showLogs} />}
    </div>}
    {serviceId && !item && !stale && <EmptyState title="当前目录中没有此服务"
      action={ownerAccess && <a className="text-link" href={ownerAccess}>核对所属节点的访问权限<Icon name="arrow-up-right" size={14} /></a>}>
      刚保存权限时可同步服务目录。
    </EmptyState>}
    {!serviceId && !stale && !data?.services.length && <p>此节点暂无可管理的服务目录。</p>}
    {!serviceId && !!data?.services.length && <ul className="service-list">{data.services.map((service) => <li key={service.id}>
      <a href={remoteServiceHref(id, service.id)}>
        {service.name}
      </a>
      <span><RemoteServiceState observation={service.status ? service.observation : null} directoryStale={stale} now={now} /></span>
      {!stale && service.logs && <RemoteLogsLink nodeId={id} service={service} />}
    </li>)}</ul>}
    {item && <RemoteDetail key={`${nodeId}-${item.id}`} item={item} stale={stale} memberOrigin={memberOrigin}
      nodeId={id} showLogs={showLogs} path={`${path}/${encodeURIComponent(item.id)}`} onUnauthorized={onUnauthorized}
      connectionId={connectionId} directoryGeneration={peer?.directory_generation} requestId={requestId}
      completedRequest={completedRequest} onRouteLost={recoverLostConnection} />}
    {serviceId && <ServiceLogs path={`${path}/${encodeURIComponent(serviceId)}`} serviceId={serviceId} onUnauthorized={onUnauthorized}
      remote active={canRead && showLogs && item?.logs === true} paused={stale} connectionId={connectionId}
      directoryGeneration={peer?.directory_generation} onRouteLost={recoverLostConnection} />}
    {operations}
    {item && <FrpMappings key={`frp-${item.id}`} path={`${path}/${encodeURIComponent(item.id)}`} stale={stale}
      session={session} onUnauthorized={onUnauthorized} connectionId={connectionId} />}
  </>
}

export function RemoteServicePage({ nodeId, serviceId, requestId, showLogs, syncOnOpen }: {
  nodeId: string; serviceId?: string; requestId?: string; showLogs: boolean; syncOnOpen?: boolean
}) {
  const { remoteNodes, memberPanelOrigins, meshError, meshLoading, session, onUnauthorized } = useConsole()
  const node = remoteNodes.find((item) => item.id === nodeId)
  const origin = memberPanelOrigins.get(nodeId)
  const memberOrigin = origin !== location.origin ? origin : undefined
  useEffect(() => { window.scrollTo(0, 0) }, [])
  return <>
    <a className="back-link" href={serviceId ? `#/services/remote/${encodeURIComponent(nodeId)}` : '#/services/remote'}>
      <Icon name="arrow-left" size={15} />{serviceId ? '返回节点服务目录' : '返回远程服务'}
    </a>
    <PageHeading eyebrow="OPERATIONS / SERVICE" title={serviceId ? '远程服务' : node?.name ?? '节点服务目录'}
      description={serviceId ? '通过当前面板查看服务状态、日志和操作回执。' : '查看并管理此节点上的服务。'} />
    <Panel>
      {meshError && <Notice tone="amber">{meshError}</Notice>}
      {serviceId && requestId && <a className="text-link" href={savedRemoteOperationHref(nodeId, serviceId, requestId)}>
        打开发起面板保存的回执<Icon name="arrow-right" size={14} />
      </a>}
      {node?.peer ? <PeerDirectory node={node}
        memberOrigin={memberOrigin} session={session} onUnauthorized={onUnauthorized} serviceId={serviceId} requestId={requestId}
        showLogs={showLogs} syncOnOpen={syncOnOpen} />
        : <>
          {node && <NodeConnectionBadge node={node} />}
          {!meshError && (meshLoading ? <Loading label="正在读取远程节点…" /> :
            <EmptyState title={node?.status === 'unknown' ? '当前连接状态暂时无法确认'
              : node ? '当前面板未配置到此成员的 Mesh 连接' : '当前面板找不到此远程节点'} />)}
          {(memberOrigin || node && !serviceId) && <div className="button-row">
            {node && !serviceId && <OwnerRegistrationLink nodeId={nodeId} />}
            {memberOrigin && <OwnerServiceLink origin={memberOrigin} serviceId={serviceId} showLogs={showLogs} />}
          </div>}
        </>}
    </Panel>
  </>
}

export function ServiceInventory({ includeLocal, filter, onFilter }: {
  includeLocal: boolean; filter: ServiceFilter; onFilter: (filter: ServiceFilter) => void
}) {
  const { remoteNodes, meshError, meshLoading, localName, services } = useConsole()
  const { data, error: directoryError, directories, entries } = useRemoteCatalog()
  const [query, setQuery] = useState('')
  const search = query.trim().toLowerCase()
  const localError = includeLocal && services.error
  const local = includeLocal ? (services.data ?? []).filter((service) =>
    `${serviceSearchText(service)} 本机 ${localName}`.toLowerCase().includes(search)
    && matchesServiceStatus(filter, { ...service.observation, stale: service.observation.stale || !!localError })) : []
  const matchingRemote = entries.filter(({ node, service }) =>
    `${service.name} ${node.name} ${node.id} ${drivers[service.driver]} ${service.id}`.toLowerCase().includes(search))
  const now = useRemoteObservationTime(matchingRemote.map(({ service, stale }) => stale ? null : service.observation))
  const visibleRemote = matchingRemote.filter(({ service, stale }) => matchesServiceStatus(filter,
    service.status && service.observation ? remoteObservationState(service.observation, stale, now) : null))
  const showLogLinks = visibleRemote.some(({ service, stale }) => !stale && service.logs)
  const hasResults = local.length > 0 || visibleRemote.length > 0
  const loading = (!data && !directoryError) || (includeLocal && !services.data && !localError)
  const filtering = !!search || filter !== 'all'
  return <div className="stack"><Panel title={includeLocal ? '服务目录' : '远程服务目录'} action={<button className="btn btn-secondary btn-small" onClick={refreshConsole}>
    <Icon name="refresh" size={14} />刷新列表</button>}>
    <div className="filter-toolbar"><label className="search-box"><Icon name="search" size={17} />
      <input aria-label={includeLocal ? '搜索全部服务' : '搜索远程服务'} placeholder="搜索服务或所属节点…" value={query} onChange={(event) => setQuery(event.target.value)} />
    </label><ServiceStatusFilters value={filter} onChange={onFilter} /></div>
    {directoryError && <Notice tone="amber" title="暂时无法更新远程服务目录">{directoryError}</Notice>}
    {localError && <Notice tone="amber" title="暂时无法更新本机服务">{localError}</Notice>}
    {loading && !hasResults && <Loading label="正在读取服务目录…" />}
    {!loading && !hasResults && !directoryError && !localError && <EmptyState icon={filtering ? 'search' : 'layers'}
      title={filtering ? '没有匹配的服务' : includeLocal ? '暂无可查看的服务' : '暂无已同步的远程服务'}>
      {filtering ? '换个关键词，或选择其他状态。' : '可在下方打开节点目录，按需连接并同步服务。'}
    </EmptyState>}
    {hasResults && <div className="table-wrap"><table className="data-table service-table">
      <thead><tr><th scope="col">服务</th><th scope="col">所属节点</th><th scope="col">运行状态</th>
        <th scope="col">最近检查</th>{showLogLinks && <th scope="col">日志</th>}</tr></thead>
      <tbody>{local.map((service) => <tr key={`local/${service.id}`}>
        <td><a className="text-link" href={`#/services/${encodeURIComponent(service.id)}`}>
          {service.name}<Icon name="arrow-up-right" size={14} /></a></td>
        <td>{localName}</td><td><ServiceState observation={service.observation} unavailable={!!localError} /></td>
        <td className="time-cell">{service.observation.checked_at == null ? '—' : timestamp(service.observation.checked_at)}</td>
        {showLogLinks && <td />}
      </tr>)}{visibleRemote.map(({ node, service, stale }) => {
        const observed = service.status ? service.observation : null
        return <tr key={`${node.id}/${service.id}`}>
          <td><a className="text-link" href={remoteServiceHref(node.id, service.id)}>
            {service.name}<Icon name="arrow-up-right" size={14} /></a></td>
          <td><a href={`#/services/remote/${encodeURIComponent(node.id)}`}>{node.name}</a></td>
          <td><RemoteServiceState observation={observed} directoryStale={stale} now={now} /></td>
          <td className="time-cell">{observed?.checked_at == null ? '—' : timestamp(observed.checked_at)}</td>
          {showLogLinks && <td>{!stale && service.logs && <RemoteLogsLink nodeId={node.id} service={service} />}</td>}
        </tr>
      })}</tbody>
    </table></div>}
  </Panel><Panel title="远程节点">
    {meshError && <Notice tone="amber">{meshError}</Notice>}
    {remoteNodes.length ? <ul className="remote-node-list">{remoteNodes.map((node) => {
      const directory = directories.get(node.id)
      const current = directory && remoteDirectoryCurrent(node, directory) && !directoryError
      return <li key={node.id}>
        <a href={`#/services/remote/${encodeURIComponent(node.id)}`}>
          <span className="service-symbol"><Icon name="cloud" size={20} /></span>
          <span className="node-mini-content"><strong>{node.name}</strong><small>{current
            ? `${directory.services.length} 项已授权服务`
            : !node.peer ? '查看成员的服务入口'
            : node.peer.enabled && node.status !== 'quarantined' && node.status !== 'disabled' ? '打开节点以同步服务' : shortId(node.id)}</small></span>
          <NodeConnectionBadge node={node} /><Icon name="chevron-right" size={16} />
        </a>
      </li>
    })}</ul> : !meshError && (meshLoading ? <Loading label="正在读取远程节点…" />
      : <EmptyState icon="network" title="还没有远程节点">先配置节点互联，再查看对方发布的服务。</EmptyState>)}
  </Panel></div>
}
