import { useState, type FormEvent } from 'react'
import { ApiError, api, READ_TIMEOUT_MS, timestamp } from './api'
import { eventLabel, refreshConsole, useConsole, type AuditEntry, type NodeView, type PeerReputation, type Preferences } from './console-data'
import { meshPathError, OwnerRegistrationLink, PeerDirectory, RouteDetails, RouteObservations, RouteSelectionStatus } from './remote'
import { Badge, bytes, CopyValue, duration, EmptyState, GardenArt, HealthRing, Icon, Loading, Metric, Modal, NodeConnectionBadge, Notice, PageHeading, Panel, shortId, Tabs } from './ui'
import { drivers, ServiceState } from './services'
import { NetworkMap } from './network-map'
import { NodeQuarantine } from './node-quarantine'
import { PolicyEvidence } from './policy-evidence'
import { useGroveDirectorySync } from './grove-auth'
import { publicPanelLabel } from './grove-directory'
import { groveServiceRegistrationHref, nodeResourcesHref, seedProgressHref } from './grove-navigation'
import { SeedConnectionProgress } from './seed-deployment'
import { SeedWizard } from './seed-wizard'
import { connectionGroup, connectionLabels, countConnections, meshEndpointLabel, nodeConnectionGroup, pathLabel, reachabilityLabel, reportedPath, type ConnectionGroup } from './connection-status'
import { hostResources, hostSampleCurrent, resourceWarningPercent, type HostResource } from './host-resources'
import { HostResourceTrend } from './host-resource-trend'

const connectionFilters = Object.keys(connectionLabels) as ConnectionGroup[]

function RoutePath({ path, names }: { path: string[]; names: ReadonlyMap<string, string> }) {
  return <ol className="real-route">{path.map((id, index) => <li key={`${id}-${index}`}>
    <span aria-hidden="true">{index + 1}</span><strong>{names.get(id) || shortId(id)}</strong>
  </li>)}</ol>
}

function PathStatus({ node, names }: { node: NodeView; names: ReadonlyMap<string, string> }) {
  if (node.activePath) return <RoutePath path={node.activePath} names={names} />
  switch (node.status) {
    case 'online': return <p className="muted">路径待报告</p>
    case 'idle': return <p className="muted">空闲会话已关闭，可按需重新建立。</p>
    case 'probing': return <p className="muted">{node.peer?.route_diagnostics?.switch_reason === 'idle'
      ? '正在恢复连接。' : '当前节点正在寻找可用路径。'}</p>
    default: return <p className="muted">暂无活动路径</p>
  }
}

function NodeAddresses({ node, directoryCurrent }: { node: NodeView; directoryCurrent: boolean }) {
  const peer = node.peer
  const live = node.status === 'online' && peer?.neighbor_use?.connected !== false ? peer?.connected_ip : undefined
  const endpoint = node.status !== 'unknown' && peer?.enabled && peer.automatic_endpoint
    ? meshEndpointLabel(...peer.automatic_endpoint) : undefined
  const fixed = meshEndpointLabel(peer?.source_ip, peer?.port)
  const origin = node.memberOrigin ?? (node.local ? location.origin : undefined)
  const panelAddress = publicPanelLabel(origin)
  return <dl className="facts">
    <div><dt>{node.memberOrigin && !node.local && !directoryCurrent ? '上次同步的公网面板入口' : '公网面板入口'}</dt>
      <dd>{origin && panelAddress !== '无公网 IP' ? <CopyValue value={origin} /> : panelAddress}</dd></div>
    {fixed && <div><dt>固定 Mesh 地址</dt><dd>{fixed}</dd></div>}
    {endpoint && <div><dt>发现的 Mesh 端点</dt><dd>{endpoint}</dd></div>}
    {!node.local && <div><dt>直连对端 IP</dt><dd>{live || '暂无观测'}</dd></div>}
  </dl>
}

function NodeIndicator({ node }: { node: NodeView }) {
  const group = nodeConnectionGroup(node)
  const tone = group === 'connected' ? 'online' : group === 'unreachable' ? 'offline' : group === 'idle' || group === 'observed' ? 'dormant' : ''
  return <span className={`indicator ${tone}`} aria-hidden="true" />
}

export function NodeHelp({ onClose }: { onClose: () => void }) {
  return <Modal title="让新节点加入 Grove" onClose={onClose}>
    <ol className="setup-steps">
      <li><span>1</span><div><h3>通过 SSH 安装并启动</h3><p>在节点播种页选择已配置的设备，由 Spearmint 分发对应平台的原生包并启动。</p></div></li>
      <li><span>2</span><div><h3>确认加入 Grove</h3><p>在目标设备完成首次配置，再到签发节点核对回执中的 Node ID 和面板地址并确认。</p></div></li>
      <li><span>3</span><div><h3>建立 Mesh 并共享服务</h3><p>配置邻居互信后，在服务所属节点选择导出范围和允许的操作。</p></div></li>
    </ol>
    <a href="#/seeds" className="btn btn-primary btn-full" onClick={onClose}>打开节点播种<Icon name="arrow-right" size={16} /></a></Modal>
}

export function NodeMini({ item }: { item: NodeView }) {
  const evidence = reachabilityLabel(item)
  return <a className="node-mini" href={`#/nodes/${item.id}`}><span className="node-mini-icon"><Icon name={item.local ? 'server' : 'cloud'} size={20} /><NodeIndicator node={item} /></span>
    <span className="node-mini-content"><strong>{item.name}</strong><small>{item.local ? '当前节点' : pathLabel(item.activePath) ?? '远程节点'}</small>
      {evidence && <small>{evidence}</small>}</span>
    <span className="node-mini-end"><NodeConnectionBadge node={item} /><Icon name="chevron-right" size={15} /></span></a>
}

function AuditList({ entries }: { entries: AuditEntry[] }) {
  return entries.length ? <div className="activity-list">{entries.map((entry) => <div key={entry.id} className="activity-row"><span className={`activity-ico ${entry.event.includes('session') ? 'purple' : ''}`}><Icon name={entry.event.includes('session') ? 'shield-check' : 'activity'} size={17} /></span>
    <div className="activity-content"><strong>{eventLabel(entry.event)}</strong><small>{entry.actor} · {timestamp(entry.recorded_at)}</small></div></div>)}</div>
    : <EmptyState icon="leaf" title="花园里暂时很安静">新的登录、配置变更和服务操作会显示在这里。</EmptyState>
}

export function OverviewPage() {
  const { session, admin, listedNodes, memberNodes, remoteNodes, connections, meshCurrent, meshLoading, services, local,
    alerts, audit, metrics, grove, directoryCurrent, directoryLoading, directoryPending } = useConsole()
  const standalone = grove.data?.configured === false && !grove.error
  const memberCount = standalone ? (meshCurrent ? listedNodes.length : '—') : memberNodes?.length ?? '—'
  const memberDetail = memberNodes ? directoryCurrent ? '来自 Grove 成员目录' : '上次同步的成员目录'
    : directoryPending ? '等待首次同步成员目录' : directoryLoading ? '正在读取成员目录' : '暂时无法读取成员目录'
  return <>
    <section className="hero-garden overview-network" aria-labelledby="page-title">
      <header className="overview-network-heading">
        <div><div className="hero-kicker"><span className="pulse-dot" />RHIZOME · GROVE NETWORK</div>
          <h1 tabIndex={-1} id="page-title">Grove 网络</h1>
          <p>拖动画布 · Ctrl + 滚轮缩放</p></div>
        <div className="overview-network-actions">
          <a className="overview-topology-link" href="#/topology">打开拓扑<Icon name="arrow-up-right" size={15} /></a>
          {admin && <a className="btn btn-white" href="#/seeds"><Icon name="plus" size={16} />添加节点</a>}
        </div>
      </header>
      <div className="overview-network-layout">
        <div className="overview-network-main" aria-label="节点连接拓扑"><NetworkMap compact /></div>
        <aside className="overview-network-mini" aria-labelledby="overview-node-map-title">
          <h2 id="overview-node-map-title">节点关系</h2>
          <NetworkMap mini />
          <div className="overview-network-legend"><span><i />当前节点</span><span><i />已连接</span></div>
        </aside>
      </div>
    </section>
    {admin ? <>
      <div className="metrics-grid"><Metric label={standalone ? '节点清单' : 'Grove 成员'}
        value={memberCount} unit="台" detail={standalone ? '本机及已登记节点' : memberDetail} icon="sprout" />
        <Metric label="正在生长" value={services.data?.filter((s) => s.observation.status === 'running' && !s.observation.stale).length ?? '—'} unit="项" detail="本机运行的服务" icon="layers" />
        <Metric label="延伸的根茎" value={meshCurrent ? remoteNodes.filter((n) => n.activePath?.length === 2).length : '—'} unit="条" detail="当前显示的直连路径" icon="network" />
        <Metric label="需要你的关注" value={local.data ? alerts.length : '—'} unit="项" detail={alerts.length ? '查看节点与服务状态' : '暂未发现需要关注的事项'} icon="bell" /></div>
      <div className="columns-2"><Panel title="当前节点的连接状态" action={<a className="panel-link" href="#/alerts">全部提醒<Icon name="arrow-up-right" size={14} /></a>}>
        {meshLoading ? <Loading label="正在读取连接状态…" /> : !meshCurrent ? <Notice tone="amber">当前节点的连接状态暂时无法更新。</Notice>
          : remoteNodes.length > 0 ? <HealthRing connections={connections} total={remoteNodes.length} />
          : <EmptyState title="当前节点暂无远程连接记录" />}
        <div className="divider" /><div className="inline-warning"><Icon name={alerts.length ? 'alert-triangle' : 'check-circle'} size={17} /><span>{alerts.length ? `${alerts.length} 项状态需要关注。` : '节点和服务状态会自动更新。'}</span><a href="#/alerts">查看提醒</a></div></Panel>
        <Panel title="当前节点与邻居观测" action={<a className="panel-link" href="#/nodes">所有节点<Icon name="arrow-up-right" size={14} /></a>}>{listedNodes.length ? listedNodes.slice(0, 4).map((node) => <NodeMini item={node} key={node.id} />) : <Loading />}</Panel></div>
      <div className="columns-2"><Panel title="本机资源" action={local.data && <NodeResourceLink id={local.data.node_id} />}><ResourceBars /></Panel>
        <Panel title="本机服务" action={<a className="panel-link" href="#/services/local">服务管理<Icon name="arrow-up-right" size={14} /></a>}>
          {services.error ? <Notice tone="amber">暂时无法读取本机服务。{services.error}</Notice>
            : !services.data ? <Loading label="正在读取本机服务…" />
            : !services.data.length ? <EmptyState title="本机还没有登记服务" action={<a href={groveServiceRegistrationHref()} className="btn btn-primary">
              登记第一个服务<Icon name="arrow-right" size={15} /></a>} />
            : services.data.slice(0, 4).map((service) => <a key={service.id} className="service-mini" href={`#/services/${service.id}`}>
              <span className="service-symbol"><Icon name={service.driver === 'docker' ? 'package' : 'terminal'} size={18} /></span>
              <span className="node-mini-content"><strong>{service.name}</strong><small>{drivers[service.driver]}</small></span>
              <span><ServiceState observation={service.observation} /></span>
            </a>)}
        </Panel></div>
      <Panel title="花园动态" action={<a className="panel-link" href="#/audit">活动记录<Icon name="arrow-up-right" size={14} /></a>}>{audit.data ? <AuditList entries={audit.data.slice(0, 4)} /> : <Loading />}</Panel>
      <div className="bottom-note"><Icon name="leaf" size={17} />{metrics.data?.sampled_at ? `最近采样 ${timestamp(metrics.data.sampled_at)} · 所有状态均来自节点实际观测。` : '正在等待主机采样。'}</div>
    </> : <div className="columns-2"><Panel title="开始一次远程操作"><EmptyState icon="shield-check" title="只操作你获准访问的服务" action={<a className="btn btn-primary" href="#/operations">查看授权服务<Icon name="arrow-right" size={16} /></a>}>选择目标，下载挑战，再导入独立工作站签署的批准。</EmptyState></Panel><Panel title="账户与安全"><dl className="facts"><div><dt>当前账户</dt><dd>{session.display_name || session.username}</dd></div><div><dt>账户角色</dt><dd>远程操作员</dd></div></dl><a className="text-link" href="#/sessions">管理我的登录会话<Icon name="arrow-right" size={15} /></a></Panel></div>}
  </>
}

export function ResourceBars() {
  const { metrics } = useConsole()
  const data = metrics.data
  const current = !metrics.error && hostSampleCurrent(data, Date.now())
  const values: HostResource[] = [{ id: 'cpu', label: 'CPU 使用率', percent: data?.cpu_percent, icon: 'cpu' },
    ...hostResources(data)]
  return <div className="resource-bars">
    {metrics.error && <p className="error" role="alert">{metrics.error}</p>}
    {!current && data?.sampled_at != null && <p className="muted">上次采样于 {timestamp(data.sampled_at)}</p>}
    {values.map(({ id, label, percent, icon, available, total }) => <div className="resource-row" key={id}>
      <div><span><Icon name={icon} size={15} />{label}</span><strong>{percent == null ? '暂无采样'
        : `${percent.toFixed(1)}%${available != null && total != null ? ` · 可用 ${bytes(available)} / ${bytes(total)}` : ''}`}</strong></div>
      {percent != null && <div className="progress"><span className={current && percent >= resourceWarningPercent ? 'warning' : 'green'}
        style={{ width: `${Math.max(0, Math.min(100, percent))}%`, opacity: current ? 1 : 0.45 }} /></div>}
    </div>)}
    <div className="resource-footer"><span><Icon name="clock" size={14} />{duration(data?.uptime_seconds)}</span>
      <span>{data?.network ? `↓ ${bytes(data.network.received_per_second)}/s · ↑ ${bytes(data.network.sent_per_second)}/s` : '等待网络采样'}</span></div>
  </div>
}

function NodeResourceLink({ id, origin }: { id: string; origin?: string }) {
  return <a className="panel-link" href={`${origin ? `${origin}/` : ''}${nodeResourcesHref(id)}`}>
    {origin ? '在所属面板查看资源' : '查看资源趋势'}<Icon name={origin ? 'arrow-up-right' : 'arrow-right'} size={14} /></a>
}

function ReputationPanel({ observation }: { observation: PeerReputation }) {
  const { quotas } = observation
  return <Panel title="本机请求观察" action={<Badge tone={observation.state === 'suspected' ? 'amber' : 'outline'}>
    {observation.state === 'suspected' ? '暂时收紧配额' : '常规配额'}</Badge>}>
    <dl className="facts">
      <div><dt>近一分钟格式错误</dt><dd>{observation.invalid_requests}</dd></div>
      <div><dt>本次运行限流次数</dt><dd>{observation.limited_requests}</dd></div>
      <div><dt>正在处理的日志和证据请求</dt><dd>{observation.in_flight}</dd></div>
      <div><dt>证据请求剩余配额</dt><dd>{quotas.evidence.remaining} / {quotas.evidence.limit}</dd></div>
      <div><dt>日志请求剩余配额</dt><dd>{quotas.logs.remaining} / {quotas.logs.limit}</dd></div>
      {observation.restriction_seconds > 0 && <div><dt>收紧配额剩余时间</dt><dd>{observation.restriction_seconds} 秒</dd></div>}
      {observation.last_invalid_method && <div><dt>最近校验失败的请求</dt><dd><code>{observation.last_invalid_method}</code></dd></div>}
    </dl>
  </Panel>
}

function MemberDirectoryNotice() {
  const { grove, groveDetails, members, directoryCurrent, directoryLoading, directoryPending, directorySequence,
    session, onUnauthorized, local, memberPanelOrigins } = useConsole()
  const syncRealmId = !grove.error && groveDetails?.local_issuer === false && !groveDetails.frozen && !groveDetails.issuer_paused
    ? groveDetails.realm?.id : undefined
  const canCompare = !local.error && !!local.data && [...memberPanelOrigins.keys()].some(id => id !== local.data?.node_id)
  const { checking, sync, message } = useGroveDirectorySync(syncRealmId, session.csrf_token, onUnauthorized)
  if (!grove.data?.configured) return null
  return <div className="stack-small">
    {members && !directoryCurrent ? <Notice tone="amber">
      {groveDetails?.frozen ? 'Grove 身份服务等待恢复。'
        : groveDetails?.issuer_paused && !groveDetails.issuer_retired ? '身份签发已暂停。' : ''}
      显示上次同步的 Grove 成员目录{directorySequence === undefined ? '。' : ` · 第 ${directorySequence} 版`}
    </Notice> : directoryCurrent && directorySequence !== undefined ? <p className="muted">Grove 成员目录 · 第 {directorySequence} 版</p>
      : directoryPending ? <Notice>等待首次同步 Grove 成员目录。当前显示本机及已登记的 Mesh 节点。</Notice>
      : !members && !directoryLoading && <Notice tone="amber">暂时无法读取 Grove 成员目录。</Notice>}
    {(syncRealmId || canCompare) && <div className="button-row">
      {syncRealmId && <button type="button" className="btn btn-secondary btn-small" disabled={checking}
        onClick={() => void sync()}><Icon name="refresh" size={14} />{checking ? '正在同步成员目录…' : '同步成员目录'}</button>}
      {canCompare && <a className="text-link" href="#/deployments">核对各面板版本与成员目录<Icon name="arrow-right" size={14} /></a>}
    </div>}
    {message && <p className={message.error ? 'error' : 'muted'} role="status">{message.text}</p>}
  </div>
}

export function NodeNote({ nodeId, onSave }: { nodeId: string; onSave: (value: Preferences) => void }) {
  const { preferences, nodeNotes, session, grove } = useConsole()
  const [draft, setDraft] = useState<string>()
  const [message, setMessage] = useState('')
  const [pending, setPending] = useState(false)
  const shared = !!grove.data?.realm
  const note = draft ?? nodeNotes[nodeId] ?? ''
  async function save(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    try {
      if (shared) {
        await api(`/grove/node-notes/${nodeId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
          body: JSON.stringify({ note: note.trim() }) })
        refreshConsole()
      } else {
        const browserNotes = { ...preferences.nodeNotes }
        if (note.trim()) browserNotes[nodeId] = note.trim()
        else delete browserNotes[nodeId]
        onSave({ ...preferences, nodeNotes: browserNotes })
      }
      setDraft(undefined)
      setMessage(shared ? '已保存，其他节点将自动同步' : '已保存')
    } catch {
      setMessage('暂时无法保存备注')
    } finally { setPending(false) }
  }
  return <form className="stack-small" onSubmit={(event) => void save(event)}>
    <label className="field-label">节点备注<input className="input" maxLength={80} value={note} placeholder="例如 NAS 或内网工作站"
      onChange={(event) => { setDraft(event.target.value); setMessage('') }} disabled={pending} /></label>
    <p className="muted">{shared ? 'Grove 所有节点共用此备注。' : '备注保存在当前浏览器。'}留空保存可清除备注。</p>
    <div className="button-row"><button className="btn btn-secondary" disabled={pending}>保存备注</button>
      {message && <span role="status">{message}</span>}</div>
  </form>
}

export function NodesPage({ nodeId, resources = false, onSave }: { nodeId?: string; resources?: boolean; onSave: (value: Preferences) => void }) {
  const { listedNodes, memberNodes, meshLoading, meshError, local, metrics, preferences, session, admin, directoryCurrent,
    directoryLoading, directoryPending, memberPanelOrigins, onUnauthorized } = useConsole()
  const [query, setQuery] = useState(''); const [filter, setFilter] = useState<ConnectionGroup | 'all'>('all'); const [help, setHelp] = useState(false); const [tab, setTab] = useState('overview')
  const [nodeScope, setNodeScope] = useState('members')
  const selected = listedNodes.find((node) => node.id === nodeId)
  if (nodeId) {
    if (!selected) return <><PageHeading eyebrow="INFRASTRUCTURE / NODE" title="节点详情" description="读取节点身份与连接状态。" />{meshLoading || directoryLoading ? <Loading /> : <Panel><EmptyState title={directoryPending ? '等待首次同步成员目录' : '未找到这个节点'} action={<a className="btn btn-secondary" href="#/nodes">返回节点列表</a>}>{directoryPending ? '同步完成后可查看 Grove 成员。' : '该节点可能未登记，或你没有查看权限。'}</EmptyState></Panel>}</>
    const origin = selected.local ? undefined : memberPanelOrigins.get(selected.id)
    const memberOrigin = origin !== location.origin ? origin : undefined
    const openPanel = memberOrigin &&
      <a className="btn btn-secondary" href={`${memberOrigin}/`} target="_blank" rel="noopener noreferrer">
        <Icon name="arrow-up-right" size={15} />打开节点面板
      </a>
    if (resources) return <>
      <a href={`#/nodes/${selected.id}`} className="back-link"><Icon name="arrow-left" size={15} />返回节点概览</a>
      <PageHeading eyebrow="INFRASTRUCTURE / NODE" title={`${selected.name} · 主机资源`} description="查看资源使用率与最近采样。" />
      {selected.local ? <div className="stack"><Panel title="当前采样"><ResourceBars /></Panel><HostResourceTrend /></div>
        : <Panel title="主机资源">{memberOrigin ? <NodeResourceLink id={selected.id} origin={memberOrigin} />
          : <EmptyState title="当前目录暂无此节点的面板入口" />}</Panel>}
    </>
    if (!selected.local && !selected.peer) return <>
      <a href="#/nodes" className="back-link"><Icon name="arrow-left" size={15} />返回节点列表</a>
      <PageHeading eyebrow="INFRASTRUCTURE / NODE" title={selected.name} description="从 Grove 成员目录读取的节点。">{openPanel}</PageHeading>
      <Panel title="Grove 成员" action={<NodeConnectionBadge node={selected} />}>
        <dl className="facts"><div><dt>Node ID</dt><dd><CopyValue value={selected.id} /></dd></div></dl>
        <NodeAddresses node={selected} directoryCurrent={directoryCurrent} />
        {admin && <NodeNote key={selected.id} nodeId={selected.id} onSave={onSave} />}
        <p className="muted">{selected.status === 'unconfigured' ? '当前节点还没有此成员的 Mesh 互联配置。'
          : directoryCurrent ? '正在等待当前节点的 Mesh 状态。' : '成员信息来自上次同步的目录。'}</p>
        <div className="button-row"><OwnerRegistrationLink nodeId={selected.id} />
          {memberOrigin && <NodeResourceLink id={selected.id} origin={memberOrigin} />}</div>
      </Panel>
    </>
    const peer = selected.peer
    const path = pathLabel(selected.activePath)
    const direct = selected.activePath?.length === 2
    const names = new Map(listedNodes.map(({ id, name }) => [id, name]))
    const observations = selected.observations
    return <><a href="#/nodes" className="back-link"><Icon name="arrow-left" size={15} />返回节点列表</a><PageHeading eyebrow="INFRASTRUCTURE / NODE" title={selected.name} description={selected.local ? '你当前连接的 Spearmint 节点。' : '已登记的 Mesh 节点，其服务与权限由所属节点管理。'}>{openPanel}<button className="btn btn-secondary" onClick={refreshConsole}><Icon name="refresh" size={15} />刷新状态</button></PageHeading>
      <div className="detail-identity"><span className="detail-identity-icon"><Icon name={selected.local ? 'server' : 'cloud'} size={26} /></span><div className="detail-identity-tags"><NodeConnectionBadge node={selected} /><Badge tone="outline">{selected.local ? '本机节点' : direct ? '直连邻居' : '远程节点'}</Badge><CopyValue value={selected.id} /></div></div>
      <Tabs label="节点详情" current={tab} onChange={setTab} items={[{ id: 'overview', label: '概览', icon: 'layout-dashboard' }, { id: 'services', label: '已授权服务', icon: 'layers' }, { id: 'network', label: '网络与身份', icon: 'network' }]} />
      {tab === 'overview' && admin && <Panel title="节点备注"><NodeNote key={selected.id} nodeId={selected.id} onSave={onSave} /></Panel>}
      {tab === 'overview' && <div className="columns-2"><Panel title={selected.local ? '主机资源' : '当前节点的连接状态'}
        action={selected.local && <NodeResourceLink id={selected.id} />}>{selected.local ? <ResourceBars /> : <>
        <NodeAddresses node={selected} directoryCurrent={directoryCurrent} />
        <dl className="facts">
          {peer?.host && <div><dt>Mesh 证书主机</dt><dd>{peer.host}</dd></div>}
          <div><dt>心跳 RTT</dt><dd>{selected.status === 'online' && peer?.rtt_ms != null ? `${peer.rtt_ms.toFixed(1)} ms` : '暂无观测'}</dd></div>
          <div><dt>传输加密</dt><dd>{(selected.status === 'online' && peer?.tls) || '暂无会话信息'}</dd></div>
          <div><dt>当前会话建链时间</dt><dd>{selected.status === 'online' && peer?.connected_at != null ? timestamp(peer.connected_at) : '暂无活动会话'}</dd></div>
        </dl>
        <section className="topology-path" aria-label="从当前节点出发的路径">
          <h4>从当前节点出发的路径{path && ` · ${path}`}</h4>
          <PathStatus node={selected} names={names} />
        </section>
        <div className="button-row">
          <a href={`#/topology/${encodeURIComponent(selected.id)}`} className="text-link">查看此节点的拓扑<Icon name="arrow-right" size={15} /></a>
          {memberOrigin && <NodeResourceLink id={selected.id} origin={memberOrigin} />}
          {memberOrigin && peer?.enabled === true && peer.legacy === false && !['disabled', 'quarantined', 'unknown'].includes(selected.status) &&
            <a href={`#/deployments/${selected.id}`} className="text-link">核对此节点的版本<Icon name="arrow-right" size={15} /></a>}
        </div>
      </>}</Panel>
        <Panel title="节点信息"><dl className="facts"><div><dt>显示名称</dt><dd>{selected.name}</dd></div><div><dt>节点类型</dt><dd>{selected.local ? '本机' : 'Mesh 成员'}</dd></div><div><dt>运行系统</dt><dd>{selected.local ? `${local.data?.platform?.os || '未知'} ${local.data?.platform?.architecture || ''}` : '未通过当前接口发布'}</dd></div><div><dt>执行后端</dt><dd>{selected.local ? local.data?.platform?.process_backend || '未知' : '由所属节点管理'}</dd></div>{selected.local && <div><dt>主机运行时间</dt><dd>{duration(metrics.data?.uptime_seconds)}</dd></div>}</dl>
          {selected.local && <NodeAddresses node={selected} directoryCurrent={directoryCurrent} />}
        </Panel></div>}
      {tab === 'overview' && observations.length > 0 && <Panel title="邻居的可达观测">
        <RouteObservations observations={observations} names={names} />
      </Panel>}
      {tab === 'services' && <Panel title="已授权服务">{selected.local ? <><p className="muted">管理本机已经登记的程序与容器。</p><a href="#/services" className="btn btn-primary">打开服务管理<Icon name="arrow-right" size={15} /></a></> : peer && <PeerDirectory node={selected} memberOrigin={memberOrigin} session={session} onUnauthorized={onUnauthorized} />}</Panel>}
      {tab === 'network' && <div className="columns-2"><Panel title="稳定节点身份"><p className="muted">Node ID 标识节点身份，地址、位置和显示名称的变化不会替代它。</p><CopyValue value={selected.id} />{peer?.fingerprint && <><div className="divider" /><p className="muted">已核对的证书指纹</p><CopyValue value={peer.fingerprint} /></>}</Panel><Panel title="网络状态"><dl className="facts"><div><dt>当前状态</dt><dd><NodeConnectionBadge node={selected} /></dd></div><div><dt>成员准入</dt><dd>{selected.local ? '当前节点' : peer?.enabled ? '已启用' : '已停用'}</dd></div><div><dt>Mesh ID</dt><dd>{peer?.mesh_id || '本机身份独立保存'}</dd></div><div><dt>中继使用</dt><dd>{peer?.routed ? '已配置跨跳使用' : '未配置跨跳使用'}</dd></div></dl><a href="#/topology" className="text-link">查看网络拓扑<Icon name="arrow-right" size={15} /></a></Panel></div>}
      {tab === 'network' && !selected.local && peer?.local_quarantine !== undefined &&
        <NodeQuarantine key={selected.id} nodeId={selected.id} isolation={peer.local_quarantine} session={session} onUnauthorized={onUnauthorized} />}
      {tab === 'network' && peer?.local_reputation && <ReputationPanel observation={peer.local_reputation} />}
    </>
  }
  const otherNodes = listedNodes.filter((node) => !node.local && node.memberOrigin === undefined)
  const scopedNodes = memberNodes ? (nodeScope === 'members' ? memberNodes : otherNodes) : listedNodes
  const connections = countConnections(scopedNodes.filter((node) => !node.local))
  const search = query.trim().toLowerCase()
  const visible = scopedNodes.filter((node) => [node.name, node.id, node.memberOrigin, node.peer?.host,
    node.peer?.source_ip, node.peer?.display_host, node.peer?.connected_ip, node.peer?.automatic_endpoint?.[0]].join(' ').toLowerCase().includes(search)
    && (filter === 'all' || !node.local && filter === nodeConnectionGroup(node)))
  const filters = connectionFilters.filter((group) => group === filter || connections[group] > 0 || ['connected', 'idle', 'unreachable'].includes(group))
  return <><PageHeading eyebrow="INFRASTRUCTURE / NODES" title="节点管理" description="查看 Grove 成员、当前面板的连接状态和邻居的近期观测。"><button className="btn btn-primary" onClick={() => setHelp(true)}><Icon name="plus" size={16} />添加节点</button></PageHeading>
    {memberNodes && <Tabs label="节点清单" current={nodeScope} onChange={(scope) => { setNodeScope(scope); setFilter('all') }}
      items={[{ id: 'members', label: `Grove 成员 ${memberNodes.length}` }, { id: 'other', label: `其他 Mesh 节点 ${otherNodes.length}` }]} />}
    <div className="filter-toolbar"><label className="search-box"><Icon name="search" size={17} /><input placeholder="搜索节点名称、地址或 Node ID…" aria-label="搜索节点" value={query} onChange={(e) => setQuery(e.target.value)} /></label><div className="filter-pills"><button className={`pill ${filter === 'all' ? 'active' : ''}`} aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>全部 {scopedNodes.length}</button>{filters.map((group) => <button className={`pill ${filter === group ? 'active' : ''}`} aria-pressed={filter === group} key={group} onClick={() => setFilter(group)}>{connectionLabels[group]} {connections[group]}</button>)}</div></div>
    {meshError && <Notice tone="amber" title="节点状态暂时无法更新">{meshError}</Notice>}
    <MemberDirectoryNotice />
    {!visible.length && (meshLoading || directoryLoading) ? <Loading /> : !visible.length ? <Panel><EmptyState icon="search" title="没有匹配的节点">试试其他状态筛选、节点地址或 Node ID。</EmptyState></Panel> : <div className="node-grid">{visible.map((node) => {
      const path = pathLabel(node.activePath)
      const evidence = reachabilityLabel(node)
      return <a key={node.id} className="node-card" href={`#/nodes/${node.id}`}><div className="node-card-top"><span className="node-card-icon"><Icon name={node.local ? 'server' : 'cloud'} size={25} /><NodeIndicator node={node} /></span><Icon name="arrow-up-right" className="node-card-menu" size={17} /></div>
        <div className="node-card-title"><strong>{node.name}</strong><small>{publicPanelLabel(node.memberOrigin ?? (node.local ? location.origin : undefined))}</small></div><div className="tag-row"><Badge tone={node.local ? 'sage' : 'outline'}>{node.local ? '当前节点' : node.memberOrigin !== undefined ? 'Grove 成员' : 'Mesh 成员'}</Badge>{path && <Badge tone="outline">{path}</Badge>}</div><div className="node-card-divider" /><div className="node-card-facts"><span><Icon name={node.local ? 'cpu' : 'network'} size={13} />{node.local ? local.data?.platform?.process_backend || '本机执行' : node.status === 'online' && node.peer?.rtt_ms != null ? `${node.peer.rtt_ms.toFixed(1)} ms RTT` : '暂无链路采样'}</span></div><div className="node-card-bottom"><NodeConnectionBadge node={node} /><span>{node.local ? preferences.grove : shortId(node.id)}</span></div>
        {evidence && <small className="node-reachability">{evidence}</small>}
      </a>
    })}</div>}
    <div className="bottom-note"><Icon name="shield-check" size={17} />节点连接、服务导出与操作授权分别管理，加入网络不会自动获得写权限。</div>{help && <NodeHelp onClose={() => setHelp(false)} />}</>
}

function TopologyPaths({ node }: { node: NodeView }) {
  const { listedNodes, directoryCurrent, meshCurrent, local, onUnauthorized } = useConsole()
  const [route, setRoute] = useState<{ path: string[]; business_session_selected?: boolean; connection_error?: { code: string; detail: string } }>()
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const diagnostics = node.status !== 'unknown' ? node.peer?.route_diagnostics : undefined
  const observations = node.observations
  const idlePath = node.idlePath
  const names = new Map(listedNodes.map(({ id, name }) => [id, name]))

  async function probe() {
    setPending(true); setError(''); setRoute(undefined)
    try {
      const value = await api<NonNullable<typeof route>>(`/peers/${node.id}/route?probe=true`, { signal: AbortSignal.timeout(READ_TIMEOUT_MS) })
      if (reportedPath(local.data?.node_id, { node_id: node.id, status: 'online', path: value.path })) {
        setRoute(value)
        if (value.connection_error) setError(`未建立 Mesh 会话 · ${meshPathError(value.connection_error.code, value.connection_error.detail)}`)
      } else setError('无法确认探测结果的起点和目标。')
    }
    catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof ApiError ? meshPathError(failure.code, failure.message) : '路径探测超时，请重试。')
    }
    finally { setPending(false); refreshConsole() }
  }

  return <>
    <section className="topology-path" aria-label="当前路径">
      <div className="topology-path-head"><h4>当前路径{node.activePath && ` · ${pathLabel(node.activePath)}`}</h4><NodeConnectionBadge node={node} /></div>
      <PathStatus node={node} names={names} />
      {node.activePath && diagnostics && <div className="route-comparison"><RouteSelectionStatus diagnostics={diagnostics} /></div>}
    </section>
    <NodeAddresses node={node} directoryCurrent={directoryCurrent} />
    {!node.activePath && idlePath && <section className="topology-path" aria-label="上次空闲关闭的路径">
      <h4>上次空闲关闭的路径</h4>
      <RoutePath path={idlePath.path} names={names} />
      <p className="muted">当前节点于 {Math.floor(idlePath.age_seconds)} 秒前关闭此会话 · 记录还显示 {Math.ceil(idlePath.remaining_seconds)} 秒</p>
    </section>}
    {observations.length > 0 && <section className="topology-path" aria-label="邻居的可达观测">
      <div className="topology-path-head"><h4>邻居的可达观测</h4></div>
      <RouteObservations observations={observations} names={names} />
    </section>}
    {diagnostics?.candidate_sessions && <RouteDetails diagnostics={diagnostics} neighbor={node.peer?.neighbor_use} names={names} showSelection={!node.activePath} />}
    {node.peer?.enabled && <button className="btn btn-primary btn-full" disabled={pending || !meshCurrent || connectionGroup(node.status) === 'restricted'}
      onClick={() => void probe()}><Icon name="route" size={16} />{pending ? '正在探测…' : '探测路径'}</button>}
    {!node.peer && <a className="text-link" href={`#/nodes/${node.id}`}>查看成员详情<Icon name="arrow-right" size={15} /></a>}
    {route && <section className="topology-path" aria-label="探测时的路径">
      <h4>{route.business_session_selected === true ? '探测已验证的活动路径'
        : route.business_session_selected === false ? '探测发现的候选路径' : '探测时的路径'} · {pathLabel(route.path)}</h4>
      <RoutePath path={route.path} names={names} />
    </section>}
    {error && <p role="alert" className="error">{error}</p>}
  </>
}

export function TopologyPage({ target }: { target?: string }) {
  const { listedNodes: nodes, remoteNodes: peers, connections, meshCurrent, meshLoading, meshError,
    memberNodes, directoryCurrent, directoryLoading } = useConsole()
  const selected = target ? peers.find((node) => node.id === target) : peers[0]
  const diagnostics = selected?.peer?.route_diagnostics
  const backup = diagnostics?.comparison?.path ?? diagnostics?.best_alternative?.path
  const active = selected?.activePath
  const alternative = selected && active && backup && backup.join('/') !== active.join('/') ? reportedPath(active[0], {
    node_id: selected.id, status: selected.status, path: backup,
  }) : undefined
  return <>
    <PageHeading eyebrow="INFRASTRUCTURE / RHIZOME" title="网络拓扑" description={`路径起点为 ${location.host}。点击节点可查看路径，深绿实线标出所选目标的活动路径。`}>
      <button className="btn btn-secondary" onClick={refreshConsole}><Icon name="refresh" size={15} />刷新状态</button>
    </PageHeading>
    <MemberDirectoryNotice />
    {meshError && <Notice tone="amber" title="节点状态暂时无法更新">{meshError}</Notice>}
    <Panel className="topology-panel" title="节点连接图" action={meshCurrent &&
      <span className="topology-count">{directoryCurrent && memberNodes && `Grove ${memberNodes.length} 台 · `}
        本机已连接 {connections.connected} 台 · {connections.idle} 按需连接 · {connections.unreachable} 本机未连通
        {connections.pending > 0 && ` · ${connections.pending} 等待连接`}
        {connections.observed > 0 && ` · ${connections.observed} 邻居近期可达`}
        {connections.unconfigured > 0 && ` · ${connections.unconfigured} 未配置互联`}
        {connections.restricted > 0 && ` · ${connections.restricted} 停用或隔离`}
        {connections.unknown > 0 && ` · ${connections.unknown} 状态未知`}</span>}>
      <NetworkMap target={selected?.id} alternative={alternative} />
    </Panel>
    <div className="topology-tools">
      <Panel title="节点与本机连接">{nodes.length ? nodes.map((node) => <NodeMini key={node.id} item={node} />) : <Loading />}</Panel>
      <Panel title="节点路径">
        {peers.length > 0 && <label className="field-label">目标节点
          <select className="input" value={selected?.id ?? ''} onChange={(e) => { location.hash = `#/topology/${encodeURIComponent(e.target.value)}` }}>
            {!selected && <option value="" disabled>选择目标节点</option>}
            {peers.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}
          </select>
        </label>}
        {selected ? <TopologyPaths key={selected.id} node={selected} />
          : meshLoading || directoryLoading ? <Loading label="正在读取目标节点…" />
          : target ? <EmptyState icon="route" title="当前面板暂无该目标的路径信息" />
          : <EmptyState icon="route" title="等待第一个邻居">连接远程节点后，就可以在这里探测路径。</EmptyState>}
      </Panel>
    </div>
  </>
}

export function AlertsPage() {
  const { alerts, local } = useConsole(); const [filter, setFilter] = useState('all')
  const visible = alerts.filter((alert) => filter === 'all' || alert.kind === filter)
  return <><PageHeading eyebrow="WORKSPACE / ATTENTION" title="告警中心" description="把需要处理的节点、服务和连接状态放在一起，先处理最重要的事。"><button className="btn btn-secondary" onClick={refreshConsole}><Icon name="refresh" size={15} />重新检查</button></PageHeading>
    <div className="metrics-grid"><Metric label="需要关注" value={local.data ? alerts.length : '—'} detail="根据当前观测状态整理" icon="bell" /><Metric label="节点连接" value={alerts.filter((a) => a.kind === 'node').length} detail="节点未连接或正在探测" icon="network" /><Metric label="服务状态" value={alerts.filter((a) => a.kind === 'service').length} detail="异常或观测已过期" icon="layers" /><Metric label="本机资源" value={alerts.filter((a) => a.kind === 'resource').length} detail={`内存或磁盘使用率达到 ${resourceWarningPercent}%`} icon="hard-drive" /></div>
    <Panel><div className="filter-pills">{[['all', '全部'], ['node', '节点'], ['service', '服务'], ['resource', '主机资源'], ['connection', '连接']].map(([id, title]) => <button className={`pill ${filter === id ? 'active' : ''}`} key={id} aria-pressed={filter === id} onClick={() => setFilter(id)}>{title}</button>)}</div>
      {!visible.length ? <EmptyState icon="check-circle" title={alerts.length ? '这个分类暂无提醒' : '当前暂无提醒'} />
        : <div className="attention-list">{visible.map((alert) => <a href={alert.href} key={alert.id} className="attention-row">
          <span className={`activity-ico ${alert.tone === 'red' ? 'warning' : 'amber'}`}><Icon name="alert-triangle" size={20} /></span>
          <div><strong>{alert.title}</strong><p>{alert.detail}</p>{alert.source && <p>
            {alert.source}{alert.checkedAt != null && ` · 检查于 ${timestamp(alert.checkedAt)}`}
            {alert.validUntil !== undefined && ` · 有效期至 ${timestamp(alert.validUntil)}`}
          </p>}</div><Icon name="arrow-up-right" size={17} />
        </a>)}</div>}
    </Panel><div className="bottom-note"><Icon name="info" size={16} />提醒依据当前节点已有的观测更新。</div></>
}

export function AuditPage() {
  const { audit, onUnauthorized } = useConsole(); const [query, setQuery] = useState(''); const [category, setCategory] = useState('all')
  const visible = (audit.data || []).filter((entry) => `${entry.event} ${eventLabel(entry.event)} ${entry.actor} ${entry.target || ''}`.toLowerCase().includes(query.toLowerCase()) && (category === 'all' || entry.event.startsWith(category)))
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(visible, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = `spearmint-audit-${new Date().toISOString().slice(0, 10)}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return <><PageHeading eyebrow="SECURITY / AUDIT" title="安全审计" description="回看每一次登录、配置变更和服务操作，找到事件的来龙去脉。"><button className="btn btn-secondary" disabled={!visible.length} onClick={download}><Icon name="download" size={15} />导出当前结果</button></PageHeading>
    <Panel><div className="filter-toolbar"><label className="search-box"><Icon name="search" size={17} /><input aria-label="搜索审计记录" placeholder="搜索事件、账户或关联标识…" value={query} onChange={(e) => setQuery(e.target.value)} /></label><select className="input filter-select" aria-label="事件类型" value={category} onChange={(e) => setCategory(e.target.value)}><option value="all">所有事件</option><option value="session.">登录与会话</option><option value="operation.">服务操作</option><option value="service.">服务管理</option><option value="peer.">节点互联</option><option value="security.">安全策略</option></select></div>
      {audit.error && <Notice tone="amber">{audit.error}</Notice>}{!audit.data && !audit.error ? <Loading /> : visible.length ? <div className="table-wrap"><table className="data-table audit-table"><thead><tr><th>事件</th><th>操作者</th><th>来源</th><th>发生时间</th><th>详情</th></tr></thead><tbody>{visible.map((entry) => <tr key={entry.id}><td><strong>{eventLabel(entry.event)}</strong><small className="table-secondary">{entry.event}</small></td><td>{entry.actor}</td><td><Badge tone={entry.source === 'local' ? 'sage' : 'outline'}>{entry.source === 'local' ? '本机' : entry.source}</Badge></td><td className="time-cell muted">{timestamp(entry.recorded_at)}</td><td><details><summary>查看</summary><div className="audit-extra">{entry.target && <CopyValue value={entry.target} />}{entry.reason && <p>{entry.reason}</p>}<small>事件 #{entry.id}{entry.count && entry.count > 1 ? ` · 汇总 ${entry.count} 次` : ''}</small></div></details></td></tr>)}</tbody></table></div> : <EmptyState icon="file-text" title="没有匹配的审计事件">尝试其他关键词或事件类型。</EmptyState>}
      <div className="table-footer">显示最近 100 条记录中的 {visible.length} 条。完整历史可从节点终端导出。</div></Panel>
    <PolicyEvidence onUnauthorized={onUnauthorized} /></>
}

export function SettingsPage({ onSave }: { onSave: (preferences: Preferences) => void }) {
  const { preferences, local, session, webBuild } = useConsole(); const [draft, setDraft] = useState(preferences); const [saved, setSaved] = useState(false); const [error, setError] = useState('')
  const build = local.error ? undefined : local.data?.build
  const buildPending = !local.data && !local.error
  function save() { try { onSave({ ...draft, grove: draft.grove.trim() || '我的 Grove', localName: draft.localName.trim() || '本机节点' }); setSaved(true); setError('') } catch { setError('浏览器无法保存显示偏好，请检查存储设置。') } }
  return <><PageHeading eyebrow="SYSTEM / SETTINGS" title="系统设置" description="给你的工作台一点自己的风格，同时随时查看当前节点的运行信息。"><button className="btn btn-primary" onClick={save}><Icon name="check" size={16} />保存显示偏好</button></PageHeading>
    {saved && <Notice title="显示偏好已保存">名称与列表密度已更新，只在当前浏览器生效。</Notice>}{error && <p className="error" role="alert">{error}</p>}
    <div className="columns-2"><Panel title="工作台与显示"><div className="form-grid"><label className="field-label">Grove 显示名称<input className="input" maxLength={40} value={draft.grove} onChange={(e) => { setDraft({ ...draft, grove: e.target.value }); setSaved(false) }} /></label><label className="field-label">本机显示名称<input className="input" maxLength={40} value={draft.localName} onChange={(e) => { setDraft({ ...draft, localName: e.target.value }); setSaved(false) }} /></label></div><div className="setting-row"><span>紧凑列表密度</span><label className="switch"><input type="checkbox" aria-label="紧凑列表密度" checked={draft.compact} onChange={(e) => { setDraft({ ...draft, compact: e.target.checked }); setSaved(false) }} /><span /></label></div><div className="setting-row"><span>主题</span><strong>Spearmint Light</strong></div><p className="settings-note">显示名称不会改变 Node ID 或节点授权。</p></Panel>
      <Panel title="当前节点"><dl className="facts"><div><dt>运行系统</dt><dd>{local.data?.platform?.os || '读取中…'}</dd></div><div><dt>架构</dt><dd>{local.data?.platform?.architecture || '—'}</dd></div><div><dt>进程管理</dt><dd>{local.data?.platform?.process_backend || '—'}</dd></div><div><dt>文件保护</dt><dd>{local.data?.platform?.file_security === 'windows-acl' ? 'Windows ACL' : local.data?.platform?.file_security === 'posix-owner-mode' ? 'POSIX 所有权与权限' : '—'}</dd></div><div><dt>当前账户</dt><dd>{session.display_name || session.username}</dd></div>
        {!local.error && local.data?.node_id && <div><dt>Node ID</dt><dd><CopyValue value={local.data.node_id} short /></dd></div>}
        <div><dt>面板后端版本</dt><dd>{build?.version || (buildPending ? '读取中…' : '未知')}</dd></div>
        <div><dt>运行方式</dt><dd>{build ? (build.runtime === 'native' ? '原生部署包' : 'Python 环境') : '—'}</dd></div>
        <div><dt>后端构建提交</dt><dd>{build?.commit ? <CopyValue value={build.commit} short /> : '—'}</dd></div>
        <div><dt>前端资源标识（脚本 / 样式）</dt><dd>{webBuild || '未知'}</dd></div>
      </dl></Panel></div>
    <Panel title="备份与维护"><p className="muted">备份、恢复与节点信任配置在节点终端完成。更新或恢复之前，先保存当前状态并核对节点身份。</p><a href="#/access" className="text-link">查看账户与安全<Icon name="arrow-right" size={15} /></a></Panel></>
}

export function SeedsPage({ progressOrigin, progressNodeId }: { progressOrigin?: string; progressNodeId?: string }) {
  if (progressOrigin) return <>
    <a href="#/seeds" className="back-link"><Icon name="arrow-left" size={15} />返回节点播种</a>
    <PageHeading eyebrow="GROVE / SEEDS" title="Mesh 接入状态" description="查看新节点的成员身份、活动路径和服务目录。" />
    <Panel title="目标节点">
      {progressNodeId && <div>Node ID <CopyValue value={progressNodeId} short /></div>}
      <SeedConnectionProgress origin={progressOrigin} nodeId={progressNodeId} syncOnJoin />
    </Panel>
  </>
  return <>
    <PageHeading eyebrow="GROVE / SEEDS" title="节点播种" description="选择发起节点，通过 SSH 安装 Spearmint 并加入当前 Grove。" />
    <SeedWizard follow={(origin, nodeId) => {
      location.hash = seedProgressHref(origin, nodeId)
      refreshConsole()
    }} />
  </>
}

const futurePages: Record<string, { title: string; eyebrow: string; icon: string; phrase: string; description: string; steps: [string, string][] }> = {
  pollen: { title: '移动节点', eyebrow: 'GROVE / POLLEN', icon: 'wind', phrase: '无论走到哪里，都与你的 Grove 相连。', description: '面向休眠、漫游和网络切换的节点运行策略。', steps: [['轻装运行', '为笔记本和移动设备选择合适的运行策略。'], ['自然离线', '区分休眠、失联和真正需要关注的故障。'], ['再次连接', '恢复网络后重新核对身份、权限和状态。']] },
  federation: { title: '跨 Grove 连接', eyebrow: 'GROVE / GRAFT', icon: 'git-merge', phrase: '让不同的花园，有边界地连接。', description: '两个独立 Grove 之间，按明确范围建立互信与共享。', steps: [['独立身份', '保留各自的节点和策略信任边界。'], ['最小共享', '只共享双方明确批准的服务和操作。'], ['双向核验', '让连接、授权变更和撤销都可以追溯。']] },
}
export function FuturePage({ page }: { page: string }) {
  const content = futurePages[page]
  if (!content) return <Panel><EmptyState title="没有找到这个页面" action={<a className="btn btn-primary" href="#/overview">返回花园总览</a>} /></Panel>
  return <><PageHeading eyebrow={content.eyebrow} title={content.title} description={content.description}><Badge tone="purple">未完成</Badge></PageHeading>
    <div className="hero-garden future-hero"><div className="hero-copy"><div className="hero-kicker"><Icon name={content.icon} size={16} />ROOM TO GROW</div><h2>{content.phrase}</h2><p>这片空间为下一步生长预留。当前版本尚未开放此功能。</p><a href="#/nodes" className="btn btn-white">查看当前节点<Icon name="arrow-right" size={15} /></a></div><GardenArt /></div>
    <div className="columns-3">{content.steps.map(([title, description], index) => <Panel key={title} className="planned-step"><span className="planned-number">0{index + 1}</span><h3>{title}</h3><p className="muted">{description}</p></Panel>)}</div>
    <Notice icon="info">这里是后续能力的说明，未连接模拟节点，也不会改变当前节点策略。</Notice></>
}
