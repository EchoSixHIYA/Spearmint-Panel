import { useState } from 'react'
import { timestamp, usePoll } from './api'
import { useConsole, type AuditEntry, type Metrics, type Preferences, refreshConsole } from './console-data'
import { NodeNote, SettingsPage, TopologyPaths } from './console-pages'
import { nodeTypes } from './node-types'
import { GroveCard } from './grove-auth'
import { Sessions } from './sessions'
import { GrovePasswordDialog } from './security-pages'
import { GroveAccountDialog } from './grove-account-access'
import { ServiceList } from './service-workspace'
import { useWorkspace, returnRoute, withReturn } from './workspace-api'
import { nodeResourcesTarget, groveServiceRegistrationHref, localServiceHref, savedRemoteOperationHref, savedRemoteOperationTarget } from './grove-navigation'
import { SavedRemoteOperation } from './operation-history'
import type { History } from './remote-operations'
import { actions, type Operation } from './services'
import { hostResources, hostTrendSeries, type HostTrend } from './host-resources'
import { publicPanelLabel } from './grove-directory'
import { Badge, CopyValue, EmptyState, Icon, Loading, NodeConnectionBadge, Notice, PageHeading, Panel, StateBadge, Tabs } from './ui'

type Host = { node_id: string; platform: { os: string; architecture: string }; metrics: Metrics; trend?: HostTrend }

export function SectionNavigation({ page }: { page: string }) {
  const groups = [
    [{ id: 'operations', label: '操作记录' }, { id: 'alerts', label: '告警' }],
    [{ id: 'identity', label: '账号与登录' }, { id: 'audit', label: '安全审计' }],
  ]
  const group = groups.find(items => items.some(item => item.id === page))
  return group ? <div className="section-tabs"><Tabs label="区域导航" items={group} current={page} onChange={next => { location.hash = '#/' + next }} /></div> : null
}

function NodeSample({ target, full = false }: { target: string; full?: boolean }) {
  const { session, onUnauthorized } = useConsole()
  const host = useWorkspace<Host>(target, session, 'host', full ? { trend: true } : {}, onUnauthorized, 5000)
  const metrics = host.data?.metrics
  const fresh = !host.error && metrics && !metrics.stale && (metrics.valid_until || 0) * 1000 > Date.now()
  if (!full) return <span className="muted tiny">{host.data && <small className="table-secondary">{host.data.platform.os} · {host.data.platform.architecture}</small>}{fresh ? `${metrics.cpu_percent?.toFixed(0) ?? '—'}% CPU · ${metrics.memory ? ((1 - metrics.memory.available / metrics.memory.total) * 100).toFixed(0) + '% 内存' : '—'}` : host.error ? '等待节点更新或响应' : '读取采样…'}</span>
  return <div className="stack">{host.error && <Notice tone="amber">{host.error}</Notice>}
    <Panel title="目标节点资源" action={<button className="btn btn-secondary" onClick={host.reload}>刷新采样</button>}>
      {!host.data && !host.error && <Loading />}
      {metrics && <><p className="muted">{fresh ? '最近采样' : '上次已知采样，正在等待刷新'} · {timestamp(metrics.sampled_at)}</p>
        <div className="resource-row"><span>CPU</span><strong>{fresh ? `${metrics.cpu_percent?.toFixed(1) ?? '—'}%` : '待确认'}</strong></div>
        {hostResources(metrics).map(item => <div key={item.id} className="resource-row"><span>{item.label}</span><strong>{fresh && item.percent != null ? `${item.percent.toFixed(1)}%` : '待确认'}</strong></div>)}
      </>}
    </Panel>
    {host.data?.trend && <Panel title="最近 15 分钟"> <div className="resource-trends">{hostTrendSeries(host.data.trend).map(series => <section className="resource-trend" key={series.label}><h4>{series.label}</h4><svg viewBox="0 0 100 100" preserveAspectRatio="none" className="resource-trend-chart" aria-label={`${series.label} 趋势`}>{series.segments.map((segment, i) => <polyline key={i} points={segment.map(point => `${point.x},${point.y}`).join(' ')} vectorEffect="non-scaling-stroke" />)}</svg></section>)}</div></Panel>}
  </div>
}

export function NodeInspector({ nodeId, onSave, embedded = false, initialTab }: { nodeId: string; onSave: (preferences: Preferences) => void; embedded?: boolean; initialTab?: string }) {
  const { listedNodes, localName } = useConsole()
  const selected = listedNodes.find(node => node.id === nodeId)
  const params = new URLSearchParams(location.hash.split('?')[1])
  const [tab, setTab] = useState(initialTab || (nodeResourcesTarget(location.hash.split('?')[0]) ? 'resources' : params.get('tab') || 'overview'))
  if (!selected) return <Panel><EmptyState title="正在等待节点目录" /></Panel>
  const online = selected.status === 'online'
  return <>{!embedded && <><a className="back-link" href={returnRoute('#/nodes')}>返回来源</a><PageHeading eyebrow="INFRASTRUCTURE / NODE" title={selected.name} description="在当前面板查看目标节点和管理服务。">
    <a className="btn btn-secondary" href={withReturn(`#/ssh/${selected.id}`)}>终端与文件</a><a className="btn btn-primary" href={withReturn(groveServiceRegistrationHref(selected.id))}>登记服务</a>
  </PageHeading></>}<div className="workspace-context"><span>当前面板 <strong>{localName}</strong></span><Icon name="arrow-right" size={15} /><span>目标节点 <strong>{selected.name}</strong></span><NodeConnectionBadge node={selected} /></div>
    <Tabs label="节点工作区" current={tab} onChange={setTab} items={[{ id: 'overview', label: '概况' }, { id: 'services', label: '服务' }, { id: 'network', label: '网络' }, { id: 'resources', label: '资源' }, { id: 'version', label: '版本' }]} />
    {tab === 'overview' && <div className="columns-2"><Panel title="节点信息"><dl className="facts"><div><dt>节点标识</dt><dd><CopyValue value={selected.id} short /></dd></div><div><dt>节点类型</dt><dd>{nodeTypes[selected.nodeType ?? 'generic'].label}</dd></div><div><dt>面板地址</dt><dd>{publicPanelLabel(selected.memberOrigin || (selected.local ? location.origin : undefined))}</dd></div><div><dt>连接</dt><dd>{selected.activePath?.length ? `${selected.activePath.length - 1} 跳` : selected.local ? '当前面板' : '暂无活动路径'}</dd></div></dl></Panel><Panel title="节点资料"><NodeNote nodeId={selected.id} onSave={onSave} /></Panel></div>}
    {tab === 'services' && <ServiceList key={selected.id} initialNode={selected.id} embedded />}
    {tab === 'network' && <Panel title="网络路径">{selected.local ? <p className="muted">这是当前节点，可在拓扑中选择其他节点查看连接路径。</p> : <TopologyPaths key={selected.id} node={selected} />}</Panel>}
    {tab === 'resources' && (online ? <NodeSample target={selected.local ? 'local' : selected.id} full /> : <Notice tone="amber">目标节点当前不可达，等待连接恢复后读取真实采样。</Notice>)}
    {tab === 'version' && <Panel title="版本与更新"><p>查看目标节点版本和群组更新结果。</p><a className="btn btn-primary" href={`#/maintenance/${selected.id}`}>查看版本与更新</a></Panel>}
  </>
}

export function IdentityWorkspace({ onFactors }: { onFactors: () => void }) {
  const { session, onUnauthorized, groveDetails, groveError, directoryCurrent, admin } = useConsole()
  return <><PageHeading eyebrow="MANAGEMENT / IDENTITY" title="身份与安全" description="管理 Grove 账号、角色和登录访问。" />
    <div className="identity-workspace">
      {groveDetails?.configured ? <GroveCard data={groveDetails} error={groveError} session={session} onUnauthorized={onUnauthorized} directoryCurrent={directoryCurrent} />
        : <Panel title="Grove 账号">{groveError ? <Notice tone="amber">{groveError}</Notice> : !groveDetails ? <Loading label="正在读取账号信息…" />
          : <div className="identity-local-state"><p className="muted">当前使用本机账号。创建或加入 Grove 后，可在这里管理 Grove 账号。</p><a className="btn btn-secondary" href="#/nodes?join=1">设置 Grove<Icon name="arrow-right" size={14} /></a></div>}</Panel>}
      <Panel title="登录与会话" className="identity-login-panel"><div className="identity-signed-in"><span className="avatar-circle">{(session.display_name || session.username).slice(0, 1).toUpperCase()}</span><div><strong>{session.display_name || session.username}</strong><small>{session.grove ? 'Grove 账号' : '本机账号'} · {admin ? '管理员' : '操作员'}</small></div></div>
        <div className="identity-login-actions">
          <button type="button" onClick={onFactors}><Icon name="key" size={16} /><span>管理登录验证器</span><Icon name="arrow-right" size={14} /></button>
          {session.grove && groveDetails?.account_management && <a href="#/account/identity">
            <Icon name="key" size={16} /><span>登录设备与账号恢复</span><Icon name="arrow-right" size={14} /></a>}
          <a href="#/account/sessions"><Icon name="monitor" size={16} /><span>查看登录会话</span><Icon name="arrow-right" size={14} /></a></div>
      </Panel>
    </div>
  </>
}

export function AccountWorkspace({ onFactors, onSave, section }: { onFactors: () => void; onSave: (preferences: Preferences) => void; section?: string }) {
  const { session, onUnauthorized } = useConsole()
  const [tab, setTab] = useState(section || 'identity')
  const [passwordOpen, setPasswordOpen] = useState(false)
  const [deviceOpen, setDeviceOpen] = useState(false)
  const [recoveryOpen, setRecoveryOpen] = useState(false)
  const recovery = usePoll<{ available: boolean; configured: boolean; device_bound?: boolean }>(session.grove ? '/auth/grove/account/recovery-code' : null, onUnauthorized)
  const password = usePoll<{ available: boolean }>(session.grove ? '/auth/grove/password' : null, onUnauthorized)
  return <><PageHeading eyebrow="ACCOUNT" title="我的账户" description="登录验证、个人会话和浏览器显示偏好。" /><Tabs label="个人账户" current={tab} onChange={setTab} items={[{ id: 'identity', label: '账户验证' }, { id: 'sessions', label: '会话' }, { id: 'settings', label: '显示偏好' }]} />
    {tab === 'identity' && <Panel title="当前登录身份"><strong>{session.display_name || session.username}</strong><p className="muted">{session.grove ? 'Grove 账号' : '本机账号'}</p><div className="button-row"><button className="btn btn-secondary" onClick={onFactors}>管理登录验证器</button>{password.data?.available && <button className="btn btn-secondary" onClick={() => setPasswordOpen(true)}>修改 Grove 密码</button>}
      {recovery.data?.available && <><button className="btn btn-secondary" onClick={() => setRecoveryOpen(true)}>{recovery.data.configured ? '重新生成账号恢复码' : '生成账号恢复码'}</button>
      {!recovery.data.device_bound && <button className="btn btn-secondary" disabled={!recovery.data.configured} onClick={() => setDeviceOpen(true)}>绑定登录设备</button>}</>}</div>
      {recovery.data?.available && !recovery.data.device_bound && !recovery.data.configured && <p className="muted">绑定前请生成并保存账号恢复码。</p>}</Panel>}
    {tab === 'sessions' && <Sessions session={session} onUnauthorized={onUnauthorized} />}{tab === 'settings' && <SettingsPage onSave={onSave} />}
    {recoveryOpen && <GroveAccountDialog action="recovery-code" deviceBound={recovery.data?.device_bound} session={session} onClose={() => setRecoveryOpen(false)} onUnauthorized={onUnauthorized} />}
    {deviceOpen && <GroveAccountDialog action="bind-device" session={session} onClose={() => setDeviceOpen(false)} onUnauthorized={onUnauthorized} />}
    {passwordOpen && <GrovePasswordDialog session={session} onUnauthorized={onUnauthorized} onClose={() => setPasswordOpen(false)} />}
  </>
}

const operationEvents: Partial<Record<string, { subject: string; action: string; status: string }>> = {
  'service.registered': { subject: '服务登记', action: '登记服务', status: 'succeeded' },
  'service.unregistered': { subject: '服务登记', action: '取消登记', status: 'succeeded' },
  'service.details.updated': { subject: '服务登记', action: '修改服务信息', status: 'succeeded' },
  'service.deployment.started': { subject: '服务部署', action: '启动部署', status: 'started' },
  'service.deployment.succeeded': { subject: '服务部署', action: '完成部署', status: 'succeeded' },
  'service.deployment.failed': { subject: '服务部署', action: '部署失败', status: 'failed' },
  'service.deployment.cancelled': { subject: '服务部署', action: '取消部署', status: 'cancelled' },
  'seed.wizard.accepted': { subject: '节点播种', action: '接收播种任务', status: 'accepted' },
  'seed.wizard.started': { subject: '节点播种', action: '启动目标面板', status: 'started' },
  'seed.wizard.joined': { subject: '节点播种', action: '加入 Grove', status: 'succeeded' },
  'seed.wizard.failed': { subject: '节点播种', action: '播种失败', status: 'failed' },
  'grove.update.started': { subject: 'Grove 群组更新', action: '发起群组更新', status: 'started' },
  'grove.update.accepted': { subject: 'Grove 群组更新', action: '接收更新任务', status: 'accepted' },
  'grove.update.succeeded': { subject: 'Grove 群组更新', action: '本机更新完成', status: 'succeeded' },
  'grove.update.failed': { subject: 'Grove 群组更新', action: '本机更新失败', status: 'failed' },
  'grove.node_note_changed': { subject: '节点资料', action: '修改节点备注', status: 'succeeded' },
  'grove.node_profile_changed': { subject: '节点资料', action: '修改节点资料', status: 'succeeded' },
}
type HistoryTarget = { service_id: string; service_name: string | null }
type OperationRow = { id: string; source: 'local' | 'remote' | 'change'; subject: string; node: string;
  action: string; status: string; time: number; href?: string; reference?: string }

export function OperationCenter() {
  const { admin, onUnauthorized, localName, listedNodes, services } = useConsole()
  const local = usePoll<Array<Operation & HistoryTarget>>(admin ? '/operations/local' : null, onUnauthorized)
  const remote = usePoll<Array<History & HistoryTarget & { node_id: string }>>(admin ? '/operations/remote' : null, onUnauthorized)
  const audit = usePoll<AuditEntry[]>(admin ? '/audit?limit=200' : null, onUnauthorized, 15000)
  const [source, setSource] = useState('all'), [status, setStatus] = useState('all')
  const saved = savedRemoteOperationTarget(location.hash)
  if (!admin) return <EmptyState title="操作记录仅向节点管理员开放" />
  if (saved) return <SavedRemoteOperation {...saved} />
  const nodeNames = new Map(listedNodes.map(node => [node.id, node.name]))
  const serviceNames = new Map((services.data || []).map(service => [service.id, service.name]))
  const rows: OperationRow[] = [
    ...(local.data || []).map<OperationRow>(item => ({ id: `local/${item.id}`, source: 'local', subject: item.service_name || '已移除的服务',
      node: localName, action: actions[item.action], status: item.status, time: item.updated_at, reference: item.id,
      href: item.service_name ? withReturn(localServiceHref(item.service_id, 'history')) : undefined })),
    ...(remote.data || []).map<OperationRow>(item => ({ id: `remote/${item.node_id}/${item.request_id}`, source: 'remote',
      subject: item.service_name || '远程服务', node: nodeNames.get(item.node_id) || item.node_id, action: actions[item.action],
      status: item.receipt?.operation?.status || (item.receipt ? 'accepted' : 'uncertain'), time: item.updated_at, reference: item.request_id,
      href: savedRemoteOperationHref(item.node_id, item.service_id, item.request_id) })),
    ...(audit.data || []).flatMap<OperationRow>(entry => {
      const event = operationEvents[entry.event]
      if (!event) return []
      return [{ ...event, id: `audit/${entry.id}`, source: 'change', time: entry.recorded_at,
        subject: serviceNames.get(entry.target || '') || event.subject, node: nodeNames.get(entry.target || '') || localName }]
    }),
  ].sort((a, b) => b.time - a.time).filter(item => (source === 'all' || source === item.source)
    && (status === 'all' || status === item.status || (status === 'pending' && item.source !== 'change'
      && ['accepted', 'queued', 'running', 'uncertain'].includes(item.status))))
  const reads = source === 'local' ? [local] : source === 'remote' ? [remote] : source === 'change' ? [audit] : [local, remote, audit]
  const loading = reads.some(read => !read.data && !read.error)
  const failed = reads.some(read => !!read.error)
  const phaseLabels: Record<string, string> = { started: '已启动', accepted: '已受理', cancelled: '已取消' }
  return <><PageHeading eyebrow="WORKSPACE / OPERATIONS" title="操作中心" description="查看此面板保存的服务回执、任务与变更记录。" />
    <Panel title="操作记录" action={<button className="btn btn-secondary" onClick={refreshConsole}>刷新</button>}><div className="workspace-filters">
      <select className="input" aria-label="记录类型" value={source} onChange={event => setSource(event.target.value)}><option value="all">全部记录</option><option value="local">本机服务操作</option><option value="remote">远程服务操作</option><option value="change">任务与变更</option></select>
      <select className="input" aria-label="操作结果" value={status} onChange={event => setStatus(event.target.value)}><option value="all">全部状态</option><option value="pending">待跟踪</option><option value="uncertain">结果待确认</option><option value="succeeded">已完成</option><option value="failed">失败</option></select></div>
      {failed && <Notice tone="amber">部分记录暂时无法读取，可刷新重试。</Notice>}
      {rows.length ? <div className="table-wrap"><table className="data-table">
        <thead><tr><th>服务 / 任务</th><th>节点</th><th>动作</th><th>结果</th><th>时间</th></tr></thead>
        <tbody>{rows.map(item => <tr key={item.id}>
          <td>{item.href ? <a className="text-link" href={item.href}>{item.subject}</a> : item.subject}
            {item.reference && <small className="table-secondary">{item.reference}</small>}</td>
          <td>{item.node}</td><td>{item.action}</td>
          <td>{phaseLabels[item.status] ? <Badge>{phaseLabels[item.status]}</Badge> : <StateBadge state={item.status} />}</td>
          <td className="time-cell">{timestamp(item.time)}</td>
        </tr>)}</tbody>
      </table></div> : loading ? <Loading /> : !failed && <EmptyState title="没有匹配的操作记录" />}
    </Panel></>
}
