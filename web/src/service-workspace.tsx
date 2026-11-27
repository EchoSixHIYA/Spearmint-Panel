import { Fragment, useEffect, useState } from 'react'
import { ApiError, timestamp, usePoll } from './api'
import { useConsole, refreshConsole } from './console-data'
import { remoteDirectoryCurrent, useRemoteCatalog, useRemoteObservationTime } from './remote-catalog'
import { ServiceLogs } from './service-logs'
import { FrpMappings } from './frp-mappings'
import { GroveServiceSetup } from './remote-service-setup'
import { ServiceDeployment, deployedBySpearmint } from './service-deployment'
import { ServiceAccessLinks, type AccessLink } from './service-access-links'
import { HostServiceAuthorization } from './host-service-authorization'
import { ServiceGroupActions, ServiceGroupEditor, type GroupTarget, type ServiceGroup } from './service-groups'
import { allowNavigation } from './navigation-guard'
import { type Service, actions as actionNames, serviceDriver } from './services'
import { groveServiceRegistrationHref, localServiceHref, remoteServiceHref } from './grove-navigation'
import { useServiceOperation, useWorkspace, workspace, workspaceError, returnRoute, withReturn } from './workspace-api'
import { Badge, bytes, CopyValue, duration, EmptyState, Icon, Loading, Modal, Notice, PageHeading, Panel, StateBadge, Tabs } from './ui'

type ServiceResources = { pid: number | null; sampled_at: number | null; valid_until: number | null; scope: string | null;
  cpu_percent: number | null; memory_bytes: number | null; uptime_seconds: number | null;
  gpu: { utilization_percent: number | null; memory_used_bytes: number | null; valid_until?: number | null } }
type Receipt = { id?: string; action: string; status: string; updated_at?: number; message?: string | null; reason?: string }
type Detail = Service & { command?: string; managed: boolean; can_edit_details: boolean; can_unregister: boolean; can_deploy?: boolean;
  access_links?: AccessLink[]; controls_only?: boolean;
  deployment?: { source?: string; kind?: string; directory?: string };
  unregister_reason?: string; can_change_mode: boolean; resources?: ServiceResources; operations: Array<Receipt & { id: string; updated_at: number }> }

function ServiceUsage({ service, unavailable }: { service: Detail; unavailable: boolean }) {
  const data = service.resources
  const [revision, refresh] = useState(0)
  useEffect(() => {
    const future = [data?.valid_until, data?.gpu?.valid_until].filter((value): value is number => value != null && value * 1000 > Date.now())
    if (!future.length) return
    const timer = setTimeout(() => refresh(value => value + 1), Math.max(0, Math.min(...future) * 1000 - Date.now()) + 1)
    return () => clearTimeout(timer)
  }, [data, service.observation.pid, revision])
  const current = !unavailable && service.observation.status === 'running' && data?.pid === service.observation.pid
    && data?.valid_until != null && data.valid_until * 1000 > Date.now()
  const gpuCurrent = current && (data?.gpu?.valid_until === undefined || (data.gpu.valid_until != null && data.gpu.valid_until * 1000 > Date.now()))
  const shared = data?.scope === 'shared-process'
  const percent = (value?: number | null) => typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)}%` : '—'
  return <Panel className="service-runtime-panel"><div className="service-runtime-state">
    <StateBadge state={service.observation.status} stale={unavailable} />
    <span>PID <strong>{!unavailable && service.observation.pid > 0 ? service.observation.pid : '—'}</strong></span>
    {shared && <span className="muted tiny">共享进程占用</span>}
    <span className="muted tiny service-runtime-time">最近检查 {timestamp(service.observation.checked_at)}</span>
  </div><dl className="service-usage">
    <div title="服务进程组占节点全部 CPU 的比例"><dt>CPU</dt><dd>{percent(current ? data?.cpu_percent : undefined)}</dd></div>
    <div title={shared ? '此服务与其他服务共享宿主进程，显示共享进程的占用' : '服务及其子进程的内存占用'}><dt>内存</dt><dd>{current && data?.memory_bytes != null ? bytes(data.memory_bytes) : '—'}</dd></div>
    <div><dt>运行时长</dt><dd>{current && data?.uptime_seconds != null ? duration(data.uptime_seconds) : '—'}</dd></div>
    <div title="服务进程组的 GPU 占用"><dt>GPU</dt><dd>{percent(gpuCurrent ? data?.gpu?.utilization_percent : undefined)}</dd>
      {gpuCurrent && data?.gpu?.memory_used_bytes != null && <small>显存 {bytes(data.gpu.memory_used_bytes)}</small>}</div>
  </dl></Panel>
}

function receiptReason(receipt?: Receipt) {
  if (receipt?.reason === 'RESTART_BEFORE_DISPATCH') return '面板重启前，这笔操作尚未派发。'
  if (receipt?.reason === 'PANEL_RESTARTED') return '面板重启，执行结果待确认。'
  if (receipt?.reason === 'POLICY_CHANGED') return '执行前，所属节点的管理授权已变更。'
  if (receipt?.reason === 'HOST_ERROR') return '所属节点执行出错。'
  if (receipt?.reason === 'HOST_TIMEOUT') return '所属节点执行命令超时。'
  if (receipt?.reason === 'RUNTIME_NOT_READY') return '执行时，服务尚未就绪。'
  if (receipt?.reason === 'STATE_NOT_REACHED') return '服务未进入请求的运行状态。'
  if (receipt?.reason === 'OUTCOME_UNCONFIRMED') return '所属节点未能确认执行结果。'
  return receipt?.reason
}

export function ServiceWorkspace({ section, segments }: { section?: string; segments: string[] }) {
  const { session, onUnauthorized, local } = useConsole()
  if (section === 'register') return <GroveServiceSetup targetId={segments[0]} session={session} onUnauthorized={onUnauthorized} />
  if (section === 'remote' && segments[1]) return <ServiceDetail key={`${segments[0]}/${segments[1]}`} target={segments[0]} id={segments[1]} initialTab={segments[2]} />
  if (section && /^[a-f0-9]{32}$/.test(section)) return <ServiceDetail key={`local/${section}`} target="local" id={section} initialTab={segments[0]} />
  return <ServiceList initialNode={section === 'local' ? local.data?.node_id : section === 'remote' ? segments[0] : undefined} />
}

export function ServiceList({ initialNode, embedded = false }: { initialNode?: string; embedded?: boolean }) {
  const { services, listedNodes, local, localName, onUnauthorized } = useConsole()
  const { entries, error, directories } = useRemoteCatalog()
  const localGroups = usePoll<ServiceGroup[]>('/services/groups', onUnauthorized)
  const now = useRemoteObservationTime(entries.map(entry => entry.service.observation)) / 1000
  const query = new URLSearchParams(location.hash.split('?')[1])
  const [search, setSearch] = useState(query.get('q') || '')
  const [node, setNode] = useState((embedded ? initialNode : query.get('node') || initialNode) || '')
  const [status, setStatus] = useState(query.get('status') || '')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [editor, setEditor] = useState<{ target: string; group?: ServiceGroup }>()
  const localId = local.data?.node_id || 'local'
  const selectedPeers = listedNodes.filter(item => !item.local && item.peer?.enabled
    && item.status !== 'quarantined' && item.status !== 'disabled' && (!node || item.id === node))
  const partialCatalog = selectedPeers.some(item => !remoteDirectoryCurrent(item, directories.get(item.id)))
  const upgradeCatalog = selectedPeers.some(item => directories.get(item.id)?.catalog_upgrade_required)
  const readOnlyCatalog = selectedPeers.some(item => {
    const directory = directories.get(item.id)
    return directory?.catalog_read_only && !directory.catalog_upgrade_required
  })
  const rows = [
    ...(services.data || []).map(service => ({ service, node: localId, name: localName, local: true, stale: !!services.error || service.observation.stale, observation: service.observation })),
    ...entries.map(entry => ({ service: entry.service, node: entry.node.id, name: entry.node.name, local: false,
      stale: entry.stale || entry.service.observation?.stale !== false || (entry.service.observation?.valid_until ?? 0) <= now,
      observation: entry.service.observation })),
  ].sort((a, b) => a.name.localeCompare(b.name, 'zh-CN') || a.node.localeCompare(b.node)
    || a.service.name.localeCompare(b.service.name, 'zh-CN') || a.service.id.localeCompare(b.service.id))
  const targets = [
    { node: localId, id: 'local', label: localName, available: !!localGroups.data && !localGroups.error && !services.error, canEdit: true, groups: localGroups.data || [] },
    ...listedNodes.filter(item => !item.local && directories.get(item.id)?.service_groups !== undefined).map(item => {
      const directory = directories.get(item.id)
      return { node: item.id, id: item.id, label: item.name,
        available: !error && !directory?.catalog_read_only && remoteDirectoryCurrent(item, directory),
        canEdit: !directory?.catalog_controls_only,
        groups: directory?.service_groups || [] }
    }),
  ].map(target => ({ ...target, services: rows.filter(row => row.node === target.node).map(row => row.service) }))
  const selectableTargets = targets.filter(target => (!embedded || target.node === initialNode) && target.available && target.canEdit && target.services.length)
  const preferredTarget = selectableTargets.find(target => target.node === node) ?? selectableTargets[0]
  const searchTerm = search.trim().toLowerCase()
  function statusMatches(row: typeof rows[number]) {
    return !status || (status === 'stale' ? row.stale : row.observation?.status === status)
  }
  function searchMatches(row: typeof rows[number]) {
    return `${row.service.name} ${row.name} ${row.service.id}`.toLowerCase().includes(searchTerm)
  }
  const assigned = new Set(targets.flatMap(target => target.groups.flatMap(group =>
    group.members.map(member => `${target.node}/${member.service_id}`))))
  const groups = targets.filter(target => !node || target.node === node).flatMap(target => target.groups.map(group => {
    const members = group.members.map(member => ({ ...member,
      row: rows.find(row => row.node === target.node && row.service.id === member.service_id) }))
    const named = group.name.toLowerCase().includes(searchTerm)
    const matching = members.filter(member => member.row && statusMatches(member.row) && (named || searchMatches(member.row)))
    return { target, group, members, matching }
  }).filter(item => item.matching.length || (!status && item.group.name.toLowerCase().includes(searchTerm))))
  const visible = rows.filter(row => (!node || row.node === node) && !assigned.has(`${row.node}/${row.service.id}`)
    && statusMatches(row) && searchMatches(row))
  function update(field: 'q' | 'node' | 'status', value: string) {
    if (field === 'q') setSearch(value); else if (field === 'node') setNode(value); else setStatus(value)
    const params = new URLSearchParams(location.hash.split('?')[1]); if (value) params.set(field, value); else params.delete(field)
    history.replaceState(null, '', location.hash.split('?')[0] + (params.size ? '?' + params : ''))
  }
  function serviceRow(row: typeof rows[number], options?: { statusOnly: boolean; groupRunning: boolean }) {
    const href = withReturn(row.local ? localServiceHref(row.service.id) : remoteServiceHref(row.node, row.service.id))
    const directory = directories.get(row.node)
    return <tr className={options ? 'service-group-child' : undefined} key={row.service.id}><td>
      {options?.statusOnly ? <strong>{row.service.name}</strong> : <a className="text-link" href={href}><strong>{row.service.name}</strong></a>}
      <small className="table-secondary">{row.service.driver === 'docker' ? 'Docker 容器' : '系统服务 / 程序'}</small>
    </td><td><a href={withReturn(`#/nodes/${row.node}`)}>{row.name}</a><small className="table-secondary">{row.local ? '当前面板 · 本机' : '通过 Mesh 管理'}</small></td>
      <td><StateBadge state={row.observation?.status || 'unknown'} stale={row.stale} /></td><td className="muted time-cell">{timestamp(row.observation?.checked_at ?? null)}</td>
      <td>{options?.statusOnly ? <span className="muted tiny">仅显示状态</span>
        : <ServiceRowActions target={row.local ? 'local' : row.node} serviceId={row.service.id} nodeName={row.name}
          path={row.local ? `/services/${row.service.id}` : `/peers/${row.node}/services/${row.service.id}`}
          name={row.service.name} status={row.observation?.status} allowed={options?.groupRunning ? [] : row.service.actions}
          version={row.service.version || 1} stale={row.stale}
          blocked={options?.groupRunning} readOnly={directory?.catalog_read_only} controlsOnly={directory?.catalog_controls_only}
          detailsHref={href} logsHref={withReturn(row.local ? localServiceHref(row.service.id, 'logs') : remoteServiceHref(row.node, row.service.id, true))} />}</td>
    </tr>
  }
  return <>{!embedded && <PageHeading eyebrow="WORKSPACE / SERVICES" title="服务" description="找到程序，控制启停，确认结果。">
    <button type="button" className="btn btn-secondary" disabled={!preferredTarget} onClick={() => {
      if (preferredTarget) setEditor({ target: preferredTarget.id })
    }}><Icon name="layers" size={16} />新建服务组</button>
    <a className="btn btn-primary" href={withReturn(groveServiceRegistrationHref(node || undefined))}><Icon name="plus" size={16} />登记服务</a>
  </PageHeading>}{embedded && <div className="button-row"><a className="btn btn-primary" href={withReturn(groveServiceRegistrationHref(initialNode))}>在此节点登记服务</a>
    {preferredTarget && <button type="button" className="btn btn-secondary" onClick={() => setEditor({ target: preferredTarget.id })}>新建服务组</button>}</div>}
    <div className="workspace-summary"><strong>{rows.length} 个{partialCatalog ? '已显示服务' : '已登记服务'}</strong><span>{rows.filter(row => !row.stale && row.observation?.status === 'running').length} 个运行中</span>
      <span role="status">{services.error || error || partialCatalog ? '部分节点的服务目录暂不可用' : ''}</span></div>
    {upgradeCatalog && <Notice tone="amber">部分节点需要更新后才能使用本次登录的服务操作权限。<a href="#/maintenance">查看群组更新</a></Notice>}
    {readOnlyCatalog && <Notice tone="amber">使用 Grove 登录设备重新登录后，即可管理远程服务和查看日志。</Notice>}
    <Panel><div className="workspace-filters"><label className="search-box"><Icon name="search" size={16} /><input aria-label="搜索服务" value={search} onChange={e => update('q', e.target.value)} placeholder="搜索服务、节点或程序名称…" /></label>
      <select className="input" aria-label="按节点筛选" value={node} disabled={embedded} onChange={e => update('node', e.target.value)}><option value="">全部节点</option>{listedNodes.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
      <select className="input" aria-label="按状态筛选" value={status} onChange={e => update('status', e.target.value)}><option value="">全部状态</option><option value="running">运行中</option><option value="stopped">已停止</option><option value="failed">失败</option><option value="stale">状态待确认</option></select>
      <button className="btn btn-secondary" onClick={refreshConsole}>刷新</button></div>
      {!services.data && !services.error ? <Loading /> : visible.length || groups.length ? <div className="table-wrap"><table className="data-table workspace-service-table"><thead><tr><th>服务</th><th>所属节点</th><th>运行状态</th><th>最近检查</th><th>操作</th></tr></thead><tbody>
        {groups.map(({ target, group, members, matching }) => {
          const key = `${target.id}/${group.id}`
          const open = expanded[key] ?? false
          const running = members.filter(({ row }) => row && !row.stale && row.observation?.status === 'running' && row.observation.health !== 'unhealthy').length
          const unknown = members.some(({ row }) => !row || row.stale)
          const failed = members.some(({ row }) => row && !row.stale &&
            (['missing', 'failed'].includes(row.observation?.status || '') || row.observation?.health === 'unhealthy'))
          return <Fragment key={key}><tr className="service-group-header">
            <td><button type="button" className="service-group-toggle" aria-expanded={open}
              onClick={() => setExpanded(previous => ({ ...previous, [key]: !open }))}>
              <Icon name={open ? 'chevron-down' : 'chevron-right'} size={15} /><Icon name="layers" size={17} />
              <strong>{group.name}</strong><small>{members.length} 项</small>
            </button></td>
            <td>{target.label}</td>
            <td><Badge tone={failed ? 'red' : running === members.length ? 'green' : 'neutral'}>{running}/{members.length} 运行中</Badge>
              {(unknown || failed) && <small className="table-secondary">{failed ? '成员异常' : '部分状态待确认'}</small>}</td>
            <td>—</td>
            <td><ServiceGroupActions group={group} target={target satisfies GroupTarget} onEdit={() => setEditor({ target: target.id, group })} /></td>
          </tr>
          {open && matching.map(member => member.row && serviceRow(member.row, { statusOnly: member.status_only,
            groupRunning: group.operation?.status === 'running' }))}
          </Fragment>
        })}
        {visible.map(row => <Fragment key={`${row.node}/${row.service.id}`}>{serviceRow(row)}</Fragment>)}
      </tbody></table></div> : <EmptyState title={partialCatalog ? '所选范围的服务目录尚未读全' : '没有匹配的服务'} />}
    </Panel>
    {editor && <ServiceGroupEditor targets={editor.group ? targets.filter(target => target.id === editor.target) : selectableTargets}
      initialTarget={editor.target} group={editor.group} onClose={() => setEditor(undefined)} />}
  </>
}

function ServiceRowActions({ target, serviceId, nodeName, path, name, status, allowed, version, stale, blocked, readOnly, controlsOnly, detailsHref, logsHref }: {
  target: string; serviceId: string; nodeName: string
  path: string; name: string; status?: string; allowed: readonly string[]; version: number; stale: boolean; blocked?: boolean; readOnly?: boolean; controlsOnly?: boolean; detailsHref: string; logsHref: string
}) {
  const { session } = useConsole()
  const flow = useServiceOperation(path, session, version, refreshConsole)
  const [confirmRemoval, setConfirmRemoval] = useState(false)
  const availableAction = status === 'running' ? 'stop' : status === 'stopped' || status === 'failed' ? 'start' : undefined
  const actionBlock = flow.tracking ? '操作执行中，等待回执' : readOnly ? '当前会话尚未授权远程服务操作' : stale ? '状态待确认' : undefined
  return <div className="service-row-actions">
    <div className="service-action-icons" role="group" aria-label={`${name} 的操作`}>
      {(['start', 'stop'] as const).map(action => <button key={action} type="button"
        className={`icon-button service-action-${action}`} aria-label={`${actionNames[action]} ${name}`}
        title={actionBlock ?? (!allowed.includes(action) ? '当前服务不支持此操作' : `${actionNames[action]} ${name}`)}
        disabled={!!actionBlock || availableAction !== action || !allowed.includes(action)} onClick={() => {
          if (action === 'start' || confirm(`停止 ${name}？操作由所属节点执行。`)) void flow.submit(action)
        }}><Icon name={action === 'start' ? 'play' : 'stop'} size={16} /></button>)}
      <a className="icon-button" title={`查看 ${name} 详情`} aria-label={`查看 ${name} 详情`} href={detailsHref}><Icon name="info" size={16} /></a>
      <a className="icon-button" title={`查看 ${name} 日志`} aria-label={`查看 ${name} 日志`} href={logsHref}><Icon name="file-text" size={16} /></a>
      <button type="button" className="icon-button" aria-label={`重启 ${name}`}
        title={actionBlock ?? (!allowed.includes('restart') ? '当前服务不支持重启' : `重启 ${name}`)}
        disabled={!!actionBlock || !availableAction || !allowed.includes('restart')} onClick={() => {
          if (confirm(`重启 ${name}？操作由所属节点执行。`)) void flow.submit('restart')
        }}><Icon name="refresh" size={16} /></button>
      <button type="button" className="icon-button service-action-unregister" aria-label={`取消登记 ${name}`}
        title={readOnly || controlsOnly ? '取消登记需要远程服务管理授权' : flow.tracking ? '操作执行中，等待回执' : `取消登记 ${name}`}
        disabled={flow.tracking || blocked || readOnly || controlsOnly} onClick={() => setConfirmRemoval(true)}><Icon name="x" size={16} /></button>
    </div>
    {flow.tracking && (flow.intent?.operation?.status === 'uncertain'
      ? <button type="button" className="service-action-receipt" onClick={() => void flow.query()}>查询原请求</button>
      : <span className="service-action-receipt" role="status">执行中…</span>)}
    {confirmRemoval && <ServiceRowRemoval target={target} serviceId={serviceId} name={name} nodeName={nodeName}
      onClose={() => setConfirmRemoval(false)} />}
  </div>
}

function ServiceRowRemoval({ target, serviceId, name, nodeName, onClose }: {
  target: string; serviceId: string; name: string; nodeName: string; onClose: () => void
}) {
  const { session, onUnauthorized } = useConsole()
  type Registration = Pick<Detail, 'name' | 'version' | 'can_unregister' | 'unregister_reason'>
  const [registration, setRegistration] = useState<Registration>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    workspace<Registration>(target, session, 'detail', { service_id: serviceId }, controller.signal).then(value => {
      if (!controller.signal.aborted) setRegistration(value)
    }).catch(failure => {
      if (controller.signal.aborted) return
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      setError(workspaceError(failure))
    })
    return () => controller.abort()
  }, [target, serviceId, session, onUnauthorized])

  async function remove() {
    if (busy || !registration?.can_unregister || registration.version === undefined) return
    setBusy(true)
    try {
      await workspace(target, session, 'remove', { service_id: serviceId, version: registration.version })
      refreshConsole()
      onClose()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      setError(workspaceError(failure))
    } finally { setBusy(false) }
  }

  return <Modal title={`取消登记 ${registration?.name ?? name}？`} dismissOnEscape={!busy} onClose={() => { if (!busy) onClose() }}>
    <p>将从 {nodeName} 的 Spearmint 中移除此服务的登记记录。服务文件和数据会保留。</p>
    {error ? <Notice tone="amber">{error}</Notice> : !registration ? <Loading /> : !registration.can_unregister
      && <Notice tone="amber">{registration.unregister_reason || '此服务的登记受保护，请在所属节点处理。'}</Notice>}
    <div className="modal-actions">
      <button type="button" className="btn btn-secondary" onClick={onClose} disabled={busy}>取消</button>
      <button type="button" className="btn btn-danger" disabled={busy || !!error || !registration?.can_unregister || registration.version === undefined}
        onClick={() => void remove()}>{busy ? '正在取消登记…' : '确认取消登记'}</button>
    </div>
  </Modal>
}

function ServiceDetail({ target, id, initialTab }: { target: string; id: string; initialTab?: string }) {
  const { session, onUnauthorized, listedNodes, localName } = useConsole()
  const detail = useWorkspace<Detail>(target, session, 'detail', { service_id: id }, onUnauthorized)
  const [tab, setTab] = useState(initialTab === 'logs' || initialTab === 'history' || initialTab === 'links'
    ? initialTab : initialTab === 'access' ? 'settings' : 'overview')
  const [confirmation, setConfirmation] = useState<string>()
  const [editing, setEditing] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('')
  const local = target === 'local', nodeName = local ? localName : listedNodes.find(node => node.id === target)?.name || target
  const path = local ? `/services/${id}` : `/peers/${target}/services/${id}`
  const flow = useServiceOperation(path, session, detail.data?.version || 1, () => { detail.reload(); refreshConsole() })
  const current = detail.data, unavailable = !!detail.error || !current || current.observation.stale
  const canUpdateCode = !!current?.can_deploy && deployedBySpearmint(current)
  const writeBlocked = busy || !!detail.error || flow.tracking
  const runtimeBlocked = writeBlocked || unavailable || ['unknown', 'missing', 'starting', 'stopping'].includes(current?.observation.status || 'unknown')
  const canUnregister = !!current?.can_unregister && current.version !== undefined && !writeBlocked
  const targetMissing = !unavailable && current?.observation.status === 'missing'
  const receipt: Receipt | undefined = flow.intent ? { ...flow.intent.operation, action: flow.intent.action,
    status: flow.intent.operation?.status || 'queued', id: flow.intent.request_id || flow.intent.operation?.id || flow.intent.key } : current?.operations[0]
  const reasons = [...new Set([flow.intent?.error, receipt?.message, receiptReason(receipt), current?.observation.message].filter(Boolean))]
  const hasReceipt = !!receipt || reasons.length > 0
  async function mutate(action: string, body: object) {
    if (!current || busy) return
    setBusy(true); setError('')
    try {
      await workspace(target, session, action, { service_id: id, version: current.version, ...body })
      setEditing(false); detail.reload(); refreshConsole()
      if (action === 'remove') location.hash = returnRoute()
    } catch (failure) { setError(workspaceError(failure)) }
    finally { setBusy(false) }
  }
  function command(action: string) {
    if (action === 'start') void flow.submit(action)
    else setConfirmation(action)
  }
  return <>
    <a className="back-link" href={returnRoute()}><Icon name="arrow-left" size={15} />返回来源</a>
    <PageHeading eyebrow="SERVICE / CONTROL" title={current?.name || '服务详情'} description={`${nodeName} · ${current ? serviceDriver(current) : '正在读取目标节点'}`}>
      {current?.actions.includes(current.observation.status === 'running' ? 'stop' : 'start') && <button className="btn btn-primary" disabled={runtimeBlocked} onClick={() => command(current.observation.status === 'running' ? 'stop' : 'start')}>{current.observation.status === 'running' ? '停止' : '启动'}</button>}
      {current?.actions.includes('restart') && <button className="btn btn-secondary" disabled={runtimeBlocked} onClick={() => command('restart')}>重启</button>}
      <button className="btn btn-secondary" onClick={detail.reload}>核对状态</button>
    </PageHeading>
    {detail.error && <Notice tone="amber">{detail.error}</Notice>}{error && <Notice tone="amber">{error}</Notice>}
    <Tabs label="服务工作区" current={tab} onChange={next => { if (allowNavigation()) setTab(next) }} items={[{ id: 'overview', label: '概览' }, { id: 'links', label: '访问链接' }, { id: 'logs', label: '日志' }, { id: 'history', label: '操作记录' }, { id: 'settings', label: '管理设置' }, ...(canUpdateCode ? [{ id: 'update', label: '代码与更新' }] : [])]} />
    {!current && !detail.error && <Loading />}
    {current && tab === 'overview' && <div className="stack service-overview">
      {targetMissing && <Panel title={current.driver === 'docker' ? '已登记的容器已不存在' : '已登记的运行目标已不存在'}
        action={current.can_unregister && <button type="button" className="btn btn-danger btn-small"
          disabled={!canUnregister} onClick={() => setConfirmation('remove')}>取消登记</button>}>
        <p className="muted tiny">{current.unregister_reason || (!current.can_unregister
          ? '请在所属节点处理这条登记。'
          : current.driver === 'docker' ? '如果容器已重建，可以取消旧登记，再从服务页接管新容器。'
            : '如果服务已替换，可以取消旧登记，再登记新的服务。')}</p>
      </Panel>}
      <ServiceUsage service={current} unavailable={unavailable} />
      <div className={`service-overview-content${hasReceipt ? ' has-receipt' : ''}`}>
        <ServiceLogs path={path} serviceId={id} onUnauthorized={onUnauthorized} remote={!local}
          active={!unavailable && current.logs_available !== false} preview
          fullLogsHref={withReturn(local ? localServiceHref(id, 'logs') : remoteServiceHref(target, id, true))} />
        {hasReceipt && <Panel title="回执与原因" className="service-receipt">
          {receipt && <><div className="button-row"><strong>{actionNames[receipt.action as keyof typeof actionNames] || receipt.action}</strong><StateBadge state={receipt.status} /></div>
            {receipt.updated_at != null && <p className="muted tiny">{timestamp(receipt.updated_at)}</p>}
            {receipt.id && <CopyValue value={receipt.id} short />}</>}
          {reasons.map(reason => <p key={reason}>{reason}</p>)}
          {flow.tracking && <div className="button-row"><button className="btn btn-secondary btn-small" onClick={() => void flow.query()}>查询原请求</button>
            <button className="btn btn-ghost btn-small" onClick={() => { if (confirm('结束结果跟踪？已发出的操作仍可能在目标节点执行。')) flow.clear() }}>结束跟踪</button></div>}
        </Panel>}
      </div>
    </div>}
    {current && tab === 'logs' && <ServiceLogs path={path} serviceId={id} onUnauthorized={onUnauthorized} remote={!local} active={!unavailable && current.logs_available !== false} />}
    {current?.controls_only && tab === 'links' && <Notice tone="amber">请使用 Grove 登录设备重新登录后查看访问链接。</Notice>}
    {current && !current.controls_only && tab === 'links' && <ServiceAccessLinks links={current.access_links} version={current.version ?? 1}
      canEdit={current.can_edit_details && !writeBlocked}
      onSave={async (links, version) => {
        const updated = await workspace<Detail>(target, session, 'edit',
          { service_id: id, version, name: current.name, endpoint: current.endpoint, access_links: links })
        detail.reload()
        refreshConsole()
        return { links: updated.access_links ?? links, version: updated.version ?? version }
      }} />}
    {current && tab === 'history' && <Panel title="此服务的操作记录">{current.operations.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>动作</th><th>结果</th><th>时间</th><th>说明</th></tr></thead><tbody>{current.operations.map(item => <tr key={item.id}><td>{actionNames[item.action as keyof typeof actionNames] || item.action}</td><td><StateBadge state={item.status} /></td><td>{timestamp(item.updated_at)}</td><td>{item.message || receiptReason(item) || '—'}</td></tr>)}</tbody></table></div> : <EmptyState title="此服务暂无操作记录" />}</Panel>}
    {current && tab === 'settings' && <Panel className="service-settings-panel">
      {current.controls_only && <Notice tone="amber">请使用 Grove 登录设备重新登录后修改服务配置。</Notice>}
      <div className="service-setting-row"><span className="service-setting-label">服务名称</span><strong className="service-setting-value">{current.name}</strong>
        <button className="btn btn-secondary btn-small" disabled={writeBlocked || !current.can_edit_details} onClick={() => setEditing(true)}>重命名</button></div>
      <div className="service-setting-row"><span className="service-setting-label">管理方式</span>
        <fieldset className="service-mode-options" aria-label="管理方式" disabled={runtimeBlocked || !current.can_change_mode}>
          <label><input type="radio" name="service-management-mode" value="manage" checked={current.managed} onChange={() => void mutate('mode', { mode: 'manage' })} />托管启停</label>
          <label><input type="radio" name="service-management-mode" value="observe" checked={!current.managed} onChange={() => void mutate('mode', { mode: 'observe' })} />观察模式</label>
        </fieldset>{!current.controls_only && current.runtime === 'systemd-system' && !current.managed && <HostServiceAuthorization nodeId={target} session={session} onUnauthorized={onUnauthorized}
          disabled={busy} onAuthorized={() => { void mutate('mode', { mode: 'manage' }) }} />}</div>
      {!current.controls_only && current.driver === 'docker' && <div className="service-setting-row"><span className="service-setting-label">Docker 访问</span>
        <HostServiceAuthorization nodeId={target} session={session} onUnauthorized={onUnauthorized} scope="docker"
          disabled={busy} onAuthorized={() => { detail.reload(); refreshConsole() }} /></div>}
      {current.command && <details className="service-settings-command"><summary>启动命令</summary><pre className="command-block">{current.command}</pre></details>}
      <section className="service-advanced-management" role="group" aria-labelledby="service-advanced-title"><h3 id="service-advanced-title">高级管理</h3>
        <div className="service-advanced-actions"><a className="btn btn-secondary btn-small" href={withReturn(`#/ssh/${local ? current.node_id : target}`)}><Icon name="terminal" size={15} />打开该节点终端</a>
          <button className="btn btn-secondary btn-small" onClick={() => setTab('mapping')}><Icon name="globe" size={15} />公网映射<Badge tone="amber">规划中</Badge></button>
          <button className="btn btn-danger btn-small" disabled={!canUnregister} title={current.unregister_reason} onClick={() => setConfirmation('remove')}>取消登记</button></div>
      </section>
    </Panel>}
    {current && tab === 'update' && canUpdateCode && <Panel title="更新服务"><ServiceDeployment target={target} service={current} onChanged={detail.reload} onOpen={() => setTab('overview')} /></Panel>}
    {current && tab === 'mapping' && <div className="stack"><div className="button-row"><button className="btn btn-ghost btn-small" onClick={() => setTab('settings')}><Icon name="arrow-left" size={14} />返回高级管理</button><Badge tone="amber">规划中</Badge></div>
      <FrpMappings path={path} session={session} onUnauthorized={onUnauthorized} stale={unavailable} /></div>}
    {confirmation && <Modal title={confirmation === 'remove' ? `取消登记 ${current?.name}？` : `${actionNames[confirmation as keyof typeof actionNames]} ${current?.name}？`} onClose={() => setConfirmation(undefined)}>
      <p>{confirmation === 'remove' ? <>将从 {nodeName} 的 Spearmint 中移除此服务的登记记录。</> : <>目标节点：{nodeName}。操作结果将在当前面板显示。</>}</p>
      <div className="modal-actions"><button className="btn btn-secondary" onClick={() => setConfirmation(undefined)}>取消</button>
        <button className="btn btn-danger" disabled={confirmation === 'remove' ? !canUnregister : runtimeBlocked} onClick={() => {
          const action = confirmation
          setConfirmation(undefined)
          if (action === 'remove') void mutate('remove', {})
          else void flow.submit(action)
        }}>确认{confirmation === 'remove' ? '取消登记' : actionNames[confirmation as keyof typeof actionNames]}</button></div></Modal>}
    {editing && current && <Modal title="编辑服务信息" onClose={() => setEditing(false)}><form className="stack" onSubmit={event => { event.preventDefault(); const values = new FormData(event.currentTarget); void mutate('edit', { name: values.get('name'), endpoint: current.endpoint }) }}>
      <label className="field-label">服务名称<input className="input" name="name" defaultValue={current.name} maxLength={80} required /></label><div className="modal-actions"><button type="button" className="btn btn-secondary" onClick={() => setEditing(false)}>取消</button><button className="btn btn-primary" disabled={busy}>保存</button></div></form></Modal>}
  </>
}
