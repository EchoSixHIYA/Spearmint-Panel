import { useState } from 'react'
import { timestamp } from './api'
import { useConsole, refreshConsole } from './console-data'
import { useRemoteCatalog } from './remote-catalog'
import { ServiceLogs } from './service-logs'
import { FrpMappings } from './frp-mappings'
import { GroveServiceSetup } from './remote-service-setup'
import { type Service, actions as actionNames, serviceDriver } from './services'
import { groveServiceRegistrationHref, localServiceHref, remoteServiceHref } from './grove-navigation'
import { useServiceOperation, useWorkspace, workspace, workspaceError, returnRoute, withReturn } from './workspace-api'
import { Badge, CopyValue, EmptyState, Icon, Loading, Modal, Notice, PageHeading, Panel, StateBadge, Tabs } from './ui'

type Detail = Service & { command?: string; managed: boolean; can_edit_details: boolean; can_unregister: boolean;
  unregister_reason?: string; can_change_mode: boolean; operations: Array<{ id: string; action: string; status: string; updated_at: number; message: string | null }> }

export function ServiceWorkspace({ section, segments }: { section?: string; segments: string[] }) {
  const { session, onUnauthorized, local } = useConsole()
  if (section === 'register') return <GroveServiceSetup targetId={segments[0]} session={session} onUnauthorized={onUnauthorized} />
  if (section === 'remote' && segments[1]) return <ServiceDetail key={`${segments[0]}/${segments[1]}`} target={segments[0]} id={segments[1]} initialTab={segments[2]} />
  if (section && /^[a-f0-9]{32}$/.test(section)) return <ServiceDetail key={`local/${section}`} target="local" id={section} initialTab={segments[0]} />
  return <ServiceList initialNode={section === 'local' ? local.data?.node_id : section === 'remote' ? segments[0] : undefined} />
}

export function ServiceList({ initialNode, embedded = false }: { initialNode?: string; embedded?: boolean }) {
  const { services, listedNodes, local, localName } = useConsole()
  const { entries, error } = useRemoteCatalog()
  const query = new URLSearchParams(location.hash.split('?')[1])
  const [search, setSearch] = useState(query.get('q') || '')
  const [node, setNode] = useState(query.get('node') || initialNode || '')
  const [status, setStatus] = useState(query.get('status') || '')
  const rows = [
    ...(services.data || []).map(service => ({ service, node: local.data?.node_id || 'local', name: localName, local: true, stale: !!services.error || service.observation.stale, observation: service.observation })),
    ...entries.map(entry => ({ service: entry.service, node: entry.node.id, name: entry.node.name, local: false, stale: entry.stale || entry.service.observation?.stale !== false, observation: entry.service.observation })),
  ]
  const visible = rows.filter(row => (!node || row.node === node) && (!status || (status === 'stale' ? row.stale : !row.stale && row.observation?.status === status))
    && `${row.service.name} ${row.name} ${row.service.id}`.toLowerCase().includes(search.toLowerCase()))
  function update(field: 'q' | 'node' | 'status', value: string) {
    if (field === 'q') setSearch(value); else if (field === 'node') setNode(value); else setStatus(value)
    const params = new URLSearchParams(location.hash.split('?')[1]); if (value) params.set(field, value); else params.delete(field)
    history.replaceState(null, '', location.hash.split('?')[0] + (params.size ? '?' + params : ''))
  }
  return <>{!embedded && <PageHeading eyebrow="WORKSPACE / SERVICES" title="服务" description="找到程序，控制启停，确认结果。">
    <a className="btn btn-primary" href={withReturn(groveServiceRegistrationHref(node || undefined))}><Icon name="plus" size={16} />登记服务</a>
  </PageHeading>}{embedded && <div className="button-row"><a className="btn btn-primary" href={withReturn(groveServiceRegistrationHref(initialNode))}>在此节点登记服务</a></div>}
    <div className="workspace-summary"><strong>{rows.length} 个已登记服务</strong><span>{rows.filter(row => !row.stale && row.observation?.status === 'running').length} 个运行中</span><span>通过 Mesh 在当前面板管理目标节点</span></div>
    <Panel><div className="workspace-filters"><label className="search-box"><Icon name="search" size={16} /><input aria-label="搜索服务" value={search} onChange={e => update('q', e.target.value)} placeholder="搜索服务、节点或程序名称…" /></label>
      <select className="input" aria-label="按节点筛选" value={node} onChange={e => update('node', e.target.value)}><option value="">全部节点</option>{listedNodes.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
      <select className="input" aria-label="按状态筛选" value={status} onChange={e => update('status', e.target.value)}><option value="">全部状态</option><option value="running">运行中</option><option value="stopped">已停止</option><option value="failed">失败</option><option value="stale">状态待确认</option></select>
      <button className="btn btn-secondary" onClick={refreshConsole}>刷新</button></div>
      {(services.error || error) && <Notice tone="amber">部分服务状态暂时无法更新，保留上次目录供查看。</Notice>}
      {!services.data && !services.error ? <Loading /> : visible.length ? <div className="table-wrap"><table className="data-table workspace-service-table"><thead><tr><th>服务</th><th>所属节点</th><th>运行状态</th><th>最近检查</th><th>操作</th></tr></thead><tbody>{visible.map(row => {
        const href = withReturn(row.local ? localServiceHref(row.service.id) : remoteServiceHref(row.node, row.service.id))
        return <tr key={`${row.node}/${row.service.id}`}><td><a className="text-link" href={href}><strong>{row.service.name}</strong></a><small className="table-secondary">{row.service.driver === 'docker' ? 'Docker 容器' : '系统服务 / 程序'}</small></td><td><a href={withReturn(`#/nodes/${row.node}`)}>{row.name}</a><small className="table-secondary">{row.local ? '当前面板 · 本机' : '通过 Mesh 管理'}</small></td>
          <td><StateBadge state={row.observation?.status || 'unknown'} stale={row.stale} /></td><td className="muted time-cell">{timestamp(row.observation?.checked_at ?? null)}</td>
          <td><RowControl path={row.local ? `/services/${row.service.id}` : `/peers/${row.node}/services/${row.service.id}`} name={row.service.name} status={row.observation?.status} allowed={row.service.actions} version={row.service.version || 1} stale={row.stale} /><a className="btn btn-secondary btn-small" href={href}>详情</a> <a className="icon-button inline-icon" aria-label={`查看 ${row.service.name} 日志`} href={withReturn(row.local ? localServiceHref(row.service.id, 'logs') : remoteServiceHref(row.node, row.service.id, true))}><Icon name="file-text" size={16} /></a></td></tr>
      })}</tbody></table></div> : <EmptyState title="没有匹配的服务" />}
    </Panel></>
}

function RowControl({ path, name, status, allowed, version, stale }: { path: string; name: string; status?: string; allowed: readonly string[]; version: number; stale: boolean }) {
  const { session } = useConsole()
  const flow = useServiceOperation(path, session, version, refreshConsole)
  const action = status === 'running' ? 'stop' : 'start'
  if (flow.tracking) return <button className="btn btn-secondary btn-small" onClick={() => void flow.query()}>{flow.intent?.operation?.status === 'uncertain' ? '查询原请求' : '执行中…'}</button>
  return <button className="btn btn-secondary btn-small" disabled={stale || !allowed.includes(action)} onClick={() => {
    if (action === 'start' || confirm(`停止 ${name}？操作由所属节点执行。`)) void flow.submit(action)
  }}>{actionNames[action]}</button>
}

function ServiceDetail({ target, id, initialTab }: { target: string; id: string; initialTab?: string }) {
  const { session, onUnauthorized, listedNodes, localName } = useConsole()
  const detail = useWorkspace<Detail>(target, session, 'detail', { service_id: id }, onUnauthorized)
  const [tab, setTab] = useState(initialTab === 'logs' ? 'logs' : initialTab === 'history' ? 'history' : initialTab === 'access' ? 'settings' : 'overview')
  const [confirmation, setConfirmation] = useState<string>()
  const [editing, setEditing] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('')
  const local = target === 'local', nodeName = local ? localName : listedNodes.find(node => node.id === target)?.name || target
  const path = local ? `/services/${id}` : `/peers/${target}/services/${id}`
  const flow = useServiceOperation(path, session, detail.data?.version || 1, () => { detail.reload(); refreshConsole() })
  const current = detail.data, unavailable = !!detail.error || !current || current.observation.stale
  const blocked = busy || unavailable || flow.tracking
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
      {current?.actions.includes(current.observation.status === 'running' ? 'stop' : 'start') && <button className="btn btn-primary" disabled={blocked} onClick={() => command(current.observation.status === 'running' ? 'stop' : 'start')}>{current.observation.status === 'running' ? '停止' : '启动'}</button>}
      {current?.actions.includes('restart') && <button className="btn btn-secondary" disabled={blocked} onClick={() => command('restart')}>重启</button>}
      <button className="btn btn-secondary" onClick={detail.reload}>核对状态</button>
    </PageHeading>
    <div className="workspace-context"><span>当前面板 <strong>{localName}</strong></span><Icon name="arrow-right" size={15} /><span>目标节点 <strong>{nodeName}</strong></span>{current && <StateBadge state={current.observation.status} stale={unavailable} />}</div>
    {detail.error && <Notice tone="amber">{detail.error}</Notice>}{error && <Notice tone="amber">{error}</Notice>}
    <Tabs label="服务工作区" current={tab} onChange={setTab} items={[{ id: 'overview', label: '概览' }, { id: 'logs', label: '日志' }, { id: 'history', label: '操作记录' }, { id: 'settings', label: '管理设置' }]} />
    {!current && !detail.error && <Loading />}
    {flow.intent && <Panel title="本次操作"><div className="button-row"><strong>{actionNames[flow.intent.action as keyof typeof actionNames]}</strong><StateBadge state={flow.intent.operation?.status || 'queued'} /><CopyValue value={flow.intent.request_id || flow.intent.key} short /></div>
      <p className="muted">{flow.intent.error || flow.intent.operation?.message || '请求已受理，正在等待目标节点执行结果。'}</p>
      {flow.tracking && <div className="button-row"><button className="btn btn-secondary" onClick={() => void flow.query()}>查询原请求</button><button className="btn btn-ghost" onClick={() => { if (confirm('结束结果跟踪？已发出的操作仍可能在目标节点执行。')) flow.clear() }}>结束跟踪</button></div>}
    </Panel>}
    {current && tab === 'overview' && <div className="columns-2"><Panel title="状态与结果"><StateBadge state={current.observation.status} stale={unavailable} /><p className="muted">最近检查 {timestamp(current.observation.checked_at)}</p>{current.observation.message && <p>{current.observation.message}</p>}
      <a className="btn btn-secondary" href={withReturn(`#/ssh/${local ? current.node_id : target}`)}><Icon name="terminal" size={16} />终端与文件</a>
      <button className="btn btn-ghost" onClick={() => setTab('mapping')}>公网映射</button></Panel><Panel title="服务信息"><dl className="facts"><div><dt>运行方式</dt><dd>{serviceDriver(current)}</dd></div><div><dt>所属节点</dt><dd>{nodeName}</dd></div><div><dt>服务版本</dt><dd>{current.version}</dd></div><div><dt>服务标识</dt><dd><CopyValue value={id} short /></dd></div></dl>
      {current.command && <details><summary>查看已登记的启动命令</summary><pre className="command-block">{current.command}</pre></details>}</Panel></div>}
    {current && tab === 'logs' && <ServiceLogs path={path} serviceId={id} onUnauthorized={onUnauthorized} remote={!local} active={!unavailable && current.logs_available !== false} />}
    {current && tab === 'history' && <Panel title="目标节点最近的操作">{current.operations.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>动作</th><th>结果</th><th>时间</th><th>说明</th></tr></thead><tbody>{current.operations.map(item => <tr key={item.id}><td>{actionNames[item.action as keyof typeof actionNames]}</td><td><StateBadge state={item.status} /></td><td>{timestamp(item.updated_at)}</td><td>{item.message}</td></tr>)}</tbody></table></div> : <EmptyState title="暂无操作记录" />}</Panel>}
    {current && tab === 'settings' && <div className="stack"><Panel title="登记信息" action={<button className="btn btn-secondary" disabled={blocked || !current.can_edit_details} onClick={() => setEditing(true)}>编辑服务信息</button>}><p>{current.name}</p><p className="muted">所属节点：{nodeName}。修改在当前面板提交，由目标节点执行。</p></Panel>
      <Panel title="管理方式"><Badge>{current.actions.length ? '托管启停' : '观察模式'}</Badge>{current.can_change_mode && <button className="btn btn-secondary" disabled={blocked} onClick={() => void mutate('mode', { mode: current.actions.length ? 'observe' : 'manage' })}>{current.actions.length ? '改为观察模式' : '启用托管'}</button>}</Panel>
      <Panel title="取消登记"><p className="muted">移除 Spearmint 中的登记，不删除目标机上的程序和数据。</p>{current.unregister_reason && <p>{current.unregister_reason}</p>}<button className="btn btn-danger" disabled={blocked || !current.can_unregister} onClick={() => setConfirmation('remove')}>取消登记</button></Panel>
    </div>}
    {current && tab === 'mapping' && <FrpMappings path={path} session={session} onUnauthorized={onUnauthorized} stale={unavailable} />}
    {confirmation && <Modal title={confirmation === 'remove' ? `取消登记 ${current?.name}？` : `${actionNames[confirmation as keyof typeof actionNames]} ${current?.name}？`} onClose={() => setConfirmation(undefined)}>
      <p>目标节点：{nodeName}。操作结果将在当前面板显示。</p><div className="modal-actions"><button className="btn btn-secondary" onClick={() => setConfirmation(undefined)}>取消</button><button className="btn btn-danger" onClick={() => { const action = confirmation; setConfirmation(undefined); if (action === 'remove') void mutate('remove', {}); else void flow.submit(action) }}>确认{confirmation === 'remove' ? '取消登记' : actionNames[confirmation as keyof typeof actionNames]}</button></div></Modal>}
    {editing && current && <Modal title="编辑服务信息" onClose={() => setEditing(false)}><form className="stack" onSubmit={event => { event.preventDefault(); const values = new FormData(event.currentTarget); void mutate('edit', { name: values.get('name'), endpoint: current.endpoint }) }}>
      <label className="field-label">服务名称<input className="input" name="name" defaultValue={current.name} maxLength={80} required /></label><div className="modal-actions"><button type="button" className="btn btn-secondary" onClick={() => setEditing(false)}>取消</button><button className="btn btn-primary" disabled={busy}>保存</button></div></form></Modal>}
  </>
}
