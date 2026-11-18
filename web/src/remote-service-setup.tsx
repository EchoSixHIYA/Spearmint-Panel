import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { refreshConsole, useConsole } from './console-data'
import { groveServiceRegistrationHref, localServiceHref, remoteServiceSyncHref } from './grove-navigation'
import { Icon, Loading, Notice, PageHeading, Panel, Tabs } from './ui'

const kinds = { systemd: 'systemd 系统服务', windows: 'Windows 系统服务', docker: 'Docker 容器' }
type Kind = keyof typeof kinds
type Candidate = { target: string; name: string }
type Registered = Candidate & { id: string; managed: boolean; version: number }
type Candidates = { candidates: Candidate[]; registered: Registered[]; truncated: boolean }
type Capabilities = { kinds: Kind[]; workflow?: number }
type SetupProps = { session: Session; onUnauthorized: () => void }
type Action = 'kinds' | 'running' | 'take-over' | 'create' | 'manage'
type Mode = 'take-over' | 'create'

function request<T>(session: Session, nodeId: string, action: Action, body: object, signal: AbortSignal) {
  return api<T>(`/peers/${encodeURIComponent(nodeId)}/service-setup/${action}`, {
    method: 'POST', body: JSON.stringify(body), headers: { 'X-CSRF-Token': session.csrf_token }, signal,
  })
}

function setupError(error: unknown, onUnauthorized: () => void) {
  if (error instanceof ApiError) {
    if (error.status === 401) { onUnauthorized(); return '' }
    if (error.code === 'DENIED') return '请用 Grove 管理员账号登录，并核对目标节点的成员状态。'
    if (['NO_ROUTE', 'OFFLINE', 'ROUTE_LOST'].includes(error.code ?? '')) return '当前面板还没有到目标节点的可用 Mesh 路径。'
    if (error.code === 'UNSUPPORTED_METHOD') return '目标节点需要升级后才能使用此登记流程。'
    if (error.code === 'HOST_PERMISSION') return '目标机的面板账号需要这个服务的启停和日志权限。请核对系统服务允许列表和账号委派。'
    if (error.code === 'SERVICE_STOPPED') return '服务已停止运行，请刷新目标节点的运行列表。'
    if (error.code === 'SERVICE_COMMAND') return '请核对程序和工作目录的绝对路径，并确认目标机上的面板账号能访问它们。'
    if (error.code === 'SERVICE_LOG') return '目标节点无法读取该应用的日志。请核对日志配置和面板账号权限。'
    if (error.code === 'INVALID_REQUEST' || error.status === 404) return '目标服务或输入已变更，请核对后重试。'
    if (error.code === 'CONFLICT') return '请核对名称或目标是否已登记，以及目标节点能否读取此类服务。'
  }
  return '暂时没有收到目标节点回执。可以用同一份配置重试。'
}

export function GroveServiceSetup({ targetId, session, onUnauthorized }: SetupProps & { targetId?: string }) {
  const { memberNodes, listedNodes, local } = useConsole()
  const targets = memberNodes ?? listedNodes
  const nodeId = targetId === local.data?.node_id ? undefined : targetId
  const remote = targets.find(node => node.id === nodeId && !node.local)
  return <>
    <a href="#/services" className="back-link"><Icon name="arrow-left" size={15} />返回服务管理</a>
    <PageHeading eyebrow="OPERATIONS / SERVICES" title="登记服务" description="选择服务所在的节点，通过当前面板接管或新建服务。" />
    <Panel title="服务所在节点">
      <label className="field-label">节点
        <select className="input" value={nodeId || ''} onChange={event => { location.hash = groveServiceRegistrationHref(event.target.value) }}>
          <option value="">本机节点</option>
          {nodeId && !remote && <option value={nodeId}>正在确认所选节点</option>}
          {targets.filter(node => !node.local).map(node => <option key={node.id} value={node.id}>{node.name}</option>)}
        </select>
      </label>
    </Panel>
    {nodeId && !remote?.peer?.enabled ? <Notice tone="amber">等待当前面板同步成员并建立到目标的 Mesh 连接。</Notice>
      : <ServiceSetup key={nodeId || 'local'} nodeId={nodeId || 'local'} session={session} onUnauthorized={onUnauthorized} />}
  </>
}

function ServiceSetup({ nodeId, session, onUnauthorized }: SetupProps & { nodeId: string }) {
  const [mode, setMode] = useState<Mode>('take-over')
  const [supported, setSupported] = useState<Capabilities>()
  const [kind, setKind] = useState<Kind>()
  const [choices, setChoices] = useState<Candidates>()
  const [candidateId, setCandidateId] = useState('')
  const [result, setResult] = useState<Registered>()
  const [error, setError] = useState('')
  const [reads, setReads] = useState(0)
  const [busy, setBusy] = useState(false)
  const mutation = useRef<AbortController | null>(null)
  useEffect(() => () => mutation.current?.abort(), [])

  useEffect(() => {
    if (supported) return
    const controller = new AbortController()
    request<Capabilities>(session, nodeId, 'kinds', {}, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) { setSupported(data); setKind(data.kinds[0]) } })
      .catch(failure => { if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized)) })
    return () => controller.abort()
  }, [session, nodeId, reads, supported, onUnauthorized])

  useEffect(() => {
    if (mode !== 'take-over' || !kind || supported?.workflow !== 2 || result) return
    const controller = new AbortController()
    request<Candidates>(session, nodeId, 'running', { kind }, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) setChoices(data) })
      .catch(failure => { if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized)) })
    return () => controller.abort()
  }, [mode, supported, kind, reads, result, session, nodeId, onUnauthorized])

  function refresh() {
    setError('')
    setChoices(undefined)
    setReads(value => value + 1)
  }

  async function mutate(action: 'take-over' | 'create' | 'manage', body: object) {
    if (mutation.current) return
    const controller = new AbortController()
    mutation.current = controller
    setBusy(true)
    setError('')
    try {
      const response = await request<{ service: Registered }>(session, nodeId, action, body,
        AbortSignal.any([controller.signal, AbortSignal.timeout(20_000)]))
      if (!controller.signal.aborted) { setResult(response.service); refreshConsole() }
    } catch (failure) {
      if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized))
    } finally {
      if (!controller.signal.aborted) { mutation.current = null; setBusy(false) }
    }
  }

  const candidate = choices?.candidates.find(item => item.target === candidateId)
  const serviceHref = (id: string) => nodeId === 'local' ? localServiceHref(id) : remoteServiceSyncHref(nodeId, id)
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    const endpoint = String(values.get('endpoint') ?? '').trim() || null
    const name = String(values.get('name') ?? '').trim()
    if (mode === 'take-over' && candidate && kind) {
      const log_path = String(values.get('log_path') ?? '').trim() || null
      void mutate('take-over', { kind, target: candidate.target, name: name || candidate.name, endpoint, log_path })
    } else if (mode === 'create') {
      const argumentsText = String(values.get('arguments') ?? '')
      const args = argumentsText ? argumentsText.split(/\r?\n/) : []
      void mutate('create', { name, endpoint, arguments: args, executable: String(values.get('executable')).trim(),
        cwd: String(values.get('cwd')).trim() })
    }
  }

  return <Panel title="登记方式" action={<button className="btn btn-secondary" type="button" onClick={refresh} disabled={busy}>刷新</button>}>
    <div className="stack">
      {error && <Notice tone="amber">{error}</Notice>}
      {!supported ? !error && <Loading label="正在读取目标节点的登记能力…" />
        : supported.workflow !== 2 ? <Notice tone="amber">目标节点需要升级后才能接管运行中的服务或新建服务。</Notice>
        : result ? <>
          <Notice title={`已托管 ${result.name}`}>{mode === 'create' ? '服务已登记。打开服务详情即可启动并查看日志。' : '服务已纳入托管，可以管理启停并查看应用日志。'}</Notice>
          <div className="button-row">
            <a className="btn btn-primary" href={serviceHref(result.id)}>打开服务</a>
            <button className="btn btn-secondary" type="button" onClick={() => { setResult(undefined); setCandidateId(''); refresh() }}>继续登记</button>
          </div>
        </> : <>
          <Tabs label="登记方式" current={mode} items={[{ id: 'take-over', label: '接管现有服务' }, { id: 'create', label: '新建服务' }]}
            onChange={value => { if (!busy && value !== mode) { setMode(value as Mode); setError(''); setChoices(undefined) } }} />
          {mode === 'take-over' && <>
            <p className="muted">列表只显示正在运行、且目标节点可以登记的系统服务或容器。</p>
            {supported.kinds.length ? <label className="field-label">服务类型<select className="input" value={kind || ''} disabled={busy}
              onChange={event => { setKind(event.target.value as Kind); setCandidateId(''); refresh() }}>
              {supported.kinds.map(item => <option value={item} key={item}>{kinds[item]}</option>)}
            </select></label> : <Notice>目标节点没有可接管的系统服务类型。</Notice>}
            {kind && !choices && !error && <Loading label="正在读取运行中的服务…" />}
            {choices && <>
              {choices.candidates.length ? <label className="field-label">运行中的服务<select className="input" value={candidate?.target || ''} disabled={busy}
                onChange={event => setCandidateId(event.target.value)}><option value="">选择服务</option>
                {choices.candidates.map(item => <option key={item.target} value={item.target}>{item.name}</option>)}
              </select></label> : <p className="muted">当前没有此类可登记的运行中服务。</p>}
              {choices.truncated && <p className="muted">目标节点仅返回了前一批服务。</p>}
              {!!choices.registered.length && <details><summary>打开已登记服务</summary><ul>
                {choices.registered.map(item => <li key={item.id}>
                  <a href={serviceHref(item.id)}>{item.name}</a>{!item.managed && <button type="button" className="btn btn-secondary btn-small" disabled={busy}
                    onClick={() => void mutate('manage', { service_id: item.id, version: item.version })}>启用托管</button>}
                </li>)}
              </ul></details>}
            </>}
          </>}
          {(mode === 'create' || candidate) && <form className="stack" onSubmit={submit} key={mode === 'create' ? mode : candidate?.target}>
            <label className="field-label">服务名称<input className="input" name="name" maxLength={80} required={mode === 'create'} placeholder={candidate?.name} disabled={busy} /></label>
            {mode === 'create' ? <>
              <p className="muted">程序在目标机的面板账号下运行，标准输出和错误输出会写入服务日志。</p>
              <label className="field-label">可执行文件的绝对路径<input className="input" name="executable" required maxLength={1024} disabled={busy} /></label>
              <label className="field-label">工作目录的绝对路径<input className="input" name="cwd" required maxLength={1024} disabled={busy} /></label>
              <label className="field-label">启动参数（可选，每行一个）<textarea className="input" name="arguments" rows={4} maxLength={8192} disabled={busy} /></label>
            </> : kind === 'windows' && <label className="field-label">目标 Windows 应用日志的绝对路径
              <input className="input" name="log_path" maxLength={420} required disabled={busy} placeholder={'C:\\Apps\\MyApp\\logs\\app.log'} />
            </label>}
            <label className="field-label">服务端点（可选）<input className="input" name="endpoint" maxLength={180} disabled={busy} placeholder="127.0.0.1:8080" /></label>
            <div><button className="btn btn-primary" disabled={busy}>{busy ? '正在登记…' : mode === 'create' ? '新建并托管' : '接管此服务'}</button></div>
          </form>}
        </>}
    </div>
  </Panel>
}
