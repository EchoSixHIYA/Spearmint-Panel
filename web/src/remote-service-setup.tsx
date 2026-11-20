import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { refreshConsole, useConsole } from './console-data'
import { groveServiceRegistrationHref, localServiceHref, remoteServiceSyncHref } from './grove-navigation'
import { Icon, Loading, Notice, PageHeading, Panel, Tabs } from './ui'
import { returnRoute, withReturn } from './workspace-api'
import { allowNavigation, useUnsavedChanges } from './navigation-guard'
import { ServiceDeployment } from './service-deployment'

const kinds = { systemd: 'systemd 系统服务', windows: 'Windows 系统服务', docker: 'Docker 容器' }
type Kind = keyof typeof kinds
type Candidate = { target: string; name: string }
type Registered = Candidate & { id: string; managed: boolean; version: number; command?: string }
type Candidates = { candidates: Candidate[]; registered: Registered[]; truncated: boolean; next_offset?: number | null; previous_offset?: number | null }
type Capabilities = { kinds: Kind[]; workflow?: number; checks?: boolean; commands?: boolean; scripts?: boolean }
type Readiness = { ready: boolean; log_path?: string | null }
type SetupProps = { session: Session; onUnauthorized: () => void }
type Action = 'kinds' | 'running' | 'inspect' | 'take-over' | 'manage'
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
    if (error.code === 'HOST_PERMISSION') return '目标机的面板账号缺少这个服务的启停或日志权限。'
    if (error.code === 'SERVICE_STOPPED') return '服务已停止运行，请刷新目标节点的运行列表。'
    if (error.code === 'SERVICE_COMMAND') return '请核对启动命令，并确认面板账号能在目标机执行它。'
    if (error.code === 'DOCKER_MISSING') return '目标节点未找到 Docker 命令。请安装 Docker，并让面板账号能找到 docker。'
    if (error.code === 'DOCKER_UNAVAILABLE') return '目标节点的本机 Docker 未启动或连接不可用。请检查 Docker 服务。'
    if (error.code === 'DOCKER_PERMISSION') return '目标节点的面板账号没有访问本机 Docker 的权限。'
    if (error.code === 'SERVICE_DISCOVERY') return '目标 Windows 未能返回运行中的系统服务，请检查目标机服务管理器和面板运行账号。'
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
    <a href={returnRoute()} className="back-link"><Icon name="arrow-left" size={15} />返回来源</a>
    <PageHeading eyebrow="OPERATIONS / SERVICES" title="登记服务" description="选择服务所在的节点，通过当前面板接管或新建服务。" />
    <Panel title="服务所在节点">
      <label className="field-label">节点
        <select className="input" value={nodeId || ''} onChange={event => { location.hash = withReturn(groveServiceRegistrationHref(event.target.value), returnRoute()) }}>
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
  const [offset, setOffset] = useState(0)
  const [checked, setChecked] = useState<Readiness>()
  const [result, setResult] = useState<Registered>()
  const [error, setError] = useState('')
  const [reads, setReads] = useState(0)
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState(1)
  const [review, setReview] = useState<{ action: 'take-over'; body: object; name: string }>()
  const [dirty, setDirty] = useState(false)
  useUnsavedChanges(dirty && !result)
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
    if (mode !== 'take-over' || !kind || !supported?.checks || result) return
    const controller = new AbortController()
    request<Candidates>(session, nodeId, 'running', supported.checks ? { kind, offset } : { kind }, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) setChoices(data) })
      .catch(failure => { if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized)) })
    return () => controller.abort()
  }, [mode, supported, kind, offset, reads, result, session, nodeId, onUnauthorized])

  useEffect(() => {
    if (mode !== 'take-over' || !kind || !candidateId || !supported?.checks || result) return
    const controller = new AbortController()
    request<Readiness>(session, nodeId, 'inspect', { kind, target: candidateId },
      AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) setChecked(data) })
      .catch(failure => { if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized)) })
    return () => controller.abort()
  }, [mode, supported, kind, candidateId, reads, result, session, nodeId, onUnauthorized])

  function selectCandidate(target: string) {
    setCandidateId(target)
    setChecked(undefined)
    setError('')
  }

  function refresh() {
    selectCandidate('')
    setChoices(undefined)
    setReads(value => value + 1)
  }

  async function mutate(action: 'take-over' | 'manage', body: object) {
    if (mutation.current) return
    const controller = new AbortController()
    mutation.current = controller
    setBusy(true)
    setError('')
    try {
      const response = await request<{ service: Registered }>(session, nodeId, action, body,
        AbortSignal.any([controller.signal, AbortSignal.timeout(20_000)]))
      if (!controller.signal.aborted) { setResult(response.service); setDirty(false); refreshConsole() }
    } catch (failure) {
      if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized))
    } finally {
      if (!controller.signal.aborted) { mutation.current = null; setBusy(false) }
    }
  }

  const candidate = choices?.candidates.find(item => item.target === candidateId)
  const canTakeOver = !!candidate && (!supported?.checks || checked?.ready === true)
  const serviceHref = (id: string) => withReturn(nodeId === 'local' ? localServiceHref(id) : remoteServiceSyncHref(nodeId, id), returnRoute())
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    const name = String(values.get('name') ?? '').trim()
    if (mode === 'take-over' && canTakeOver && candidate && kind) {
      const log_path = String(values.get('log_path') ?? '').trim() || null
      const chosenName = name || Array.from(candidate.name).slice(0, 80).join('')
      setReview({ action: 'take-over', name: chosenName, body: { kind, target: candidate.target, name: chosenName, log_path } }); setStep(3)
    }
  }

  return <Panel title="接入方式" action={<button className="btn btn-secondary" type="button" onClick={refresh} disabled={busy}>刷新</button>}>
    <Tabs label="接入方式" current={mode} items={[{ id: 'take-over', label: '接管现有服务' }, { id: 'create', label: '部署新服务' }]}
      onChange={value => { if (!busy && value !== mode && allowNavigation()) { setMode(value as Mode); setStep(1); selectCandidate(''); setChoices(undefined); setDirty(false) } }} />
    {mode === 'create' ? <ServiceDeployment target={nodeId} /> :
    <div className="stack">
      {error && <Notice tone="amber">{error}</Notice>}
      {!supported ? !error && <Loading label="正在读取目标节点的登记能力…" />
        : supported.workflow !== 2 ? <Notice tone="amber">目标节点需要升级后才能接管运行中的服务或新建服务。</Notice>
        : result ? <>
          <Notice title={`已托管 ${result.name}`}>服务已纳入托管，可以管理启停并查看应用日志。</Notice>
          {result.command && <pre className="command-block">{result.command}</pre>}
          <div className="button-row">
            <a className="btn btn-primary" href={serviceHref(result.id)}>打开服务</a>
            <button className="btn btn-secondary" type="button" onClick={() => { setResult(undefined); setCandidateId(''); refresh() }}>继续登记</button>
          </div>
        </> : <>
          <ol className="registration-steps">{['选择节点与方式', '填写登记信息', '核对并登记'].map((label, index) => <li key={label} className={step === index + 1 ? 'current' : ''}>{index + 1} · {label}</li>)}</ol>
          {step === 1 && <><p className="muted">读取目标节点正在运行的服务，选择后检查是否可以接管。</p><div><button className="btn btn-primary" onClick={() => setStep(2)}>下一步</button></div></>}
          <div hidden={step !== 2}>
          {mode === 'take-over' && (!supported.checks ? <Notice tone="amber">目标节点仍在使用允许列表过滤服务。请通过 Grove 群组更新升级目标节点，再读取运行中的服务。</Notice> : <>
            <p className="muted">列表显示正在运行的服务。选择后检查目标机的管理和日志权限。</p>
            {supported.kinds.length ? <label className="field-label">服务类型<select className="input" value={kind || ''} disabled={busy}
              onChange={event => { setKind(event.target.value as Kind); setOffset(0); refresh() }}>
              {supported.kinds.map(item => <option value={item} key={item}>{kinds[item]}</option>)}
            </select></label> : <Notice>目标节点没有可接管的系统服务类型。</Notice>}
            {kind && !choices && !error && <Loading label="正在读取运行中的服务…" />}
            {choices && <>
              {choices.candidates.length ? <label className="field-label">运行中的服务<select className="input" value={candidate?.target || ''} disabled={busy}
                onChange={event => selectCandidate(event.target.value)}><option value="">选择服务</option>
                {choices.candidates.map(item => <option key={item.target} value={item.target}>{item.name}</option>)}
              </select></label> : <p className="muted">当前没有此类可登记的运行中服务。</p>}
              {(choices.previous_offset != null || choices.next_offset != null) && <div className="button-row">
                {choices.previous_offset != null && <button className="btn btn-secondary" type="button" disabled={busy}
                  onClick={() => { setOffset(choices.previous_offset!); refresh() }}>上一页</button>}
                {choices.next_offset != null && <button className="btn btn-secondary" type="button" disabled={busy}
                  onClick={() => { setOffset(choices.next_offset!); refresh() }}>下一页</button>}
              </div>}
              {choices.truncated && choices.next_offset == null && <p className="muted">目标节点返回的列表达到读取上限。</p>}
              {!!choices.registered.length && <details><summary>打开已登记服务</summary><ul>
                {choices.registered.map(item => <li key={item.id}>
                  <a href={serviceHref(item.id)}>{item.name}</a>{!item.managed && <button type="button" className="btn btn-secondary btn-small" disabled={busy}
                    onClick={() => void mutate('manage', { service_id: item.id, version: item.version })}>启用托管</button>}
                </li>)}
              </ul></details>}
            </>}
          </>)}
          {mode === 'take-over' && candidate && supported.checks && !checked && !error && <Loading label="正在检查此服务能否接管…" />}
          {canTakeOver && <form className="stack" onSubmit={submit} onChange={() => setDirty(true)} key={candidate?.target}>
            <label className="field-label">服务名称<input className="input" name="name" maxLength={80} placeholder={candidate?.name} disabled={busy} /></label>
            {kind === 'windows' && (checked?.log_path ? <p className="muted">已识别应用日志 <code>{checked.log_path}</code></p>
              : <label className="field-label">目标 Windows 应用日志的绝对路径
              <input className="input" name="log_path" maxLength={420} required disabled={busy} placeholder={'C:\\Apps\\MyApp\\logs\\app.log'} />
            </label>)}
            <div className="button-row"><button type="button" className="btn btn-secondary" onClick={() => setStep(1)}>上一步</button><button className="btn btn-primary" disabled={busy}>核对登记信息</button></div>
          </form>}
          </div>
          {step === 3 && review && <><dl className="facts"><div><dt>服务名称</dt><dd>{review.name}</dd></div><div><dt>登记方式</dt><dd>接管现有服务 · 保留运行状态</dd></div></dl><div className="button-row"><button className="btn btn-secondary" disabled={busy} onClick={() => setStep(2)}>上一步</button><button className="btn btn-primary" disabled={busy} onClick={() => void mutate(review.action, review.body)}>{busy ? '正在登记…' : '确认登记'}</button></div></>}
        </>}
    </div>}
  </Panel>
}
