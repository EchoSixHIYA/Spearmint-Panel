import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError, api, type Session } from './api'
import { refreshConsole, useConsole } from './console-data'
import { groveServiceRegistrationHref, localServiceHref, remoteServiceSyncHref } from './grove-navigation'
import { Icon, Loading, Notice, Panel } from './ui'
import { returnRoute, withReturn } from './workspace-api'
import { allowNavigation, useUnsavedChanges } from './navigation-guard'
import { ServiceDeployment } from './service-deployment'
import { ExistingCodeRegistration } from './existing-code-registration'
import { HostServiceAuthorization } from './host-service-authorization'
import './service-registration.css'

const kinds = { systemd: 'systemd 系统服务', windows: 'Windows 系统服务', docker: 'Docker 容器' }
type Kind = keyof typeof kinds
type Candidate = { target: string; name: string }
type Registered = Candidate & { id: string; managed: boolean; version: number; command?: string }
type Candidates = { candidates: Candidate[]; registered: Registered[]; truncated: boolean; next_offset?: number | null; previous_offset?: number | null }
type Capabilities = { kinds: Kind[]; workflow?: number; checks?: boolean; commands?: boolean; scripts?: boolean; host_authorization?: number; docker_authorization?: number }
type Readiness = { ready: boolean; log_path?: string | null; observe_ready?: boolean; logs_ready?: boolean;
  control?: Record<string, boolean>; reason?: string; account?: string; enable_command?: string }
type SetupProps = { session: Session; onUnauthorized: () => void }
type Action = 'kinds' | 'running' | 'inspect' | 'take-over' | 'manage'
type Mode = 'take-over' | 'create' | 'existing'

const registrationModes: { id: Mode; label: string; description: string; icon: string }[] = [
  { id: 'create', label: '一键部署新服务', description: '部署程序包或 Docker 容器', icon: 'package' },
  { id: 'existing', label: '登记已有代码', description: '使用目标节点已有的代码', icon: 'terminal' },
  { id: 'take-over', label: '接管运行中服务', description: '从正在运行的服务中选取', icon: 'activity' },
]

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
    if (error.code === 'HOST_PERMISSION') return '目标节点尚未获得此服务的控制权限，请在节点上完成主机服务管理授权。'
    if (error.code === 'HOST_SERVICE_ACCESS') return '此节点尚未启用主机服务管理。完成一次节点授权后即可托管，当前也可先以观察模式登记。'
    if (error.code === 'SERVICE_STOPPED') return '服务已停止运行，请刷新目标节点的运行列表。'
    if (error.code === 'SERVICE_COMMAND') return '请核对启动命令，并确认面板账号能在目标机执行它。'
    if (error.code === 'DOCKER_MISSING') return '目标节点未找到 Docker 命令。请安装 Docker，并让面板账号能找到 docker。'
    if (error.code === 'DOCKER_UNAVAILABLE') return '目标节点的本机 Docker 未启动或连接不可用。请检查 Docker 服务。'
    if (error.code === 'DOCKER_PERMISSION') return '此节点尚未授权 Docker 管理，请在下方验证主机管理员身份后继续。'
    if (error.code === 'SERVICE_DISCOVERY') return '目标 Windows 未能返回运行中的系统服务，请检查目标机服务管理器和面板运行账号。'
    if (error.code === 'SERVICE_LOG') return '目标节点无法读取该应用的日志。请核对日志配置和面板账号权限。'
    if (error.code === 'INVALID_REQUEST' || error.status === 404) return '目标服务或输入已变更，请核对后重试。'
    if (error.code === 'CONFLICT') return '请核对名称或目标是否已登记，以及目标节点能否读取此类服务。'
  }
  return '暂时没有收到目标节点回执。可以用同一份配置重试。'
}

export function GroveServiceSetup({ targetId, session, onUnauthorized }: SetupProps & { targetId?: string }) {
  const { memberNodes, listedNodes, local, localName } = useConsole()
  const targets = memberNodes ?? listedNodes
  const nodeId = targetId === local.data?.node_id ? undefined : targetId
  const remote = targets.find(node => node.id === nodeId && !node.local)
  const nodePicker = <label className="field-label registration-node">
    <span><Icon name="server" size={16} />服务所在节点</span>
    <select className="input" value={nodeId || ''} onChange={event => { location.hash = withReturn(groveServiceRegistrationHref(event.target.value), returnRoute()) }}>
      <option value="">{localName === '本机节点' ? localName : `${localName} · 本机`}</option>
      {nodeId && !remote && <option value={nodeId}>正在确认所选节点</option>}
      {targets.filter(node => !node.local).map(node => <option key={node.id} value={node.id}>{node.name}</option>)}
    </select>
  </label>
  return <div className="service-registration">
    <header className="registration-heading">
      <a href={returnRoute()} className="back-link"><Icon name="arrow-left" size={15} />返回来源</a>
      <h1 tabIndex={-1} id="page-title">登记服务</h1>
    </header>
    {nodeId && !remote?.peer?.enabled
      ? <div className="registration-layout"><Panel className="registration-selector">{nodePicker}</Panel>
        <Notice tone="amber">等待当前面板同步成员并建立到目标的 Mesh 连接。</Notice></div>
      : <ServiceSetup key={nodeId || 'local'} nodeId={nodeId || 'local'} nodePicker={nodePicker} session={session} onUnauthorized={onUnauthorized} />}
  </div>
}

function ServiceSetup({ nodeId, nodePicker, session, onUnauthorized }: SetupProps & { nodeId: string; nodePicker: ReactNode }) {
  const [mode, setMode] = useState<Mode>('create')
  const [supported, setSupported] = useState<Capabilities>()
  const [kind, setKind] = useState<Kind>()
  const [choices, setChoices] = useState<Candidates>()
  const [candidateId, setCandidateId] = useState('')
  const [offset, setOffset] = useState(0)
  const [checked, setChecked] = useState<Readiness>()
  const [result, setResult] = useState<Registered>()
  const [error, setError] = useState('')
  const [dockerPermission, setDockerPermission] = useState(false)
  const [reads, setReads] = useState(0)
  const [busy, setBusy] = useState(false)
  const [review, setReview] = useState<{ action: 'take-over'; body: object; name: string }>()
  const [dirty, setDirty] = useState(false)
  const [registrationMode, setRegistrationMode] = useState<'observe' | 'manage'>('manage')
  useUnsavedChanges(dirty && !result)
  const mutation = useRef<AbortController | null>(null)
  useEffect(() => () => mutation.current?.abort(), [])

  useEffect(() => {
    if (supported) return
    const controller = new AbortController()
    request<Capabilities>(session, nodeId, 'kinds', {}, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) { setSupported(data); setKind(data.kinds[0]) } })
      .catch(failure => { if (!controller.signal.aborted) showError(failure) })
    return () => controller.abort()
  }, [session, nodeId, reads, supported, onUnauthorized])

  useEffect(() => {
    if (mode !== 'take-over' || !kind || !supported?.checks || result) return
    const controller = new AbortController()
    request<Candidates>(session, nodeId, 'running', supported.checks ? { kind, offset } : { kind }, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) setChoices(data) })
      .catch(failure => { if (!controller.signal.aborted) showError(failure) })
    return () => controller.abort()
  }, [mode, supported, kind, offset, reads, result, session, nodeId, onUnauthorized])

  useEffect(() => {
    if (mode !== 'take-over' || !kind || !candidateId || !supported?.checks || result) return
    const controller = new AbortController()
    request<Readiness>(session, nodeId, 'inspect', { kind, target: candidateId },
      AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) { setChecked(data); if (!data.ready && data.observe_ready) setRegistrationMode('observe') } })
      .catch(failure => { if (!controller.signal.aborted) showError(failure) })
    return () => controller.abort()
  }, [mode, supported, kind, candidateId, reads, result, session, nodeId, onUnauthorized])

  function selectCandidate(target: string) {
    setCandidateId(target)
    setChecked(undefined)
    setRegistrationMode('manage')
    setError('')
  }

  function showError(failure: unknown) {
    setDockerPermission(failure instanceof ApiError && failure.code === 'DOCKER_PERMISSION')
    setError(setupError(failure, onUnauthorized))
  }

  function refresh() {
    setReview(undefined)
    setDockerPermission(false)
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
      if (!controller.signal.aborted) showError(failure)
    } finally {
      if (!controller.signal.aborted) { mutation.current = null; setBusy(false) }
    }
  }

  const candidate = choices?.candidates.find(item => item.target === candidateId)
  const canTakeOver = !!candidate && (!supported?.checks || checked?.ready === true || checked?.observe_ready === true)
  const serviceHref = (id: string) => withReturn(nodeId === 'local' ? localServiceHref(id) : remoteServiceSyncHref(nodeId, id), returnRoute())
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    const name = String(values.get('name') ?? '').trim()
    if (mode === 'take-over' && canTakeOver && candidate && kind) {
      const log_path = String(values.get('log_path') ?? '').trim() || null
      const chosenName = name || Array.from(candidate.name).slice(0, 80).join('')
      setReview({ action: 'take-over', name: chosenName, body: { kind, target: candidate.target, name: chosenName, log_path,
        ...(checked?.observe_ready ? { mode: registrationMode } : {}) } })
    }
  }

  const modeTitle = registrationModes.find(item => item.id === mode)!.label
  return <div className="registration-layout">
    <Panel className="registration-selector">
      {nodePicker}
      <div className="registration-mode-group" role="group" aria-labelledby="registration-method">
        <h2 id="registration-method">接入方式</h2>
        {registrationModes.map(item => <button key={item.id} type="button" className="registration-mode"
          aria-pressed={item.id === mode} disabled={busy} onClick={() => {
            if (item.id === mode || !allowNavigation()) return
            setMode(item.id)
            setReview(undefined)
            selectCandidate('')
            setChoices(undefined)
            setDirty(false)
          }}>
          <span className="registration-mode-icon"><Icon name={item.icon} size={18} /></span>
          <span><strong>{item.label}</strong><small>{item.description}</small></span>
          {item.id === mode && <Icon name="check" size={15} />}
        </button>)}
      </div>
    </Panel>
    <section className="panel registration-form-panel" aria-labelledby="registration-form-title">
      <header className="registration-form-heading">
        <h2 id="registration-form-title">{modeTitle}</h2>
        {mode === 'take-over' && !result && !review && <button className="btn btn-secondary btn-small" type="button" onClick={refresh} disabled={busy}>
          <Icon name="refresh" size={14} />刷新
        </button>}
      </header>
      <div className="registration-form-body">
    {mode === 'create' ? <ServiceDeployment target={nodeId} /> : mode === 'existing' ? <ExistingCodeRegistration target={nodeId} windows={!!supported?.kinds.includes('windows')} /> :
    <div className="stack">
      {error && <Notice tone="amber">{error}</Notice>}
      {!supported ? !error && <Loading label="正在读取目标节点的登记能力…" />
        : supported.workflow !== 2 ? <Notice tone="amber">目标节点需要升级后才能接管运行中的服务或新建服务。</Notice>
        : result ? <>
          <Notice title={`已登记 ${result.name}`}>{result.managed ? '服务已纳入托管，可以管理启停并查看应用日志。' : '已以观察模式登记，可以查看运行状态及可读取的日志。节点授权完成后可切换为托管。'}</Notice>
          {result.command && <pre className="command-block">{result.command}</pre>}
          <div className="button-row">
            <a className="btn btn-primary" href={serviceHref(result.id)}>打开服务</a>
            <button className="btn btn-secondary" type="button" onClick={() => { setResult(undefined); refresh() }}>继续登记</button>
          </div>
        </> : <>
          <ol className="registration-steps">{['选择服务', '核对并登记'].map((label, index) => <li key={label}
            aria-current={Number(!!review) === index ? 'step' : undefined}><span>{index + 1}</span>{label}</li>)}</ol>
          <div className="stack registration-takeover" hidden={!!review}>
          {mode === 'take-over' && (!supported.checks ? <Notice tone="amber">目标节点仍在使用允许列表过滤服务。请通过 Grove 群组更新升级目标节点，再读取运行中的服务。</Notice> : <>
            <p className="muted">列表显示正在运行的服务。选择后检查目标机的管理和日志权限。</p>
            {supported.kinds.length ? <label className="field-label">服务类型<select className="input" aria-label="服务类型" value={kind || ''} disabled={busy}
              onChange={event => { setKind(event.target.value as Kind); setOffset(0); refresh() }}>
              {supported.kinds.map(item => <option value={item} key={item}>{kinds[item]}</option>)}
            </select></label> : <Notice>目标节点没有可接管的系统服务类型。</Notice>}
            {kind === 'docker' && dockerPermission && (supported.docker_authorization === 1
              ? <div className="button-row"><HostServiceAuthorization nodeId={nodeId} session={session} onUnauthorized={onUnauthorized}
                  scope="docker" onAuthorized={refresh} disabled={busy} /></div>
              : <Notice tone="amber">请先通过群组更新升级目标节点，再在此处完成 Docker 授权。</Notice>)}
            {kind && !choices && !error && <Loading label="正在读取运行中的服务…" />}
            {choices && <>
              {choices.candidates.length ? <label className="field-label">运行中的服务<select className="input" aria-label="运行中的服务" value={candidate?.target || ''} disabled={busy}
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
          {checked?.observe_ready && <div className="stack"><div className="button-row tiny">
            {(['start', 'stop', 'restart'] as const).map(action => <span key={action}>{({ start: '启动', stop: '停止', restart: '重启' })[action]}：{checked.control?.[action] ? '可用' : '需要节点授权'}</span>)}
            <span>日志：{checked.logs_ready ? '可读取' : '需要节点授权'}</span></div>
            {!checked.ready && <Notice tone="amber" title="此节点尚未启用系统服务管理">
              当前可先观察服务{checked.logs_ready ? '并读取日志' : '状态'}，也可在此授权目标主机后直接托管。
              {supported.host_authorization === 1 ? <div className="button-row"><HostServiceAuthorization nodeId={nodeId} session={session} onUnauthorized={onUnauthorized}
                onAuthorized={() => { setChecked(undefined); setRegistrationMode('manage'); setReads(value => value + 1) }} disabled={busy} /></div>
                : <p>请先通过 Grove 群组更新升级目标节点，以使用网页主机授权。</p>}
            </Notice>}
          </div>}
          {canTakeOver && <form className="stack" onSubmit={submit} onChange={() => setDirty(true)} key={candidate?.target}>
            {checked?.observe_ready && <fieldset className="service-mode-options" aria-label="接管方式">
              <label><input type="radio" name="takeover-mode" checked={registrationMode === 'manage'} disabled={!checked.ready || busy} onChange={() => setRegistrationMode('manage')} />托管启停</label>
              <label><input type="radio" name="takeover-mode" checked={registrationMode === 'observe'} disabled={busy} onChange={() => setRegistrationMode('observe')} />观察状态与日志</label>
            </fieldset>}
            <label className="field-label">服务名称<input className="input" name="name" maxLength={80} placeholder={candidate?.name} disabled={busy} /></label>
            {kind === 'windows' && (checked?.log_path ? <p className="muted">已识别应用日志 <code>{checked.log_path}</code></p>
              : <label className="field-label">目标 Windows 应用日志的绝对路径
              <input className="input" name="log_path" maxLength={420} required disabled={busy} placeholder={'C:\\Apps\\MyApp\\logs\\app.log'} />
            </label>)}
            <div className="button-row registration-submit"><button className="btn btn-primary" disabled={busy}>核对登记信息<Icon name="arrow-right" size={15} /></button></div>
          </form>}
          </div>
          {review && <><dl className="facts registration-review"><div><dt>服务名称</dt><dd>{review.name}</dd></div><div><dt>登记方式</dt><dd>{checked?.observe_ready && registrationMode === 'observe' ? '观察状态与日志' : '托管启停'} · 保留运行状态</dd></div></dl><div className="button-row registration-submit"><button className="btn btn-secondary" disabled={busy} onClick={() => setReview(undefined)}>上一步</button><button className="btn btn-primary" disabled={busy} onClick={() => void mutate(review.action, review.body)}>{busy ? '正在登记…' : '确认登记'}</button></div></>}
        </>}
    </div>}
      </div>
    </section>
  </div>
}
