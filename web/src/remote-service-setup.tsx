import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { refreshConsole, useConsole } from './console-data'
import { groveServiceRegistrationHref, remoteServiceSyncHref, serviceRegistrationRoute } from './grove-navigation'
import { Icon, Loading, Notice, PageHeading, Panel } from './ui'

const kinds = { systemd: 'systemd 系统服务', windows: 'Windows 系统服务', docker: 'Docker 容器' }
type Kind = keyof typeof kinds
type Candidate = { target: string; name: string }
type Registered = Candidate & { id: string; managed: boolean; version: number }
type Candidates = { candidates: Candidate[]; registered: Registered[]; truncated: boolean }
type Result = { service: Registered }
type SetupProps = { session: Session; onUnauthorized: () => void }
type Action = 'kinds' | 'candidates' | 'register' | 'manage'

function request<T>(session: Session, nodeId: string, action: Action, body: object, signal: AbortSignal) {
  return api<T>(`/peers/${encodeURIComponent(nodeId)}/service-setup/${action}`, {
    method: 'POST', body: JSON.stringify(body), headers: { 'X-CSRF-Token': session.csrf_token }, signal,
  })
}

function setupError(error: unknown, onUnauthorized: () => void) {
  if (error instanceof ApiError) {
    if (error.status === 401) { onUnauthorized(); return '' }
    if (error.code === 'DENIED') return '请使用已验证的 Grove 管理员账号，并确认目标仍是当前 Grove 的成员。'
    if (error.code === 'NO_ROUTE' || error.code === 'OFFLINE' || error.code === 'ROUTE_LOST') return '当前面板还没有到目标节点的可用 Mesh 路径。节点恢复连通后可重试。'
    if (error.code === 'UNSUPPORTED_METHOD') return '目标节点需要升级到支持远程登记的版本。'
    if (error.code === 'HOST_PERMISSION') return '目标节点的面板账号还没有这个服务的 systemd 启停委派权限。'
    if (error.code === 'INVALID_REQUEST' || error.status === 404) return '目标服务已变更，请重新读取。'
    if (error.code === 'CONFLICT') return '请重新读取目标列表，核对服务是否已登记、目标是否仍存在，以及 Spearmint 是否有权限托管。'
  }
  return '暂时没有收到目标节点回执。请重新读取列表核对结果后再操作。'
}

export function GroveServiceSetup({ targetId, session, onUnauthorized }: SetupProps & { targetId?: string }) {
  const { memberNodes, listedNodes, local } = useConsole()
  const targets = memberNodes ?? listedNodes
  const remote = targets.find(node => node.id === targetId && !node.local)
  return <>
    <a href="#/services" className="back-link"><Icon name="arrow-left" size={15} />返回服务管理</a>
    <PageHeading eyebrow="OPERATIONS / SERVICES" title="登记服务" description="选择服务所在的节点，从当前面板完成登记和托管。" />
    <Panel title="服务所在节点">
      <div className="button-row">
        <label className="field-label">节点
          <select className="input" value={remote?.id || (targetId && targetId !== local.data?.node_id ? targetId : '')}
            onChange={event => { location.hash = groveServiceRegistrationHref(event.target.value) }}>
            <option value="">本机节点</option>
            {targetId && !remote && targetId !== local.data?.node_id && <option value={targetId}>正在确认所选节点</option>}
            {targets.filter(node => !node.local).map(node => <option key={node.id} value={node.id}>{node.name}</option>)}
          </select>
        </label>
        {(!targetId || targetId === local.data?.node_id) && <a className="btn btn-primary" href={serviceRegistrationRoute()}>登记本机服务</a>}
      </div>
    </Panel>
    {remote?.peer?.enabled ? <RemoteServiceSetup key={remote.id} nodeId={remote.id} session={session} onUnauthorized={onUnauthorized} />
      : targetId && targetId !== local.data?.node_id && <Notice tone="amber">等待当前面板同步成员并建立到目标的 Mesh 连接。</Notice>}
  </>
}

function RemoteServiceSetup({ nodeId, session, onUnauthorized }: SetupProps & { nodeId: string }) {
  const [supported, setSupported] = useState<Kind[]>()
  const [kind, setKind] = useState<Kind>()
  const [choices, setChoices] = useState<Candidates>()
  const [candidateId, setCandidateId] = useState('')
  const [display, setDisplay] = useState('')
  const [selected, setSelected] = useState<Registered>()
  const [result, setResult] = useState<Result>()
  const [error, setError] = useState('')
  const [reads, setReads] = useState(0)
  const [busy, setBusy] = useState(false)
  const mutation = useRef<AbortController | null>(null)
  useEffect(() => () => mutation.current?.abort(), [])

  useEffect(() => {
    if (supported) return
    const controller = new AbortController()
    request<{ kinds: Kind[] }>(session, nodeId, 'kinds', {}, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => { if (!controller.signal.aborted) { setSupported(data.kinds); setKind(data.kinds[0]) } })
      .catch(failure => { if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized)) })
    return () => controller.abort()
  }, [session, nodeId, reads, supported, onUnauthorized])

  useEffect(() => {
    if (!kind) return
    const controller = new AbortController()
    request<Candidates>(session, nodeId, 'candidates', { kind }, AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]))
      .then(data => {
        if (!controller.signal.aborted) {
          setChoices(data)
          setSelected(current => current ? data.registered.find(item => item.id === current.id) : undefined)
        }
      })
      .catch(failure => { if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized)) })
    return () => controller.abort()
  }, [session, nodeId, kind, reads, onUnauthorized])

  function refresh() {
    setError('')
    setChoices(undefined)
    setReads(value => value + 1)
  }

  async function mutate(action: 'register' | 'manage', body: object) {
    if (mutation.current) return
    const controller = new AbortController()
    mutation.current = controller
    setBusy(true)
    setResult(undefined)
    setError('')
    try {
      const response = await request<Result>(session, nodeId, action, body, AbortSignal.any([controller.signal, AbortSignal.timeout(20_000)]))
      if (controller.signal.aborted) return
      setResult(response)
      setSelected(response.service)
      setCandidateId('')
      setDisplay('')
      refreshConsole()
      refresh()
    } catch (failure) {
      if (!controller.signal.aborted) setError(setupError(failure, onUnauthorized))
    } finally {
      if (!controller.signal.aborted) { mutation.current = null; setBusy(false) }
    }
  }

  const candidate = choices?.candidates.find(item => item.target === candidateId)
  function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (kind && candidate) void mutate('register', { kind, target: candidate.target, name: display.trim() || candidate.name.slice(0, 80) })
  }

  return <Panel title="远程服务">
    <div className="stack">
      {supported?.length ? <label className="field-label">服务类型<select className="input" disabled={busy} value={kind}
        onChange={event => {
          setKind(event.target.value as Kind); setChoices(undefined); setCandidateId(''); setDisplay('')
          setSelected(undefined); setError(''); setResult(undefined)
        }}>{supported.map(value => <option key={value} value={value}>{kinds[value]}</option>)}</select></label> : null}
      {!choices && !error && (!supported || kind) && <Loading label="正在通过 Mesh 读取目标服务…" />}
      {supported?.length === 0 && <Notice>此节点没有可通过网页登记的服务类型。</Notice>}
      {error && <Notice tone="amber">{error}</Notice>}
      {(error || choices) && <div><button className="btn btn-secondary" type="button" disabled={busy} onClick={refresh}>重新读取服务</button></div>}
      {choices && choices.candidates.length > 0 && <form className="stack" onSubmit={register}>
        <label className="field-label">可登记的服务<select className="input" value={candidateId} disabled={busy} required
          onChange={event => { setCandidateId(event.target.value); setDisplay(''); setResult(undefined); setSelected(undefined) }}>
          <option value="">选择服务</option>
          {choices.candidates.map(item => <option key={item.target} value={item.target}>{item.name}</option>)}
        </select></label>
        {choices.truncated && <p className="muted">节点仅返回了前一批服务。</p>}
        {candidate && <>
          <label className="field-label">显示名称<input className="input" maxLength={80} value={display} disabled={busy}
            placeholder={candidate.name} onChange={event => setDisplay(event.target.value)} /></label>
          <div><button className="btn btn-primary" disabled={busy}>登记为观察模式</button></div>
        </>}
      </form>}
      {choices && !choices.candidates.length && <p className="muted">此节点暂无待登记的此类服务。</p>}
      {!!choices?.registered.length && <label className="field-label">已登记的服务<select className="input" value={selected?.id || ''} disabled={busy}
        onChange={event => {
          setSelected(choices.registered.find(item => item.id === event.target.value))
          setCandidateId(''); setDisplay(''); setResult(undefined)
        }}>
        <option value="">选择已登记服务</option>
        {choices.registered.map(item => <option key={item.id} value={item.id}>{item.name} · {item.managed ? '托管' : '观察'}</option>)}
      </select></label>}
      {result && <Notice title={result.service.managed ? '已启用托管' : '登记完成'}>
        {!result.service.managed && <a className="text-link" href={remoteServiceSyncHref(nodeId, result.service.id)}>
          打开远程服务<Icon name="arrow-right" size={15} />
        </a>}
      </Notice>}
      {selected &&
        <div>{selected.managed ? <a className="btn btn-primary" href={remoteServiceSyncHref(nodeId, selected.id)}>打开远程服务</a>
          : <button className="btn btn-primary" type="button" disabled={busy}
            onClick={() => void mutate('manage', { service_id: selected.id, version: selected.version })}>启用托管</button>}</div>}
    </div>
  </Panel>
}
