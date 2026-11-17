import { useEffect, useMemo, useRef, useState } from 'react'
import { ApiError, api, READ_TIMEOUT_MS, type Session, timestamp, usePoll } from './api'
import { useConsole, refreshConsole } from './console-data'
import { Badge, CopyValue, EmptyState, Icon, Loading, Metric, Modal, Notice, PageHeading, Panel, ServiceHealthBadge, ServiceStatusFilters, StateBadge, Tabs } from './ui'
import { RemoteServicePage, ServiceInventory } from './remote'
import { GroveServiceSetup } from './remote-service-setup'
import { groveServiceRegistrationHref, groveServiceRegistrationTarget, localServiceHref, remoteServiceSyncHref, remoteServiceTarget,
  serviceAccessRoute, serviceRegistrationRoute, serviceRegistrationTarget, type LocalServiceTab } from './grove-navigation'
import { FrpMappings } from './frp-mappings'
import { ServiceLogs } from './service-logs'
import { uncertainSubmission, usePendingSubmission } from './pending-submission'
import { matchesServiceStatus, serviceHealthState, type ServiceFilter } from './service-status'

export type Action = 'start' | 'stop' | 'restart'
export type Operation = { id: string; action: Action; status: string; message: string | null; updated_at: number; reason?: string }
export function localOperationMessage(operation: Operation) {
  if (operation.reason === 'RESTART_BEFORE_DISPATCH') return '面板重启前，这笔操作还在排队，未执行。'
  if (operation.reason === 'PANEL_RESTARTED') return '面板派发这笔操作后重启，结果待确认。请查看服务当前状态。'
  return operation.message
}
export function LocalOperationBadge({ operation }: { operation: Operation }) {
  return operation.reason === 'RESTART_BEFORE_DISPATCH' ? <Badge tone="neutral">未执行</Badge>
    : <StateBadge state={operation.status} />
}
export type Observation = { status: string; message: string | null; health: string | null; pid: number; checked_at: number | null; last_seen_at: number | null; last_status: string | null; stale: boolean }
export type Service = {
  id: string; node_id?: string; name: string; driver: 'process' | 'docker'; runtime?: 'systemd-system' | 'windows-service'
  registered_target?: string; actions: Action[]; endpoint: string | null; observation: Observation; version?: number; approval_required?: boolean
}
type Detail = Service & { operations: Operation[]; can_unregister?: boolean; can_edit_details?: boolean }
type Mode = 'observe' | 'manage'
type ModeResult = { version: number; actions: Action[] }
type DetailsResult = Pick<Service, 'name' | 'endpoint'> & ModeResult
type SystemServiceManagement = { ready: true } | { ready: false; reason: string;
  control_rights?: { start: boolean | null; stop: boolean | null } }
type SystemdDelegation = { ready: true; listed_actions: Record<Action, boolean>; listed_logs: boolean }
  | Extract<SystemServiceManagement, { ready: false }>
const managementReasons: Record<string, string> = {
  invalid_allowlist: '本机服务允许列表无法读取，请在节点终端核对配置。',
  not_allowed: '此服务已不在本机允许列表中。',
  access_denied: 'Spearmint 运行账号没有查询该服务状态的权限。',
  control_denied: 'Spearmint 运行账号缺少此服务的启动或停止权限。',
  missing: 'Windows 服务管理器中找不到该服务。',
  unit_unavailable: '暂时无法读取这个 systemd 系统服务，请在所属节点核对单元状态。',
  sudo_blocked: '面板进程启用了 NoNewPrivileges，无法使用委派的 sudo 命令执行启停或读取服务日志。',
}

function managementNotice(management: { data?: SystemServiceManagement; error: string }, runtime: Service['runtime']) {
  if (management.error) return '暂时无法核对系统服务的管理条件。'
  if (management.data?.ready === false) {
    if (runtime === 'systemd-system' && management.data.reason === 'not_allowed') return '此单元已不在本机配置的 systemd 服务列表中。'
    return managementReasons[management.data.reason] || '暂时无法核对该系统服务的管理条件。'
  }
}
const accessPermissions = { directory: '服务目录', status: '状态', logs: '日志' }
type AccessPermission = keyof typeof accessPermissions
type PeerAccess = Record<AccessPermission, boolean> & {
  node_id: string; host: string; active: boolean; actions: Action[]; configured_account_actions?: Action[]
  revision?: string; account_grant_expires_at?: number | null
}
type ServiceAccessView = { service_version?: number; sampled_at?: number; independent_approval: boolean;
  available_actions?: Action[]; logs_available?: boolean; peers: PeerAccess[] }
type AccessSubmission = {
  permissions: Record<AccessPermission, boolean>
  grant: { mode: 'keep' } | { mode: 'revoke' } | { mode: 'replace'; actions: Action[]; hours: number; sampledAt?: number }
}
export const actions: Record<Action, string> = { start: '启动', stop: '停止', restart: '重启' }
export { stateNames as statuses } from './ui'

type LocalActionRequest = { key: string; action: Action; version?: number }

function decodeLocalAction({ key, action, version }: Record<string, unknown> & { key: string }): LocalActionRequest | undefined {
  if (typeof action !== 'string' || !Object.hasOwn(actions, action)) return
  if (version !== undefined && (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1)) return
  return { key, action: action as Action, version }
}
export const drivers = { process: '托管进程', docker: 'Docker 容器' }
const systemServices = { 'systemd-system': 'systemd 系统服务', 'windows-service': 'Windows 系统服务' }
export function serviceDriver({ driver, runtime }: Service) { return runtime ? systemServices[runtime] : drivers[driver] }
export function serviceSearchText(service: Service) {
  return [service.name, serviceDriver(service), service.registered_target, service.endpoint, service.id].join(' ')
}

type RegistrationProps = { session: Session; onUnauthorized: () => void; onClose: () => void }
type RegistrationContext = RegistrationProps & { sourceNodeId?: string }
type RegistrationKind = 'systemd' | 'windows' | 'docker'
type ServiceRegistrationRequest = { key: string; kind: RegistrationKind; target: string; name: string }
type ContainerChoices = { containers: { id: string; name: string; state: string }[]; truncated: boolean }
type SystemServiceCandidate = { readable: true; status: Observation['status'] } | { readable: false; reason: string }
const systemCandidateReasons: Record<string, string> = {
  unit_unavailable: '找不到已加载的系统服务，或面板账号暂时无法读取它。',
  missing: 'Windows 服务控制管理器未找到该服务。',
  access_denied: '面板运行账号没有查询此 Windows 服务状态的权限。',
  scm_error: 'Windows 服务控制管理器暂时无法完成查询。',
  query_failed: '无法读取该 Windows 服务的状态。',
}
const containerId = /^[a-f0-9]{64}$/
const containerStates: Record<string, string> = {
  running: '运行中', exited: '已退出', created: '已创建', paused: '已暂停', restarting: '重启中', removing: '移除中', dead: '异常退出',
}

function decodeServiceRegistration({ key, kind, target, name }: Record<string, unknown> & { key: string }): ServiceRegistrationRequest | undefined {
  if ((kind !== 'systemd' && kind !== 'windows' && kind !== 'docker') || typeof target !== 'string'
    || !target || target.length > 512 || typeof name !== 'string' || !name || name.length > 80) return
  if (kind === 'docker' && !containerId.test(target)) return
  return { key, kind, target, name }
}

function ExistingServiceRegistration({ kind, session, onUnauthorized, onClose, onBack, sourceNodeId,
  submission, replacementFor }: RegistrationContext & {
  kind: RegistrationKind; onBack: () => void; submission: ReturnType<typeof usePendingSubmission<ServiceRegistrationRequest>>
  replacementFor?: string
}) {
  const systemd = kind === 'systemd'
  const docker = kind === 'docker'
  const { pending: request, ready, remember, clear } = submission
  const registration = kind === 'windows' ? { path: '/services/windows-services', field: 'service' }
    : systemd ? { path: '/services/systemd-units', field: 'unit' } : { path: '/services/docker-containers', field: 'container' }
  const { data, error } = usePoll<{ units?: string[]; services?: string[] }>(docker || request ? null : registration.path, onUnauthorized, 15000)
  const names = data?.units ?? data?.services ?? []
  const containers = usePoll<ContainerChoices>(docker && !request ? registration.path : null, onUnauthorized, 15000)
  const [selection, setSelection] = useState('')
  const [container, setContainer] = useState<{ id: string; name: string }>()
  const [name, setName] = useState('')
  const [pending, setPending] = useState(false)
  const [failure, setFailure] = useState('')
  const [existingId, setExistingId] = useState<string>()
  const inFlight = useRef<AbortController | null>(null)
  useEffect(() => () => inFlight.current?.abort(), [])
  const entered = selection.trim()
  const reference = docker ? container?.id || entered : names.includes(selection) ? selection : ''
  const candidatePath = !docker && !request && reference
    ? `${registration.path}/candidate?${registration.field}=${encodeURIComponent(reference)}` : null
  const candidate = usePoll<SystemServiceCandidate>(candidatePath, onUnauthorized, 15_000)
  const candidateUnsupported = candidate.errorStatus === 404
  const candidateReady = docker || candidateUnsupported || (!candidate.error && candidate.data?.readable === true)
  const defaultName = (systemd ? reference.replace(/\.service$/, '') : container?.name || entered).slice(0, 80)
  const displayName = name.trim() || defaultName
  const nameInUse = docker && displayName === replacementFor
  const services = usePoll<Service[]>(request && !pending ? '/services' : null, onUnauthorized, 3000, undefined, request?.key)
  const target = kind === 'windows' ? request?.target.toLowerCase() : request?.target
  const recovered = request && !pending && !services.error
    ? services.data?.find((service) => service.registered_target === target &&
      (docker ? service.driver === 'docker' : service.runtime === (systemd ? 'systemd-system' : 'windows-service')))
    : undefined
  const registeredId = existingId ?? recovered?.id
  const registeredHref = registeredId ? serviceAccessRoute(registeredId, sourceNodeId) : undefined

  async function registerService(retry?: ServiceRegistrationRequest) {
    if (!ready || inFlight.current) return
    if (retry ? registeredId || !services.data || services.error : request || !reference || error || !candidateReady || nameInUse) return
    const controller = new AbortController()
    inFlight.current = controller
    setPending(true)
    setFailure('')
    let submitted = retry
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    const signal = AbortSignal.any([controller.signal, deadline])
    try {
      if (!submitted) {
        let target = reference
        if (docker && !containerId.test(target)) {
          const resolved = await api<{ id: string }>(`${registration.path}/resolve?container=${encodeURIComponent(target)}`, { signal })
          if (typeof resolved.id !== 'string' || !containerId.test(resolved.id)) throw new Error('Docker 返回了无效的容器 ID。')
          target = resolved.id
        }
        if (signal.aborted) return
        submitted = remember({ key: crypto.randomUUID(), kind, target, name: displayName })
        if (!submitted) return
      }
      const result = await api<{ id: string }>(registration.path, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
        signal,
        body: JSON.stringify({ [registration.field]: submitted.target, name: submitted.name }),
      })
      if (controller.signal.aborted) return
      if (typeof result?.id !== 'string' || !/^[a-f0-9]{32}$/.test(result.id)) throw new Error('登记响应缺少有效的服务 ID。')
      clear(submitted.key)
      location.hash = serviceAccessRoute(result.id, sourceNodeId)
      onClose()
    } catch (cause) {
      if (controller.signal.aborted) return
      if (submitted && !deadline.aborted && !uncertainSubmission(cause) && !retry) clear(submitted.key)
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized()
      else if (cause instanceof ApiError && cause.status === 409 && cause.code === 'TARGET_ALREADY_REGISTERED'
        && cause.serviceId && /^[a-f0-9]{32}$/.test(cause.serviceId)) {
        setExistingId(cause.serviceId)
      } else if (cause instanceof ApiError && cause.status === 409) {
        setFailure(!docker ? '登记未完成。请核对系统服务是否可读取、是否已登记，以及显示名称是否重复。'
          : '登记未完成。请核对该容器是否已经登记，以及显示名称是否重复。')
      } else if (docker && cause instanceof ApiError && cause.status === 404) {
        setFailure('在本机配置的 Docker 中找不到该容器。')
      } else if (deadline.aborted && !submitted) {
        setFailure('查询容器 ID 超时，请重试。')
      } else if (!submitted || !uncertainSubmission(cause)) setFailure(cause instanceof Error ? cause.message : '登记失败')
    } finally {
      inFlight.current = null
      if (!controller.signal.aborted) setPending(false)
      refreshConsole()
    }
  }

  const back = <button type="button" className="btn btn-secondary" disabled={pending} onClick={onBack}>返回选择服务类型</button>
  const message = failure && <p className="error" role="alert">{failure}</p>
  if (registeredHref) return <div className="stack">
    <Notice>该服务已登记，可以继续设置管理模式与访问权限。</Notice>
    <div className="modal-actions">{!request && back}<a className="btn btn-primary" href={registeredHref}
      onClick={(event) => {
        event.preventDefault()
        if (request) clear(request.key)
        location.hash = registeredHref
        onClose()
      }}>打开已登记服务</a></div>
  </div>
  if (request) return <div className="stack">
    <dl className="facts"><div><dt>登记目标</dt><dd className="break-anywhere">{request.target}</dd></div>
      <div><dt>显示名称</dt><dd>{request.name}</dd></div></dl>
    <p role="status">{pending ? '正在登记…' : services.error ? '暂时无法读取本机服务，连接恢复后会重新核对。'
      : !services.data ? '正在核对本机服务列表…' : '本机服务列表暂未返回这个目标，可重试同一笔登记。'}</p>
    {!pending && message}
    <div className="modal-actions">
      <button type="button" className="btn btn-secondary" disabled={pending} onClick={() => { clear(request.key); onBack() }}>结束跟踪</button>
      <button type="button" className="btn btn-primary" disabled={pending || !services.data || !!services.error}
        onClick={() => void registerService(request)}>重试同一目标</button>
    </div>
  </div>
  if (!docker && (error || !data || !names.length)) return <>
    {error ? <Notice tone="amber">暂时无法读取本机配置的系统服务。{error}</Notice>
      : !data ? <Loading label="正在读取已配置的系统服务…" />
      : <Notice>没有可登记的系统服务。{systemd
        ? '请在所属节点核对 SPEARMINT_SYSTEMD_UNITS 和已登记服务。'
        : '请在所属节点用 spearmint service windows-allowlist 核对允许列表和已登记服务。'}</Notice>}
    {message}
    <div className="modal-actions">{back}{failure && <a className="btn btn-primary" href="#/services/local" onClick={onClose}>查看本机服务</a>}</div>
  </>
  return <form className="stack" onSubmit={(event) => { event.preventDefault(); void registerService() }}>
    <p className="muted">{docker ? '从本机配置的 Docker 登记已有容器，即可查看状态和日志。' : '登记后以观察模式查看服务状态。'}</p>
    <div className="form-grid">
      {!docker ? <label>系统服务<select required value={reference} disabled={pending} onChange={(event) => setSelection(event.target.value)}>
        <option value="">选择服务</option>
        {names.map((value) => <option key={value} value={value}>{value}</option>)}
      </select></label> : <>
        {(container || (!containers.error && !!containers.data?.containers.length)) && <label>选择容器
          <select value={container?.id ?? ''} disabled={pending} onChange={(event) => {
            setContainer(containers.data?.containers.find((item) => item.id === event.target.value))
          }}>
            <option value="">手动输入名称或 ID</option>
            {container && (containers.error || !containers.data?.containers.some((item) => item.id === container.id)) &&
              <option value={container.id}>{container.name} · 上次选择</option>}
            {!containers.error && containers.data?.containers.map((item) => <option key={item.id} value={item.id}>
              {item.name} · {containerStates[item.state] || item.state}
            </option>)}
          </select>
        </label>}
        {!container && <label>容器名称或 ID<input required value={selection} maxLength={128}
          pattern={'[A-Za-z0-9][A-Za-z0-9_.\\-]{0,127}'} disabled={pending} onChange={(event) => setSelection(event.target.value)} /></label>}
      </>}
      <label>显示名称<input value={name} maxLength={80} placeholder={defaultName || '默认使用登记对象的名称'}
        disabled={pending} onChange={(event) => setName(event.target.value)} /></label>
    </div>
    {nameInUse && <p className="muted" role="status">该名称已用于原登记，请为新容器输入其他显示名称。</p>}
    {candidatePath && <div className="stack" aria-live="polite">
      {candidateUnsupported ? <p className="muted">当前版本会在登记时检查服务状态。</p>
        : candidate.error ? <Notice tone="amber">暂时无法核对所选服务。{candidate.error}</Notice>
        : !candidate.data ? <Loading label="正在查询所选服务…" />
        : candidate.data.readable ? <p className="muted">服务状态 <StateBadge state={candidate.data.status} /></p>
        : <Notice tone="amber">{systemCandidateReasons[candidate.data.reason] ?? '所选服务暂时无法读取。'}</Notice>}
      {!candidateUnsupported && (candidate.error || candidate.data?.readable === false) &&
        <div><button type="button" className="btn btn-secondary" onClick={refreshConsole}>重新检查服务</button></div>}
    </div>}
    {docker && (containers.error ? <p className="muted">暂时无法列出容器，仍可手动输入名称或 ID。</p>
      : !containers.data ? <p className="muted">正在读取本机容器…</p>
      : containers.data.truncated ? <p className="muted">只显示部分容器，可手动输入其他容器的名称或 ID。</p>
      : !containers.data.containers.length ? <p className="muted">暂无可登记的容器。</p> : null)}
    {message}
    <div className="modal-actions">{back}{failure && <a className="btn btn-secondary" href="#/services/local" onClick={onClose}>查看本机服务</a>}
      <button type="submit" className="btn btn-primary" disabled={!ready || !reference || !candidateReady || nameInUse || pending}>
      {pending ? '正在登记…' : '登记为观察模式'}
    </button></div>
  </form>
}

function RegistrationHelp({ session, onUnauthorized, onClose, sourceNodeId, replacementFor }: RegistrationContext & {
  replacementFor?: string
}) {
  const { local, services } = useConsole()
  const os = local.data?.platform?.os
  const [selectedKind, setKind] = useState<RegistrationKind | 'process' | undefined>(replacementFor ? 'docker' : undefined)
  const owner = local.error ? undefined : local.data?.node_id
  const submission = usePendingSubmission('spearmint-service-registration', `${owner ?? ''}:${serviceRegistrationRoute(sourceNodeId)}`,
    session.csrf_token, decodeServiceRegistration)
  const kind = submission.pending?.kind ?? selectedKind
  const system = os === 'Windows' ? { id: 'windows', title: 'Windows 系统服务' } as const
    : os === 'Linux' ? { id: 'systemd', title: 'systemd 系统服务' } as const : undefined
  const title = kind === 'docker' ? 'Docker 容器' : kind === 'process' ? '前台程序' : systemServices[kind === 'windows' ? 'windows-service' : 'systemd-system']
  return <Modal title={kind ? `登记${title}` : '登记一个服务'} onClose={onClose}>
    {replacementFor && kind === 'docker' && !submission.pending && <Notice>
      「{replacementFor}」的原登记还占用这个显示名称。登记新容器时请选择不同的显示名称，然后为新服务配置访问权限。
    </Notice>}
    {local.error ? <Notice tone="amber">暂时无法确认当前节点。{local.error}</Notice>
      : !owner || !submission.ready ? <Loading label="正在读取登记进度…" /> : !kind ? <div className="stack">
      {system && <button type="button" className="btn btn-secondary" onClick={() => setKind(system.id)}><Icon name="server" />{system.title}</button>}
      <button type="button" className="btn btn-secondary" onClick={() => setKind('docker')}><Icon name="package" />Docker 容器</button>
      <button type="button" className="btn btn-secondary" onClick={() => setKind('process')}><Icon name="terminal" />前台程序</button>
      {sourceNodeId && <details>
        <summary>打开已登记服务</summary>
        {services.error ? <Notice tone="amber">暂时无法读取已登记服务。{services.error}</Notice>
          : !services.data ? <Loading label="正在读取已登记服务…" />
          : !services.data.length ? <p>此节点还没有已登记服务。</p>
          : <ul className="service-list">{services.data.map((service) => <li key={service.id}>
            <a className="text-link" href={serviceAccessRoute(service.id, sourceNodeId)}>
              {service.name}<Icon name="arrow-right" size={14} />
            </a><span>{serviceDriver(service)}</span>
            {service.registered_target && <span className="break-anywhere">{service.driver === 'docker'
              ? service.registered_target.slice(0, 12) : service.registered_target}</span>}
          </li>)}</ul>}
      </details>}
    </div> : kind === 'process' ? <ProcessRegistration os={os} sourceNodeId={sourceNodeId}
      onClose={onClose} onBack={() => setKind(undefined)} />
    : <ExistingServiceRegistration kind={kind} session={session} onUnauthorized={onUnauthorized} onClose={onClose}
      sourceNodeId={sourceNodeId} onBack={() => setKind(undefined)} submission={submission} replacementFor={replacementFor} />}
  </Modal>
}

function ProcessRegistration({ os, sourceNodeId, onClose, onBack }: {
  os?: string; sourceNodeId?: string; onClose: () => void; onBack: () => void
}) {
  const { services } = useConsole()
  const [input, setInput] = useState('')
  const [lookup, setLookup] = useState<{ id: string; requestedAt: number }>()
  const id = input.trim()
  const validId = /^[a-f0-9]{32}$/.test(id)
  const fresh = lookup && (services.requestedAt ?? 0) >= lookup.requestedAt
  const service = lookup && fresh && !services.error && services.data?.find(item =>
    item.id === lookup.id && item.driver === 'process' && !item.runtime)
  const href = service && (sourceNodeId ? serviceAccessRoute(service.id, sourceNodeId) : localServiceHref(service.id))
  return <form className="stack" onSubmit={event => {
    event.preventDefault()
    if (!validId) return
    setLookup({ id, requestedAt: performance.now() })
    refreshConsole()
  }}>
    <p>在所属节点的终端，以 Spearmint 运行账号执行。沿用面板的状态目录，填写程序的绝对路径、工作目录和启动参数。</p>
    <pre className="command-block">{os === 'Windows' ? '.\\spearmint.exe service register-process --name "我的服务" --cwd "C:\\Apps\\MyApp" -- "C:\\Apps\\MyApp\\app.exe"' : './spearmint service register-process --name "我的服务" --cwd /srv/my-app -- /srv/my-app/start'}</pre>
    <label className="field-label">终端返回的服务 ID
      <input className="input" value={input} onChange={event => { setInput(event.target.value); setLookup(undefined) }}
        autoComplete="off" spellCheck={false} />
    </label>
    {lookup && <p role="status">{services.error ? '暂时无法读取本机服务。连接恢复后会重新核对。'
      : !fresh ? '正在核对本机服务…' : service ? `已找到「${service.name}」。` : '本机尚未找到对应的前台程序。请核对服务 ID 和登记使用的状态目录。'}</p>}
    <div className="modal-actions">
      <button type="button" className="btn btn-secondary" onClick={onBack}>返回选择服务类型</button>
      {href ? <a className="btn btn-primary" href={href}
        onClick={event => { event.preventDefault(); location.hash = href; onClose() }}>打开已登记服务</a>
        : <button type="submit" className="btn btn-primary" disabled={!validId}>查找服务</button>}
    </div>
  </form>
}

export function Services({ session, onUnauthorized, section, segments }: {
  session: Session; onUnauthorized: () => void; section?: string; segments: string[]
}) {
  const { local, services } = useConsole()
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<ServiceFilter>('all')
  const groveRegistration = section === 'register' ? groveServiceRegistrationTarget(location.hash) : undefined
  if (groveRegistration) return <GroveServiceSetup {...groveRegistration} session={session} onUnauthorized={onUnauthorized} />
  const scope = section === 'remote' ? 'remote' : section === 'local' ? 'local' : 'all'
  const registration = scope === 'local' ? serviceRegistrationTarget(`#/services/local/${segments.join('/')}`) : undefined
  const remote = scope === 'remote' ? remoteServiceTarget(location.hash) : undefined
  if (remote) return <RemoteServicePage key={JSON.stringify([remote.nodeId, remote.serviceId])} {...remote} />
  if (scope === 'remote' && segments.length === 1 && segments[0]) {
    return <RemoteServicePage key={segments[0]} nodeId={segments[0]} showLogs={false} />
  }
  if (section && section !== 'local' && section !== 'remote') {
    const requestedTab = segments[0]
    const tab = requestedTab === 'access' || requestedTab === 'logs' || requestedTab === 'history' ? requestedTab : 'overview'
    const sourceNodeId = tab === 'access' && segments.length === 2 && /^spm1-[a-f0-9]{64}$/.test(segments[1])
      ? segments[1] : undefined
    return <ServiceDetail key={section} id={section} tab={tab}
      sourceNodeId={sourceNodeId} session={session} onUnauthorized={onUnauthorized} />
  }
  const data = services.data
  const observed = (item: Service) => ({ ...item.observation, stale: item.observation.stale || !!services.error })
  const count = (status: ServiceFilter) => data?.filter((item) => matchesServiceStatus(status, observed(item))).length ?? '—'
  const visible = data?.filter((item) => serviceSearchText(item).toLowerCase().includes(query.trim().toLowerCase())
    && matchesServiceStatus(filter, observed(item)))
  return <>
    <PageHeading eyebrow="OPERATIONS / SERVICES" title="服务管理" description="管理已经登记的程序与容器，让每一次操作都有清楚的状态和结果。">
      <a className="btn btn-primary" href={scope === 'local' ? serviceRegistrationRoute() : groveServiceRegistrationHref()}>
        <Icon name="plus" size={16} />{scope === 'local' ? '登记本机服务' : '登记服务'}
      </a>
    </PageHeading>
    {scope === 'local' && <div className="metrics-grid">
      <Metric label="本机已登记" value={data?.length ?? '—'} detail="当前节点的服务" icon="layers" />
      <Metric label="运行中" value={count('running')} detail="最近一次有效观测" icon="play" />
      <Metric label="需要关注" value={count('attention')} detail="异常或数据陈旧" icon="alert-triangle" />
      <Metric label="已停止" value={count('stopped')} detail="等待下一次启动" icon="pause" />
    </div>}
    <Tabs label="服务范围" current={scope} onChange={(value) => { location.hash = value === 'all' ? '#/services' : `#/services/${value}` }}
      items={[{ id: 'all', label: '全部服务', icon: 'layers' }, { id: 'local', label: '本机服务', icon: 'server' }, { id: 'remote', label: '远程服务', icon: 'network' }]} />
    {scope === 'local' ? <Panel>
      <div className="filter-toolbar"><label className="search-box"><Icon name="search" size={17} /><input aria-label="搜索服务" placeholder="搜索服务名称、单元名或容器 ID…" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
        <ServiceStatusFilters value={filter} onChange={setFilter} />
      </div>
      {services.error && <Notice tone="amber" title="服务状态暂时无法更新">{services.error}</Notice>}
      {!data ? services.error ? <EmptyState icon="wifi-off" title="等待恢复服务连接">连接恢复后会自动重新读取服务列表。</EmptyState> : <Loading label="正在读取服务…" /> : !data.length ? <EmptyState icon="layers" title="让你的第一个服务在这里生长" action={<a className="btn btn-secondary" href={serviceRegistrationRoute()}><Icon name="plus" size={16} />查看登记方式</a>}>登记一个前台程序或已有容器，即可查看状态、读取日志并控制启停。</EmptyState>
        : !visible?.length ? <EmptyState icon="search" title="没有匹配的服务">换个关键词，或选择其他状态。</EmptyState>
          : <div className="table-wrap"><table className="data-table service-table"><thead><tr><th>服务</th><th>所属节点</th><th>驱动</th><th>状态</th><th>最近观测</th><th><span className="sr-only">服务入口</span></th></tr></thead>
            <tbody>{visible.map((item) => <tr key={item.id}><td><a className="service-name-cell" href={`#/services/${item.id}`}><span className="service-cell-icon"><Icon name={item.driver === 'docker' ? 'package' : 'terminal'} size={20} /></span><span><strong>{item.name}</strong><small title={item.registered_target}>{item.registered_target
              ? item.driver === 'docker' ? item.registered_target.slice(0, 12) : item.registered_target
              : item.endpoint || (item.actions.length ? '可管理生命周期' : '只读观察模式')}</small></span></a></td>
              <td><span className="subtle-link">本机节点</span></td><td><Badge tone="outline">{serviceDriver(item)}</Badge></td><td><ServiceState observation={item.observation} unavailable={!!services.error} /></td><td className="muted time-cell">{timestamp(item.observation.checked_at)}</td>
              <td><div className="button-row">
                {item.runtime && <a className="text-link" href={localServiceHref(item.id, 'access')} aria-label={`查看 ${item.name} 的管理条件`}>管理条件</a>}
                <a className="icon-button" href={`#/services/${item.id}`} aria-label={`查看 ${item.name}`}><Icon name="arrow-up-right" size={16} /></a>
              </div></td></tr>)}</tbody></table></div>}
    </Panel> : <ServiceInventory includeLocal={scope === 'all'} filter={filter} onFilter={setFilter} />}
    {registration && <RegistrationHelp key={JSON.stringify([local.data?.node_id, registration.sourceNodeId])}
      session={session} onUnauthorized={onUnauthorized}
      sourceNodeId={registration.sourceNodeId} onClose={() => {
        if (serviceRegistrationTarget(location.hash)) location.replace('#/services/local')
      }} />}
  </>
}

export function ServiceState({ observation, unavailable = false }: { observation: Observation; unavailable?: boolean }) {
  const stale = observation.stale || unavailable
  const health = serviceHealthState(observation.health, stale)
  return <><StateBadge state={observation.status} stale={stale} />
    {health && <span className="table-secondary"><ServiceHealthBadge health={health} /></span>}
  </>
}

function ServiceDetail({ id, tab, sourceNodeId, session, onUnauthorized }: {
  id: string; tab: LocalServiceTab; sourceNodeId?: string; session: Session; onUnauthorized: () => void
}) {
  const { services, localName, local } = useConsole()
  const path = `/services/${encodeURIComponent(id)}`
  const actionsPath = `${path}/actions`
  const { data: detail, error: pollError, requestedAt } = usePoll<Detail>(path, onUnauthorized)
  const [changedService, setChangedService] = useState<DetailsResult>()
  const [editing, setEditing] = useState(false)
  const [registeringReplacement, setRegisteringReplacement] = useState(false)
  const service = detail || services.data?.find((item) => item.id === id)
  const current = service && changedService && changedService.version > (service.version ?? 0)
    ? { ...service, ...changedService } : service
  function setTab(value: string) {
    if (value === 'overview' || value === 'logs' || value === 'history' || value === 'access') {
      if (value !== tab) location.hash = localServiceHref(id, value)
    }
  }
  const managementEndpoint = current?.runtime === 'windows-service' ? 'windows-management'
    : current?.runtime === 'systemd-system' ? 'systemd-management' : undefined
  const managementPath = managementEndpoint && (tab !== 'history' || !!current?.actions.length)
    ? `${path}/${managementEndpoint}` : null
  const [managementRefresh, setManagementRefresh] = useState(0)
  const managementScope = `${current?.version ?? ''}/${managementRefresh}`
  const management = usePoll<SystemServiceManagement>(managementPath, onUnauthorized, 10000, undefined, managementScope)
  const managementUnavailable = !!managementEndpoint && (management.error !== '' || management.data?.ready !== true)
  const managementIssue = managementNotice(management, current?.runtime)
  const [accepted, setAccepted] = useState<Operation>()
  const [confirmation, setConfirmation] = useState<{ action: 'stop' | 'restart'; scope: string }>()
  const [submitting, setSubmitting] = useState(false)
  const [actionError, setActionError] = useState('')
  const [refreshActionsAfter, setRefreshActionsAfter] = useState<number>()
  const inFlight = useRef(false)
  const { pending, ready, remember, clear } = usePendingSubmission(
    'spearmint-local-operation', actionsPath, session.csrf_token, decodeLocalAction,
  )
  const lookupKey = submitting ? undefined : pending?.key
  const lookupHeaders = useMemo(() => lookupKey ? { 'Idempotency-Key': lookupKey } : undefined, [lookupKey])
  const { data: recovered } = usePoll<Operation | null>(lookupKey ? `${actionsPath}/request` : null,
    onUnauthorized, 3000, lookupHeaders)
  useEffect(() => {
    if (!lookupKey || !recovered?.id || recovered.action !== pending?.action) return
    setAccepted(recovered)
    setActionError('')
    clear(lookupKey)
    refreshConsole()
  }, [clear, lookupKey, pending?.action, recovered])

  const operations = detail?.operations ?? []
  const recent = accepted && !operations.some((operation) => operation.id === accepted.id) ? [accepted, ...operations] : operations
  const busy = submitting || recent.some((operation) => ['queued', 'running'].includes(operation.status))
  const hasLogs = !!current && current.runtime !== 'windows-service'
  const status = current?.observation.status
  const blocked = !detail || !current || current.approval_required || busy || !!pollError || current.observation.stale
    || (refreshActionsAfter !== undefined && (requestedAt ?? 0) < refreshActionsAfter)
    || managementUnavailable || ['unknown', 'missing', 'starting', 'stopping'].includes(status ?? 'unknown')
  const newActionBlocked = blocked || !ready || !!pending
  const scope = `${current?.version}/${status}/${tab}`
  const confirmed = !newActionBlocked && confirmation?.scope === scope && current?.actions.includes(confirmation.action)
    ? confirmation.action : undefined
  useEffect(() => {
    if (!confirmed) setConfirmation(undefined)
  }, [confirmed])

  async function submit(intent: LocalActionRequest) {
    if (blocked || inFlight.current || !current?.actions.includes(intent.action)) return
    const request = remember(intent)
    if (!request) return
    inFlight.current = true
    setConfirmation(undefined)
    setSubmitting(true)
    setActionError('')
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      const submitPath = request.version === undefined ? actionsPath : `${actionsPath}?service_version=${request.version}`
      setAccepted(await api<Operation>(submitPath, {
        method: 'POST', signal: deadline,
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': request.key, 'X-CSRF-Token': session.csrf_token },
        body: JSON.stringify({ action: request.action }),
      }))
      clear(request.key)
      refreshConsole()
    } catch (error) {
      if (error instanceof ApiError && error.code === 'SERVICE_VERSION_CHANGED') {
        clear(request.key)
        setActionError('服务登记已变化，本次操作未提交。请核对最新登记后重新发起。')
        setRefreshActionsAfter(performance.now())
        refreshConsole()
        return
      }
      if (!pending && !deadline.aborted && !uncertainSubmission(error)) clear(request.key)
      if (error instanceof ApiError && error.status === 401) onUnauthorized()
      else setActionError(deadline.aborted ? '提交响应超时，正在查询原请求的回执。'
        : error instanceof Error ? error.message : '操作结果尚未确认，请检查操作记录。')
    } finally {
      inFlight.current = false
      setSubmitting(false)
    }
  }
  function begin(action: Action) {
    void submit({ key: crypto.randomUUID(), action, version: current?.version })
  }
  if (!current) return <><PageHeading eyebrow="OPERATIONS / SERVICE" title="服务详情" description="读取服务的最新状态与操作记录。" />{pollError ? <Panel><EmptyState title="无法读取这个服务">{pollError}</EmptyState><a href="#/services" className="btn btn-secondary">返回服务列表</a></Panel> : <Loading />}</>
  const observation = current.observation
  const observationStale = observation.stale || !!pollError
  const health = serviceHealthState(observation.health, observationStale)
  const managed = current.actions.length > 0
  const modeInPanel = current.driver === 'docker' || !!current.runtime
  const containerMissing = !!detail && current.driver === 'docker' && !observationStale && observation.status === 'missing'
  let containerIssue: string | undefined
  if (current.driver === 'docker') {
    if (observationStale || observation.status === 'unknown') containerIssue = '暂时无法确认已登记容器的状态。请等待新的 Docker 观测。'
    else if (observation.status === 'missing') containerIssue = '原容器已不存在。请登记新容器后再启用管理。'
    else if (['starting', 'stopping'].includes(observation.status)) containerIssue = '容器正在启动或停止。状态稳定后会重新核对可用操作。'
  }
  const foregroundModeCommand = `spearmint service mode ${id} manage`
  const primaryAction = observation.status === 'running' ? 'stop' : 'start'
  const detailsBusy = busy || !!pollError
  return <>
    <a className="back-link" href="#/services"><Icon name="arrow-left" size={15} />返回服务列表</a>
    <PageHeading eyebrow="OPERATIONS / SERVICE" title={current.name} description={`${localName} · ${serviceDriver(current)}`}>
      {!current.approval_required && current.actions.includes(primaryAction) && <button className="btn btn-primary" disabled={newActionBlocked}
        onClick={() => primaryAction === 'stop' ? setConfirmation({ action: 'stop', scope }) : begin('start')}>
        <Icon name={primaryAction === 'stop' ? 'pause' : 'play'} size={15} />{submitting ? '正在提交…' : primaryAction === 'stop' ? '停止服务' : '启动服务'}</button>}
      {!current.approval_required && current.actions.includes('restart') && <button className="btn btn-secondary" disabled={newActionBlocked}
        onClick={() => setConfirmation({ action: 'restart', scope })}><Icon name="refresh" size={15} />重启</button>}
    </PageHeading>
    <div className="detail-identity"><span className="detail-identity-icon service"><Icon name={current.driver === 'docker' ? 'package' : 'terminal'} size={25} /></span>
      <div className="detail-identity-tags"><StateBadge state={observation.status} stale={observationStale} /><Badge tone="outline">{current.actions.length ? '管理模式' : '观察模式'}</Badge><CopyValue value={current.id} /></div><span className="muted tiny">最近检查 {timestamp(observation.checked_at)}</span></div>
    {current.approval_required && <Notice tone="amber" title="此服务需要独立批准">请从获准的来源节点完成签署。{' '}
      <a className="text-link" href="#/operations/approvals">打开操作与审批<Icon name="arrow-right" size={14} /></a>
    </Notice>}
    {(pollError || actionError) && <Notice title="操作或状态更新未完成" tone="amber">{actionError || pollError}</Notice>}
    {pending && !submitting && <div className="stack">
      <Notice title={`${actions[pending.action]}请求待确认`} tone="amber">
        正在查询原请求的回执。可在核对服务状态和操作记录后结束跟踪。
      </Notice>
      <div className="button-row">
        <button className="btn btn-secondary btn-small" disabled={blocked || !current.actions.includes(pending.action)}
          onClick={() => void submit(pending)}>重试同一请求</button>
        <button className="btn btn-secondary btn-small" onClick={() => { clear(pending.key); setActionError('') }}>结束跟踪</button>
      </div>
    </div>}
    {tab !== 'access' && managementIssue && (managed || tab === 'logs') && <Notice tone="amber">{managementIssue}
      {managementEndpoint && <>{' '}<a className="text-link" href={localServiceHref(id, 'access')}>查看管理条件</a></>}
    </Notice>}
    {containerMissing && <Notice tone="amber" title="原容器已不存在">
      如已重建容器，可选择新容器登记为观察模式。{' '}
      <button type="button" className="btn btn-secondary btn-small" onClick={() => setRegisteringReplacement(true)}>登记新容器</button>
    </Notice>}
    {observation.message && <Notice tone={['failed', 'unknown'].includes(observation.status) ? 'amber' : ''}>{observation.message}</Notice>}
    <Tabs label="服务详情" current={tab} onChange={setTab} items={[{ id: 'overview', label: '概览', icon: 'layout-dashboard' }, { id: 'logs', label: '运行日志', icon: 'terminal' }, { id: 'history', label: '操作记录', icon: 'clock' }, { id: 'access', label: '管理设置', icon: 'shield' }]} />
    <div role="tabpanel" aria-labelledby={`服务详情-${tab}`}>
      {tab === 'overview' && <>{!managed && <Notice title="此服务处于观察模式">
        {modeInPanel ? <>{managementIssue || containerIssue || (managementEndpoint && managementUnavailable ? '正在核对运行账号权限。'
          : '可在管理设置中核对所需权限并启用管理模式。')}{' '}
          <a className="text-link" href={localServiceHref(id, 'access')}>前往管理设置<Icon name="arrow-right" size={14} /></a></>
          : <>以 Spearmint 运行账号确认原进程已停止，再执行 <code>{foregroundModeCommand}</code>。</>}
      </Notice>}
        <div className="metrics-grid"><Metric label="运行状态" value={<StateBadge state={observation.status} stale={observationStale} />} detail={observationStale ? '请等待新的有效观测' : '来自执行节点'} icon="activity" />
        <Metric label="主进程 PID" value={observation.pid > 0 ? observation.pid : '—'} detail="最近观测到的主进程" icon="cpu" />
        <Metric label="健康检查" value={health ? <ServiceHealthBadge health={health} /> : observationStale ? '待更新' : '暂无结果'} detail="由工作负载报告" icon="shield-check" />
        <Metric label="本机操作" value={current.approval_required ? '需审批' : !managed ? '观察模式' : managementUnavailable ? '待核对' : '可管理'}
          detail={current.approval_required ? '独立签名批准' : !managed ? '可查看服务状态' : managementUnavailable
            ? managementIssue || '正在核对系统服务的管理条件' : current.actions.map((a) => actions[a]).join(' / ')} icon="settings" /></div>
        <div className="columns-2"><Panel title="服务信息" action={detail?.can_edit_details && current.version !== undefined &&
          <button type="button" className="btn btn-secondary btn-small" disabled={detailsBusy} onClick={() => setEditing(true)}>编辑服务信息</button>}>
          <dl className="facts"><div><dt>所属节点</dt><dd>{localName}</dd></div><div><dt>执行方式</dt><dd>{current.runtime ? systemServices[current.runtime] : current.driver === 'process' ? local.data?.platform?.process_backend === 'systemd' ? 'systemd 用户服务' : '原生进程监管' : '本机 Docker'}</dd></div>
            {current.registered_target && <div><dt>{current.driver === 'docker' ? 'Docker 容器 ID'
              : current.runtime === 'systemd-system' ? 'systemd 单元名' : 'Windows 服务名称'}</dt><dd><CopyValue value={current.registered_target} /></dd></div>}
            <div><dt>服务版本</dt><dd>{current.version ?? '—'}</dd></div><div><dt>登记端点</dt><dd>{current.endpoint || '未登记'}</dd></div><div><dt>最近有效观测</dt><dd>{timestamp(observation.last_seen_at)}</dd></div></dl>
        </Panel>
          <Panel title="最近操作" action={<button className="panel-link plain-button" onClick={() => setTab('history')}>全部记录<Icon name="arrow-up-right" size={14} /></button>}><OperationList operations={recent.slice(0, 3)} /></Panel></div>
        <FrpMappings path={path} session={session} onUnauthorized={onUnauthorized} /></>}
      {tab === 'logs' && !hasLogs && <Panel title="运行日志"><Notice>Windows 系统服务的应用日志由服务自身管理。请使用该服务的日志工具或 Windows 事件查看器。</Notice></Panel>}
      {tab === 'logs' && current.runtime === 'systemd-system' && managementUnavailable && !managementIssue
        && <Loading label="正在核对系统服务的管理条件…" />}
      {hasLogs && <ServiceLogs path={path} serviceId={id} onUnauthorized={onUnauthorized}
        active={tab === 'logs' && !(current.runtime === 'systemd-system' && managementUnavailable)} />}
      {tab === 'history' && <Panel title="操作记录"><OperationList operations={recent} /></Panel>}
      {tab === 'access' && <div className="stack"><Panel title="本机访问"><dl className="facts"><div><dt>当前账户</dt><dd>{session.username}</dd></div><div><dt>账户角色</dt><dd>节点管理员</dd></div><div><dt>服务模式</dt><dd>{current.actions.length ? '可管理' : '只读观察'}</dd></div><div><dt>授权操作</dt><dd>{current.approval_required ? '需要独立批准' : current.actions.map((a) => actions[a]).join('、') || '状态与日志'}</dd></div></dl></Panel>
        {modeInPanel && current.version !== undefined
          && <ServiceModeControl path={path} version={current.version} managed={managed}
            runtime={current.runtime} busy={busy || !!pollError || !detail} management={management}
            managementScope={managementScope} onRecheckManagement={() => setManagementRefresh(value => value + 1)}
            detail={pollError ? undefined : detail} requestedAt={requestedAt}
            unavailable={!managed && (managementUnavailable || !!containerIssue)} containerIssue={containerIssue}
            session={session} onUnauthorized={onUnauthorized}
            onChanged={(result) => setChangedService({ name: current.name, endpoint: current.endpoint, ...result })} />}
        {(!session.grove || current.approval_required) && <ServiceAccess key={sourceNodeId ?? 'access'} path={path} serviceId={id}
          sourceNodeId={sourceNodeId} serviceVersion={current.version} managementIssue={!!(managementIssue || containerIssue)}
          session={session} onUnauthorized={onUnauthorized} />}
        {detail?.can_unregister && current.version !== undefined
          && <UnregisterService path={path} serviceId={id} name={current.name} version={current.version}
            busy={busy || !!pollError} session={session} onUnauthorized={onUnauthorized} />}
      </div>}
    </div>
    {confirmed && <ServiceActionConfirmation action={confirmed} name={current.name} onClose={() => setConfirmation(undefined)}
      onConfirm={() => begin(confirmed)} />}
    {editing && detail?.can_edit_details && current.version !== undefined && <EditServiceDetails path={path}
      name={current.name} endpoint={current.endpoint} version={current.version} busy={detailsBusy}
      detail={pollError ? undefined : detail} requestedAt={requestedAt}
      session={session} onUnauthorized={onUnauthorized} onClose={() => setEditing(false)} onSaved={setChangedService} />}
    {registeringReplacement && <RegistrationHelp replacementFor={current.name} session={session} onUnauthorized={onUnauthorized}
      onClose={() => setRegisteringReplacement(false)} sourceNodeId={sourceNodeId} />}
  </>
}

export function ServiceActionConfirmation({ action, name, onClose, onConfirm, disabled = false }: {
  action: 'stop' | 'restart'; name: string; onClose: () => void; onConfirm: () => void; disabled?: boolean
}) {
  return <Modal title={`${actions[action]} ${name}？`} onClose={onClose}>
    <p>此操作可能中断正在使用的连接。</p>
    <div className="modal-actions">
      <button className="btn btn-secondary" onClick={onClose}>取消</button>
      <button className={`btn ${action === 'stop' ? 'btn-danger' : 'btn-primary'}`} disabled={disabled}
        onClick={onConfirm}>确认{actions[action]}</button>
    </div>
  </Modal>
}

function EditServiceDetails({ path, name, endpoint, version, busy, detail, requestedAt, session, onUnauthorized, onClose, onSaved }: {
  path: string; name: string; endpoint: string | null; version: number; busy: boolean; session: Session
  detail?: Detail; requestedAt?: number
  onUnauthorized: () => void; onClose: () => void; onSaved: (result: DetailsResult) => void
}) {
  const [baseVersion, setBaseVersion] = useState(version)
  const [draftName, setDraftName] = useState(name)
  const [draftEndpoint, setDraftEndpoint] = useState(endpoint ?? '')
  const [pending, setPending] = useState(false)
  const [attempt, setAttempt] = useState<{ name: string; endpoint: string | null; recheckAfter: number }>()
  const [error, setError] = useState('')
  const inFlight = useRef(false)
  const changed = version !== baseVersion
  const fresh = !!detail && (requestedAt ?? -1) > (attempt?.recheckAfter ?? Infinity)
  const waiting = !!attempt && !fresh
  const checked = !!attempt && fresh && detail.version === baseVersion + 1
    && detail.name === attempt.name && detail.endpoint === attempt.endpoint
  const canSave = !busy && !changed && !pending && !waiting && !!draftName.trim()

  function close() {
    if (!inFlight.current) onClose()
  }

  function loadCurrent() {
    setBaseVersion(version)
    setDraftName(name)
    setDraftEndpoint(endpoint ?? '')
    setAttempt(undefined)
    setError('')
  }

  async function save() {
    if (inFlight.current || !canSave) return
    const submitted = { name: draftName.trim(), endpoint: draftEndpoint.trim() || null }
    inFlight.current = true
    setPending(true)
    setAttempt(undefined)
    setError('')
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      const result = await api<DetailsResult>(`${path}/details`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
        signal: deadline,
        body: JSON.stringify({ ...submitted, version: baseVersion }),
      })
      onSaved(result)
      onClose()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized()
      else if (deadline.aborted || uncertainSubmission(cause)) setAttempt({ ...submitted, recheckAfter: performance.now() })
      else setError(cause instanceof Error ? cause.message : '无法保存服务信息')
    } finally {
      inFlight.current = false
      setPending(false)
      refreshConsole()
    }
  }

  return <Modal title="编辑服务信息" onClose={close}>
    {checked ? <div className="stack">
      <Notice>已从所属节点确认保存结果。</Notice>
      <div className="modal-actions"><button type="button" className="btn btn-primary" onClick={close}>完成</button></div>
    </div> : <form onSubmit={(event) => { event.preventDefault(); void save() }}>
      <div className="form-grid">
        <label className="field-label">显示名称<input className="input" required maxLength={80} value={draftName}
          disabled={pending} onChange={(event) => setDraftName(event.target.value)} /></label>
        <label className="field-label">登记端点<input className="input" maxLength={180} placeholder="可选，例如 127.0.0.1:8554"
          value={draftEndpoint} disabled={pending} onChange={(event) => setDraftEndpoint(event.target.value)} /></label>
      </div>
      {waiting ? <Notice tone="amber">{detail ? '正在从所属节点核对保存结果。草稿已保留。'
        : '暂时无法核对保存结果。草稿已保留。'}</Notice>
        : changed ? <Notice tone="amber">服务登记已更新。载入当前信息会替换此草稿。</Notice>
        : attempt && <Notice tone="amber">当前记录仍是保存前的版本。可以核对后重试。</Notice>}
      {error && <p className="error" role="alert">{error}</p>}
      <div className="modal-actions">
        <button type="button" className="btn btn-secondary" disabled={pending} onClick={close}>取消</button>
        {changed && <button type="button" className="btn btn-secondary" disabled={busy || pending || waiting}
          onClick={loadCurrent}>载入当前信息</button>}
        <button type="submit" className="btn btn-primary" disabled={!canSave}>
          {pending ? '正在保存…' : '保存服务信息'}
        </button>
      </div>
    </form>}
  </Modal>
}

function UnregisterService({ path, serviceId, name, version, busy, session, onUnauthorized }: {
  path: string; serviceId: string; name: string; version: number; busy: boolean; session: Session; onUnauthorized: () => void
}) {
  const { services } = useConsole()
  const [confirmVersion, setConfirmVersion] = useState<number>()
  const [pending, setPending] = useState(false)
  const [recheckAfter, setRecheckAfter] = useState<number>()
  const [error, setError] = useState('')
  const inFlight = useRef(false)
  const fresh = recheckAfter !== undefined && !services.error && !!services.data && (services.requestedAt ?? -1) > recheckAfter
  const registered = fresh ? services.data?.find((service) => service.id === serviceId) : undefined
  const removed = fresh && !registered
  const waiting = recheckAfter !== undefined && !fresh
  const changed = confirmVersion !== version || (registered?.version !== undefined && confirmVersion !== registered.version)
  const canRemove = !busy && !pending && !waiting && !removed && !changed

  useEffect(() => {
    if (removed) location.hash = '#/services'
  }, [removed])

  function close() {
    if (!inFlight.current) setConfirmVersion(undefined)
  }

  async function remove() {
    if (inFlight.current || !canRemove) return
    inFlight.current = true
    setPending(true)
    setRecheckAfter(undefined)
    setError('')
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      await api<void>(`${path}?version=${version}`, {
        method: 'DELETE', signal: deadline, headers: { 'X-CSRF-Token': session.csrf_token },
      })
      setConfirmVersion(undefined)
      location.hash = '#/services'
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized()
      else if (deadline.aborted || uncertainSubmission(cause) || (cause instanceof ApiError && cause.status === 404)) {
        setRecheckAfter(performance.now())
      } else setError(cause instanceof Error ? cause.message : '无法取消登记')
    } finally {
      inFlight.current = false
      setPending(false)
      refreshConsole()
    }
  }

  return <Panel title="取消登记" action={<button type="button" className="btn btn-secondary" disabled={busy || pending || waiting || removed}
    onClick={() => { setError(''); setConfirmVersion(version) }}>取消登记</button>}>
    <p className="muted">将服务从面板目录移除，并撤销此登记的跨节点授权。</p>
    {confirmVersion !== undefined && <Modal title={`取消登记 ${name}？`} onClose={close}>
      <p>原服务会留在所属主机上，并继续保持当前运行状态。</p>
      {waiting ? <Notice tone="amber">{services.error ? '暂时无法核对本机服务目录，正在等待恢复。'
        : '正在从本机服务目录核对取消登记的结果。'}</Notice>
        : changed ? <Notice tone="amber">服务登记已更新，请重新打开确认窗口。</Notice>
        : fresh && registered && <Notice tone="amber">该服务仍在目录中。可以核对后重试。</Notice>}
      {error && <p className="error" role="alert">{error}</p>}
      <div className="modal-actions">
        <button type="button" className="btn btn-secondary" disabled={pending} onClick={close}>返回</button>
        <button type="button" className="btn btn-danger" disabled={!canRemove}
          onClick={() => void remove()}>{pending ? '正在取消登记…' : '确认取消登记'}</button>
      </div>
    </Modal>}
  </Panel>
}

function ServiceModeControl({ path, version, managed, runtime, busy, management, managementScope, onRecheckManagement,
  detail, requestedAt, unavailable, containerIssue, session, onUnauthorized, onChanged }: {
  path: string; version: number; managed: boolean; runtime?: Service['runtime']; busy: boolean; unavailable: boolean
  containerIssue?: string
  detail?: Detail; requestedAt?: number
  management: { data?: SystemServiceManagement; error: string }
  managementScope: string; onRecheckManagement: () => void
  session: Session; onUnauthorized: () => void; onChanged: (result: ModeResult) => void
}) {
  const [pending, setPending] = useState(false)
  const [recheck, setRecheck] = useState<{ mode: Mode; version: number; after: number }>()
  const [error, setError] = useState('')
  const inFlight = useRef(false)
  const mode: Mode = managed ? 'observe' : 'manage'
  const label = managed ? '切回观察模式' : '启用管理模式'
  const windows = runtime === 'windows-service'
  const reason = managementNotice(management, runtime)
  const controlRights = windows && !management.error && management.data?.ready === false
    ? management.data.control_rights : undefined
  const waiting = !!recheck && (!detail || (requestedAt ?? -1) <= recheck.after)
  const confirmed = recheck && !waiting && detail?.version === recheck.version + 1
    && (detail.actions.length > 0) === (recheck.mode === 'manage')
  const disabled = busy || pending || unavailable || waiting

  async function save() {
    if (inFlight.current || disabled) return
    inFlight.current = true
    setPending(true)
    setError('')
    setRecheck(undefined)
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      const result = await api<ModeResult>(`${path}/mode`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
        signal: deadline,
        body: JSON.stringify({ mode, version }),
      })
      onChanged(result)
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized()
      else if (deadline.aborted || uncertainSubmission(cause)) setRecheck({ mode, version, after: performance.now() })
      else setError(cause instanceof Error ? cause.message : '无法切换服务模式')
    } finally {
      inFlight.current = false
      setPending(false)
      refreshConsole()
    }
  }

  return <Panel title="管理模式" action={<button type="button" className="btn btn-secondary" disabled={disabled}
    onClick={() => void save()}>{pending ? '正在切换…' : label}</button>}>
    <p className="muted">切换模式只更新面板的管理设置，当前服务会继续运行。</p>
    {containerIssue && <Notice tone="amber">{containerIssue}</Notice>}
    {reason && runtime && <Notice tone="amber">{reason}</Notice>}
    {controlRights && <dl className="facts">
      {(['start', 'stop'] as const).map(action => <div key={action}>
        <dt>{actions[action]}权限</dt><dd>{controlRights[action] === true ? '已确认' : controlRights[action] === false ? '被拒绝' : '未能确认'}</dd>
      </div>)}
    </dl>}
    {runtime && !reason && <p role="status" className="muted">{!management.data?.ready ? '正在核对系统服务的管理条件…'
      : windows ? 'Spearmint 运行账号具备查询、启动和停止权限。'
      : '启停和重启需要主机管理员为此单元配置 sudo 委派。'}</p>}
    {runtime && <div><button type="button" className="btn btn-secondary btn-small"
      disabled={!management.data && !management.error} onClick={onRecheckManagement}>重新核对管理条件</button></div>}
    {runtime === 'systemd-system' && !reason && management.data?.ready &&
      <SystemdDelegationCheck key={managementScope} path={path} onUnauthorized={onUnauthorized} />}
    {recheck && <Notice tone={confirmed ? '' : 'amber'}><span role="status">
      {waiting ? '正在从所属节点核对模式切换结果。' : confirmed ? `已确认${recheck.mode === 'manage' ? '启用管理模式' : '切回观察模式'}。`
        : '已重新读取服务模式，请核对当前状态。'}
    </span></Notice>}
    {error && <p className="error" role="alert">{error}</p>}
  </Panel>
}

function SystemdDelegationCheck({ path, onUnauthorized }: { path: string; onUnauthorized: () => void }) {
  const [sample, setSample] = useState<{ result: SystemdDelegation; checkedAt: number }>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => request.current?.abort(), [])

  async function check() {
    if (request.current) return
    const controller = new AbortController()
    request.current = controller
    setPending(true)
    setSample(undefined)
    setError('')
    try {
      const result = await api<SystemdDelegation>(`${path}/systemd-management?check_delegation=true`, {
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(READ_TIMEOUT_MS)]),
      })
      if (!controller.signal.aborted) setSample({ result, checkedAt: Date.now() / 1000 })
    } catch (cause) {
      if (controller.signal.aborted) return
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized()
      else setError(cause instanceof Error ? cause.message : '无法核对 sudo 委派。')
    } finally {
      request.current = null
      if (!controller.signal.aborted) setPending(false)
    }
  }

  const result = sample?.result
  return <div className="stack">
    <div><button type="button" className="btn btn-secondary btn-small" disabled={pending}
      onClick={() => void check()}>{pending ? '正在核对 sudo 委派…' : '核对 sudo 委派'}</button></div>
    {error && <p className="error" role="alert">{error}</p>}
    {result?.ready === false && <Notice tone="amber">{managementNotice({ data: result, error: '' }, 'systemd-system')}</Notice>}
    {sample && result?.ready && <div role="status">
      <dl className="facts">
        {(Object.keys(actions) as Action[]).map((action) => <div key={action}>
          <dt>{actions[action]}</dt><dd>{result.listed_actions[action] ? 'sudo 已列出' : '未能确认'}</dd>
        </div>)}
        <div><dt>读取日志</dt><dd>{result.listed_logs ? 'sudo 已列出' : '未能确认'}</dd></div>
      </dl>
      <p className="muted">上次核对 · {timestamp(sample.checkedAt)}。实际操作仍由主机校验，包括是否需要密码。</p>
    </div>}
  </div>
}

function accessSummary(peer: PeerAccess, service: ServiceAccessView, now: number) {
  if (!peer.active) return '节点当前未获准访问'
  if (!peer.directory) return '未向此节点导出服务目录'
  if (service.independent_approval) return '需要独立审批'
  if (service.available_actions?.length === 0) return '服务处于观察模式'
  if (peer.account_grant_expires_at != null && peer.account_grant_expires_at <= now) return '操作授权已过期'
  if (peer.actions.length) return peer.actions.map((action) => actions[action]).join('、')
  return '无操作授权'
}

function matchesAccountGrant(grant: AccessSubmission['grant'], previous: PeerAccess, latest: PeerAccess, sampledAt?: number) {
  const expiry = latest.account_grant_expires_at
  const configured = latest.configured_account_actions ?? latest.actions
  const previousActions = previous.configured_account_actions ?? previous.actions
  if (grant.mode === 'revoke') return expiry === null && configured.length === 0
  if (grant.mode === 'keep') {
    return expiry === previous.account_grant_expires_at && configured.length === previousActions.length
      && configured.every((action) => previousActions.includes(action))
  }
  if (sampledAt === undefined || grant.sampledAt === undefined || expiry == null || expiry <= sampledAt) return false
  const issuedAt = expiry - grant.hours * 3600
  return issuedAt >= grant.sampledAt && issuedAt <= sampledAt
    && configured.length === grant.actions.length && grant.actions.every((action) => configured.includes(action))
}

function ServiceAccess({ path, serviceId, sourceNodeId, serviceVersion, managementIssue, session, onUnauthorized }: {
  path: string; serviceId: string; sourceNodeId?: string; serviceVersion?: number
  managementIssue: boolean; session: Session; onUnauthorized: () => void
}) {
  const { nodes, local, memberPanelOrigins } = useConsole()
  const { data: snapshot, error, requestedAt } = usePoll<ServiceAccessView>(`${path}/access`, onUnauthorized, 3000,
    undefined, `${serviceVersion ?? ''}`)
  const data = snapshot?.service_version === undefined || snapshot.service_version === serviceVersion ? snapshot : undefined
  const [editing, setEditing] = useState<{ generation: number; peer: PeerAccess; available: Action[]; logsAvailable: boolean }>()
  const [savedSourceRevision, setSavedSourceRevision] = useState<string>()
  const names = new Map(nodes.map((node) => [node.id, node.name]))
  const selected = data?.peers.find((peer) => peer.node_id === sourceNodeId)
  const latest = data?.peers.find((peer) => peer.node_id === editing?.peer.node_id)
  const sourceName = selected && (names.get(selected.node_id) || selected.host)
  const now = data?.sampled_at ?? Date.now() / 1000
  const ownerId = local.error ? undefined : local.data?.node_id
  const sourceOrigin = sourceNodeId ? memberPanelOrigins.get(sourceNodeId) : undefined
  const returnHref = ownerId && sourceNodeId !== ownerId && sourceOrigin && sourceOrigin !== location.origin
    ? `${sourceOrigin}/${remoteServiceSyncHref(ownerId, serviceId)}` : undefined

  function edit(peer: PeerAccess) {
    if (!data || error || !peer.revision) return
    if (peer.node_id === sourceNodeId) setSavedSourceRevision(undefined)
    setEditing((previous) => ({ generation: (previous?.generation ?? 0) + 1, peer,
      available: data.independent_approval ? [] : data.available_actions || [], logsAvailable: data.logs_available !== false }))
  }

  return <Panel title="跨节点授权">
    {error ? <Notice tone="amber">暂时无法读取跨节点授权。{error}</Notice>
      : !data ? <Loading label="正在读取跨节点授权…" />
      : <>
        {sourceNodeId && <div className="stack">
          {selected ? <Notice title={`来自 ${sourceName} 的访问`}><span role="status">
            {selected.active && savedSourceRevision && selected.revision === savedSourceRevision && '来源权限已保存。'}当前授权：{accessSummary(selected, data, now)}。
          </span></Notice>
            : <Notice tone="amber" title="当前服务节点未登记此来源">请先核对两台节点的 Mesh 互联配置。</Notice>}
          {((data.available_actions && selected?.revision) || returnHref) && <div className="button-row">
              {data.available_actions && selected?.revision &&
                <button type="button" className="btn btn-secondary btn-small" onClick={() => edit(selected)}>编辑来源权限</button>}
              {returnHref && <a className="btn btn-secondary btn-small" href={returnHref}>返回来源面板查看服务<Icon name="arrow-up-right" size={14} /></a>}
            </div>}
        </div>}
        {data.independent_approval && <Notice>此服务的跨节点操作需要独立批准。<a className="text-link" href="#/operations/approvals">进入操作与审批</a></Notice>}
        {managementIssue && !!data.available_actions?.length && !data.independent_approval &&
          <Notice tone="amber">当前主机暂时无法执行已授权的操作。请查看上方的管理模式检查结果。</Notice>}
        {data.peers.length ? <div className="table-wrap"><table className="data-table">
          <thead><tr><th scope="col">来源节点</th><th scope="col">读取权限</th><th scope="col">操作授权</th>{data.available_actions && <th scope="col">设置</th>}</tr></thead>
          <tbody>{data.peers.map((peer) => <tr key={peer.node_id}>
            <td><strong>{names.get(peer.node_id) || peer.host}</strong> <CopyValue value={peer.node_id} short /></td>
            <td>{(Object.keys(accessPermissions) as AccessPermission[]).filter((key) => peer[key]).map((key) => accessPermissions[key]).join('、') || '未导出'}</td>
            <td>{accessSummary(peer, data, now)}
              {!!peer.configured_account_actions?.length && !peer.actions.length &&
                <div className="muted">原授权动作 · {peer.configured_account_actions.map((action) => actions[action]).join('、')}</div>}
              {peer.actions.length > 0 && peer.account_grant_expires_at != null && peer.account_grant_expires_at > now &&
                <div className="muted">有效至 {timestamp(peer.account_grant_expires_at)}</div>}</td>
            {data.available_actions && <td>{peer.revision && <button type="button" className="btn btn-secondary btn-small"
              aria-label={`编辑 ${names.get(peer.node_id) || peer.host} 的权限`}
              onClick={() => edit(peer)}>编辑</button>}</td>}
          </tr>)}</tbody>
        </table></div> : <EmptyState icon="network" title="还没有配置远程节点" />}
      </>}
    {editing && <ServiceAccessEditor key={editing.generation} path={path} name={names.get(editing.peer.node_id) || editing.peer.host}
      peer={editing.peer} available={editing.available} logsAvailable={editing.logsAvailable}
      latest={error ? undefined : latest} requestedAt={requestedAt} sampledAt={data?.sampled_at} unavailable={!!error || !data}
      onReload={latest?.revision && !error ? () => edit(latest) : undefined}
      session={session} onUnauthorized={onUnauthorized} onClose={() => setEditing(undefined)} onSaved={revision => {
        if (editing.peer.node_id === sourceNodeId) setSavedSourceRevision(revision)
        setEditing(undefined)
      }} />}
  </Panel>
}

function ServiceAccessEditor({ path, name, peer, available, logsAvailable, latest, requestedAt, sampledAt, unavailable, onReload,
  session, onUnauthorized, onClose, onSaved }: RegistrationProps & {
  path: string; name: string; peer: PeerAccess; available: Action[]; logsAvailable: boolean; onSaved: (revision: string) => void
  latest?: PeerAccess; requestedAt?: number; sampledAt?: number; unavailable: boolean; onReload?: () => void
}) {
  const [permissions, setPermissions] = useState({ directory: peer.directory, status: peer.status, logs: peer.logs })
  const [grantMode, setGrantMode] = useState<'keep' | 'replace' | 'revoke'>('keep')
  const [selected, setSelected] = useState<Action[]>(() =>
    (peer.configured_account_actions ?? peer.actions).filter((action) => available.includes(action)))
  const [hours, setHours] = useState('24')
  const [pending, setPending] = useState(false)
  const [conflict, setConflict] = useState(false)
  const [recheckAfter, setRecheckAfter] = useState<number>()
  const [submitted, setSubmitted] = useState<AccessSubmission>()
  const [acknowledged, setAcknowledged] = useState(false)
  const [error, setError] = useState('')
  const inFlight = useRef(false)
  const replace = grantMode === 'replace' && permissions.directory
  const duration = Number(hours)
  const validDuration = Number.isInteger(duration) && duration >= 1 && duration <= 2160
  const changed = (Object.keys(permissions) as AccessPermission[]).some((key) => permissions[key] !== peer[key]) || grantMode === 'revoke' || replace
  const waiting = recheckAfter !== undefined && (requestedAt ?? -1) <= recheckAfter
  const outdated = !unavailable && (!latest || latest.revision !== peer.revision || latest.active !== peer.active)
  const confirmed = submitted && latest?.revision && !waiting && !unavailable && latest.active === peer.active
    && (latest.revision !== peer.revision || (acknowledged && submitted.grant.mode !== 'replace'))
    && (Object.keys(submitted.permissions) as AccessPermission[]).every((key) => latest[key] === submitted.permissions[key])
    && matchesAccountGrant(submitted.grant, peer, latest, sampledAt)
  const confirmedRevision = confirmed ? latest?.revision : undefined
  const canSave = changed && !pending && !acknowledged && !conflict && !outdated && !unavailable && !waiting
    && (!replace || selected.length > 0 && validDuration)
  const fieldsLocked = pending || waiting || acknowledged

  useEffect(() => {
    if (acknowledged && confirmedRevision) onSaved(confirmedRevision)
  }, [acknowledged, confirmedRevision, onSaved])

  async function save() {
    if (inFlight.current || !canSave) return
    inFlight.current = true
    setPending(true)
    setError('')
    setRecheckAfter(undefined)
    setSubmitted(undefined)
    setAcknowledged(false)
    const intent: AccessSubmission = {
      permissions,
      grant: replace ? { mode: 'replace', actions: selected, hours: duration, sampledAt }
        : { mode: grantMode === 'revoke' || permissions.directory !== peer.directory ? 'revoke' : 'keep' },
    }
    function verifyWrite() {
      setSubmitted(intent)
      setRecheckAfter(performance.now())
      refreshConsole()
    }
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      await api(`${path}/access/${encodeURIComponent(peer.node_id)}`, {
        method: 'PUT', signal: deadline, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
        body: JSON.stringify({ revision: peer.revision, ...permissions,
          actions: replace ? selected : grantMode === 'revoke' ? [] : null, hours: replace ? duration : null }),
      })
      setAcknowledged(true)
      verifyWrite()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) onUnauthorized()
      else if (cause instanceof ApiError && cause.code === 'CONFLICT') {
        setConflict(true)
        setRecheckAfter(performance.now())
        refreshConsole()
      } else if (deadline.aborted || uncertainSubmission(cause)) verifyWrite()
      else setError(cause instanceof Error ? cause.message : '保存权限失败')
    } finally {
      inFlight.current = false
      setPending(false)
    }
  }

  if (confirmedRevision && !acknowledged) {
    const finish = () => onSaved(confirmedRevision)
    return <Modal title={`编辑 ${name} 的权限`} onClose={finish}>
      <Notice>当前权限与提交内容一致。
        {submitted?.grant.mode === 'replace' && latest?.account_grant_expires_at != null &&
          <>操作授权有效至 {timestamp(latest.account_grant_expires_at)}。</>}
      </Notice>
      <div className="modal-actions"><button type="button" className="btn btn-primary" onClick={finish}>完成</button></div>
    </Modal>
  }

  return <Modal title={`编辑 ${name} 的权限`} onClose={() => { if (!inFlight.current) onClose() }}>
    {(unavailable || waiting || outdated || conflict || recheckAfter !== undefined) && <Notice tone="amber">
      {unavailable ? '暂时无法读取当前权限。草稿已保留。'
        : waiting ? '正在重新读取权限，请稍候。'
        : !latest?.revision ? '该来源的最新权限不可用。草稿已保留。'
        : outdated || conflict ? '当前权限或节点状态已有变化。载入最新权限会替换此草稿。'
        : acknowledged && submitted?.grant.mode === 'replace' && (sampledAt === undefined || submitted.grant.sampledAt === undefined)
          ? '所属节点已接受保存。当前面板版本缺少采样时间，无法核对授权有效期。可载入最新权限查看。'
        : acknowledged ? '所属节点已接受保存，最新权限仍待核对。'
        : '上次保存结果待确认。已重新读取权限，可核对后重试。'}
    </Notice>}
    {!peer.active && <Notice>该节点当前未获准访问。你可以撤销已有权限。</Notice>}
    <fieldset className="service-access-fields" disabled={fieldsLocked}><legend>读取权限</legend><div className="button-row">
      {(Object.keys(permissions) as AccessPermission[]).filter((key) => key !== 'logs' || logsAvailable).map((key) => <label className="inline-checkbox" key={key}>
        <input type="checkbox" checked={permissions[key]} disabled={!peer.active && !permissions[key]}
          onChange={(event) => setPermissions({ ...permissions, [key]: event.target.checked })} />{accessPermissions[key]}
      </label>)}
    </div></fieldset>
    {(available.length > 0 || peer.account_grant_expires_at != null) && <fieldset className="service-access-fields" disabled={fieldsLocked}><legend>账号操作授权</legend>
      <select className="input" aria-label="账号操作授权" value={grantMode} onChange={(event) => {
        const mode = event.target.value
        if (mode === 'keep' || mode === 'replace' || mode === 'revoke') setGrantMode(mode)
      }}>
        <option value="keep">保持现有授权</option>
        <option value="replace" disabled={!peer.active || !permissions.directory || !available.length}>设置授权</option>
        <option value="revoke" disabled={peer.account_grant_expires_at == null}>撤销授权</option>
      </select>
      {replace && <><div className="button-row">{available.map((action) => <label className="inline-checkbox" key={action}>
        <input type="checkbox" checked={selected.includes(action)} onChange={(event) => setSelected(event.target.checked
          ? [...selected, action] : selected.filter((item) => item !== action))} />{actions[action]}
      </label>)}</div><label className="field-label">有效期（小时）<input className="input" type="number" min={1} max={2160}
        value={hours} onChange={(event) => setHours(event.target.value)} /></label></>}
      {peer.directory && !permissions.directory && <p className="muted">取消服务目录会同时撤销该节点的账号操作授权。</p>}
    </fieldset>}
    {error && <p className="error" role="alert">{error}</p>}
    <div className="modal-actions"><button type="button" className="btn btn-secondary" disabled={pending} onClick={onClose}>取消</button>
      {(outdated || conflict || acknowledged) && onReload && <button type="button" className="btn btn-secondary" disabled={pending || waiting}
        onClick={onReload}>载入最新权限</button>}
      <button type="button" className="btn btn-primary" disabled={!canSave}
        onClick={() => void save()}>{pending ? '正在保存…' : '保存权限'}</button></div>
  </Modal>
}

export function OperationList({ operations }: { operations: Operation[] }) {
  return operations.length ? <div className="activity-list">{operations.map(operation => {
    const message = localOperationMessage(operation)
    return <div className="activity-row" key={operation.id}>
      <span className={`activity-ico ${operation.status === 'failed' && operation.reason !== 'RESTART_BEFORE_DISPATCH' ? 'warning' : ''}`}>
        <Icon name={operation.status === 'succeeded' ? 'check-circle' : 'activity'} size={18} /></span>
      <div className="activity-content">
        <div className="activity-title"><strong>{actions[operation.action]}服务</strong><LocalOperationBadge operation={operation} /></div>
        <small>{timestamp(operation.updated_at)}</small>
        {message && <p className="operation-message">{message}</p>}
        <details><summary>操作标识</summary><CopyValue value={operation.id} /></details>
      </div>
    </div>
  })}</div>
    : <EmptyState icon="clock" title="还没有操作记录">从这里发起的操作会在执行后留下记录。</EmptyState>
}
