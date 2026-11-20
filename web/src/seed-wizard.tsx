import { useEffect, useEffectEvent, useRef, useState, type FormEvent } from 'react'
import { ApiError, api } from './api'
import { useConsole } from './console-data'
import { NetworkMap } from './network-map'
import { Icon, Loading, Notice, Panel } from './ui'
import './seed-wizard.css'

type Job = { source: string; id: string }
type Directory = { parent: string | null; writable: boolean; free: number | null; truncated: boolean;
  items: Array<{ name: string; path: string }> }
type SeedView = { status: string; fingerprint?: string; platform?: string; package?: { name: string; size: number; commit: string; host_services?: number };
  path?: string; directory?: Directory; install?: string; state?: string; origin?: string; node_id?: string; error?: string
  failed_stage?: string; failure_detail?: string; failure_phase?: string; failure_exit?: number; host_services_supported?: boolean }

const progress: Record<string, string> = {
  'host-check': '正在核对 SSH 主机身份…', 'ssh-login': '正在测试 SSH 登录并读取系统信息…',
  package: '发起节点正在自动获取并校验部署包…', reading: '正在读取当前目录…', installing: '发起节点正在传包、安装并启动服务…',
  admitting: '面板已启动，正在通过 Grove 多数成员完成入网…',
}
const stages: Record<string, string> = {
  'host-check': '主机身份核对', 'ssh-login': 'SSH 登录与系统识别', package: '验包与部署入口探测',
  reading: '目录读取', installing: '安装与启动', admitting: 'Grove 入网',
}
const problems: Record<string, string> = {
  SEED_SSH: '无法完成 SSH 连接。请核对地址、端口及发起节点的网络可达性。',
  SEED_SSH_AUTH: '目标未接受 SSH 登录。请核对账号与凭据。', SEED_HOST_KEY: 'SSH 主机指纹不一致，请核对目标身份。',
  SEED_SYSTEM: '目标系统、架构或 SSH 账号不满足原生安装条件。', SEED_PACKAGE: '发起节点暂无对应系统和架构的可校验部署包。',
  SEED_PACKAGE_RELEASE: '暂时无法获取与目标系统和架构兼容的签名发布。',
  SEED_PACKAGE_FETCH: '发起节点暂时无法从 GitHub 或 Grove 成员取得并校验部署包，请稍后重试。',
  SEED_DIRECTORY: '暂时无法读取该目录。', SEED_INSTALL: '安装器未确认服务启动。', SEED_QUORUM: '当前 Grove 多数成员未能完成入网。',
  SEED_WINDOWS_STAGING: '目标 Windows 无法通过 SFTP 接收或解压部署包。请核对 SFTP 子系统和临时空间。',
  SEED_WINDOWS_PACKAGE: '目标 Windows 无法运行原生播种入口。请核对部署包版本和目标的应用执行策略。',
  SEED_WINDOWS_TASK_PERMISSION: '目标 SSH 账号无法注册 Windows 开机任务。请使用有权限的部署账号。',
  SEED_WINDOWS_TASK_CONFLICT: '目标已存在同名计划任务，请检查现有 Spearmint 安装。',
  SEED_WINDOWS_PORT: '目标 Windows 的面板端口已占用。',
  SEED_WINDOWS_STARTUP: 'Windows 计划任务已注册，面板未通过本地启动检查。',
  SEED_SERVICE: 'SSH 账号无法启用 Linux 用户服务的开机运行。',
  SEED_HOST_AUTHORIZATION: '未能启用主机服务管理。请核对目标账号的 sudo 权限或管理员密码，也可关闭该选项仅安装普通面板。',
  SEED_HOST_PACKAGE: '当前部署包尚不支持主机服务管理。请使用包含该能力的新版发布，或关闭此选项仅安装普通面板。',
  SEED_GROVE_STATE: '面板正在等待 Grove 成员目录或签发状态同步。',
  SEED_SOURCE_OFFLINE: '当前面板通过 Mesh 联系不上所选发起节点。',
  DENIED: '请用当前 Grove 的管理员账号登录。发起节点也应是 Grove 的有效成员。',
  CONFLICT: 'Grove 管理员权限已变化，请刷新后重新开始播种。',
  UNSUPPORTED_METHOD: '所选发起节点版本过旧，请先升级它。',
  NOT_FOUND: '播种任务已过期、发起节点未配对或已重启。',
}
const storageKey = 'spearmint-seed-wizard'
const failurePhases: Record<string, string> = {
  target: '目标系统预检', transfer: '部署包传输', verify: '验包与运行库检查', install: '安装器执行与启动检查',
  systemd: 'systemd 用户服务预检', staging: '临时目录检查', 'staging-space': '临时空间检查',
  timeout: '等待安装回执超时', receipt: '启动回执检查', ssh: 'SSH 执行',
}

function savedJob(sourceId?: string): Job | undefined {
  try {
    const saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null')
    if (/^spm1-[a-f0-9]{64}$/.test(saved?.source) && /^[a-f0-9]{32}$/.test(saved?.id) && (!sourceId || saved.source === sourceId)) return saved
  } catch { /* Persistence is optional in restricted browsers. */ }
}

export function savedSeedSource() { return savedJob()?.source }

export function SeedWizard({ follow, sourceId }: { follow: (origin: string, nodeId?: string) => void; sourceId?: string }) {
  const { session, onUnauthorized, listedNodes, grove } = useConsole()
  const [job, setJob] = useState(() => savedJob(sourceId))
  const [source, setSource] = useState(job?.source ?? sourceId)
  const [view, setView] = useState<SeedView>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [key, setKey] = useState(false)
  const [hostServices, setHostServices] = useState(true)
  const [hostPassword, setHostPassword] = useState('')
  const polling = useRef(false)

  async function request(target: Job, action: string, body: object = {}) {
    return api<SeedView>(`/grove/seed-wizard/${target.source}/${target.id}/${action}`, {
      method: 'POST', headers: { 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    })
  }

  function report(failure: unknown) {
    if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
    else setError(failure instanceof ApiError && failure.code && problems[failure.code]
      || '暂时无法取得发起节点的回执，请稍后重试。')
  }

  const poll = useEffectEvent(async (target: Job) => {
    if (polling.current) return
    polling.current = true
    try { setView(await request(target, 'status')); setError('') } catch (failure) { report(failure) }
    finally { polling.current = false }
  })
  useEffect(() => {
    if (!job || busy || view && !progress[view.status] && !error) return
    const timer = window.setInterval(() => void poll(job), 1800)
    return () => window.clearInterval(timer)
  }, [job, view, busy, error])

  async function send(target: Job, action: string, body: object) {
    setBusy(true)
    setError('')
    try { setView(await request(target, action, body)) } catch (failure) { report(failure) }
    finally { setBusy(false) }
  }

  function remember(target?: Job) {
    setJob(target)
    try {
      if (target) sessionStorage.setItem(storageKey, JSON.stringify(target))
      else sessionStorage.removeItem(storageKey)
    } catch { /* The job still runs on the executing node. */ }
  }

  function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!source || busy) return
    const values = new FormData(event.currentTarget)
    const target = { source, id: crypto.randomUUID().replaceAll('-', '') }
    const connection = { host: String(values.get('host')).trim(), port: Number(values.get('port')), username: String(values.get('user')).trim(),
      secret: String(values.get('secret')), key, fingerprint: String(values.get('fingerprint')).trim() }
    const secret = event.currentTarget.elements.namedItem('secret') as HTMLInputElement | HTMLTextAreaElement
    secret.value = ''
    remember(target)
    void send(target, 'start', { connection })
  }

  const directory = view?.directory
  const browsing = view?.status === 'choose' || view?.status === 'reading' && !!directory
  const windowsPolicyBlocked = view?.platform === 'windows-amd64' && view.error === 'SEED_WINDOWS_PACKAGE'
    && view.failure_detail === 'version:exit=0x000011C7'
  const sourceName = listedNodes.find(node => node.id === source)?.name
  function browse(path: string) { if (job) void send(job, 'directory', { path }) }

  return <Panel title="SSH 播种" className="seed-wizard">
    <div className="stack">
      {!job && !sourceId && <><h3>选择发起节点</h3><NetworkMap target={source} onPick={setSource} /></>}
      {source && <p className="muted">发起节点 · {sourceName || source}</p>}
      {!job && source && <form className="stack" onSubmit={start}>
        <div className="form-grid">
          <label className="field-label">SSH 地址<input className="input" name="host" required maxLength={253} autoComplete="off" placeholder="192.168.1.20" /></label>
          <label className="field-label">端口<input className="input" name="port" required type="number" min="1" max="65535" defaultValue="22" /></label>
          <label className="field-label">用户名<input className="input" name="user" required maxLength={128} autoComplete="off" /></label>
          <label className="field-label">登录方式<select className="input" value={key ? 'key' : 'password'} onChange={event => setKey(event.target.value === 'key')}>
            <option value="password">密码</option><option value="key">SSH 私钥</option></select></label>
        </div>
        {key ? <label className="field-label">SSH 私钥<textarea className="input" name="secret" required maxLength={10500} rows={4} spellCheck={false} autoComplete="off" /></label>
          : <label className="field-label">SSH 密码<input className="input" name="secret" required type="password" autoComplete="new-password" /></label>}
        <label className="field-label">SSH 主机指纹（可选）<input className="input" name="fingerprint" maxLength={60} placeholder="SHA256:…" autoComplete="off" /></label>
        <div><button className="btn btn-primary" disabled={!grove.data?.issuer_retired}>测试 SSH 连接</button></div>
        {!grove.data?.issuer_retired && <p className="muted">自动播种需要可共同批准新节点的 Grove 多数成员。</p>}
      </form>}
      {job && (!view || progress[view.status]) && <Loading label={view ? progress[view.status] : '正在读取播种状态…'} />}
      {job && view?.status === 'verify-host' && <Notice tone="amber" title="核对 SSH 主机指纹">
        <p>请核对这是目标设备的指纹，再发送 SSH 登录凭据。</p><p><code>{view.fingerprint}</code></p>
        <button className="btn btn-secondary" disabled={busy} onClick={() => void send(job, 'verify', { fingerprint: view.fingerprint })}>确认指纹并测试登录</button>
      </Notice>}
      {view?.platform && <dl className="facts"><div><dt>目标系统</dt><dd>{view.platform}</dd></div>
        {view.package && <div><dt>部署包</dt><dd>{view.package.name}</dd></div>}</dl>}
      {job && browsing && directory && <div className="seed-directory stack-small">
        <div className="button-row"><button type="button" className="btn btn-secondary" disabled={busy || view.status === 'reading' || directory.parent == null}
          onClick={() => browse(directory.parent!)}><Icon name="arrow-left" size={15} />上一级</button>
          <code className="seed-directory-path">{view.path || '磁盘列表'}</code></div>
        <div className="seed-directory-list" aria-label="当前层级的目录">
          {directory.items.map(item => <button key={item.path} className="btn btn-secondary" type="button" disabled={busy || view.status === 'reading'}
            onClick={() => browse(item.path)}><Icon name="folder" size={16} />{item.name}<Icon name="arrow-right" size={14} /></button>)}
          {!directory.items.length && <p className="muted">此处没有可进入的子目录。</p>}
        </div>
        {directory.truncated && <p className="muted">此层显示前 100 个子目录。</p>}
        {view.path && <dl className="facts"><div><dt>安装位置</dt><dd>{view.install}</dd></div><div><dt>数据位置</dt><dd>{view.state}</dd></div>
          <div><dt>可用空间</dt><dd>{directory.free == null ? '未知' : `${(directory.free / 1024 ** 3).toFixed(1)} GiB`}</dd></div></dl>}
        {view.path && !directory.writable && <p className="error">当前目录不可写或可用空间不足。</p>}
        {view.platform?.startsWith('linux') && <div className="stack">
          <label className="checkbox-row"><input type="checkbox" checked={hostServices} onChange={event => { setHostServices(event.target.checked); if (!event.target.checked) setHostPassword('') }} />启用节点系统服务管理</label>
          <p className="muted tiny">安装一次主机管理服务，之后可直接接管系统服务。需要目标账号具备 sudo 权限，密码登录时默认使用本次 SSH 密码，仅在安装期间使用。</p>
          {hostServices && !view.host_services_supported && <Notice tone="amber">请先升级发起节点以自动完成主机授权；关闭此选项仍可播种普通面板。</Notice>}
          {hostServices && view.host_services_supported && view.package?.host_services !== 1 && <Notice tone="amber">当前部署包尚不包含主机服务管理，需要包含此能力的新版发布。关闭此选项仍可播种普通面板。</Notice>}
          {hostServices && view.host_services_supported && <details><summary>使用不同的主机管理员密码</summary><label className="field-label">sudo 密码<input type="password" className="input" autoComplete="new-password" value={hostPassword} onChange={event => setHostPassword(event.target.value)} /></label></details>}
        </div>}
        <div><button className="btn btn-primary" type="button" disabled={busy || view.status !== 'choose' || !directory.writable || !!(view.platform?.startsWith('linux') && hostServices && (!view.host_services_supported || view.package?.host_services !== 1))}
          onClick={() => { const options = view.platform?.startsWith('linux') ? { host_services: hostServices, host_password: hostPassword } : {}; setHostPassword(''); void send(job, 'install', { path: view.path, ...options }) }}>安装到此位置</button></div>
      </div>}
      {view?.error && <div className="error" role="alert">
        <p>{problems[view.error] || '播种操作尚未完成。'}{view.node_id && ` 节点 ID · ${view.node_id}`}</p>
        <small>{[view.failed_stage && stages[view.failed_stage], view.error,
          view.failure_phase && (failurePhases[view.failure_phase] || view.failure_phase),
          view.failure_exit != null && `退出码 ${view.failure_exit}`].filter(Boolean).join(' · ')}</small>
        {view.failure_detail && <pre className="seed-failure-detail">{view.failure_detail}</pre>}
      </div>}
      {windowsPolicyBlocked && <Notice tone="amber" title="检查目标机的智能应用控制">
        若目标机的代码完整性日志确认是智能应用控制拦截，请在目标机打开「Windows 安全中心 → 应用和浏览器控制 → 智能应用控制设置」，选择「关」。
        关闭会对整台设备生效。完成后点击「开始新播种」。
      </Notice>}
      {error && <p className="error" role="alert">{error}</p>}
      {view?.status === 'joined' && <Notice title="Spearmint 已启动并加入 Grove">
        {view.origin && <button className="btn btn-secondary" onClick={() => follow(view.origin!, view.node_id)}>查看 Mesh 接入状态</button>}
      </Notice>}
      {job && !busy && (!view || !['installing', 'admitting'].includes(view.status)) &&
        <div><button className="btn btn-secondary" onClick={() => { remember(); setSource(sourceId ?? source); setError(''); setView(undefined) }}>开始新播种</button></div>}
    </div>
  </Panel>
}
