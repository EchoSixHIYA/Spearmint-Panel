import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, timestamp } from './api'
import { refreshConsole, useConsole } from './console-data'
import { localServiceHref, remoteServiceSyncHref } from './grove-navigation'
import { useUnsavedChanges } from './navigation-guard'
import { Badge, bytes, Icon, Loading, Notice, Tabs } from './ui'
import { returnRoute, withReturn } from './workspace-api'
import './service-deployment.css'
import { defaultOptions, DeploymentSettings, type DeploymentOptions } from './deployment-options'
import { digestBytes, digestFile } from './deployment-transfer'

type Job = { id: string; service_id?: string; kind: string; name: string; command: string; filename: string;
  status: string; phase: string; size: number; offset: number; error?: string; log?: string; rolled_back?: boolean; updated_at: number;
  received?: number[]; received_bytes?: number; upload_chunk?: number; expected_sha256?: string; readiness_result?: { status: string; mode: string; detail?: string } }
type Service = { id: string; name: string; driver: string; version?: number; command?: string;
  deployment?: { source?: string; kind?: string; directory?: string } }
export function deployedBySpearmint(service: Service) {
  return service.deployment?.source === 'managed' || ['package', 'docker'].includes(service.deployment?.kind || '')
}
type History = { jobs: Job[]; can_update: boolean; can_rollback: boolean; options: DeploymentOptions }
const ended = (job?: Job) => !!job && ['succeeded', 'failed', 'cancelled'].includes(job.status)
const storageKey = (target: string, service?: Service) => `spearmint-deploy/${target}/${service?.id || 'new'}`
function saved(key: string): string | undefined { try { const value = localStorage.getItem(key); return value && /^[a-f0-9]{32}$/.test(value) ? value : undefined } catch { return undefined } }

export function ServiceDeployment({ target, service, onChanged, onOpen }: { target: string; service?: Service; onChanged?: () => void; onOpen?: () => void }) {
  const { session, onUnauthorized } = useConsole()
  const key = storageKey(target, service) + '/' + session.username
  const [jobId, setJobId] = useState(() => saved(key))
  const [job, setJob] = useState<Job>()
  const [kind, setKind] = useState(service?.driver === 'docker' ? 'docker' : 'package')
  const [name, setName] = useState(service?.name || '')
  const [command, setCommand] = useState(service?.command || '')
  const [file, setFile] = useState<File>()
  const [directory, setDirectory] = useState('')
  const [history, setHistory] = useState<History>()
  const [capable, setCapable] = useState<boolean>()
  const [settings, setSettings] = useState<DeploymentOptions>(defaultOptions)
  const [hashProgress, setHashProgress] = useState<number>()
  const [recoverable, setRecoverable] = useState<Job[]>([])
  const [error, setError] = useState(''), [busy, setBusy] = useState(false), [dirty, setDirty] = useState(false)
  const [revision, setRevision] = useState(0)
  const active = useRef(true), working = useRef(false)
  useEffect(() => { active.current = true; return () => { active.current = false } }, [])
  useUnsavedChanges(dirty || busy)
  async function call<T>(action: string, body: object): Promise<T> {
    return api<T>(`/peers/${encodeURIComponent(target)}/service-deployment/${action}`, {
      method: 'POST', headers: { 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body), signal: AbortSignal.timeout(30_000),
    })
  }
  function fail(failure: unknown) {
    if (!active.current) return
    if (failure instanceof ApiError && failure.status === 401) { onUnauthorized(); return }
    if (failure instanceof ApiError && failure.code === 'UNSUPPORTED_METHOD') {
      setError('目标节点尚不支持服务部署，请先通过 Grove 群组更新升级该节点。'); return
    }
    setError(failure instanceof ApiError ? failure.message : '暂时无法获取部署回执。任务已保存，可查询后继续。')
  }
  function remember(value?: string, updateState = true) {
    try { if (value) localStorage.setItem(key, value); else localStorage.removeItem(key) } catch { /* Optional persistence. */ }
    if (active.current && updateState) setJobId(value)
  }
  function changed() { refreshConsole(); onChanged?.(); setRevision(value => value + 1) }
  useEffect(() => {
    let live = true
    void call<{ deployment: number; code_ownership?: number }>('capabilities', {}).then(result => { if (live) { setCapable(result.deployment >= 2 && result.code_ownership === 1); if (result.deployment < 2 || result.code_ownership !== 1) setError('请通过群组更新升级目标节点，以使用独立的一键部署和已有代码登记流程。') } }).catch(failure => { if (live) { setCapable(false); if (failure instanceof ApiError && failure.status === 404) setError('目标节点尚不支持服务部署，请先通过 Grove 群组更新升级该节点。'); else fail(failure) } })
    return () => { live = false }
  }, [target, session])
  useEffect(() => {
    if (!service || !capable) return
    let live = true
    void call<History>('history', { service_id: service.id }).then(result => { if (live) { setHistory(result); if (!dirty) setSettings(result.options) } }).catch(failure => { if (live) fail(failure) })
    return () => { live = false }
  }, [service?.id, capable, revision])
  useEffect(() => {
    if (!capable || jobId) return
    let live = true
    void call<{ jobs: Job[] }>('list', {}).then(result => { if (live) setRecoverable(result.jobs.filter(item => !ended(item) && (!service || item.service_id === service.id))) }).catch(fail)
    return () => { live = false }
  }, [capable, jobId, revision])
  useEffect(() => {
    if (!jobId || !capable) return
    let live = true, timer: number | undefined
    async function poll() {
      try {
        const next = await call<Job>('status', { job: jobId })
        if (!live) return
        setJob(next)
        if (ended(next)) { changed(); return }
      } catch (failure) { if (live) { if (failure instanceof ApiError && failure.code === 'NOT_FOUND') remember(); fail(failure) } }
      if (live) timer = window.setTimeout(() => void poll(), 1500)
    }
    void poll()
    return () => { live = false; clearTimeout(timer) }
  }, [jobId, capable, target])

  async function transfer(current: Job, input?: File, verified = false) {
    let next = current
    if (ended(next) || next.status === 'deploying') return
    if (next.size && (next.received_bytes ?? next.offset) < next.size) {
      if (!input || input.name !== next.filename || input.size !== next.size) throw new Error('请重新选择同一份服务包以继续上传。')
      if (!verified) {
        setHashProgress(0)
        const digest = await digestFile(input, setHashProgress, () => active.current)
        setHashProgress(undefined)
        if (digest !== next.expected_sha256) throw new Error('所选服务包与原任务不同，请选择同一份文件，或取消原任务重新部署。')
      }
      const chunk = next.upload_chunk || 262144
      const received = new Set(next.received || [])
      const parts = Array.from({ length: Math.ceil(next.size / chunk) }, (_, index) => index).filter(index => !received.has(index))
      let cursor = 0
      async function worker() {
        while (cursor < parts.length && active.current) {
          const index = parts[cursor++], offset = index * chunk
          const data = new Uint8Array(await input!.slice(offset, offset + chunk).arrayBuffer())
          for (let attempt = 0; ; attempt++) {
            try {
              const result = await api<{ received_bytes: number }>(`/peers/${encodeURIComponent(target)}/service-deployment-upload/${next.id}?offset=${offset}`, {
                method: 'PUT', headers: { 'X-CSRF-Token': session.csrf_token, 'X-Chunk-SHA256': digestBytes(data), 'Content-Type': 'application/octet-stream' },
                body: data, signal: AbortSignal.timeout(60_000),
              })
              if (active.current) setJob(old => old ? { ...old, received_bytes: Math.max(old.received_bytes || 0, result.received_bytes) } : old)
              break
            } catch (failure) {
              if (attempt >= 3 || !active.current || failure instanceof ApiError && [401, 403, 404].includes(failure.status)) throw failure
              await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)))
              const status = await call<Job>('status', { job: next.id })
              if (status.received?.includes(index)) break
              if (status.status !== 'uploading') throw failure
            }
          }
        }
      }
      const results = await Promise.allSettled([worker(), worker()])
      const failed = results.find(result => result.status === 'rejected')
      if (failed?.status === 'rejected') throw failed.reason
      next = await call<Job>('status', { job: next.id })
    }
    if (!active.current) return
    next = await call<Job>('launch', { job: next.id })
    setJob(next); setDirty(false)
  }
  async function start(event?: FormEvent, rollback = false) {
    event?.preventDefault()
    if (working.current) return
    working.current = true; setBusy(true); setError('')
    const identifier = crypto.randomUUID().replaceAll('-', '')
    let begun = false
    try {
      // Remember before sending: a lost response is queried with the same identifier.
      remember(identifier, false)
      let digest: string | undefined
      if (!rollback && kind !== 'docker' && file) {
        setHashProgress(0)
        digest = await digestFile(file, setHashProgress, () => active.current)
        setHashProgress(undefined)
      }
      const next = await call<Job>('begin', { job: identifier, kind: rollback ? 'rollback' : kind === 'docker' ? 'docker' : file ? 'package' : 'command',
        name: name.trim(), command: rollback ? '' : command, service_id: service?.id || null, version: service?.version || null,
        filename: !rollback && kind !== 'docker' && file ? file.name : '', size: !rollback && kind !== 'docker' && file ? file.size : 0,
        options: { ...settings, data_paths: settings.data_paths.map(path => path.trim()).filter(Boolean) }, ...(digest ? { sha256: digest } : {}),
        ...(!service && kind !== 'docker' ? { directory: directory.trim() } : {}) })
      begun = true
      if (!active.current) return
      remember(identifier)
      setJob(next)
      await transfer(next, file, true)
    } catch (failure) {
      if (!begun && failure instanceof ApiError && failure.status >= 400 && failure.status < 500) remember()
      else if (active.current) remember(identifier)
      if (failure instanceof Error && !(failure instanceof ApiError) && active.current) setError(failure.message)
      else fail(failure)
    } finally { working.current = false; if (active.current) { setBusy(false); setHashProgress(undefined) } }
  }
  async function resume() {
    if (!jobId || working.current) return
    working.current = true; setBusy(true); setError('')
    try { await transfer(await call<Job>('status', { job: jobId }), file) }
    catch (failure) { if (failure instanceof Error && !(failure instanceof ApiError)) setError(failure.message); else fail(failure) }
    finally { working.current = false; if (active.current) { setBusy(false); setHashProgress(undefined) } }
  }
  const pending = !!jobId && !ended(job)
  const href = job?.service_id ? withReturn(target === 'local' ? localServiceHref(job.service_id) : remoteServiceSyncHref(target, job.service_id), returnRoute()) : undefined
  return <div className="stack service-deployment">
    {error && <Notice tone="amber">{error}</Notice>}
    {capable === undefined && <Loading label="正在读取目标节点的部署能力…" />}
    {hashProgress !== undefined && <small className="muted" role="status">正在校验服务包 · {bytes(hashProgress)} / {bytes(file?.size || 0)}</small>}
    {capable && !jobId && recoverable.length > 0 && <div className="button-row"><small className="muted">目标节点有未完成任务：</small>{recoverable.map(item => <button key={item.id} className="btn btn-secondary" onClick={() => { remember(item.id); setJob(undefined) }}>{item.name} · {item.phase}</button>)}</div>}
    {capable && !jobId && <form className="stack" onSubmit={event => void start(event)} onChange={() => setDirty(true)}>
      {!service && <Tabs label="部署方式" current={kind} onChange={value => { setKind(value); setFile(undefined); setDirty(true) }}
        items={[{ id: 'package', label: '程序包' }, { id: 'docker', label: 'Docker 单容器' }]} />}
      {!service && <label>服务名称（可选）<input className="input" maxLength={80} value={name} onChange={event => setName(event.target.value)} /></label>}
      {kind !== 'docker' && <label>{service ? '新版服务包（只修改命令时可留空）' : '服务压缩包（可选）'}
        <input type="file" accept=".zip,.tar,.tar.gz,.tgz,.tar.xz,.tar.bz2" onChange={event => setFile(event.target.files?.[0])} />
        {file && <small className="muted">{file.name} · {bytes(file.size)}</small>}</label>}
      <label>{kind === 'docker' ? 'Docker 启动命令' : '启动命令'}<textarea aria-label={kind === 'docker' ? 'Docker 启动命令' : '启动命令'} className="input deploy-command" required rows={5} maxLength={8192} value={command}
        placeholder={kind === 'docker' ? 'docker run -d --name my-app -p 8080:8080 my-image:latest' : 'python hello.py --port 8080'} onChange={event => setCommand(event.target.value)} /></label>
      <p className="muted tiny">{kind === 'docker' ? '自动拉取镜像并按容器 ID 托管；后台运行和自动删除参数由 Spearmint 统一处理。' : 'Spearmint 自动进入本次部署的代码目录后执行命令，无需填写 cd。支持后续上传新版代码和回滚。'}</p>
      {kind !== 'docker' && !service && <details className="deployment-location"><summary>指定部署目录（可选）</summary><label>部署目录<input aria-label="部署目录" className="input" value={directory} onChange={event => setDirectory(event.target.value)} placeholder="留空使用 Spearmint 专用目录；也可填写目标节点上的空目录" /></label><p className="muted tiny">默认使用 Spearmint 数据目录下的独立应用目录。自定义位置用于存放代码版本和持久数据。</p></details>}
      {service?.deployment?.directory && <small className="muted">部署目录：{service.deployment.directory}</small>}
      {kind === 'docker' && <p className="muted tiny">自动保留已有卷与绑定目录，镜像声明的数据卷和 /data 使用持久卷。请将需要保留的数据放入这些目录。</p>}
      <DeploymentSettings value={settings} onChange={value => { setSettings(value); setDirty(true) }} docker={kind === 'docker'} />
      <div className="button-row"><button className="btn btn-primary" disabled={busy || (!!history && !history.can_update)} type="submit"><Icon name="package" size={16} />{service ? '更新并启动' : '部署并启动'}</button>
        {service && history?.can_rollback && <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => { if (confirm('回滚到上一版并重启此服务？应用数据目录保持原样。')) void start(undefined, true) }}>回滚上一版</button>}</div>
      {service && <p className="muted tiny">更新会短暂停止服务；启动失败自动恢复上一版，最多保留一份回滚版本。</p>}
    </form>}
    {jobId && <div className="stack deployment-progress" role="status">
      {!job ? <Loading label="正在查询原部署任务…" /> : <>
        <div className="button-row"><strong>{job.phase}</strong><Badge tone={job.status === 'succeeded' ? 'green' : ended(job) ? 'amber' : 'neutral'}>{job.status === 'succeeded' ? '已完成' : job.status === 'failed' ? '失败' : job.status === 'cancelled' ? '已取消' : '进行中'}</Badge></div>
        {job.size > 0 && <><progress max={job.size} value={job.received_bytes ?? job.offset} aria-label="服务包上传进度" /><small className="muted">{bytes(job.received_bytes ?? job.offset)} / {bytes(job.size)} · 断线后可继续上传</small></>}
        {job.readiness_result && <small className="muted">就绪检查 · {job.readiness_result.status === 'ready' ? '通过' : job.readiness_result.detail || '等待应用就绪'}</small>}
        {job.error && <Notice tone="amber">{job.error}{job.rolled_back && <p>已恢复上一版服务。</p>}</Notice>}
        {job.log && <details open={job.status === 'failed'}><summary>部署输出</summary><pre className="command-block deployment-output">{job.log}</pre></details>}
        {job.status === 'uploading' && !busy && <label>继续上传同一份服务包<input type="file" onChange={event => setFile(event.target.files?.[0])} /></label>}
      </>}
      <div className="button-row">
        {job && ['ready', 'uploading'].includes(job.status) && <><button className="btn btn-primary" disabled={busy} onClick={() => void resume()}>继续部署</button><button className="btn btn-secondary" disabled={busy} onClick={() => void call<Job>('cancel', { job: jobId }).then(next => { setJob(next); setDirty(false) }).catch(fail)}>取消任务</button></>}
        {href && ended(job) && <a className="btn btn-primary" href={href} onClick={event => { if (onOpen && !event.ctrlKey && !event.metaKey && !event.shiftKey) { event.preventDefault(); onOpen() } }}>打开服务</a>}
        {!pending && <button className="btn btn-secondary" disabled={busy} onClick={() => { remember(); setJob(undefined); setFile(undefined); setError(''); changed() }}>{service ? '返回更新配置' : '继续部署其他服务'}</button>}
        {pending && !busy && <button className="btn btn-secondary" onClick={() => void call<Job>('status', { job: jobId }).then(setJob).catch(fail)}>查询原任务</button>}
      </div>
      {pending && <p className="muted tiny">任务保存在目标节点。开始部署后关闭页面，目标节点仍会继续执行。</p>}
    </div>}
    {service && history && history.jobs.length > 0 && <details className="deployment-history"><summary>部署与更新记录</summary><div className="table-wrap"><table className="data-table"><thead><tr><th>时间</th><th>动作</th><th>结果</th><th>说明</th></tr></thead><tbody>{history.jobs.map(item => <tr key={item.id}><td>{timestamp(item.updated_at)}</td><td>{item.kind === 'rollback' ? '回滚' : item.filename ? '程序包' : item.kind === 'docker' ? 'Docker' : '启动命令'}</td><td>{item.phase}</td><td>{item.error || '—'}</td></tr>)}</tbody></table></div></details>}
  </div>
}
