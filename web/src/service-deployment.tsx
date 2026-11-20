import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, timestamp } from './api'
import { refreshConsole, useConsole } from './console-data'
import { localServiceHref, remoteServiceSyncHref } from './grove-navigation'
import { useUnsavedChanges } from './navigation-guard'
import { Badge, bytes, Icon, Loading, Notice, Tabs } from './ui'
import { returnRoute, withReturn } from './workspace-api'
import './service-deployment.css'

type Job = { id: string; service_id?: string; kind: string; name: string; command: string; filename: string;
  status: string; phase: string; size: number; offset: number; error?: string; log?: string; rolled_back?: boolean; updated_at: number }
type Service = { id: string; name: string; driver: string; version?: number; command?: string }
type History = { jobs: Job[]; can_update: boolean; can_rollback: boolean }
const ended = (job?: Job) => !!job && ['succeeded', 'failed', 'cancelled'].includes(job.status)
const storageKey = (target: string, service?: Service) => `spearmint-deploy/${target}/${service?.id || 'new'}`
function saved(key: string): string | undefined { try { const value = sessionStorage.getItem(key); return value && /^[a-f0-9]{32}$/.test(value) ? value : undefined } catch { return undefined } }
function encode(data: Uint8Array) { return btoa(String.fromCharCode(...data)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '') }

export function ServiceDeployment({ target, service, onChanged, onOpen }: { target: string; service?: Service; onChanged?: () => void; onOpen?: () => void }) {
  const { session, onUnauthorized } = useConsole()
  const key = storageKey(target, service)
  const [jobId, setJobId] = useState(() => saved(key))
  const [job, setJob] = useState<Job>()
  const [kind, setKind] = useState(service?.driver === 'docker' ? 'docker' : 'package')
  const [name, setName] = useState(service?.name || '')
  const [command, setCommand] = useState(service?.command || '')
  const [file, setFile] = useState<File>()
  const [history, setHistory] = useState<History>()
  const [capable, setCapable] = useState<boolean>()
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
    try { if (value) sessionStorage.setItem(key, value); else sessionStorage.removeItem(key) } catch { /* Optional persistence. */ }
    if (active.current && updateState) setJobId(value)
  }
  function changed() { refreshConsole(); onChanged?.(); setRevision(value => value + 1) }
  useEffect(() => {
    let live = true
    void call<{ deployment: number }>('capabilities', {}).then(result => { if (live) setCapable(result.deployment === 1) }).catch(failure => { if (live) { setCapable(false); if (failure instanceof ApiError && failure.status === 404) setError('目标节点尚不支持服务部署，请先通过 Grove 群组更新升级该节点。'); else fail(failure) } })
    return () => { live = false }
  }, [target, session])
  useEffect(() => {
    if (!service || !capable) return
    let live = true
    void call<History>('history', { service_id: service.id }).then(result => { if (live) setHistory(result) }).catch(failure => { if (live) fail(failure) })
    return () => { live = false }
  }, [service?.id, capable, revision])
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

  async function transfer(current: Job, input?: File) {
    let next = current
    if (next.size) {
      if (!input || input.name !== next.filename || input.size !== next.size) throw new Error('请重新选择同一份服务包以继续上传。')
      while (next.offset < next.size) {
        if (!active.current) return
        const offset = next.offset
        const data = encode(new Uint8Array(await input.slice(offset, offset + 8192).arrayBuffer()))
        next = await call<Job>('write', { job: next.id, offset, data })
        if (active.current) setJob(next)
      }
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
      const next = await call<Job>('begin', { job: identifier, kind: rollback ? 'rollback' : kind === 'docker' ? 'docker' : file ? 'package' : 'command',
        name, command: rollback ? '' : command, service_id: service?.id || null, version: service?.version || null,
        filename: !rollback && kind !== 'docker' && file ? file.name : '', size: !rollback && kind !== 'docker' && file ? file.size : 0 })
      begun = true
      if (!active.current) return
      remember(identifier)
      setJob(next)
      await transfer(next, file)
    } catch (failure) {
      if (!begun && failure instanceof ApiError && failure.status >= 400 && failure.status < 500) remember()
      else if (active.current) remember(identifier)
      if (failure instanceof Error && !(failure instanceof ApiError) && active.current) setError(failure.message)
      else fail(failure)
    } finally { working.current = false; if (active.current) setBusy(false) }
  }
  async function resume() {
    if (!jobId || working.current) return
    working.current = true; setBusy(true); setError('')
    try { await transfer(await call<Job>('status', { job: jobId }), file) }
    catch (failure) { if (failure instanceof Error && !(failure instanceof ApiError)) setError(failure.message); else fail(failure) }
    finally { working.current = false; if (active.current) setBusy(false) }
  }
  const pending = !!jobId && !ended(job)
  const href = job?.service_id ? withReturn(target === 'local' ? localServiceHref(job.service_id) : remoteServiceSyncHref(target, job.service_id), returnRoute()) : undefined
  return <div className="stack service-deployment">
    {error && <Notice tone="amber">{error}</Notice>}
    {capable === undefined && <Loading label="正在读取目标节点的部署能力…" />}
    {capable && !jobId && <form className="stack" onSubmit={event => void start(event)} onChange={() => setDirty(true)}>
      {!service && <Tabs label="部署方式" current={kind} onChange={value => { setKind(value); setFile(undefined); setDirty(true) }}
        items={[{ id: 'package', label: '程序包 / 启动命令' }, { id: 'docker', label: 'Docker' }]} />}
      {!service && <label>服务名称<input className="input" required maxLength={80} value={name} onChange={event => setName(event.target.value)} /></label>}
      {kind !== 'docker' && <label>{service ? '新版服务包（只修改命令时可留空）' : '服务压缩包（程序已在目标机上时可留空）'}
        <input type="file" accept=".zip,.tar,.tar.gz,.tgz,.tar.xz,.tar.bz2" onChange={event => setFile(event.target.files?.[0])} />
        {file && <small className="muted">{file.name} · {bytes(file.size)}</small>}</label>}
      <label>{kind === 'docker' ? 'Docker 启动命令' : '启动命令'}<textarea aria-label={kind === 'docker' ? 'Docker 启动命令' : '启动命令'} className="input deploy-command" required rows={5} maxLength={8192} value={command}
        placeholder={kind === 'docker' ? 'docker run -d --name my-app -p 8080:8080 my-image:latest' : 'python hello.py --port 8080'} onChange={event => setCommand(event.target.value)} /></label>
      <p className="muted tiny">{kind === 'docker' ? '自动拉取镜像并按容器 ID 托管；后台运行和自动删除参数由 Spearmint 统一处理。' : '支持多行命令。有压缩包时从解压目录运行；无压缩包时可在命令中 cd 到程序目录。持久化文件可写入 SPMT_DATA_DIR，更新保留此目录。'}</p>
      <div className="button-row"><button className="btn btn-primary" disabled={busy || (!!history && !history.can_update)} type="submit"><Icon name="package" size={16} />{service ? '更新并启动' : '部署并启动'}</button>
        {service && history?.can_rollback && <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => { if (confirm('回滚到上一版并重启此服务？应用数据目录保持原样。')) void start(undefined, true) }}>回滚上一版</button>}</div>
      {service && <p className="muted tiny">更新会短暂停止服务；启动失败自动恢复上一版，最多保留一份回滚版本。</p>}
    </form>}
    {jobId && <div className="stack deployment-progress" role="status">
      {!job ? <Loading label="正在查询原部署任务…" /> : <>
        <div className="button-row"><strong>{job.phase}</strong><Badge tone={job.status === 'succeeded' ? 'green' : ended(job) ? 'amber' : 'neutral'}>{job.status === 'succeeded' ? '已完成' : job.status === 'failed' ? '失败' : job.status === 'cancelled' ? '已取消' : '进行中'}</Badge></div>
        {job.size > 0 && <><progress max={job.size} value={job.offset} aria-label="服务包上传进度" /><small className="muted">{bytes(job.offset)} / {bytes(job.size)}</small></>}
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
