import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { Loading, Modal, Notice } from './ui'
import './host-service-authorization.css'

type Access = { supported: boolean; enabled: boolean; account: string | null; port: number }
type Job = { job: string; status: string; error?: string | null }
const complete = (job?: Job) => job && ['succeeded', 'failed'].includes(job.status)
const phases: Record<string, string> = { connecting: '正在连接目标节点的本机 SSH…', authenticating: '正在验证主机管理员身份…', authorizing: '正在启用节点管理权限…' }

function message(error: unknown) {
  const code = error instanceof ApiError ? error.code : typeof error === 'string' ? error : undefined
  if (['INVALID_REQUEST', 'UNSUPPORTED_METHOD'].includes(code || '') || error instanceof ApiError && error.status === 404 && code !== 'NOT_FOUND') return '请先通过群组更新升级目标节点，以使用网页主机授权。'
  if (code === 'HOST_SSH_AUTH') return '主机登录验证失败，请核对账号和密码或私钥。'
  if (code === 'HOST_SSH_CONNECTION') return '无法连接目标节点的本机 SSH。请确认该节点已启用 SSH 服务，并核对高级选项中的端口。'
  if (code === 'HOST_ADMIN_AUTH') return '主机授权未完成。请核对 sudo 密码及该账号的管理员权限；目标机还需要已有 Python 3 和 systemd。'
  if (code === 'BUSY') return '目标节点正在处理其他主机授权，请稍后重试。'
  if (code === 'DENIED') return 'Grove 管理员身份已变化，请重新登录后重试。'
  if (code === 'NOT_FOUND') return '授权任务已过期或目标面板已重启。请重新检查节点状态后重试。'
  if (code === 'HOST_AUTH_FAILED') return '目标节点未能完成主机授权，请检查主机状态后重试。'
  return '暂未收到授权回执。保留原任务并继续查询，避免重复执行。'
}

export function HostServiceAuthorization({ nodeId, session, onUnauthorized, onAuthorized, disabled = false, scope = 'systemd' }: {
  nodeId: string; session: Session; onUnauthorized: () => void; onAuthorized: () => void; disabled?: boolean; scope?: 'systemd' | 'docker'
}) {
  const [open, setOpen] = useState(false), [access, setAccess] = useState<Access>()
  const [username, setUsername] = useState(''), [secret, setSecret] = useState(''), [sudoPassword, setSudoPassword] = useState('')
  const [key, setKey] = useState(false), [port, setPort] = useState(22), [busy, setBusy] = useState(false)
  const [job, setJob] = useState<Job>(), [error, setError] = useState(''), [revision, refresh] = useState(0)
  const changed = useRef(onAuthorized), submitted = useRef(false), notified = useRef<string | undefined>(undefined)
  changed.current = onAuthorized
  const storage = `spearmint-host-authorization/${session.csrf_token}/${nodeId}/${scope}`
  const active = busy || !!job && !complete(job)

  async function request<T>(action: string, body: object, signal?: AbortSignal) {
    return api<T>(`/peers/${encodeURIComponent(nodeId)}/service-setup/${action}`, { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000) })
  }
  function forget() { try { sessionStorage.removeItem(storage) } catch { /* Polling can continue without storage. */ } }
  function accept(value: Job) {
    setJob(value)
    if (complete(value)) forget()
    if (value.status === 'succeeded' && notified.current !== value.job) { notified.current = value.job; changed.current() }
  }
  function failure(value: unknown) {
    if (value instanceof ApiError && value.status === 401) onUnauthorized()
    setError(message(value))
  }
  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    void request<Access>('host-access', scope === 'docker' ? { scope } : {}, controller.signal).then(value => {
      if (controller.signal.aborted) return
      setAccess(value); setUsername(previous => previous || value.account || '')
      if (value.enabled) { forget(); changed.current() }
      else if (!job) {
        try { const saved = sessionStorage.getItem(storage); if (saved && /^[a-f0-9]{32}$/.test(saved)) setJob({ job: saved, status: 'connecting' }) } catch { /* No stored credentials. */ }
      }
    }).catch(value => { if (!controller.signal.aborted) failure(value) })
    return () => controller.abort()
  }, [open, nodeId, session, revision])
  useEffect(() => {
    if (!open || !job || complete(job)) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    async function poll() {
      try {
        const value = await request<Job>('host-authorization-status', { job: job!.job }, controller.signal)
        if (!controller.signal.aborted) { setError(''); accept(value) }
      } catch (value) {
        if (!controller.signal.aborted) {
          failure(value)
          if (value instanceof ApiError && value.code === 'NOT_FOUND') { forget(); setJob(undefined); refresh(previous => previous + 1) }
        }
      } finally { if (!controller.signal.aborted) timer = setTimeout(() => void poll(), 1200) }
    }
    void poll()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [open, job?.job, job?.status, nodeId, session])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (submitted.current || active) return
    submitted.current = true; setBusy(true); setError('')
    const identifier = crypto.randomUUID().replaceAll('-', '')
    const body = { job: identifier, username: username.trim(), secret, key, port, sudo_password: sudoPassword, ...(scope === 'docker' ? { scope } : {}) }
    setSecret(''); setSudoPassword('')
    try {
      try { sessionStorage.setItem(storage, identifier) } catch { /* Only the task ID is persisted. */ }
      const response = await request<Job>('host-authorize', body)
      accept(response)
    } catch (value) {
      failure(value)
      if (value instanceof ApiError && value.status >= 400 && value.status < 500) forget()
      else setJob({ job: identifier, status: 'connecting' })
    } finally { body.secret = ''; body.sudo_password = ''; submitted.current = false; setBusy(false) }
  }
  function close() { setSecret(''); setSudoPassword(''); setOpen(false) }
  const succeeded = access?.enabled || job?.status === 'succeeded'
  return <>
    <button type="button" className="btn btn-secondary btn-small" disabled={disabled} onClick={() => { setError(''); setOpen(true) }}>{scope === 'docker' ? '授权 Docker 管理' : '授权此节点'}</button>
    {open && <Modal title={scope === 'docker' ? '启用节点 Docker 管理' : '启用节点系统服务管理'} onClose={close}>
      {error && <Notice tone="amber">{error}</Notice>}
      {succeeded ? <><Notice>{scope === 'docker' ? 'Docker 授权已完成，可以接管容器、启停、读取日志及部署更新。' : '节点主机授权已完成，可以在当前页面托管系统服务。'}</Notice><div className="modal-actions"><button className="btn btn-primary" onClick={close}>完成</button></div></>
        : !access ? <>{!error && <Loading label="正在检查目标节点的授权能力…" />}{error && <button className="btn btn-secondary" onClick={() => { setError(''); refresh(value => value + 1) }}>重新检查</button>}</>
        : !access.supported ? <Notice>此节点不需要 Linux 主机服务授权。</Notice>
        : <form className="host-authorization-form" onSubmit={event => void submit(event)}>
          <p className="muted">验证目标主机的管理员身份，为面板账号 <strong>{access.account}</strong> 启用此节点的{scope === 'docker' ? ' Docker 管理' : '系统服务管理'}。此后接管其他{scope === 'docker' ? '容器' : '服务'}无需重复授权。</p>
          {job && !complete(job) && <Loading label={phases[job.status] || '正在等待主机授权回执…'} />}
          {job?.status === 'failed' && <Notice tone="amber">{message(job.error)}</Notice>}
          <label className="field-label">主机管理员账号<input className="input" value={username} onChange={event => setUsername(event.target.value)} required maxLength={128} disabled={active} autoComplete="off" /></label>
          <label className="field-label">身份验证<select className="input" value={key ? 'key' : 'password'} disabled={active} onChange={event => { setKey(event.target.value === 'key'); setSecret('') }}><option value="password">密码</option><option value="key">SSH 私钥（未加密）</option></select></label>
          <label className="field-label">{key ? 'SSH 私钥' : '主机登录密码'}{key ? <textarea className="input" rows={4} value={secret} onChange={event => setSecret(event.target.value)} required disabled={active} autoComplete="off" maxLength={10500} />
            : <input type="password" className="input" value={secret} onChange={event => setSecret(event.target.value)} required disabled={active} autoComplete="new-password" maxLength={1024} />}</label>
          <details><summary>高级选项</summary><div className="stack">
            <label className="field-label">目标节点本机 SSH 端口<input type="number" className="input" value={port} onChange={event => setPort(Number(event.target.value))} required min={1} max={65535} disabled={active} /></label>
            <label className="field-label">sudo 密码（与登录密码不同时填写）<input type="password" className="input" value={sudoPassword} onChange={event => setSudoPassword(event.target.value)} disabled={active} autoComplete="new-password" maxLength={1024} /></label>
          </div></details>
          <p className="muted tiny">由目标节点通过本机 SSH 执行，无需公网 IP 或打开终端。凭据仅用于本次授权，不保存；不会重启业务服务。</p>
          <div className="modal-actions"><button type="button" className="btn btn-secondary" onClick={close}>{active ? '后台继续' : '取消'}</button><button className="btn btn-primary" disabled={active}>{active ? '正在授权…' : '授权并继续'}</button></div>
        </form>}
    </Modal>}
  </>
}
