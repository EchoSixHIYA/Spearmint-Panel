import { useRef, useState, type FormEvent } from 'react'
import { api, ApiError } from './api'
import { refreshConsole, useConsole } from './console-data'
import { localServiceHref, remoteServiceSyncHref } from './grove-navigation'
import { useUnsavedChanges } from './navigation-guard'
import { returnRoute, withReturn } from './workspace-api'
import { Icon, Notice } from './ui'

export function ExistingCodeRegistration({ target, windows }: { target: string; windows: boolean }) {
  const { session, onUnauthorized } = useConsole()
  const defaultName = useRef('已有代码 ' + crypto.randomUUID().slice(0, 8))
  const [name, setName] = useState(''), [command, setCommand] = useState('')
  const [error, setError] = useState(''), [busy, setBusy] = useState(false)
  const [registered, setRegistered] = useState<{ id: string; name: string }>()
  useUnsavedChanges(!registered && !!command.trim())
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try {
      const result = await api<{ service: { id: string; name: string } }>(`/peers/${encodeURIComponent(target)}/service-setup/create`, {
        method: 'POST', headers: { 'X-CSRF-Token': session.csrf_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim() || defaultName.current, command }), signal: AbortSignal.timeout(30_000),
      })
      setRegistered(result.service); refreshConsole()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof ApiError ? failure.message : '暂时未收到登记回执，可使用同一配置重试。')
    } finally { setBusy(false) }
  }
  const href = registered ? withReturn(target === 'local' ? localServiceHref(registered.id) : remoteServiceSyncHref(target, registered.id), returnRoute()) : undefined
  return <div className="stack service-deployment">
    {error && <Notice tone="amber">{error}</Notice>}
    {registered ? <><Notice tone="green">已登记 {registered.name}，可在服务详情中启动并查看日志。</Notice><a className="btn btn-primary" href={href}>打开服务<Icon name="arrow-right" size={15} /></a></>
      : <form className="stack" onSubmit={event => void submit(event)}>
        <label><span>服务名称 <small className="registration-optional">可选</small></span>
          <input className="input" placeholder="例如 Web 应用" maxLength={80} value={name} onChange={event => setName(event.target.value)} /></label>
        <label><span className="registration-command-label"><Icon name="terminal" size={15} />启动命令</span><textarea aria-label="已有代码启动命令" className="input deploy-command" rows={4} required maxLength={8192} value={command}
          placeholder={windows ? 'cd /d "D:\\my-app"\npython hello.py --port 8080' : 'cd /srv/my-app\npython hello.py --port 8080'} onChange={event => setCommand(event.target.value)} /></label>
        <p className="muted tiny">请在命令中 cd 到已有代码目录。Spearmint 托管启停和日志，代码由你自行更新。</p>
        <div className="button-row registration-submit"><button className="btn btn-primary" disabled={busy}><Icon name="plus" size={15} />{busy ? '正在登记…' : '登记服务'}</button></div>
      </form>}
  </div>
}
