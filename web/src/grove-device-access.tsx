import { useEffect, useState, type FormEvent } from 'react'
import { api, type Session } from './api'
import { AuthStory, CopyValue, Loading, Notice } from './ui'

export function GroveDeviceReturn({ ticket, onSession }: { ticket: string; onSession: (session: Session) => void }) {
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    api<Session>('/auth/grove/device/finish-browser', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket }), signal: controller.signal,
    }).then(onSession, (failure) => {
      if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : '暂时无法完成登录。')
    })
    return () => controller.abort()
  }, [ticket])
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card">
    <h1>登录 Grove</h1>
    {error ? <><Notice tone="red">{error}</Notice><a href="#/signin" className="text-link">返回登录</a></>
      : <Loading label="正在完成登录…" />}
  </section></div></div>
}

export function GroveDeviceAccess({ onSession }: { onSession: (session: Session) => void }) {
  const [request, setRequest] = useState<Record<string, unknown>>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const headers = { 'Content-Type': 'application/json' }
    setPending(true); setError('')
    try {
      if (!request) {
        const value = await api<Record<string, unknown>>('/auth/grove/device/challenge', {
          method: 'POST', headers, body: JSON.stringify({ username: String(form.get('username')).trim(), session_authorization: true }),
        })
        setRequest(value)
      } else {
        const signed = String(form.get('proof') || '').trim()
        try { JSON.parse(signed) } catch { throw new Error('请粘贴完整的签名文件内容。') }
        onSession(await api<Session>('/auth/grove/device/login', { method: 'POST', headers, body: signed }))
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : '登录验证暂时不可用。')
    } finally { setPending(false) }
  }

  function download() {
    const path = URL.createObjectURL(new Blob([JSON.stringify(request, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = path
    link.download = 'grove-device-login.json'
    link.click()
    setTimeout(() => URL.revokeObjectURL(path), 1000)
  }

  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card">
    <h1>Grove 管理员登录</h1>
    <form className="grove-account-form" onSubmit={submit}>
      {!request ? <label className="field-label">Grove 账号<input name="username" className="input" maxLength={64}
        autoComplete="username" autoCapitalize="none" required /></label> : <>
        <button type="button" className="btn btn-secondary" onClick={download}>下载登录请求</button>
        <div className="grove-account-secret"><strong>面板标识</strong><CopyValue value={String(request.source)} /></div>
        <p>在持有 Grove 设备密钥的设备上签名，将签名文件内容粘贴到这里。</p>
        {Array.isArray(request.scopes) && request.scopes.includes('updates') &&
          <p className="muted">本次登录期间，可直接管理 Grove 节点和服务。</p>}
        <label className="field-label">设备签名<textarea className="input" name="proof" maxLength={32768} autoComplete="off" required /></label>
      </>}
      {error && <Notice tone="red">{error}</Notice>}
      <button className="btn btn-primary btn-full" disabled={pending}>{pending ? '正在核对…' : request ? '登录 Grove' : '生成登录请求'}</button>
      {request && <button type="button" className="btn btn-ghost" onClick={() => { setRequest(undefined); setError('') }}>重新生成登录请求</button>}
    </form>
    <div className="auth-links"><a href="#/signin" className="text-link">返回登录</a></div>
  </section></div></div>
}
