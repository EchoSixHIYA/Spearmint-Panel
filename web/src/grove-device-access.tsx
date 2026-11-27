import { useState, type FormEvent } from 'react'
import { api, type Session } from './api'
import { AuthStory, CopyValue, Notice } from './ui'

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
          method: 'POST', headers, body: JSON.stringify({ username: String(form.get('username')).trim(), service_controls: true }),
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
    <h1>使用设备签名登录</h1>
    <form className="grove-account-form" onSubmit={submit}>
      {!request ? <label className="field-label">Grove 账号<input name="username" className="input" maxLength={64}
        autoComplete="username" autoCapitalize="none" required /></label> : <>
        <button type="button" className="btn btn-secondary" onClick={download}>下载登录请求</button>
        <div className="grove-account-secret"><strong>面板标识</strong><CopyValue value={String(request.source)} /></div>
        <p>在持有 Grove 设备密钥的设备上签名，将签名文件内容粘贴到这里。</p>
        {Array.isArray(request.scopes) && request.scopes.includes('service-control') &&
          <p className="muted">本次设备登录同时开启远程服务启停、重启和日志访问，授权随登录会话结束。</p>}
        <label className="field-label">设备签名<textarea className="input" name="proof" maxLength={32768} autoComplete="off" required /></label>
      </>}
      {error && <Notice tone="red">{error}</Notice>}
      <button className="btn btn-primary btn-full" disabled={pending}>{pending ? '正在核对…' : request ? '登录 Grove' : '生成登录请求'}</button>
      {request && <button type="button" className="btn btn-ghost" onClick={() => { setRequest(undefined); setError('') }}>重新生成登录请求</button>}
    </form>
    <div className="auth-links"><a href="#/signin" className="text-link">返回登录</a></div>
  </section></div></div>
}
