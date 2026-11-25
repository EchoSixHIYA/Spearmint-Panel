import { useEffect, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { AuthenticatorQR } from './onboarding'
import { AuthStory, CopyValue, Modal, Notice } from './ui'

export type AccountAction = 'invite' | 'create' | 'assist' | 'recovery-code'
type AccountResult = { code?: string; recovery_code?: string; provisioning_uri?: string }

const usernamePattern = '[a-z0-9][a-z0-9._\\-]{0,63}'
const codePattern = '[A-Za-z0-9_\\-]{43}'

const actionLabels: Record<AccountAction, string> = {
  invite: '邀请注册',
  create: '创建账号',
  assist: '生成密码重置码',
  'recovery-code': '生成密码恢复码',
}

function field(data: FormData, name: string) {
  return String(data.get(name) ?? '')
}

function post(path: string, body: object, session?: Session) {
  return api<AccountResult>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(session ? { 'X-CSRF-Token': session.csrf_token } : {}) },
    body: JSON.stringify(body),
  })
}

function Authenticator({ uri }: { uri: string }) {
  return <div className="grove-account-authenticator">
    <AuthenticatorQR uri={uri} />
    <details><summary>手动配置验证器</summary><CopyValue value={new URL(uri).searchParams.get('secret') || uri} /></details>
  </div>
}

function RecoveryCode({ value }: { value: string }) {
  return <div className="grove-account-secret"><strong>密码恢复码</strong><CopyValue value={value} />
    <small>请妥善保存，仅显示一次。用它重置密码后会生成新的恢复码。</small></div>
}

export function GroveAccountDialog({ action, username, role, session, onClose, onUnauthorized }: {
  action: AccountAction; username?: string; role?: string; session: Session; onClose: () => void; onUnauthorized: () => void
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<AccountResult>()
  const [submittedName, setSubmittedName] = useState(username)
  const selectRole = action === 'create' || action === 'invite'

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const name = username || field(data, 'username').trim()
    setPending(true); setError('')
    try {
      const body = action === 'recovery-code' ? { current_password: field(data, 'password') }
        : { username: name, ...(selectRole && { role: field(data, 'role') }),
          ...(action === 'create' && { password: field(data, 'password') }) }
      const path = action === 'recovery-code' ? '/auth/grove/account/recovery-code' : '/grove/accounts/' + action
      setResult(await post(path, body, session))
      setSubmittedName(name)
      window.dispatchEvent(new Event('spearmint:refresh'))
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof Error ? failure.message : '暂时无法确认账号变更。')
    } finally { setPending(false) }
  }

  return <Modal title={actionLabels[action]} onClose={() => { if (!pending) onClose() }}>
    {result ? <div className="grove-account-form">
      {submittedName && <strong>{submittedName}</strong>}
      {result.code && <div className="grove-account-secret">
        <strong>{action === 'invite' ? '一次性邀请码' : '一次性密码重置码'}</strong>
        <CopyValue value={result.code} />
        <small>{action === 'invite' ? '邀请码 24 小时内有效。请把账号名和邀请码交给受邀人，在任一已更新的 Grove 面板选择「接受账号邀请」。'
          : '重置码 30 分钟内有效。请交给账号持有人，在登录页选择「忘记密码」。'}</small>
      </div>}
      {result.provisioning_uri && <div className="grove-account-secret"><strong>登录验证器</strong>
        <small>请把初始密码和验证器配置安全交给账号持有人。登录时需要输入动态验证码。</small>
        <Authenticator uri={result.provisioning_uri} />
      </div>}
      {result.recovery_code && <RecoveryCode value={result.recovery_code} />}
      <div className="button-row"><button className="btn btn-primary" onClick={onClose}>完成</button></div>
    </div> : <form className="grove-account-form" onSubmit={submit}>
      {selectRole && <>
        <label className="field-label">账号<input name="username" className="input" defaultValue={username} readOnly={!!username}
          autoCapitalize="none" spellCheck={false} autoComplete="off" pattern={usernamePattern} maxLength={64} required /></label>
        <label className="field-label">角色<select name="role" className="input" defaultValue={role || 'remote_operator'}>
          <option value="remote_operator">操作员</option><option value="node_admin">管理员</option>
        </select></label>
      </>}
      {action === 'create' && <label className="field-label">初始密码<input className="input" name="password" type="password"
        autoComplete="new-password" minLength={12} maxLength={256} required /><small className="muted">至少 12 个字符</small></label>}
      {action === 'assist' && <p>为 <strong>{username}</strong> 生成一次性重置码。由账号持有人自行设置新密码。</p>}
      {action === 'recovery-code' && <>
        <p>生成后，之前的密码恢复码会失效。</p>
        <label className="field-label">当前 Grove 密码<input name="password" className="input" type="password" autoComplete="current-password" maxLength={256} required /></label>
      </>}
      {error && <Notice tone="red">{error}</Notice>}
      <div className="button-row"><button className="btn btn-primary" disabled={pending}>{pending ? '正在等待 Grove 确认…' : actionLabels[action]}</button></div>
    </form>}
  </Modal>
}

function newSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => alphabet[byte & 31]).join('')
}

export function GroveAccountAccess({ mode }: { mode: 'register' | 'reset' }) {
  const joining = mode === 'register'
  const title = joining ? '接受账号邀请' : '重置 Grove 密码'
  const [name, setName] = useState('')
  const [secret, setSecret] = useState('')
  const [result, setResult] = useState<AccountResult>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { document.title = title + ' · Spearmint' }, [title])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const password = field(data, 'password')
    if (password !== field(data, 'confirmation')) { setError('两次填写的密码不一致。'); return }
    setPending(true); setError('')
    try {
      setResult(await post('/auth/grove/account/' + mode, {
        username: name.trim(), code: field(data, 'code').trim(), password,
        ...(joining && { totp: secret, otp: field(data, 'otp') }),
      }))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : '暂时无法确认，请稍后再试。')
    } finally { setPending(false) }
  }

  const uri = secret ? 'otpauth://totp/' + encodeURIComponent('Spearmint Grove:' + name)
    + '?secret=' + secret + '&issuer=Spearmint%20Grove' : ''
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap">
    <section className="auth-form-card" aria-labelledby="grove-account-heading">
      <h1 id="grove-account-heading">{title}</h1>
      {result ? <div className="grove-account-form">
        <div className="auth-success" role="status">{joining ? 'Grove 账号已激活。' : '密码已重置。请使用原验证器和新密码登录。'}</div>
        {result.recovery_code && <RecoveryCode value={result.recovery_code} />}
        <a className="btn btn-primary btn-full" href="#/signin">返回登录</a>
      </div> : <>
        <p className="auth-subtitle">{joining ? '输入管理员发给你的账号和邀请码，再设置自己的密码和验证器。'
          : '使用已保存的密码恢复码，也可以请另一位 Grove 管理员生成一次性重置码。'}</p>
        <form className="grove-account-form" onSubmit={submit}>
          <label className="field-label">Grove 账号<input name="username" className="input" autoCapitalize="none" autoComplete="username"
            value={name} onChange={event => setName(event.target.value)} pattern={usernamePattern} maxLength={64} required /></label>
          <label className="field-label">{joining ? '邀请码' : '恢复码或重置码'}
            <input name="code" className="input" type="password" autoComplete="off" maxLength={43} pattern={codePattern} required />
          </label>
          <label className="field-label">新密码<input name="password" className="input" type="password" autoComplete="new-password" minLength={12} maxLength={256} required /></label>
          <label className="field-label">确认新密码<input name="confirmation" className="input" type="password" autoComplete="new-password" minLength={12} maxLength={256} required /></label>
          {joining && (secret ? <>
            <strong>用验证器 App 扫描二维码，再输入动态验证码。</strong>
            <Authenticator uri={uri} />
            <label className="field-label">动态验证码<input className="input otp-input" name="otp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required /></label>
          </> : <button type="button" className="btn btn-secondary" onClick={() => setSecret(newSecret())}>设置登录验证器</button>)}
          {error && <Notice tone="red">{error}</Notice>}
          {(!joining || secret) && <button className="btn btn-primary btn-full" disabled={pending}>{pending ? '正在等待 Grove 确认…' : joining ? '激活账号' : '重置密码'}</button>}
        </form>
        <div className="auth-links"><a className="text-link" href="#/signin">返回登录</a></div>
      </>}
    </section>
  </div></div>
}
