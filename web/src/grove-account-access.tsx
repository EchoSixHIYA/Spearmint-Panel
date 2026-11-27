import { useEffect, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { AuthStory, CopyValue, Modal, Notice } from './ui'

export type AccountAction = 'invite' | 'create' | 'assist' | 'recovery-code' | 'bind-device'
type AccountResult = { code?: string; recovery_code?: string }

const usernamePattern = '[a-z0-9][a-z0-9._\\-]{0,63}'
const codePattern = '[A-Za-z0-9_\\-]{43}'

const actionLabels: Record<AccountAction, string> = {
  invite: '邀请注册',
  create: '创建账号',
  assist: '生成账号重置码',
  'recovery-code': '生成账号恢复码',
  'bind-device': '绑定登录设备',
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

function RecoveryCode({ value }: { value: string }) {
  return <div className="grove-account-secret"><strong>账号恢复码</strong><CopyValue value={value} />
    <small>请妥善保存，仅显示一次。用它换绑登录设备后会生成新的恢复码。</small></div>
}

export function GroveAccountDialog({ action, username, role, session, onClose, onUnauthorized, deviceBound = false }:  {
  action: AccountAction; username?: string; role?: string; session: Session; deviceBound?: boolean; onClose: () => void; onUnauthorized: () => void
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
      const body = action === 'bind-device' ? {} : action === 'recovery-code' ? { current_password: field(data, 'password') || null }
        : { username: name, ...(selectRole && { role: field(data, 'role') }),
          ...(action === 'create' && { device_key: field(data, 'device_key').trim() }) }
      const path = action === 'bind-device' ? '/auth/grove/device/bind'
        : action === 'recovery-code' ? '/auth/grove/account/recovery-code' : '/grove/accounts/' + action
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
      {action === 'bind-device' && <Notice tone="green">登录设备已绑定。请使用设备签名重新登录。</Notice>}
      {result.code && <div className="grove-account-secret">
        <strong>{action === 'invite' ? '一次性邀请码' : '一次性账号重置码'}</strong>
        <CopyValue value={result.code} />
        <small>{action === 'invite' ? '邀请码 24 小时内有效。请把账号名和邀请码交给受邀人，在任一已更新的 Grove 面板选择「接受账号邀请」。'
          : '重置码 30 分钟内有效。请交给账号持有人，在登录页选择「忘记密码」。'}</small>
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
      {action === 'create' && <label className="field-label">用户的设备公钥<input name="device_key" className="input"
        autoComplete="off" spellCheck={false} minLength={43} maxLength={43} required /></label>}
      {action === 'assist' && <p>为 <strong>{username}</strong> 生成一次性重置码。由账号持有人自行绑定新的登录设备。</p>}
      {action === 'recovery-code' && <>
        <p>生成后，之前的账号恢复码会失效。</p>
        {!deviceBound && <label className="field-label">当前 Grove 密码<input name="password" className="input" type="password" autoComplete="current-password" maxLength={256} required /></label>}
      </>}
      {action === 'bind-device' && <><p>绑定本次 Grove 登录使用的设备公钥。</p>
        <label><input type="checkbox" required /> 我已保存账号恢复码</label></>}
      {error && <Notice tone="red">{error}</Notice>}
      <div className="button-row"><button className="btn btn-primary" disabled={pending}>{pending ? '正在等待 Grove 确认…' : actionLabels[action]}</button></div>
    </form>}
  </Modal>
}

export function GroveAccountAccess({ mode }: { mode: 'register' | 'reset' }) {
  const joining = mode === 'register'
  const title = joining ? '接受账号邀请' : '恢复 Grove 账号'
  const [name, setName] = useState('')
  const [result, setResult] = useState<AccountResult>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { document.title = title + ' · Spearmint' }, [title])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setPending(true); setError('')
    try {
      setResult(await post('/auth/grove/account/' + mode, {
        username: name.trim(), code: field(data, 'code').trim(), device_key: field(data, 'device_key').trim(),
      }))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : '暂时无法确认，请稍后再试。')
    } finally { setPending(false) }
  }

  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap">
    <section className="auth-form-card" aria-labelledby="grove-account-heading">
      <h1 id="grove-account-heading">{title}</h1>
      {result ? <div className="grove-account-form">
        <div className="auth-success" role="status">{joining ? 'Grove 账号已激活。' : '登录设备已更换，请使用新设备签名登录。'}</div>
        {result.recovery_code && <RecoveryCode value={result.recovery_code} />}
        <a className="btn btn-primary btn-full" href="#/signin">返回登录</a>
      </div> : <>
        <p className="auth-subtitle">{joining ? '输入管理员发给你的账号和邀请码，绑定你的登录设备。'
          : '使用已保存的账号恢复码，也可以请另一位 Grove 管理员生成一次性重置码。'}</p>
        <form className="grove-account-form" onSubmit={submit}>
          <label className="field-label">Grove 账号<input name="username" className="input" autoCapitalize="none" autoComplete="username"
            value={name} onChange={event => setName(event.target.value)} pattern={usernamePattern} maxLength={64} required /></label>
          <label className="field-label">{joining ? '邀请码' : '恢复码或重置码'}
            <input name="code" className="input" type="password" autoComplete="off" maxLength={43} pattern={codePattern} required />
          </label>
          <label className="field-label">登录设备公钥<input name="device_key" className="input"
            autoComplete="off" spellCheck={false} minLength={43} maxLength={43} required /></label>
          {error && <Notice tone="red">{error}</Notice>}
          <button className="btn btn-primary btn-full" disabled={pending}>{pending ? '正在等待 Grove 确认…' : joining ? '激活账号' : '恢复账号'}</button>
        </form>
        <div className="auth-links"><a className="text-link" href="#/signin">返回登录</a></div>
      </>}
    </section>
  </div></div>
}
