import { type FormEvent, type MouseEvent, useEffect, useState } from 'react'
import { ApiError, api, type Session } from './api'
import { createPasskey, getPasskey, supportsPasskey } from './webauthn'
import { AuthStory, Icon, Loading, Tabs } from './ui'
import { AuthenticatorQR } from './onboarding'
import { GroveLoginButton, type GroveInfo } from './grove-auth'

type Flow = { flow_id: string; method: 'totp' | 'recovery' | 'totp_rebind' | 'passkey_enroll'; expires_at: number }

function post<T>(path: string, body: object, csrfToken?: string) {
  return api<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
    body: JSON.stringify(body),
  })
}

export function SignIn({ onSession, initialError, enrollmentSession, onEnrollmentExit, authorizeRequest, mode = 'signin' }: {
  onSession: (session: Session) => void
  initialError: string
  mode?: 'signin' | 'enroll' | 'recover'
  enrollmentSession?: Session
  onEnrollmentExit?: (completed: boolean) => void
  authorizeRequest?: string
}) {
  const [flow, setFlow] = useState<Flow>()
  const [useRecovery, setUseRecovery] = useState(mode === 'recover')
  const [useEnrollment, setUseEnrollment] = useState(Boolean(enrollmentSession))
  const [method, setMethod] = useState('password')
  const [visiblePassword, setVisiblePassword] = useState(false)
  const [uri, setUri] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>()
  const [error, setError] = useState(initialError)
  const [pending, setPending] = useState(false)
  const [directIssuer, setDirectIssuer] = useState(false)
  const [loginInfo, setLoginInfo] = useState<GroveInfo | null>()
  const [localLogin, setLocalLogin] = useState(false)
  useEffect(() => { document.title = `${mode === 'recover' ? '恢复访问' : mode === 'enroll' || enrollmentSession ? '设置登录验证' : '登录'} · Spearmint` }, [mode, enrollmentSession])

  function reset() {
    if (enrollmentSession) {
      onEnrollmentExit?.(Boolean(recoveryCodes))
      return
    }
    setFlow(undefined)
    setUseRecovery(false)
    setUseEnrollment(false)
    setUri('')
    setRecoveryCodes(undefined)
    setError('')
    if (mode !== 'signin') location.hash = '#/signin'
  }

  async function signInWithPasskey(event: MouseEvent<HTMLButtonElement>) {
    const form = event.currentTarget.form
    if (!form || !form.reportValidity()) return
    const username = new FormData(form).get('username')
    setPending(true)
    setError('')
    try {
      const options = await post<{ flow_id: string; public_key: PublicKeyCredentialRequestOptionsJSON }>(
        '/auth/passkey/options', { username },
      )
      const credential = await getPasskey(options.public_key)
      onSession(await post<Session>('/auth/passkey/finish', { flow_id: options.flow_id, credential }))
      form.reset()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 429) setError('尝试次数过多，请稍后再试。')
      else setError('Passkey 登录未完成，请确认选择的凭据与账户和节点地址一致。')
    } finally {
      setPending(false)
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    setPending(true)
    setError('')
    try {
      if (!flow) {
        const result = await post<Session | Flow>('/session', {
          username: fields.get('username'), password: fields.get('password'),
          ...(useEnrollment ? { enrollment_token: fields.get('enrollment_token') } : {}),
        }, enrollmentSession?.csrf_token)
        if ('flow_id' in result) {
          setFlow(result)
          setUseRecovery(result.method === 'recovery' || mode === 'recover')
        } else {
          onSession(result)
        }
      } else if (flow.method === 'passkey_enroll') {
        const options = await post<{ public_key: PublicKeyCredentialCreationOptionsJSON }>(
          '/auth/passkey/register/options', { flow_id: flow.flow_id },
        )
        const credential = await createPasskey(options.public_key)
        const result = await post<{ recovery_codes: string[] }>('/auth/passkey/register/finish', {
          flow_id: flow.flow_id, credential,
        })
        setRecoveryCodes(result.recovery_codes)
        setFlow(undefined)
      } else if (flow.method === 'totp_rebind') {
        if (!uri) {
          const result = await post<{ provisioning_uri: string }>('/auth/totp/register/options', { flow_id: flow.flow_id })
          setUri(result.provisioning_uri)
        } else {
          const result = await post<{ recovery_codes: string[] }>('/auth/totp/register/finish', {
            flow_id: flow.flow_id, code: fields.get('code'),
          })
          setRecoveryCodes(result.recovery_codes)
          setUri('')
          setFlow(undefined)
        }
      } else if (useRecovery) {
        setFlow(await post<Flow>('/auth/recovery/finish', { flow_id: flow.flow_id, code: fields.get('code') }))
        setUseRecovery(false)
      } else {
        onSession(await post<Session>('/auth/totp/finish', { flow_id: flow.flow_id, code: fields.get('code') }))
      }
      form.reset()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 429) {
        setError('尝试次数过多，请稍后再试。')
      } else if (failure instanceof ApiError && failure.code === 'FACTOR_REENROLLMENT_REQUIRED') {
        setError('需要在节点本机终端重新登记验证器。')
      } else if (failure instanceof ApiError && failure.code === 'REAUTHENTICATION_REQUIRED') {
        setError('请返回面板，退出后用原有 Passkey 或动态验证码重新登录，并在 5 分钟内更换验证器。若原验证器已遗失，请由本机终端执行恢复。')
      } else if (failure instanceof ApiError && failure.status === 401) {
        setError(flow ? '验证码无效或流程已过期。'
          : useEnrollment ? '账号、密码或登记令牌无效。' : '用户名或密码错误。')
      } else if (flow && failure instanceof ApiError && failure.status === 503) {
        setError('本机验证材料不可用，请联系节点管理员。')
      } else if (flow?.method === 'passkey_enroll') {
        setError('Passkey 登记未完成，请使用支持 Passkey 的浏览器和验证器重试。')
      } else {
        setError('登录失败，请检查面板连接。')
      }
    } finally {
      setPending(false)
    }
  }

  if (authorizeRequest && !directIssuer) return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap">
    <section className="auth-form-card">
      <h1>验证 Grove 身份</h1>
      <GroveLoginButton onSession={onSession} authorizeRequest={authorizeRequest} onIssuer={setDirectIssuer} onInfo={setLoginInfo} />
      <button type="button" className="btn btn-ghost btn-full" onClick={() => history.back()}>返回上一页</button>
    </section>
  </div></div>

  const enrolling = useEnrollment || Boolean(enrollmentSession)
  const member = !!loginInfo?.configured && !loginInfo.local_issuer
  const showLocal = !!flow || enrolling || mode !== 'signin' || directIssuer || localLogin || loginInfo !== undefined && !member
  const title = recoveryCodes ? '保管好你的恢复码' : flow ? flow.method === 'totp_rebind' || flow.method === 'passkey_enroll' ? '登记验证器' : useRecovery ? '恢复账户访问' : '再确认一下，是你本人' : enrollmentSession ? '更换或添加验证器' : enrolling ? '使用本机登记令牌' : mode === 'enroll' ? '继续设置登录方式' : mode === 'recover' ? '恢复账户访问' : localLogin ? '本机恢复登录' : '登录 Spearmint'
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card" aria-labelledby="sign-in-heading">
    <span className="eyebrow">{enrolling ? 'FIRST TIME SETUP' : useRecovery || mode === 'recover' ? 'ACCOUNT RECOVERY' : 'SECURE ACCESS'}</span>
    <h1 id="sign-in-heading">{title}</h1>
    <p className="auth-subtitle">{recoveryCodes ? '每个恢复码只能使用一次，请保存在只有你能访问的安全位置。' : flow ? '完成验证后，继续进入你的 Grove。' : enrolling ? '核对本机授权，继续登记验证器。' : mode === 'enroll' ? '先用账号和密码登录，再在网页扫码设置验证器。首次登记无需控制台令牌。' : '欢迎回来，继续照看你的基础设施。'}</p>
    {!flow && !enrolling && !localLogin && mode === 'signin' && <GroveLoginButton onSession={onSession} onInfo={setLoginInfo} />}
    {!showLocal && loginInfo?.account_management && <div className="auth-links grove-auth-links">
      <a className="text-link" href="#/grove-forgot">忘记密码</a>
      <a className="text-link" href="#/grove-register">接受账号邀请</a>
    </div>}
    {!showLocal && loginInfo === undefined && <Loading label="正在读取登录方式…" />}
    {member && !showLocal && loginInfo.local_login !== false && <div className="auth-local-entry"><button type="button" className="text-link" onClick={() => { setLocalLogin(true); setError('') }}>本机恢复登录</button></div>}
    {member && localLogin && !flow && <button type="button" className="text-link auth-grove-return" onClick={() => { setLocalLogin(false); setError('') }}><Icon name="arrow-left" size={14} />返回 Grove 登录</button>}
    {(showLocal || recoveryCodes) && <>
    {recoveryCodes ? <>
      <div className="auth-success"><Icon name="check-circle" size={23} /><div><strong>验证器已登记</strong><p>原登录会话已注销。保存恢复码后，请使用新验证器登录。</p></div></div>
      <ul className="recovery-codes">{recoveryCodes.map((code) => <li key={code}><code>{code}</code></li>)}</ul>
      <button className="btn btn-primary btn-full" onClick={reset}>已安全保存，返回登录<Icon name="arrow-right" size={16} /></button>
    </> : <>
      {!flow && !enrolling && mode === 'signin' && <Tabs label="登录方式" current={method} onChange={(value) => { setMethod(value); setError('') }} items={[{ id: 'passkey', label: 'Passkey', icon: 'key' }, { id: 'password', label: '密码登录', icon: 'lock' }]} />}
      <form className="auth-form" onSubmit={(event) => {
        if (!flow && !enrolling && method === 'passkey' && mode !== 'recover') { event.preventDefault(); event.currentTarget.querySelector<HTMLButtonElement>('[data-passkey]')?.click() }
        else void submit(event)
      }}>
        {!flow ? <>
          {enrollmentSession && <div className="auth-inline-note">请在使用原因子登录后的 5 分钟内完成登记。更换验证器后，本账户的其他会话也会退出。</div>}
          {enrolling && <div className="auth-inline-note"><Icon name="terminal" size={16} /><span>先在节点终端执行 <code>spearmint setup-totp</code> 或 <code>spearmint setup-passkey</code>，领取一次性登记令牌。</span></div>}
          <label className="field-label">用户名<input className="input" name="username" defaultValue={enrollmentSession?.username ?? 'admin'} readOnly={Boolean(enrollmentSession)} autoComplete="username" required maxLength={64} /></label>
          {(method === 'password' || enrolling || mode === 'recover') && <label className="field-label">密码<span className="password-field"><input className="input" name="password" type={visiblePassword ? 'text' : 'password'} autoComplete="current-password" required maxLength={256} /><button className="icon-button" type="button" aria-label={visiblePassword ? '隐藏密码' : '显示密码'} onClick={() => setVisiblePassword(!visiblePassword)}><Icon name={visiblePassword ? 'eye-off' : 'eye'} size={17} /></button></span></label>}
          {enrolling && <label className="field-label">本机登记令牌<input className="input" name="enrollment_token" type="password" autoComplete="off" required minLength={43} maxLength={43} pattern="[A-Za-z0-9_\-]{43}" placeholder="输入节点终端刚刚生成的令牌" /></label>}
          {!enrolling && method === 'passkey' && mode !== 'recover' && <div className="auth-method"><span><Icon name="key" size={25} /></span><strong>使用 Passkey 登录</strong><p>通过设备上的生物识别、PIN 或安全密钥完成验证。</p></div>}
        </> : flow.method === 'passkey_enroll' ? <div className="auth-method"><span><Icon name="key" size={25} /></span><strong>连接你的验证器</strong><p>请使用设备上的 Passkey 或已连接的安全密钥完成登记。</p></div>
          : flow.method === 'totp_rebind' && !uri ? <div className="auth-method"><span><Icon name="shield-check" size={25} /></span><strong>身份已核验</strong><p>下一步，获取配置并将它导入你的验证器。</p></div>
          : <>
            {uri && <div className="provisioning"><strong>在验证器中添加 Spearmint</strong><AuthenticatorQR uri={uri} /><p>使用验证器 App 扫码，然后输入生成的 6 位验证码。</p><details><summary>无法扫码？手工添加</summary><code>{new URL(uri).searchParams.get('secret')}</code></details></div>}
            <label className="field-label">{useRecovery ? '一次性恢复码' : '动态验证码'}<input className={`input ${useRecovery ? '' : 'otp-input'}`} key={useRecovery ? 'recovery' : 'totp'} name="code" type={useRecovery ? 'password' : 'text'} inputMode={useRecovery ? 'text' : 'numeric'} autoComplete={useRecovery ? 'off' : 'one-time-code'} autoFocus required minLength={useRecovery ? 22 : 6} maxLength={useRecovery ? 22 : 6} pattern={useRecovery ? '[A-Za-z0-9_\-]{22}' : '[0-9]{6}'} placeholder={useRecovery ? '输入一个尚未使用的恢复码' : '000000'} /></label>
            <p className="auth-input-hint">{useRecovery ? '成功恢复后旧会话将退出，随后需要重新绑定验证器。' : '打开你的验证器 App，输入当前显示的验证码。'}</p>
          </>}
        {error && <div className="auth-error" role="alert"><Icon name="alert-triangle" size={17} /><span>{error}</span></div>}
        {!flow && !enrolling && method === 'passkey' && mode !== 'recover' ? <>
          <button data-passkey type="button" className="btn btn-primary btn-full" disabled={pending || !supportsPasskey()} onClick={signInWithPasskey}><Icon name="key" size={17} />{pending ? '正在验证…' : '使用 Passkey 继续'}</button>
          {!supportsPasskey() && <p className="auth-input-hint">此浏览器或地址暂不支持 Passkey，请切换到密码登录。</p>}
        </> : <button className="btn btn-primary btn-full" disabled={pending}>{pending ? '正在验证…' : !flow ? enrolling ? '验证并继续' : '继续登录' : flow.method === 'passkey_enroll' ? '登记 Passkey' : flow.method === 'totp_rebind' && !uri ? '获取验证器配置' : useRecovery ? '验证恢复码' : '确认并继续'}<Icon name="arrow-right" size={16} /></button>}
        {flow?.method === 'totp' && <button type="button" className="text-link auth-alternative" disabled={pending} onClick={() => { setUseRecovery(!useRecovery); setError('') }}>{useRecovery ? '使用动态验证码' : '无法使用验证器？使用恢复码'}</button>}
        {(flow || enrollmentSession) && <button type="button" className="btn btn-ghost" onClick={reset} disabled={pending}><Icon name="arrow-left" size={15} />{enrollmentSession ? '返回控制台' : '返回登录'}</button>}
      </form>
      {mode === 'enroll' && !flow && !enrollmentSession && <button className="text-link auth-alternative" disabled={pending} onClick={() => { setUseEnrollment(!useEnrollment); setError('') }}>{useEnrollment ? '返回网页首次设置' : '命名账户或恢复：使用本机登记令牌'}</button>}
      <p className="auth-footnote"><Icon name="shield-check" size={15} />本地认证 · 会话保护 · 分层授权</p>
      {!enrollmentSession && <div className="auth-links"><a href={enrolling ? '#/signin' : '#/auth-enroll'} className="text-link">{enrolling ? '返回普通登录' : '首次使用 / 设置登录验证'}</a><a href={mode === 'recover' ? '#/signin' : '#/auth-recover'} className="text-link">{mode === 'recover' ? '返回登录' : '恢复访问'}</a></div>}
    </>}
    </>}
  </section><div className="auth-copyright">Spearmint · Your infrastructure. Your Grove.</div></div></div>
}
