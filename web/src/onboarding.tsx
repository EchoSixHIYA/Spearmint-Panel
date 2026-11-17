import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { createPasskey, supportsPasskey } from './webauthn'
import { AuthStory, CopyValue, Icon, Loading, Tabs } from './ui'
import { groveError } from './grove-auth'
import { isAutomaticQuorumInvitation, isQuorumInvitation, isSignedGroveInvitation, parseGroveInvitation, type GroveRealm } from './grove-invitation'
import { GroveInvitationField } from './grove-invitation-fields'
import { startBrowserJoin } from './grove-join'
import { parseSetupEntry } from './setup-entry'

type Flow = { flow_id: string; method: string; expires_at: number }
type FactorInfo = { eligible: boolean; recent: boolean; passkey_available: boolean; grove_totp?: boolean }

export function takeSetupEntry() {
  const entry = parseSetupEntry(location.hash)
  if (location.hash.startsWith('#/setup/')) history.replaceState(null, '', `${location.pathname}${location.search}#/setup`)
  return entry
}

export function AuthenticatorQR({ uri }: { uri: string }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    let active = true
    setError(false)
    void import('qrcode').then(async (qr) => {
      if (active && canvas.current) await qr.toCanvas(canvas.current, uri, { width: 224, margin: 4, errorCorrectionLevel: 'M', color: { dark: '#173b2c', light: '#ffffff' } })
    }).catch(() => { if (active) setError(true) })
    return () => { active = false }
  }, [uri])
  return <div className="authenticator-qr"><canvas ref={canvas} aria-label="使用验证器 App 扫描此二维码" role="img" />{error && <p role="status">二维码暂不可用，请展开下方的手工配置。</p>}</div>
}

function ErrorMessage({ children }: { children: string }) {
  return children ? <div className="auth-error" role="alert"><Icon name="alert-triangle" size={17} /><span>{children}</span></div> : null
}

export function Setup({ token, initialRealm, expired, localBrowser, onCreated }: {
  token: string; initialRealm?: GroveRealm; expired: boolean; localBrowser: boolean; onCreated: (session: Session, quorumCode?: string) => void
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const [ownerCode, setOwnerCode] = useState(expired ? '' : token)
  const [visible, setVisible] = useState(false)
  const [mode, setMode] = useState(initialRealm ? 'join' : 'create')
  const [invitation, setInvitation] = useState<string>()
  const realm = invitation === undefined ? initialRealm : parseGroveInvitation(invitation)
  const quorumCode = mode === 'join' && invitation && isQuorumInvitation(invitation) ? invitation : undefined
  const canJoin = !!realm || isSignedGroveInvitation(invitation ?? '')
  const code = ownerCode.trim()
  const ownerReady = localBrowser || /^[A-Za-z0-9_-]{43}$/.test(code)
  useEffect(() => { document.title = '首次配置 · Spearmint' }, [])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!ownerReady) return
    const form = event.currentTarget
    const values = new FormData(form)
    if (values.get('password') !== values.get('confirmation')) { setError('两次输入的密码不一致，请再检查一下。'); return }
    setPending(true); setError('')
    try {
      const session = await api<Session>('/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: localBrowser ? null : code, username: values.get('username'), password: values.get('password'), confirmation: values.get('confirmation'), grove_name: values.get('grove_name') }) })
      form.reset(); onCreated(session, quorumCode)
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) setError(localBrowser
        ? '首次配置已结束或暂时不可用，请刷新后重试。' : '配置代码无效或已过期，请向部署者获取当前的配置代码。')
      else setError(failure instanceof ApiError && failure.status === 429 ? '尝试次数较多，请稍后再试。' : '暂时无法创建账户，请检查连接后重试。')
    } finally { setPending(false) }
  }
  async function join() {
    if (!canJoin || !ownerReady) return
    setPending(true); setError('')
    try {
      const result = await startBrowserJoin(invitation ?? '', realm, { headers: { 'Content-Type': 'application/json' },
        setupToken: localBrowser ? null : code })
      location.assign(result.authorize_url)
    } catch (failure) { setError(groveError(failure)); setPending(false) }
  }
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card setup-card" aria-labelledby="setup-title">
    <span className="eyebrow">WELCOME TO YOUR GROVE</span><div className="setup-progress"><span className="active">1 选择你的 Grove</span><i /><span>2 账号与登录验证</span></div>
    <h1 id="setup-title">从这里，开始你的 Grove。</h1><p className="auth-subtitle">只需设置账号和登录方式，剩下的交给 Spearmint。</p>
    {!localBrowser && <div className="stack-small setup-join">
      <label className="field-label">节点配置代码<input className="input" type="password" autoComplete="off"
        value={ownerCode} onChange={(event) => { setOwnerCode(event.target.value); setError('') }} disabled={pending} /></label>
      <p className="muted">请向这台节点的部署者获取一次性配置代码。</p>
    </div>}
    <Tabs label="首次配置方式" current={mode} onChange={(value) => { setMode(value); setError('') }} items={[{ id: 'create', label: '创建新 Grove', icon: 'sprout' }, { id: 'join', label: '加入已有 Grove', icon: 'network' }]} />
    {mode === 'join' ? <div className="setup-join stack-small">
      <p className="muted">从已有 Grove 的「用户与授权」复制邀请代码。Spearmint 会自动找到可认证的成员。</p>
      <GroveInvitationField code={invitation ?? ''} realm={realm} disabled={pending}
        onChange={(value) => { setInvitation(value); setError('') }} />
      {quorumCode ? <p className="muted">{isAutomaticQuorumInvitation(quorumCode)
        ? '先设置本机管理员，再验证 Grove 账号。获多数批准后会自动完成 Mesh 配对。'
        : '先设置本机管理员。节点完成 Mesh 配对并获多数批准后，可用此邀请码加入 Grove。'}</p> : <>
        <ErrorMessage>{error}</ErrorMessage>
        <button className="btn btn-primary btn-full" disabled={pending || !canJoin || !ownerReady} onClick={() => void join()}>
        {pending ? '正在查找认证成员…' : '前往 Grove 登录并确认加入'}<Icon name="arrow-right" size={16} />
        </button>
      </>}
    </div> : null}
    {(mode !== 'join' || quorumCode) && <form className="auth-form" onSubmit={(event) => void submit(event)}>
      <div className="auth-inline-note"><Icon name="shield-check" size={17} /><span>你正在配置一台新节点。这个入口只用于首次创建管理员，完成后自动失效。</span></div>
      {!quorumCode && <label className="field-label">Grove 名称<input className="input" name="grove_name" defaultValue="我的 Grove" required maxLength={40} /></label>}
      <label className="field-label">管理员用户名<input className="input" name="username" defaultValue="admin" required pattern="[a-z0-9][a-z0-9._\-]{0,63}" maxLength={64} autoComplete="username" autoFocus /></label><p className="auth-input-hint">使用小写字母、数字、点、短横线或下划线。</p>
      <label className="field-label">设置密码<span className="password-field"><input className="input" name="password" type={visible ? 'text' : 'password'} required minLength={12} maxLength={256} autoComplete="new-password" /><button type="button" className="icon-button" aria-label={visible ? '隐藏密码' : '显示密码'} onClick={() => setVisible(!visible)}><Icon name={visible ? 'eye-off' : 'eye'} size={17} /></button></span></label><p className="auth-input-hint">至少 12 个字符，建议使用密码管理器生成和保存。</p>
      <label className="field-label">确认密码<input className="input" name="confirmation" type={visible ? 'text' : 'password'} required minLength={12} maxLength={256} autoComplete="new-password" /></label><ErrorMessage>{error}</ErrorMessage>
      <button className="btn btn-primary btn-full" disabled={pending || !ownerReady}>{pending ? '正在创建…' : '创建管理员并继续'}<Icon name="arrow-right" size={16} /></button>
    </form>}
    <div className="auth-links"><a href="#/signin" className="text-link" onClick={() => location.reload()}>已经配置过？返回登录</a></div>
  </section><div className="auth-copyright">Spearmint · Your infrastructure. Your Grove.</div></div></div>
}

export function FirstFactor({ session, onExit, onUnauthorized, reauthenticating, reauthenticationError, onReauthenticate }: {
  session: Session; onExit: (completed: boolean) => void; onUnauthorized: () => void
  reauthenticating: boolean; reauthenticationError: string; onReauthenticate: () => void
}) {
  const [info, setInfo] = useState<FactorInfo>()
  const [flow, setFlow] = useState<Flow>()
  const [uri, setUri] = useState('')
  const [codes, setCodes] = useState<string[]>()
  const [saved, setSaved] = useState(false)
  const [pending, setPending] = useState(false)
  const [reauthenticationRequired, setReauthenticationRequired] = useState(false)
  const [error, setError] = useState('')
  const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }
  useEffect(() => {
    let active = true
    document.title = '设置登录验证 · Spearmint'
    api<FactorInfo>('/auth/first-factor').then((value) => { if (active) setInfo(value) }).catch((failure) => {
      if (!active) return
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError('无法读取登录验证设置，请检查连接后重试。')
    })
    return () => { active = false }
  }, [onUnauthorized])
  async function post<T>(path: string, body: object) { return api<T>(path, { method: 'POST', headers, body: JSON.stringify(body) }) }
  function showError(failure: unknown) {
    if (failure instanceof ApiError && failure.status === 401 && !flow) onUnauthorized()
    else if (failure instanceof ApiError && failure.code === 'REAUTHENTICATION_REQUIRED') {
      setFlow(undefined); setUri(''); setReauthenticationRequired(true)
    } else setError(failure instanceof ApiError && failure.status === 401 ? '验证码无效或这次配置已过期。请核对当前验证码，或重新开始配置。'
      : failure instanceof ApiError && failure.status === 429 ? '尝试次数较多，请稍后再试。' : '这次配置未完成，可以重试或稍后继续。')
  }
  async function begin(method: 'totp' | 'passkey') {
    setPending(true); setError(''); setFlow(undefined); setUri('')
    try {
      const next = await post<Flow>('/auth/first-factor', { method })
      if (method === 'totp') setUri((await post<{ provisioning_uri: string }>('/auth/totp/register/options', { flow_id: next.flow_id })).provisioning_uri)
      setFlow(next)
    } catch (failure) { showError(failure) }
    finally { setPending(false) }
  }
  async function finish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!flow) return
    const form = event.currentTarget; const values = new FormData(form)
    setPending(true); setError('')
    try {
      const result = flow.method === 'passkey_enroll'
        ? await (async () => { const options = await post<{ public_key: PublicKeyCredentialCreationOptionsJSON }>('/auth/passkey/register/options', { flow_id: flow.flow_id }); const credential = await createPasskey(options.public_key); return post<{ recovery_codes: string[] }>('/auth/passkey/register/finish', { flow_id: flow.flow_id, credential }) })()
        : await post<{ recovery_codes: string[] }>('/auth/totp/register/finish', { flow_id: flow.flow_id, code: values.get('code') })
      setCodes(result.recovery_codes); setUri(''); setFlow(undefined); form.reset()
    } catch (failure) { showError(failure) }
    finally { setPending(false) }
  }
  function downloadCodes() {
    if (!codes) return
    const url = URL.createObjectURL(new Blob([`Spearmint recovery codes — ${session.username}\nEach code can be used once. Keep this file private.\n\n${codes.join('\n')}\n`], { type: 'text/plain;charset=utf-8' }))
    const link = document.createElement('a'); link.href = url; link.download = 'spearmint-recovery-codes.txt'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  const passkey = info?.passkey_available && supportsPasskey()
  const needsSignIn = reauthenticationRequired || (info?.eligible && !info.recent)
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card setup-card" aria-labelledby="factor-title">
    <span className="eyebrow">MAKE YOUR GROVE YOURS</span><div className="setup-progress"><span className="done"><Icon name="check" size={13} />管理员已就绪</span><i /><span className="active">{codes ? '2 保存恢复码' : '2 设置登录验证'}</span></div>
    <h1 id="factor-title">{codes ? '把备用钥匙，留在安全的地方。' : flow ? flow.method === 'passkey_enroll' ? '连接你的 Passkey。' : '扫一扫，完成登录验证。' : info?.grove_totp ? '为 Grove 登录添加动态验证码' : '选择你习惯的登录方式。'}</h1>
    <p className="auth-subtitle">{codes ? '验证器已经启用。这些恢复码只展示一次，每个只能使用一次。' : flow ? '全程在这个页面完成，无需切换到控制台。' : info?.grove_totp ? '添加后可在支持成员侧登录的面板使用原账号、密码和验证码。原 Passkey 也可以继续在原节点使用。' : `${session.username}，你的账号已经可以使用。再加一道登录验证，让访问更安心。`}</p>
    {codes ? <><div className="auth-success"><Icon name="shield-check" size={24} /><div><strong>登录验证已开启</strong><p>下次登录请使用刚刚设置的验证器。</p></div></div><ul className="recovery-codes">{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul><button className="btn btn-secondary btn-full" onClick={downloadCodes}><Icon name="download" size={16} />下载恢复码</button><label className="inline-checkbox recovery-saved"><input type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} />我已将恢复码保存到安全的位置</label><button className="btn btn-primary btn-full" disabled={!saved} onClick={() => onExit(true)}>完成设置，前往登录<Icon name="arrow-right" size={16} /></button></>
      : flow ? <form className="auth-form" onSubmit={(event) => void finish(event)}>{flow.method === 'passkey_enroll' ? <div className="auth-method"><span><Icon name="key" size={28} /></span><strong>使用设备上的指纹、面容或安全密钥</strong><p>点击下方按钮，由浏览器带你完成登记。</p></div> : <>{uri ? <><AuthenticatorQR key={uri} uri={uri} /><p className="auth-input-hint qr-hint">打开验证器 App，扫描二维码，然后输入当前的 6 位验证码。</p><details className="manual-authenticator"><summary>无法扫码？手工添加</summary><p>在验证器中选择手工添加账户，使用下面的密钥。</p><CopyValue value={new URL(uri).searchParams.get('secret') || ''} /></details><label className="field-label">动态验证码<input className="input otp-input" name="code" inputMode="numeric" autoComplete="one-time-code" required minLength={6} maxLength={6} pattern="[0-9]{6}" placeholder="000000" autoFocus /></label></> : <Loading label="正在准备二维码…" />}</>}
        <ErrorMessage>{error}</ErrorMessage><button className="btn btn-primary btn-full" disabled={pending || flow.method !== 'passkey_enroll' && !uri}>{pending ? '正在验证…' : flow.method === 'passkey_enroll' ? '登记 Passkey' : '验证并启用'}<Icon name="arrow-right" size={16} /></button><button className="btn btn-ghost btn-full" type="button" disabled={pending} onClick={() => { setFlow(undefined); setUri(''); setError('') }}>重新选择登录方式</button></form>
        : <>{!info && !error ? <Loading /> : needsSignIn ? <div className="setup-owner-note"><Icon name="shield" size={28} />
          <p>{info?.grove_totp ? '请使用已有 Passkey 重新登录后继续。' : '你的管理员账号已保存。请重新登录后继续设置验证器。'}</p>
          <button className="btn btn-primary btn-full" disabled={reauthenticating} onClick={onReauthenticate}>{reauthenticating ? '正在退出当前会话…' : '重新登录并继续'}</button>
        </div> : info && !info.eligible ? <div className="setup-owner-note"><Icon name="shield" size={28} /><p>当前账户不适用首次验证器设置。已有验证器的更换与恢复，请从账户安全页面继续。</p></div>
          : info && <div className="authenticator-choices"><button className="authenticator-choice" disabled={pending} onClick={() => void begin('totp')}><span className="service-symbol"><Icon name="smartphone" size={24} /></span><span><strong>验证器 App</strong><p>扫码添加，登录时输入 6 位动态验证码。</p></span><Icon name="chevron-right" size={18} /></button>{!info.grove_totp && <button className="authenticator-choice" disabled={!passkey || pending} onClick={() => void begin('passkey')}><span className="service-symbol"><Icon name="key" size={24} /></span><span><strong>Passkey</strong><p>{passkey ? '使用指纹、面容或安全密钥快速登录。' : '需要固定 HTTPS 域名和支持 Passkey 的浏览器。'}</p></span><Icon name="chevron-right" size={18} /></button>}</div>}
        <ErrorMessage>{error || reauthenticationError}</ErrorMessage><button className="btn btn-ghost btn-full" disabled={pending || reauthenticating} onClick={() => onExit(false)}>{info?.eligible && !info.grove_totp && !needsSignIn ? '稍后再设置，进入 Grove' : '返回控制台'}</button></>}
  </section><div className="auth-copyright">Spearmint · Your infrastructure. Your Grove.</div></div></div>
}
