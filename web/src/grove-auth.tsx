import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { Badge, CopyValue, EmptyState, Icon, Loading, Modal, Notice, Panel, AuthStory, shortId } from './ui'
import { groveReturnRoute, seedJoinTarget } from './grove-navigation'
import { memberPanelOrigin, publicPanelLabel, type DirectoryMember, type MemberDirectoryVersion } from './grove-directory'
import { isAutomaticQuorumInvitation, isQuorumInvitation, isSignedGroveInvitation, parseGroveInvitation, takeQuorumInvitation, type GroveRealm } from './grove-invitation'
import { CopyGroveInvitation, GroveInvitationField } from './grove-invitation-fields'
import { startBrowserJoin } from './grove-join'

export type GroveInfo = { configured: boolean; realm?: GroveRealm; local_issuer?: boolean; frozen?: string; issuer_paused?: boolean;
  member_login?: boolean; issuer_retired?: boolean; continuity_configured?: boolean; operator_revocation?: 'available' | 'awaiting-quorum';
  recovery_admin?: string; role_votes?: string[];
  identity_voter?: boolean;
  directory_requested_at?: Record<string, number>; directory_mesh_requested_at?: Record<string, number>;
  member_directory?: MemberDirectoryVersion;
  members?: DirectoryMember[]; users?: { id: string; name: string; role: string; enabled: boolean; require_mfa?: boolean; can_suspend?: boolean }[]; valid_until?: number; sequence?: number }

type DirectorySyncReport = {
  realm_id: string; previous_sequence: string | null; member_directory: MemberDirectoryVersion;
  source: 'issuer-mesh' | 'issuer-https' | 'member-https' | 'neighbor' | 'local-issuer' | 'member-quorum' | 'member-standby'
}

const directorySources = {
  'issuer-mesh': '已通过 Mesh 向签发节点核对。', 'issuer-https': '已通过 HTTPS 向签发节点核对。',
  'member-https': '已通过成员面板核对签名目录。',
  neighbor: '已核对邻居缓存的签名目录，签发节点的最新版本待确认。', 'local-issuer': '已在签发节点核对。',
  'member-quorum': '在线成员已共同续期身份目录。',
  'member-standby': '原身份节点暂不可达，在线成员已共同续期备用身份目录。',
}

export function useGroveDirectorySync(realmId: string | undefined, csrfToken: string, onUnauthorized: () => void) {
  const [checking, setChecking] = useState(false)
  const [message, setMessage] = useState<{ realmId: string; text: string; error?: boolean }>()
  const inFlight = useRef(false)

  async function sync() {
    if (!realmId || inFlight.current) return undefined
    inFlight.current = true
    setChecking(true)
    setMessage(undefined)
    try {
      const result = await api<DirectorySyncReport | undefined>('/grove/sync-directory?report=true', {
        method: 'POST', headers: { 'X-CSRF-Token': csrfToken }, signal: AbortSignal.timeout(40_000),
      })
      if (!result) setMessage({ realmId, text: '已检查身份目录，可查看当前同步版本。' })
      else if (result.realm_id === realmId) {
        const { previous_sequence: previous, member_directory: { sequence }, source } = result
        const change = previous === null ? `首次同步到第 ${sequence} 版。` : previous === sequence ? `本机目录仍为第 ${sequence} 版。`
          : `本机目录从第 ${previous} 版更新到第 ${sequence} 版。`
        setMessage({ realmId, text: `${change}${directorySources[source]}` })
      } else return undefined
      return { sequence: result?.member_directory.sequence }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else {
        const code = failure instanceof ApiError ? failure.code : undefined
        setMessage({ realmId,
          text: code === 'BUSY' ? '当前节点正在同步，请稍后查看目录版本。'
            : code === 'CONFLICT' ? 'Grove 配置已变化或正在等待恢复，请查看当前状态。'
              : '暂时无法获取有效目录，请检查 Mesh 连接或签发节点的 HTTPS 入口。',
          error: code !== 'BUSY',
        })
      }
    } finally {
      inFlight.current = false
      setChecking(false)
      window.dispatchEvent(new Event('spearmint:refresh'))
    }
  }

  return { checking, sync, message: message?.realmId === realmId ? message : undefined }
}

export function downloadGroveInvitation(realm: GroveRealm) {
  downloadGroveFile(realm, 'spearmint-invitation.grove.json')
}

function downloadGroveFile(value: object, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const serviceReturnKey = 'spearmint-grove-service-return'

export function takeGroveDestination() {
  const destination = sessionStorage.getItem(serviceReturnKey)
  sessionStorage.removeItem(serviceReturnKey)
  return groveReturnRoute(destination || '')
}

export function takeGroveReturn() {
  const match = /^#\/grove-return\/([A-Za-z0-9_-]{1,12000})$/.exec(location.hash)
  if (location.hash.startsWith('#/grove-return/')) history.replaceState(null, '', `${location.pathname}${location.search}#/grove-return`)
  return match?.[1] || ''
}

export function groveError(failure: unknown) {
  if (failure instanceof ApiError) {
    if (failure.code === 'GROVE_PAIRING_REQUIRED') return '请先让此节点与 Grove 的投票成员完成 Mesh 配对。'
    if (failure.code === 'GROVE_ADMISSION_PENDING') return '在线配对成员暂未提供此节点的有效多数审批。请核对目标 Node ID 和面板地址，批准后重试。'
    if (failure.code === 'GROVE_NO_VERIFIER') return '邀请码中的成员暂时无法认证。请检查浏览器能否访问成员，稍后重试或重新复制邀请代码。'
    if (failure.code === 'GROVE_INVITATION_NEEDS_REFRESH' || failure.code === 'GROVE_INVITATION_EXPIRED') return '请从已有 Grove 重新复制邀请代码，再继续加入。'
    if (failure.status === 401) return '登录已过期，请重新登录后继续。'
    if (failure.code === 'REAUTHENTICATION_REQUIRED') return '请在当前成员面板重新登录 Grove，再批准节点加入。'
    if (failure.code === 'EXPIRED') return '这次登录已过期，请从原节点重新开始。'
    if (failure.code === 'DENIED') return '暂时无法使用这个 Grove 身份，请核对加入信息、节点地址和登录状态。'
    if (failure.code === 'CONFLICT') return '当前节点的 Grove 配置或身份版本已经变化，请重新检查。'
    if (failure.status === 429) return '尝试次数较多，请稍后再试。'
  }
  return '暂时无法完成 Grove 登录，请检查连接后重试。'
}

export function GroveLoginButton({ onSession, authorizeRequest, onIssuer }: {
  onSession: (session: Session) => void; authorizeRequest?: string; onIssuer?: (direct: boolean) => void
}) {
  const [info, setInfo] = useState<GroveInfo>()
  const [error, setError] = useState(''); const [pending, setPending] = useState(false)
  const [local, setLocal] = useState(false)
  const [destination, setDestination] = useState<string>()
  useEffect(() => {
    let active = true
    async function load() {
      try {
        const current = await api<GroveInfo>('/auth/grove/info')
        if (!active) return
        setInfo(current)
        if (authorizeRequest && current.local_issuer) onIssuer?.(true)
        else if (authorizeRequest) {
          const result = await api<{ name: string }>('/auth/grove/join-destination', { method: 'POST',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ request: authorizeRequest }) })
          if (active) setDestination(result.name)
        }
      } catch {
        if (active && authorizeRequest) setError('这个面板当前无法验证该请求。请返回新节点，重新查找可用的 Grove 成员。')
      }
    }
    void load()
    return () => { active = false }
  }, [authorizeRequest, onIssuer])
  async function start() {
    setPending(true); setError('')
    try {
      const result = await api<{ authorize_url: string }>('/auth/grove/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind: 'login' }) })
      sessionStorage.setItem(serviceReturnKey, groveReturnRoute(location.hash))
      location.assign(result.authorize_url)
    }
    catch (failure) { setError(groveError(failure)); setPending(false) }
  }
  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setPending(true); setError('')
    try {
      const session = await api<Session>('/auth/grove/member-login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: fields.get('grove_username'), password: fields.get('grove_password'),
          code: fields.get('grove_code') || null }),
      })
      onSession(session)
    } catch (failure) {
      setError(failure instanceof ApiError && failure.status === 401
        ? '账号、密码或动态验证码不正确。启用了动态验证码的账号需要填写当前验证码。' : groveError(failure))
    } finally { setPending(false) }
  }
  if (authorizeRequest && !info?.local_issuer && !destination) return error
    ? <p className="error" role="alert">{error}</p> : <Loading label="正在核对此 Grove 成员…" />
  if (!info?.configured || info.local_issuer) return null
  const issuerOrigin = info.realm?.issuer_origin && memberPanelOrigin(info.realm.issuer_origin)
  const issuer = issuerOrigin ? new URL(issuerOrigin) : undefined
  const loopback = issuer && (issuer.hostname === 'localhost' || issuer.hostname === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(issuer.hostname))
  const fallbackAvailable = !info.issuer_retired && !!issuer && !loopback
  return <div className="grove-login">
    <div className="grove-login-label"><Icon name="leaf" size={19} /><span>已加入 <strong>{info.realm?.name}</strong></span></div>
    {local || destination ? <form className="auth-form" onSubmit={event => void signIn(event)}>
      <label className="field-label">Grove 用户名<input className="input" name="grove_username" autoComplete="username" maxLength={64} required /></label>
      <label className="field-label">Grove 密码<input className="input" name="grove_password" type="password" autoComplete="current-password" maxLength={256} required /></label>
      <label className="field-label">动态验证码（启用时填写）<input className="input" name="grove_code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} /></label>
      <button className="btn btn-primary btn-full" disabled={pending}>{pending ? '正在验证…' : '登录 Grove'}</button>
      {!destination && fallbackAvailable && <button type="button" className="text-link" disabled={pending} onClick={() => void start()}>前往身份节点登录</button>}
    </form> : <button className="btn btn-primary btn-full" disabled={pending || (!fallbackAvailable && !info.member_login)} onClick={() => {
      if (info.member_login) setLocal(true)
      else void start()
    }}>
      <Icon name="shield-check" size={17} />{pending ? '正在前往身份节点…' : '使用 Grove 账号登录'}<Icon name="arrow-right" size={16} />
    </button>}
    {info.member_login ? <p>在当前成员验证你的 Grove 账号。</p>
      : !fallbackAvailable ? <p>正在同步 Grove 登录授权。现在可使用下方的节点账号登录。</p>
        : <p>Grove 登录需要浏览器能访问{issuer ? `身份节点 ${issuer.host}` : '身份节点'}。</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {!destination && <div className="auth-divider"><span>或使用本机账号</span></div>}
  </div>
}

export function GroveAuthorize({ request, session, signedInForRequest, onReauthenticate, reauthenticating, reauthenticationError }: {
  request: string; session: Session; signedInForRequest: boolean;
  onReauthenticate: () => void; reauthenticating: boolean; reauthenticationError: string
}) {
  const [info, setInfo] = useState<{ kind: string; node_id: string; origin: string; grove: string; username: string; role: string }>()
  const [pending, setPending] = useState(false); const [error, setError] = useState('')
  const [needsSignIn, setNeedsSignIn] = useState(false)
  const verifyJoin = info?.kind === 'join' && !signedInForRequest
  const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }

  function showError(failure: unknown) {
    setNeedsSignIn(failure instanceof ApiError && (failure.status === 401 || failure.code === 'REAUTHENTICATION_REQUIRED'))
    setError(groveError(failure))
  }

  useEffect(() => {
    let active = true; document.title = '确认 Grove 登录 · Spearmint'
    api<typeof info>('/auth/grove/inspect', { method: 'POST', headers, body: JSON.stringify({ request }) }).then((value) => { if (active) setInfo(value) }).catch((failure) => { if (active) showError(failure) })
    return () => { active = false }
  }, [request, session.csrf_token])
  async function approve() {
    if (!info || needsSignIn || verifyJoin) return
    setPending(true); setError('')
    try { const result = await api<{ redirect_url: string }>('/auth/grove/approve', { method: 'POST', headers, body: JSON.stringify({ request }) }); location.assign(result.redirect_url) }
    catch (failure) {
      if (failure instanceof ApiError && ['OFFLINE', 'TIMEOUT', 'NOT_FOUND', 'ROUTE_LOST', 'UNSUPPORTED_METHOD'].includes(failure.code ?? '')) {
        setError('成员面板当前无法经 Mesh 完成签发。请返回新节点重新查找，或等待签发节点恢复。')
      } else showError(failure)
      setPending(false)
    }
  }
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card setup-card"><span className="eyebrow">ONE IDENTITY. YOUR GROVE.</span><h1>{info?.kind === 'join' ? '让这台节点加入 Grove？' : '继续登录这个节点？'}</h1><p className="auth-subtitle">{info?.kind === 'join' ? '确认设备和地址，再沿用你已经建立的管理员身份。' : '使用同一个 Grove 账号，回到你刚刚访问的节点。'}</p>
    {!info && !error ? <Loading /> : info && <><div className="grove-approval-identity"><Icon name="shield-check" size={27} /><div><strong>{info.username}</strong><small>{info.grove} · {info.role === 'node_admin' ? '管理员' : '操作员'}</small></div></div><dl className="facts"><div><dt>目标地址</dt><dd className="break-anywhere">{info.origin}</dd></div><div><dt>目标身份</dt><dd><CopyValue value={info.node_id} short /></dd></div><div><dt>确认内容</dt><dd>{info.kind === 'join' ? '将节点加入当前 Grove，并登录管理界面' : '使用当前 Grove 身份登录目标节点'}</dd></div></dl><Notice>目标节点只接收签发的短期证明。</Notice>{!needsSignIn && !verifyJoin && <button className="btn btn-primary btn-full" disabled={pending} onClick={() => void approve()}>{pending ? '正在确认…' : info.kind === 'join' ? '确认加入并继续' : '确认并返回目标节点'}<Icon name="arrow-right" size={16} /></button>}</>}
    {error && <p className="error" role="alert">{error}</p>}
    {(needsSignIn || verifyJoin) && <button type="button" className="btn btn-primary btn-full" disabled={reauthenticating} onClick={onReauthenticate}>
      {reauthenticating ? '正在退出当前会话…' : '登录 Grove 并验证身份'}<Icon name="arrow-right" size={16} />
    </button>}
    {reauthenticationError && <p className="error" role="alert">{reauthenticationError}</p>}
    <a className="btn btn-ghost btn-full" href="#/overview">取消，返回我的 Grove</a></section></div></div>
}

export function GroveReturn({ request, onSession }: { request: string; onSession: (session: Session) => void }) {
  const [error, setError] = useState(''); const started = useRef(false)
  useEffect(() => {
    if (started.current) return
    started.current = true; document.title = '正在进入 Grove · Spearmint'
    api<Session>('/auth/grove/finish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ request }) }).then(onSession).catch((failure) => setError(groveError(failure)))
  }, [request, onSession])
  return <div className="auth-layout"><AuthStory /><div className="auth-form-wrap"><section className="auth-form-card"><span className="eyebrow">WELCOME TO YOUR GROVE</span><h1>{error ? '这次登录还没完成。' : '正在进入你的 Grove。'}</h1>{error ? <><p className="error" role="alert">{error}</p><button className="btn btn-primary btn-full" onClick={() => location.assign(location.origin + '/#/signin')}>返回节点入口</button></> : <Loading label="正在核对身份并建立本机会话…" />}</section></div></div>
}

export function GroveCard({ session, data, error, members, names, icons, directoryCurrent, directoryLoading, memberPanelOrigins, onUnauthorized, openJoin }: {
  session: Session; data?: GroveInfo; error: string; members?: GroveInfo['members'];
  names: ReadonlyMap<string, string>;
  icons?: ReadonlyMap<string, string>;
  directoryCurrent: boolean; directoryLoading: boolean; memberPanelOrigins: ReadonlyMap<string, string>; onUnauthorized: () => void; openJoin?: boolean
}) {
  const [name, setName] = useState('我的 Grove'); const [pending, setPending] = useState(false); const [message, setMessage] = useState('')
  const [initialInvitation] = useState(takeQuorumInvitation)
  const [invitation, setInvitation] = useState(initialInvitation); const [joinError, setJoinError] = useState('')
  const [resumeJoin, setResumeJoin] = useState(false)
  const realm = parseGroveInvitation(invitation)
  const quorumCode = isQuorumInvitation(invitation)
  const automaticJoin = isAutomaticQuorumInvitation(invitation)
  const canJoin = !!realm || isSignedGroveInvitation(invitation) || quorumCode
  const [confirmRetirement, setConfirmRetirement] = useState(false)
  const [retirementDelivery, setRetirementDelivery] = useState<{ delivered: number; required: number }>()
  const retirementIncomplete = retirementDelivery && retirementDelivery.delivered < retirementDelivery.required
  const [operatorToRevoke, setOperatorToRevoke] = useState<{ id: string; name: string }>()
  const [roleChange, setRoleChange] = useState<{ id: string; name: string; role: 'node_admin' | 'remote_operator' }>()
  const [revocation, setRevocation] = useState('')
  const directorySync = useGroveDirectorySync(data?.realm?.id, session.csrf_token, onUnauthorized)
  const joinForm = useRef<HTMLDetailsElement>(null)
  useEffect(() => {
    if (openJoin && data?.configured === false) joinForm.current?.scrollIntoView({ block: 'center' })
  }, [openJoin, data?.configured])
  const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }
  async function create(event: FormEvent) {
    event.preventDefault(); setPending(true); setMessage('')
    try { await api('/grove', { method: 'POST', headers, body: JSON.stringify({ name }) }); window.dispatchEvent(new Event('spearmint:refresh')) }
    catch (failure) { setMessage(groveError(failure)) } finally { setPending(false) }
  }
  async function memberAdmission(event: FormEvent<HTMLFormElement>, joining: boolean) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const nodeId = String(fields.get('node_id') ?? '').trim()
    setPending(true); setMessage(''); setRevocation('')
    try {
      const body = joining ? { node_id: nodeId } : { node_id: nodeId, origin: String(fields.get('origin') ?? '').trim() }
      const result = await api<{ name?: string; approved?: number; required?: number; applied?: boolean }>(
        joining ? '/grove/join-from-member' : '/grove/members/admit', { method: 'POST', headers, body: JSON.stringify(body) })
      setRevocation(joining ? `已加入 ${result.name}，正在同步 Grove 登录状态。`
        : result.applied ? '成员审批已生效。请在目标面板选择「通过在线成员加入」。'
          : `已批准 ${result.approved} / ${result.required}。请在其他身份成员核对同一个节点并批准。`)
      window.dispatchEvent(new Event('spearmint:refresh'))
    } catch (failure) {
      setMessage(failure instanceof ApiError && failure.code === 'REAUTHENTICATION_REQUIRED'
        ? '请重新登录后再确认。' : failure instanceof ApiError ? failure.message : '暂时无法处理成员申请。')
    } finally { setPending(false) }
  }
  async function join(credentials?: FormData) {
    if (!canJoin) return
    setPending(true); setJoinError('')
    try {
      if (quorumCode) {
        const body = automaticJoin ? { invitation: invitation.trim(), credentials: credentials ? {
          username: credentials.get('username'), password: credentials.get('password'), code: credentials.get('code'),
        } : undefined } : { code: invitation.trim() }
        const joined = await api<GroveRealm>(automaticJoin ? '/grove/join-with-quorum' : '/grove/join-from-invitation',
          { method: 'POST', headers, body: JSON.stringify(body) })
        setRevocation(`已加入 ${joined.name}，正在同步多数续期后的 Grove 登录状态。`)
        setPending(false)
        window.dispatchEvent(new Event('spearmint:refresh'))
        return
      }
      const result = await startBrowserJoin(invitation, realm, { headers })
      if (openJoin && seedJoinTarget(location.hash)) {
        try { sessionStorage.setItem(serviceReturnKey, location.hash) } catch { /* The standard overview can still open. */ }
      }
      location.assign(result.authorize_url)
    }
    catch (failure) {
      if (automaticJoin && failure instanceof ApiError && ['OFFLINE', 'GROVE_PAIRING_REQUIRED'].includes(failure.code ?? '')) setResumeJoin(true)
      setJoinError(automaticJoin && failure instanceof ApiError && failure.code === 'GROVE_ADMISSION_PENDING'
        ? '尚未取得多数批准。请检查管理员凭据和验证节点是否在线，使用下一组动态验证码重试。' : groveError(failure))
      setPending(false)
    }
  }
  async function retire() {
    setPending(true); setMessage('')
    try {
      const { authorization, delivered, required } = await api<{ authorization: object; delivered: number; required: number }>(
        '/grove/retire-issuer', { method: 'POST', headers })
      downloadGroveFile(authorization, 'spearmint-continuity.grove.json')
      setRetirementDelivery({ delivered, required })
      setConfirmRetirement(false)
    } catch (failure) {
      setMessage(failure instanceof ApiError && failure.code === 'REAUTHENTICATION_REQUIRED'
        ? '请先重新登录当前节点，再继续退役。' : failure instanceof ApiError ? failure.message : '暂时无法完成交接。')
    } finally {
      setPending(false)
      window.dispatchEvent(new Event('spearmint:refresh'))
    }
  }
  async function revokeOperator() {
    if (!operatorToRevoke) return
    setPending(true); setMessage('')
    try {
      const { confirmed, members } = await api<{ confirmed: number; members: number }>(
        `/grove/operators/${encodeURIComponent(operatorToRevoke.id)}/revoke`, { method: 'POST', headers })
      setRevocation(`${operatorToRevoke.name} 已在本节点停用，${confirmed} / ${members} 个成员已确认。`)
      setOperatorToRevoke(undefined)
    } catch (failure) {
      setMessage(failure instanceof ApiError ? failure.message : '暂时无法停用该账号。')
    } finally {
      setPending(false)
      window.dispatchEvent(new Event('spearmint:refresh'))
    }
  }
  async function approveRole() {
    if (!roleChange) return
    setPending(true); setMessage('')
    try {
      const result = await api<{ approved: number; required: number; applied: boolean }>(
        `/grove/users/${encodeURIComponent(roleChange.id)}/role`, { method: 'POST', headers, body: JSON.stringify({ role: roleChange.role }) })
      setRevocation(result.applied ? `${roleChange.name} 的角色已更新。`
        : `本成员已批准。当前有 ${result.approved} / ${result.required} 票，请在其他成员面板继续批准。`)
      setRoleChange(undefined)
    } catch (failure) {
      setMessage(failure instanceof ApiError && failure.code === 'REAUTHENTICATION_REQUIRED'
        ? '请重新登录并完成动态验证码验证，再批准角色变更。' : failure instanceof ApiError ? failure.message : '暂时无法批准角色变更。')
    } finally {
      setPending(false)
      window.dispatchEvent(new Event('spearmint:refresh'))
    }
  }
  return <Panel title="Grove 身份与成员" action={data?.configured ? <Badge tone="green">统一登录</Badge> : <Badge tone="outline">本机模式</Badge>}>
    {error && <Notice tone="amber">{error}</Notice>}
    {!data ? <Loading /> : !data.configured ? <>
      {openJoin && session.grove && <Notice tone="amber">请用这台节点的本机管理员账号登录后继续加入 Grove。</Notice>}
      <p className="muted">创建一个 Grove，或让这台已有节点加入你的 Grove。同一个账号即可从所有成员登录。</p>
      <form className="grove-create-form" onSubmit={(event) => void create(event)}>
        <label className="field-label">Grove 名称<input className="input" maxLength={40} value={name}
          onChange={(event) => setName(event.target.value)} required /></label>
        <button className="btn btn-primary" disabled={pending}>创建 Grove</button>
      </form>
      {(!openJoin || !session.grove) && <details className="grove-existing-join" open={openJoin || !!initialInvitation || undefined} ref={joinForm}>
        <summary>加入已有 Grove</summary>
        <p className="muted">{automaticJoin ? '通过在线成员验证 Grove 管理员账号，获多数批准后自动完成 Mesh 配对。'
          : quorumCode ? 'Spearmint 会通过已配对的成员核对多数批准。' : '粘贴邀请码后，Spearmint 会自动找到可用成员。'}</p>
        <GroveInvitationField code={invitation} realm={realm} disabled={pending}
          onChange={(value) => { setInvitation(value); setJoinError(''); setResumeJoin(false) }} />
        {automaticJoin ? <form className="auth-form" onSubmit={(event) => {
          event.preventDefault(); const values = new FormData(event.currentTarget); event.currentTarget.reset(); void join(values)
        }}>
          <label className="field-label">Grove 管理员账号<input className="input" name="username" autoComplete="username" required maxLength={64} /></label>
          <label className="field-label">Grove 密码<input className="input" name="password" type="password" autoComplete="current-password" required maxLength={256} /></label>
          <label className="field-label">动态验证码<input className="input" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required /></label>
          <button className="btn btn-primary" disabled={pending}>{pending ? '正在验证并配对…' : '验证并加入 Grove'}</button>
        </form> : <button className="btn btn-secondary" disabled={pending || !canJoin} onClick={() => void join()}>
          {pending ? '正在联系成员…' : quorumCode ? '检查审批并加入 Grove' : '前往 Grove 登录并确认加入'}<Icon name="arrow-right" size={14} />
        </button>}
        {automaticJoin && resumeJoin && <button type="button" className="btn btn-secondary" disabled={pending} onClick={() => void join()}>继续未完成的加入</button>}
        {joinError && <p className="error" role="alert">{joinError}</p>}
      </details>}
      {!session.grove && <details className="grove-existing-join">
        <summary>通过在线成员加入</summary>
        <form className="auth-form" onSubmit={event => void memberAdmission(event, true)}>
          <p>目标节点获多数批准后，输入任一已批准且能通过 Mesh 到达的身份成员 ID。</p>
          <label className="field-label">身份成员 Node ID<input className="input" name="node_id" required pattern="spm1-[a-f0-9]{64}" /></label>
          <button className="btn btn-primary" disabled={pending}>加入 Grove</button>
        </form>
      </details>}
      {message && <p className="error" role="alert">{message}</p>}
    </>
      : <><div className="identity-profile"><span className="service-symbol"><Icon name="leaf" size={25} /></span><div><strong>{data.realm?.name}</strong>{!data.issuer_retired && <p>{data.local_issuer ? '当前节点提供 Grove 身份认证' : '使用已有 Grove 身份登录'}</p>}</div></div><dl className="facts"><div><dt>Grove 身份</dt><dd><CopyValue value={data.realm!.id} short /></dd></div>{!data.issuer_retired && <div><dt>身份入口</dt><dd><a className="text-link break-anywhere" href={data.realm!.issuer_origin}>{data.realm!.issuer_origin}<Icon name="external-link" size={14} /></a></dd></div>}<div><dt>同步版本</dt><dd>{data.sequence ?? '等待同步'}{Boolean(data.valid_until) && <span className="muted"> · {new Date(data.valid_until! * 1000).toLocaleTimeString()}</span>}</dd></div></dl>
      {(data.frozen || (data.issuer_paused && !data.issuer_retired)) && <Notice tone="amber">Grove 身份服务正在等待恢复确认；本机独立账号仍可按原有权限使用。</Notice>}
      {members && !directoryCurrent && <Notice tone="amber">显示上次同步的 Grove 成员目录。</Notice>}
      {members?.length ? <div className="grove-members">{members.map((member) => {
        const origin = memberPanelOrigins.get(member.node_id)
        const content = <><Icon name={icons?.get(member.node_id) ?? 'server'} size={19} /><span><strong>{names.get(member.node_id) || shortId(member.node_id)}</strong><small>{publicPanelLabel(member.origin)}</small></span>
          <Badge tone={member.enabled ? 'green' : 'neutral'}>{member.enabled ? '已加入' : '已停用'}</Badge>{origin && <Icon name="arrow-up-right" size={15} />}</>
        return origin ? <a className="grove-member" key={member.node_id} href={`${origin}/#/access`}>{content}</a>
          : <div className="grove-member" key={member.node_id}>{content}</div>
      })}</div> : directoryLoading ? <Loading label="正在读取成员目录…" /> : <EmptyState title="等待同步成员" />}
      {!data.issuer_paused && !data.frozen && data.realm && <CopyGroveInvitation />}
      {!data.local_issuer && <button className="btn btn-secondary" disabled={directorySync.checking || !!data.frozen || !!data.issuer_paused}
          onClick={() => void directorySync.sync()}><Icon name="refresh" size={16} />{directorySync.checking ? '正在同步…' : '同步成员目录'}</button>}
      {session.grove && data.identity_voter && data.operator_revocation === 'available' && <details className="grove-existing-join">
        <summary>批准新成员</summary>
        <form className="auth-form" onSubmit={event => void memberAdmission(event, false)}>
          <label className="field-label">目标节点 Node ID<input className="input" name="node_id" required pattern="spm1-[a-f0-9]{64}" /></label>
          <label className="field-label">目标面板 HTTPS 地址<input className="input" name="origin" type="url" maxLength={512} required /></label>
          <button className="btn btn-primary" disabled={pending}>在此成员批准</button>
        </form>
      </details>}
      {data.local_issuer && !data.frozen && !session.grove && !data.issuer_retired && !data.issuer_paused &&
        data.continuity_configured && !retirementDelivery &&
        <button className="btn btn-secondary" disabled={pending} onClick={() => setConfirmRetirement(true)}>退役原身份节点</button>}
      {data.local_issuer && !data.frozen && !session.grove && retirementIncomplete &&
        <button className="btn btn-secondary" disabled={pending} onClick={() => void retire()}>重试交接并下载文件</button>}
      {retirementDelivery && <Notice tone={retirementDelivery.delivered === retirementDelivery.required ? 'green' : 'amber'}>
        {`已确认交接 ${retirementDelivery.delivered} / ${retirementDelivery.required} 个成员。请在其他成员完成一次新登录，再关闭原节点。`}
      </Notice>}
      {confirmRetirement && <Modal title="退役原身份节点" onClose={() => { if (!pending) setConfirmRetirement(false) }}>
        <p>确认后原节点停止签发，并通过 Mesh 交接给其他成员。交接期间账号、角色和成员名单固定在当前版本。</p>
        {message && <p className="error" role="alert">{message}</p>}
        <button className="btn btn-primary" disabled={pending} onClick={() => void retire()}>{pending ? '正在核对成员…' : '确认退役并下载'}</button>
      </Modal>}
      {data.operator_revocation && data.users && <details className="grove-existing-join">
        <summary>Grove 账号</summary>
        {data.users.map(user => <div className="grove-member" key={user.id}>
          <span><strong>{user.name}</strong><small>{user.role === 'node_admin' ? '管理员' : '操作员'}</small></span>
          <Badge tone={user.enabled ? 'green' : 'neutral'}>{user.enabled ? '有效' : '已停用'}</Badge>
          {session.grove && user.enabled && user.can_suspend && data.operator_revocation === 'available' &&
            <button className="btn btn-secondary btn-small" disabled={pending} onClick={() => { setMessage(''); setOperatorToRevoke(user) }}>停用</button>}
          {session.grove && user.enabled && data.recovery_admin && data.recovery_admin !== user.id &&
            (user.role === 'node_admin' || user.require_mfa) && data.operator_revocation === 'available' &&
            <button className="btn btn-secondary btn-small" disabled={pending} onClick={() => {
              setMessage(''); setRoleChange({ ...user, role: user.role === 'node_admin' ? 'remote_operator' : 'node_admin' })
            }}>{data.role_votes?.includes(user.id) ? '重新核对批准' : '调整角色'}</button>}
        </div>)}
      </details>}
      {operatorToRevoke && <Modal title={`停用 ${operatorToRevoke.name}`} onClose={() => { if (!pending) setOperatorToRevoke(undefined) }}>
        <p>成员收到停用记录后会注销该账号的会话。此操作无法撤销。</p>
        {message && <p className="error" role="alert">{message}</p>}
        <button className="btn btn-primary" disabled={pending} onClick={() => void revokeOperator()}>{pending ? '正在同步…' : '确认停用'}</button>
      </Modal>}
      {roleChange && <Modal title={`调整 ${roleChange.name} 的角色`} onClose={() => { if (!pending) setRoleChange(undefined) }}>
        <p>新角色为{roleChange.role === 'node_admin' ? '管理员' : '操作员'}。多数成员批准后生效，该账号需要重新登录。</p>
        {message && <p className="error" role="alert">{message}</p>}
        <button className="btn btn-primary" disabled={pending} onClick={() => void approveRole()}>{pending ? '正在核对…' : '在此成员批准'}</button>
      </Modal>}
      {revocation && <p role="status">{revocation}</p>}
      {message && !confirmRetirement && !operatorToRevoke && !roleChange && <p className="error" role="alert">{message}</p>}
      {directorySync.message && <p className={directorySync.message.error ? 'error' : 'muted'} role="status">{directorySync.message.text}</p>}
      <p className="settings-note">成员身份经签名同步，新节点加入需管理员确认。</p></>}
  </Panel>
}
