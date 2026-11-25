import { useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ApiError, api, type Session } from './api'
import { ConsoleData, useConsole, usePreferences } from './console-data'
import { adminPages, ConsoleLayout, useRoute } from './console-layout'
import { AlertsPage, AuditPage, FuturePage, OverviewPage } from './console-pages'
import { DeploymentsPage } from './deployments'
import { Services } from './services'
import { ServiceWorkspace } from './service-workspace'
import { SectionNavigation, IdentityWorkspace, AccountWorkspace, OperationCenter } from './workspace-pages'
import { ExposuresPage } from './frp-mappings'
import { AccessPage, OperationsPage } from './security-pages'
import { Sessions } from './sessions'
import { SignIn } from './sign-in'
import { GroveAccountAccess } from './grove-account-access'
import { FirstFactor, Setup, takeSetupEntry } from './onboarding'
import { GroveAuthorize, GroveReturn, takeGroveDestination, takeGroveReturn } from './grove-auth'
import { rememberQuorumInvitation } from './grove-invitation'
import { deploymentTarget } from './grove-navigation'
import { Brand, EmptyState, Loading, Notice, PageHeading, Panel } from './ui'
import './grove.css'
import './style.css'
import './workspace.css'
import './overview.css'

import { NodesWorkspace } from './nodes-workspace'

function webAssetId(url: string, extension: 'js' | 'css') {
  const path = new URL(url).pathname
  const match = /\/assets\/index-([\w-]+)\.(js|css)$/.exec(path)
  return match?.[2] === extension ? match[1] : undefined
}

const scriptId = webAssetId(import.meta.url, 'js')
const stylesheetId = [...document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"][href]')]
  .map((link) => webAssetId(link.href, 'css')).find(Boolean)
const webBuild = import.meta.env.DEV ? '开发模式' : scriptId && stylesheetId ? `${scriptId} / ${stylesheetId}` : undefined

function ConsolePage({ route, onFactors, onSave }: { route: ReturnType<typeof useRoute>; onFactors: () => void; onSave: ReturnType<typeof usePreferences>['save'] }) {
  const { page, id, segments } = route
  const { session, onUnauthorized, admin } = useConsole()
  if (!admin && adminPages.has(page)) return <Panel><EmptyState title="此页面仅对节点管理员开放" action={<a className="btn btn-primary" href="#/operations">查看我获准访问的服务</a>}>你可以提交已授权的远程操作，并管理自己的登录会话。</EmptyState></Panel>
  switch (page) {
    case 'overview': return <OverviewPage />
    case 'nodes': case 'topology': case 'ssh': case 'seeds': return <NodesWorkspace page={page} nodeId={id} onSave={onSave} />
    case 'services': return <ServiceWorkspace section={id} segments={segments} />
    case 'exposures': return <ExposuresPage />
    case 'operations': return <><SectionNavigation page="operations" /><OperationCenter /></>
    case 'alerts': return <><SectionNavigation page="alerts" /><AlertsPage /></>
    case 'audit': return <><SectionNavigation page="audit" /><AuditPage /></>
    case 'sessions': return <><PageHeading eyebrow="SECURITY / SESSIONS" title="我的会话" description="查看你的登录记录，及时关闭不再使用或无法确认的会话。" /><Sessions session={session} onUnauthorized={onUnauthorized} /></>
    case 'identity': case 'access': return <><SectionNavigation page="identity" /><IdentityWorkspace onFactors={onFactors} /></>
    case 'account': return <AccountWorkspace section={id} onFactors={onFactors} onSave={onSave} />
    case 'settings': return <AccountWorkspace section="settings" onFactors={onFactors} onSave={onSave} />
    case 'maintenance': case 'deployments': return <DeploymentsPage targetId={id || deploymentTarget(location.hash)} />
    default: return <FuturePage page={page} />
  }
}

function App() {
  const [setupEntry, setSetupEntry] = useState(takeSetupEntry)
  const [groveReturn, setGroveReturn] = useState(takeGroveReturn)
  const [setupStatus, setSetupStatus] = useState<{ required: boolean; link_expired: boolean; browser_setup?: boolean }>()
  const [session, setSession] = useState<Session | null | undefined>()
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const [changingFactors, setChangingFactors] = useState(false)
  const [groveRequestSignIn, setGroveRequestSignIn] = useState<{ request: string; csrf: string }>()
  const { preferences, save } = usePreferences()
  const route = useRoute()
  const expireSession = useCallback(() => { setSession(null); setChangingFactors(false) }, [])
  useEffect(() => {
    function takePrivateEntry() {
      if (location.hash.startsWith('#/setup/')) setSetupEntry(takeSetupEntry())
      else if (location.hash.startsWith('#/grove-return/')) setGroveReturn(takeGroveReturn())
    }
    window.addEventListener('hashchange', takePrivateEntry)
    return () => window.removeEventListener('hashchange', takePrivateEntry)
  }, [])
  useEffect(() => {
    if (groveReturn) return
    let active = true
    api<{ required: boolean; link_expired: boolean; browser_setup?: boolean }>('/setup').then((status) => {
      if (!active) return undefined
      setSetupStatus(status)
      return status.required ? null : api<Session>('/session')
    }).then((current) => { if (active && current !== undefined) setSession(current) }).catch((failure) => {
      if (!active) return
      if (!(failure instanceof ApiError && failure.status === 401)) setError('面板暂时不可用，请检查连接后重试。')
      setSetupStatus({ required: false, link_expired: false })
      setSession(null)
    })
    return () => { active = false }
  }, [groveReturn, setupEntry])
  async function signOut(destination: string | null = '#/signin') {
    if (!session) return
    setPending(true); setError('')
    try {
      await api('/session', { method: 'DELETE', headers: { 'X-CSRF-Token': session.csrf_token } })
      expireSession()
      if (destination !== null) location.hash = destination
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) expireSession()
      else setError('暂时无法退出，请检查连接后重试。')
    } finally { setPending(false) }
  }
  function signedIn(current: Session) {
    setError(''); setSession(current); setChangingFactors(false)
    if (route.page === 'grove-authorize' && route.id) setGroveRequestSignIn({ request: route.id, csrf: current.csrf_token })
    if (['signin', 'auth-recover'].includes(route.page)) location.hash = '#/services'
  }
  async function openFactors() {
    try {
      const info = await api<{ eligible: boolean }>('/auth/first-factor')
      if (info.eligible) location.hash = '#/auth-enroll'
      else setChangingFactors(true)
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) expireSession()
      else setError('无法读取登录验证设置，请检查连接后重试。')
    }
  }
  if (groveReturn) return <GroveReturn request={groveReturn} onSession={(current) => {
    setSetupEntry({ token: '' }); setGroveReturn(''); setSetupStatus({ required: false, link_expired: false }); setSession(current); location.hash = takeGroveDestination()
  }} />
  if (setupStatus?.required) return <Setup key={`${setupEntry.token}/${setupEntry.realm?.id ?? ''}`} token={setupEntry.token}
    initialRealm={setupEntry.realm} expired={setupStatus.link_expired} localBrowser={!!setupStatus.browser_setup} onCreated={(current, quorumCode) => {
    if (quorumCode) rememberQuorumInvitation(quorumCode)
    location.hash = quorumCode ? '#/access' : '#/auth-enroll'
    setSetupEntry({ token: '' }); setSetupStatus({ required: false, link_expired: false }); setSession(current)
  }} />
  if (session === undefined) return <div className="initial-connection"><Brand /><Loading label="正在连接你的 Grove…" /></div>
  if (session && route.page === 'auth-enroll') return <FirstFactor session={session} onUnauthorized={expireSession}
    reauthenticating={pending} reauthenticationError={error} onReauthenticate={() => void signOut('#/auth-enroll')}
    onExit={(completed) => {
      if (completed) expireSession()
      location.hash = completed ? '#/signin' : '#/overview'
    }} />
  if (!session && (route.page === 'grove-register' || route.page === 'grove-forgot')) return <GroveAccountAccess
    key={route.page} mode={route.page === 'grove-register' ? 'register' : 'reset'} />
  if (!session || changingFactors) return <SignIn key={changingFactors ? 'factor-change' : route.id ?? route.page} initialError={error}
    authorizeRequest={route.page === 'grove-authorize' ? route.id : undefined}
    mode={route.page === 'auth-enroll' ? 'enroll' : route.page === 'auth-recover' ? 'recover' : 'signin'}
    enrollmentSession={changingFactors && session ? session : undefined} onSession={signedIn}
    onEnrollmentExit={(completed) => { setChangingFactors(false); if (completed) { expireSession(); location.hash = '#/signin' } }} />
  if (route.page === 'grove-authorize' && route.id) return <GroveAuthorize key={route.id} request={route.id} session={session}
    signedInForRequest={groveRequestSignIn?.request === route.id && groveRequestSignIn.csrf === session.csrf_token}
    onReauthenticate={() => void signOut(null)} reauthenticating={pending} reauthenticationError={error} />
  const page = ['signin', 'auth-recover', 'grove-register', 'grove-forgot'].includes(route.page) ? 'services' : route.page
  return <ConsoleData key={session.username} session={session} onUnauthorized={expireSession} preferences={preferences} webBuild={webBuild}>
    <ConsoleLayout page={page} onSignOut={() => void signOut()} signingOut={pending}>
      {error && <Notice tone="amber">{error}</Notice>}
      <ConsolePage route={{ ...route, page }} onFactors={() => void openFactors()} onSave={save} />
    </ConsoleLayout>
  </ConsoleData>
}

createRoot(document.getElementById('root')!).render(<App />)
