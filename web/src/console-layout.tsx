import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useConsole } from './console-data'
import { Badge, Brand, Icon, Modal, shortId } from './ui'
import { grovePanelRoute, remoteServiceHref } from './grove-navigation'
import { publicPanelLabel } from './grove-directory'
import { useRemoteCatalog } from './remote-catalog'
import { serviceSearchText } from './services'
import { allowNavigation } from './navigation-guard'
import { nodeIcon } from './node-types'

export const navigation = [
  { group: '工作台', items: [{ id: 'overview', title: '总览', icon: 'layout-dashboard' }, { id: 'services', title: '服务', icon: 'layers', admin: true }, { id: 'nodes', title: '节点', icon: 'server', admin: true }, { id: 'operations', title: '操作中心', icon: 'activity' }] },
  { group: '管理', items: [{ id: 'identity', title: '身份与安全', icon: 'shield' }, { id: 'maintenance', title: '平台维护', icon: 'package', admin: true }] },
  { group: '待实现', items: [{ id: 'pollen', title: '移动节点', icon: 'wind', admin: true, planned: true }, { id: 'federation', title: '跨 Grove 连接', icon: 'git-merge', admin: true, planned: true }] },
]
export const adminPages = new Set([...navigation.flatMap((group) => group.items).filter((item) => 'admin' in item && item.admin).map((item) => item.id), 'topology', 'ssh', 'seeds', 'deployments', 'exposures', 'audit'])
const area: Record<string, string> = { topology: 'nodes', ssh: 'nodes', seeds: 'nodes', alerts: 'operations', audit: 'identity', access: 'identity', deployments: 'maintenance', exposures: 'services' }
export function pageName(page: string) { return ({ ssh: '节点', seeds: '节点', sessions: '我的会话', settings: '显示偏好', account: '我的账户', audit: '安全审计', topology: '节点', deployments: '平台维护', exposures: '公网映射' } as Record<string, string>)[page] || navigation.flatMap((group) => group.items).find((item) => item.id === page)?.title || '服务' }
export function useRoute() {
  function read() { return location.hash.split('?')[0].replace(/^#\/?/, '').split('/').map((part) => { try { return decodeURIComponent(part) } catch { return part } }) }
  const [path, setPath] = useState(read)
  useEffect(() => {
    let accepted = location.hash
    const change = () => {
      if (!allowNavigation()) { history.replaceState(null, '', accepted); return }
      accepted = location.hash; setPath(read())
    }
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  return { page: path[0] || 'services', id: path[1], segments: path.slice(2) }
}

export function ConsoleLayout({ page, children, onSignOut, signingOut }: {
  page: string; children: ReactNode; onSignOut: () => void; signingOut: boolean
}) {
  const { local, localName, admin, alerts, preferences, session, grove } = useConsole()
  const build = local.error ? undefined : local.data?.build
  const [menu, setMenu] = useState(false); const [search, setSearch] = useState(false); const [account, setAccount] = useState(false)
  const [panelPicker, setPanelPicker] = useState(false)
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 900px)').matches)
  const menuButton = useRef<HTMLButtonElement>(null); const sidebar = useRef<HTMLElement>(null)
  useEffect(() => { const mq = window.matchMedia('(max-width: 900px)'); const change = () => { setMobile(mq.matches); if (!mq.matches) setMenu(false) }; mq.addEventListener('change', change); return () => mq.removeEventListener('change', change) }, [])
  useEffect(() => { setMenu(false); setAccount(false); document.title = `${pageName(page)} · Spearmint`; window.scrollTo(0, 0) }, [page])
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setSearch((value) => !value) }
      if (event.key === 'Escape') { setMenu(false); setAccount(false) }
    }
    window.addEventListener('keydown', key); return () => window.removeEventListener('keydown', key)
  }, [])
  useEffect(() => {
    if (!menu || !mobile) return
    const previous = document.body.style.overflow; document.body.style.overflow = 'hidden'
    sidebar.current?.querySelector<HTMLElement>('.mobile-close')?.focus()
    return () => { document.body.style.overflow = previous; menuButton.current?.focus() }
  }, [menu, mobile])
  return <div className={`app-shell ${preferences.compact ? 'compact-density' : ''}`}>
    <a href="#main-content" className="skip-link" onClick={(event) => { event.preventDefault(); const main = document.getElementById('main-content'); main?.focus(); main?.scrollIntoView() }}>跳到主要内容</a>
    <aside ref={sidebar} className={`sidebar ${menu ? 'open' : ''}`} id="console-sidebar" aria-label="主导航" inert={mobile && !menu} onKeyDown={(event) => {
      if (!mobile || !menu || event.key !== 'Tab') return
      const controls = sidebar.current?.querySelectorAll<HTMLElement>('a[href],button:not([disabled])')
      if (!controls?.length) return
      const first = controls[0]; const last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }}>
      <div className="brand"><Brand /><button className="icon-button mobile-close" aria-label="关闭导航" onClick={() => setMenu(false)}><Icon name="x" /></button></div>
      <button type="button" className="grove-switch" aria-haspopup="dialog" aria-label="查看 Grove 节点面板" onClick={() => setPanelPicker(true)}>
        <span className="grove-avatar"><Icon name="leaf" size={18} /></span>
        <span className="grove-info"><strong>{preferences.grove === '我的 Grove' ? grove.data?.realm?.name || preferences.grove : preferences.grove}</strong>
          <small>{publicPanelLabel(location.origin)}</small></span>
        <Icon name="chevron-down" size={14} />
      </button>
      <nav>{navigation.map((group) => { const items = group.items.filter((item) => !('admin' in item && item.admin) || admin); return items.length ? <div key={group.group} className="nav-group"><div className="nav-label">{group.group}</div>{items.map((item) => <a key={item.id} className={`nav-item ${(area[page] || page) === item.id ? 'active' : ''}`} href={`#/${item.id}`} aria-current={(area[page] || page) === item.id ? 'page' : undefined} onClick={() => setMenu(false)}><Icon name={item.icon} size={17} /><span>{item.title}</span>{item.id === 'operations' && alerts.length > 0 && <span className="nav-count">{alerts.length}</span>}{'planned' in item && Boolean(item.planned) && <span className="nav-planned">未完成</span>}</a>)}</div> : null })}</nav>
      <div className="sidebar-footer"><div className="sidebar-health"><span className={`pulse-dot ${local.error ? 'disconnected' : ''}`} /><span>{local.error ? '面板连接待恢复' : local.data ? '已连接当前节点' : '正在连接节点'}</span></div>
        <div className="sidebar-version" title={build?.commit || undefined}><Icon name="info" size={12} />
          {build?.version ? `后端 v${build.version}` : local.data || local.error ? '后端版本未知' : '正在读取后端版本'}
          {build?.commit && <code>{build.commit.slice(0, 8)}</code>}</div></div>
    </aside>
    <div className="main-wrap"><header className="topbar"><div className="topbar-left"><button ref={menuButton} className="icon-button mobile-menu" aria-label="打开导航" aria-expanded={menu} aria-controls="console-sidebar" onClick={() => setMenu(true)}><Icon name="menu" size={22} /></button><div className="breadcrumbs"><a href="#/overview">Spearmint</a><span>/</span>{pageName(page)}</div><span className="sync-label"><span className={`pulse-dot ${local.error ? 'disconnected' : ''}`} />{local.error ? '等待重连' : `当前面板 · ${localName}`}</span></div>
      <div className="topbar-actions"><button className="search-trigger" aria-label="搜索节点、服务或页面" onClick={() => setSearch(true)}><Icon name="search" size={15} /><span>搜索节点、服务…</span><kbd>⌘ K</kbd></button>{admin && <a href="#/alerts" className="icon-button" aria-label={alerts.length ? `${alerts.length} 项需要关注` : '查看状态提醒'}><Icon name="bell" size={19} />{alerts.length > 0 && <span className="tiny-alert" />}</a>}
        <div className="account-menu"><button className="user-avatar" aria-label="打开账户菜单" aria-expanded={account} onClick={() => setAccount(!account)}>{(session.display_name || session.username).slice(0, 1).toUpperCase()}</button>{account && <><button className="account-menu-backdrop" aria-label="关闭账户菜单" onClick={() => setAccount(false)} /><div className="account-dropdown"><strong>{session.display_name || session.username}</strong><small>{admin ? '节点管理员' : '远程操作员'}</small><a href="#/account"><Icon name="shield" size={15} />账户与验证器</a><a href="#/account/sessions"><Icon name="monitor" size={15} />我的会话</a><a href="#/account/settings"><Icon name="settings" size={15} />显示偏好</a><button disabled={signingOut} onClick={() => { if (allowNavigation()) onSignOut() }}><Icon name="log-out" size={15} />{signingOut ? '正在退出…' : '退出登录'}</button></div></>}</div>
      </div></header>
      <main className="main-content" id="main-content" tabIndex={-1}><div className="console-page-content">{children}</div><footer className="app-footer"><span><Icon name="sprout" size={15} />Spearmint · Grow with your infrastructure</span><span>YOUR INFRASTRUCTURE. YOUR GROVE.</span></footer></main>
    </div>
    {mobile && menu && <button className="mobile-overlay visible" aria-label="关闭侧边导航" onClick={() => setMenu(false)} />}
    {panelPicker && <GrovePanels onClose={() => setPanelPicker(false)} onSettings={() => { setPanelPicker(false); setMenu(false) }} />}
    {search && <SearchDialog onClose={() => setSearch(false)} />}
  </div>
}

function GrovePanels({ onClose, onSettings }: { onClose: () => void; onSettings: () => void }) {
  const { admin, local, localName, webBuild, grove, directoryLoading, directoryPending, directoryCurrent, directorySequence, memberPanelOrigins, memberNodes, listedNodes } = useConsole()
  const currentId = local.data?.node_id
  const build = local.error ? undefined : local.data?.build
  const otherMembers = memberNodes?.filter(node => !node.local)
  const panels = currentId && !local.error ? [...(otherMembers ?? [])].sort((a, b) => a.name.localeCompare(b.name)) : []
  const meshPending = directoryCurrent && otherMembers?.length && otherMembers.every(node => node.status === 'unconfigured')
  return <Modal title="Grove 节点" onClose={onClose} className="grove-panels">
    <div className="grove-panel-entry">
      <span className="service-symbol"><Icon name={nodeIcon(listedNodes.find(node => node.local) ?? { local: true })} size={18} /></span>
      <span className="grove-panel-name"><strong>{localName}</strong>
        <small>{publicPanelLabel(location.origin)}{currentId && ` · ${shortId(currentId)}`}</small>
        <small title={build?.commit || undefined}>后端 {build?.version ? `v${build.version}${build.commit ? ` · ${build.commit.slice(0, 8)}` : ''}` : local.data || local.error ? '未知' : '读取中…'}</small>
        <small>前端 {webBuild || '未知'}</small>
      </span>
      <Badge tone="sage">当前面板</Badge>
    </div>
    {directorySequence !== undefined && <p className="muted grove-panel-message">
      {directoryCurrent ? '成员目录' : '上次同步的成员目录'} · 第 {directorySequence} 版
    </p>}
    {!!panels.length && <ul className="grove-panel-list" aria-label="其他成员面板">{panels.map((node) => {
      const { id, name, memberOrigin } = node
      const origin = memberPanelOrigins.get(id)
      const entry = <><span className="service-symbol"><Icon name={nodeIcon(node)} size={18} /></span>
        <span className="grove-panel-name"><strong>{name}</strong><small>{publicPanelLabel(memberOrigin)} · {shortId(id)}</small></span></>
      return <li key={id}><a className="grove-panel-entry" href={`#/nodes/${id}`} onClick={onClose}>{entry}<Icon name="arrow-right" size={16} /></a></li>
    })}</ul>}
    {admin && !panels.length && grove.data?.configured && <p className="muted grove-panel-message" role="status">
      {local.error ? '暂时无法读取当前节点身份。' : directoryPending ? '正在自动同步成员目录…'
        : directoryLoading || !currentId ? '正在读取成员目录…' : directoryCurrent ? '暂无其他成员的面板入口。' : '暂时无法获取有效的成员目录。'}
    </p>}
    {admin && !!meshPending && <p className="muted grove-panel-message">成员目录已同步。本机的 Mesh 互联仍待配对。</p>}
    {admin && <div className="modal-actions"><a className="btn btn-secondary" href="#/settings" onClick={onSettings}>显示设置</a></div>}
  </Modal>
}

function SearchDialog({ onClose }: { onClose: () => void }) {
  const { listedNodes, services, admin, localName } = useConsole()
  const { entries, data, error } = useRemoteCatalog()
  const [query, setQuery] = useState('')
  const normalized = query.trim().toLowerCase()
  const pages = navigation.flatMap((group) => group.items).filter((item) => !('admin' in item && item.admin) || admin)
  const results = [
    ...pages.map((page) => ({ title: page.title, detail: '控制台页面', terms: page.id, href: `#/${page.id}`, icon: page.icon })),
    ...(admin ? listedNodes.map((node) => ({ title: node.name, detail: node.local ? '本机节点' : node.id,
      terms: `${node.id} ${node.memberOrigin ?? ''}`, href: `#/nodes/${encodeURIComponent(node.id)}`, icon: nodeIcon(node) })) : []),
    ...(services.data || []).map((service) => ({ title: service.name, detail: `本机服务 · ${localName}`, terms: serviceSearchText(service),
      href: `#/services/${encodeURIComponent(service.id)}`, icon: 'layers' })),
    ...entries.map(({ node, service, stale }) => ({ title: service.name,
      detail: `远程服务 · ${node.name}${stale ? ' · 目录待同步' : ''}`, terms: `${node.id} ${service.id}`,
      href: remoteServiceHref(node.id, service.id), icon: 'layers' })),
  ].filter((item) => `${item.title} ${item.detail} ${item.terms}`.toLowerCase().includes(normalized))
  const matches = (normalized ? results.sort((a, b) => Number(b.title.toLowerCase() === normalized)
    - Number(a.title.toLowerCase() === normalized)) : results).slice(0, 12)
  const pending = admin && !data && !error
  return <Modal title="搜索你的 Grove" onClose={onClose} className="search-modal">
    <label className="global-search-field"><Icon name="search" size={20} /><input autoFocus placeholder="输入节点、服务或页面名称…"
      aria-label="搜索整个控制台" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
    <div className="search-results">{matches.map((result) => <a href={result.href} key={result.href} onClick={onClose}>
      <span className="service-symbol"><Icon name={result.icon} size={18} /></span>
      <span><strong>{result.title}</strong><small>{result.detail}</small></span><Icon name="arrow-right" size={15} />
    </a>)}
    {normalized && pending && <p className="muted" role="status">正在读取已同步的远程服务…</p>}
    {normalized && error && <p className="muted" role="status">远程服务目录暂时无法更新。</p>}
    {!matches.length && !pending && !error && <p className="muted">没有找到匹配的页面、节点或服务。</p>}</div>
    <div className="search-footer"><kbd>Esc</kbd>关闭搜索</div>
  </Modal>
}
