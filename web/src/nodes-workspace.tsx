import { lazy, Suspense, useEffect, useLayoutEffect, useRef, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { useConsole, refreshConsole, type NodeView, type Preferences } from './console-data'
import { NetworkMap, type NodeMenuAnchor } from './network-map'
import { NodeInspector } from './workspace-pages'
import { GroveCard } from './grove-auth'
import { SeedsPage } from './console-pages'
import { savedSeedSource } from './seed-wizard'
import { groveServiceRegistrationHref, nodeResourcesTarget, seedProgressTarget } from './grove-navigation'
import { returnRoute, withReturn } from './workspace-api'
import { Badge, Icon, Loading, Modal, shortId } from './ui'
import './nodes-workspace.css'

const QuickSSH = lazy(() => import('./quick-ssh'))
const validNode = (value?: string | null) => !!value && /^spm1-[a-f0-9]{64}$/.test(value)
const modeNames: Record<string, string> = { terminal: '终端与文件', network: '路径诊断', detail: '节点详情', seed: '播种新节点' }
type Menu = { node: NodeView; anchor: NodeMenuAnchor }

function NodeMenu({ node, anchor, close }: Menu & { close: (restore?: boolean) => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const items = [
    { label: '节点资料与备注', icon: 'info', route: `#/nodes/${node.id}` },
    { label: '查看节点服务', icon: 'layers', route: `#/nodes/${node.id}?tab=services` },
    { label: '资源与趋势', icon: 'activity', route: `#/nodes/${node.id}/resources` },
    { label: '登记服务', icon: 'plus', route: groveServiceRegistrationHref(node.id) },
    { label: '打开终端与文件', icon: 'terminal', route: `#/ssh/${node.id}`, section: true },
    { label: '从此节点播种', icon: 'sprout', route: `#/seeds?source=${node.id}` },
    ...(!node.local ? [{ label: '路径诊断', icon: 'route', route: `#/topology/${node.id}` }] : []),
    { label: '版本与更新', icon: 'package', route: `#/maintenance/${node.id}` },
    { label: '移动节点', icon: 'wind', route: '#/pollen', planned: true, section: true },
    { label: '跨 Grove 连接', icon: 'git-merge', route: '#/federation', planned: true },
  ]
  useLayoutEffect(() => {
    const menu = ref.current
    if (!menu) return
    menu.style.left = `${Math.max(12, Math.min(anchor.x, innerWidth - menu.offsetWidth - 12))}px`
    menu.style.top = `${Math.max(12, Math.min(anchor.y, innerHeight - menu.offsetHeight - 12))}px`
    menu.querySelector<HTMLElement>('[role="menuitem"]')?.focus()
  }, [anchor])
  useEffect(() => {
    const outside = (event: PointerEvent) => { if (!ref.current?.contains(event.target as Node)) close() }
    const dismiss = (event: Event) => { if (!(event.target instanceof Node) || !ref.current?.contains(event.target)) close() }
    document.addEventListener('pointerdown', outside)
    window.addEventListener('resize', dismiss)
    window.addEventListener('scroll', dismiss, true)
    return () => {
      document.removeEventListener('pointerdown', outside)
      window.removeEventListener('resize', dismiss)
      window.removeEventListener('scroll', dismiss, true)
    }
  }, [close])
  return createPortal(<div ref={ref} className="node-context-menu" role="menu" aria-label={`${node.name}的操作菜单`}
    onKeyDown={event => {
      if (event.key === 'Escape' || event.key === 'Tab') { event.preventDefault(); event.stopPropagation(); close(true); return }
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
      event.preventDefault(); event.stopPropagation()
      const controls = [...ref.current!.querySelectorAll<HTMLElement>('[role="menuitem"]')]
      const index = controls.indexOf(document.activeElement as HTMLElement)
      controls[event.key === 'Home' ? 0 : event.key === 'End' ? controls.length - 1
        : (index + (event.key === 'ArrowDown' ? 1 : -1) + controls.length) % controls.length]?.focus()
    }}>
    <div className="node-context-title" title={node.name}>{node.name}<small>{node.local ? '当前节点' : 'Grove 成员'}</small></div>
    {items.map(item => <a key={item.label} role="menuitem" className={item.section ? 'node-menu-section' : undefined}
      href={withReturn(item.route, '#/nodes')} onClick={event => {
        if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return
        event.preventDefault(); close(); location.hash = withReturn(item.route, '#/nodes')
      }}><Icon name={item.icon} size={16} /><span>{item.label}</span>{item.planned && <Badge tone="amber">规划中</Badge>}</a>)}
  </div>, document.body)
}

export function NodesWorkspace({ page, nodeId, onSave }: {
  page: string; nodeId?: string; onSave: (preferences: Preferences) => void
}) {
  const { listedNodes, local, session, onUnauthorized, groveDetails, groveError, directoryCurrent } = useConsole()
  const [nodeAccess, setNodeAccess] = useState(() => new URLSearchParams(location.hash.split('?')[1]).get('join') === '1')
  const [menu, setMenu] = useState<Menu>()
  const [query, setQuery] = useState('')
  const [searchError, setSearchError] = useState('')
  const search = useRef<HTMLInputElement>(null)
  const routeHash = location.hash
  useEffect(() => { setMenu(undefined) }, [routeHash])
  const params = new URLSearchParams(location.hash.split('?')[1])
  const progress = page === 'seeds' ? seedProgressTarget(location.hash) : undefined
  const source = params.get('source')
  const target = page === 'seeds' ? progress?.nodeId || (validNode(source) ? source! : savedSeedSource() || local.data?.node_id)
    : validNode(nodeId) ? nodeId : undefined
  const selected = listedNodes.find(node => node.id === target)
  const mode = page === 'ssh' && target ? 'terminal' : page === 'topology' && target ? 'network'
    : page === 'nodes' && target ? 'detail' : page === 'seeds' ? progress ? 'progress' : 'seed' : undefined
  const title = mode === 'progress' ? '新节点接入状态'
    : `${selected?.name || (target ? shortId(target) : '当前节点')} · ${modeNames[mode || ''] || ''}`
  const inspectorTab = mode === 'network' ? 'network' : mode === 'detail'
    ? (nodeResourcesTarget(location.hash.split('?')[0]) ? 'resources' : params.get('tab') || 'overview') : undefined
  const dialogKey = `${mode}/${target}/${inspectorTab || ''}`
  function closeMenu(restore = false) { if (restore) menu?.anchor.trigger.focus(); setMenu(undefined) }
  function find(event: FormEvent) {
    event.preventDefault()
    const value = query.trim().toLocaleLowerCase()
    const node = value && (listedNodes.find(node => node.name.toLocaleLowerCase() === value || node.id.toLocaleLowerCase() === value)
      || listedNodes.find(node => `${node.name} ${node.id}`.toLocaleLowerCase().includes(value)))
    if (!node) { setSearchError(value ? '没有找到匹配的节点。' : '请输入节点名称或标识。'); return }
    const rect = search.current!.getBoundingClientRect()
    setSearchError(''); setMenu({ node, anchor: { x: rect.left, y: rect.bottom + 6, trigger: search.current! } })
  }
  return <>
    <section className="hero-garden overview-network nodes-network" aria-labelledby="page-title">
      <header className="overview-network-heading">
        <div><div className="hero-kicker"><span className="pulse-dot" />GROVE / NODES</div><h1 id="page-title" tabIndex={-1}>节点</h1>
          <p>右键节点打开操作菜单 · 拖动画布 · Ctrl + 滚轮缩放</p></div>
        <div className="overview-network-actions"><button className="btn btn-ghost nodes-refresh" aria-label="刷新节点状态" onClick={refreshConsole}><Icon name="refresh" size={16} /></button>
          <button className="btn btn-white" onClick={() => setNodeAccess(true)}><Icon name="link" size={15} />{groveDetails?.configured ? '邀请节点' : '设置 Grove'}</button>
          <a className="btn btn-white" href={withReturn(`#/seeds${local.data?.node_id ? `?source=${local.data.node_id}` : ''}`, '#/nodes')}><Icon name="plus" size={15} />添加节点</a></div>
      </header>
      <div className="nodes-network-tools"><span>{listedNodes.length ? `${listedNodes.length} 个节点 · ${listedNodes.filter(node => node.status === 'online').length} 个当前连通` : 'Grove 网络'}</span>
        <form onSubmit={find} className="nodes-network-search"><Icon name="search" size={15} /><input ref={search} type="search" aria-label="查找节点" list="nodes-search-options"
          value={query} onChange={event => { setQuery(event.target.value); setSearchError('') }} placeholder="查找节点，回车打开操作…" />
          <datalist id="nodes-search-options">{listedNodes.map(node => <option key={node.id} value={node.name}>{shortId(node.id)}</option>)}</datalist></form>
      </div>
      {searchError && <p className="nodes-search-error" role="status">{searchError}</p>}
      <div className="overview-network-main nodes-network-canvas"><NetworkMap compact target={target} onNodeMenu={(node, anchor) => setMenu({ node, anchor })} /></div>
    </section>
    {menu && <NodeMenu {...menu} close={closeMenu} />}
    {nodeAccess && <Modal title={groveDetails?.configured ? '邀请节点加入 Grove' : '创建或加入 Grove'} onClose={() => setNodeAccess(false)}>
      <GroveCard data={groveDetails} error={groveError} session={session} onUnauthorized={onUnauthorized} directoryCurrent={directoryCurrent} mode="nodes" openJoin={!groveDetails?.configured} />
    </Modal>}
    {mode && <Modal key={dialogKey} title={title} className={`nodes-workspace-dialog is-${mode}`} dismissOnEscape={mode !== 'terminal'} onClose={() => { location.hash = returnRoute('#/nodes') }}>
      {mode === 'terminal' && <Suspense fallback={<Loading label="正在打开终端…" />}><QuickSSH key={target} targetId={target} embedded /></Suspense>}
      {(mode === 'detail' || mode === 'network') && target && <NodeInspector nodeId={target} onSave={onSave} embedded initialTab={inspectorTab} />}
      {(mode === 'seed' || mode === 'progress') && (target || progress ? <SeedsPage key={target || 'progress'} embedded sourceId={mode === 'seed' ? target : undefined}
        progressOrigin={progress?.origin} progressNodeId={progress?.nodeId} /> : <Loading label="正在读取本机节点…" />)}
    </Modal>}
  </>
}
