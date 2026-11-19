import './mock-api'
import { useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ConsoleData, usePreferences } from '../src/console-data'
import { ConsoleLayout, useRoute } from '../src/console-layout'
import { AlertsPage, AuditPage, FuturePage, NodesPage, OverviewPage, SeedsPage, SettingsPage, TopologyPage } from '../src/console-pages'
import { Services } from '../src/services'
import { ExposuresPage } from '../src/frp-mappings'
import { AccessPage, OperationsPage } from '../src/security-pages'
import { DeploymentsPage } from '../src/deployments'
import { Sessions } from '../src/sessions'
import QuickSSH from '../src/quick-ssh'
import { nodeResourcesTarget } from '../src/grove-navigation'
import { Brand, Modal, Notice, PageHeading, Panel } from '../src/ui'
import { demoSession, event, resetDemo } from './mock-api'
import '../src/grove.css'
import '../src/style.css'
import './mock.css'

function DemoApp() {
  const { preferences, save } = usePreferences()
  const [signedIn, setSignedIn] = useState(true)
  const [guide, setGuide] = useState(false)
  const [message, setMessage] = useState('')
  const route = useRoute()
  const onUnauthorized = useCallback(() => setSignedIn(false), [])
  useEffect(() => {
    let timer: number
    const listener = (e: Event) => { setMessage((e as CustomEvent).detail); window.clearTimeout(timer); timer = window.setTimeout(() => setMessage(''), 5000) }
    window.addEventListener('spearmint-demo:message', listener)
    const link = (e: MouseEvent) => {
      const anchor = (e.target as HTMLElement).closest<HTMLAnchorElement>('a[href]')
      if (anchor && /^https?:/i.test(anchor.href)) { e.preventDefault(); event('示例面板已通过当前 Grove 展示。请在拓扑或节点管理中选择目标。') }
    }
    document.addEventListener('click', link)
    return () => { window.removeEventListener('spearmint-demo:message', listener); document.removeEventListener('click', link); window.clearTimeout(timer) }
  }, [])
  function page() {
    const { page, id, segments } = route
    switch (page) {
      case 'overview': return <OverviewPage />
      case 'nodes': return <NodesPage key={id || 'all'} nodeId={id} resources={!!id && nodeResourcesTarget(location.hash) === id} onSave={save} />
      case 'topology': return <TopologyPage target={id} />
      case 'ssh': return <QuickSSH key={id || 'picker'} targetId={id} />
      case 'services': return <Services section={id} segments={segments} session={demoSession} onUnauthorized={onUnauthorized} />
      case 'exposures': return <ExposuresPage />
      case 'operations': return <OperationsPage section={id} />
      case 'alerts': return <AlertsPage />
      case 'audit': return <AuditPage />
      case 'sessions': return <><PageHeading eyebrow="SECURITY / SESSIONS" title="我的会话" description="查看登录记录，关闭不再使用的会话。" /><Sessions session={demoSession} onUnauthorized={onUnauthorized} /></>
      case 'access': return <AccessPage onFactors={() => event('示例账号已启用动态验证码。演示验证码为 123456。')} />
      case 'settings': return <SettingsPage onSave={save} />
      case 'deployments': return <DeploymentsPage targetId={id} />
      case 'seeds': return <SeedsPage />
      case 'pollen': case 'federation': return <><Notice tone="amber" title="未完成">当前版本尚未实现{page === 'pollen' ? '移动节点' : '跨 Grove 连接'}，此页面展示规划内容。</Notice><FuturePage page={page} /></>
      default: return <OverviewPage />
    }
  }
  return <>
    <div className="demo-toolbar"><strong>Spearmint <span>离线演示 · 示例 Grove</span></strong><div>
      <button onClick={() => setGuide(true)}>演示指南</button><a href="功能说明.html" target="_blank">功能说明</a>
      <button onClick={() => { if (window.confirm('恢复全部示例数据？')) resetDemo() }}>重置示例</button>
    </div></div>
    {signedIn ? <div className="demo-application"><ConsoleData session={demoSession} onUnauthorized={onUnauthorized} preferences={preferences} webBuild="preview.17 / mock">
      <ConsoleLayout page={route.page || 'overview'} onSignOut={() => setSignedIn(false)} signingOut={false}>{page()}</ConsoleLayout>
    </ConsoleData></div> : <div className="demo-login"><Brand /><Panel title="进入示例 Grove"><form className="stack" onSubmit={e => { e.preventDefault(); setSignedIn(true); location.hash = '#/overview' }}>
      <label className="field-label">账号<input className="input" defaultValue="demo-admin" autoComplete="off" /></label>
      <label className="field-label">密码<input className="input" type="password" defaultValue="demo123456" autoComplete="off" /></label>
      <button className="btn btn-primary">进入演示</button></form></Panel></div>}
    {message && <div role="status" className="demo-toast">{message}</div>}
    {guide && <Modal title="演示指南" onClose={() => setGuide(false)}>
      <p>直接浏览内置的 6 个节点。修改只保存在当前浏览器，随时可重置。</p>
      <ol className="demo-guide"><li><a href="#/topology" onClick={() => setGuide(false)}>查看网络拓扑</a>：选择 Thor，查看经上海中转的路径。</li>
        <li><a href="#/services" onClick={() => setGuide(false)}>管理服务</a>：查看日志，启停服务，登记多行启动命令。</li>
        <li><a href="#/ssh" onClick={() => setGuide(false)}>快速 SSH</a>：拓扑选点后输入 help、ls / dir、pwd；编辑下方 README.txt。</li>
        <li><a href="#/seeds" onClick={() => setGuide(false)}>节点播种</a>：任选发起节点，填写任意示例 SSH 信息并按向导安装。</li>
        <li><a href="#/deployments" onClick={() => setGuide(false)}>群组更新</a>：检查更新并发起，观察获取包、安装和完成状态。</li></ol>
      <a href="功能说明.html" target="_blank" className="btn btn-secondary">打开完整功能说明</a>
    </Modal>}
  </>
}
if (!location.hash) location.hash = '#/overview'
createRoot(document.getElementById('root')!).render(<DemoApp />)
