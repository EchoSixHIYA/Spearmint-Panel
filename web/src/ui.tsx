import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import { iconPaths } from './icons'
import { connectionLabels, nodeConnectionGroup, type ConnectionGroup } from './connection-status'
import { serviceFilters, serviceHealthLabels, type ServiceFilter, type ServiceHealth } from './service-status'

export function Icon({ name, size = 18, className = '' }: { name: string; size?: number; className?: string }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"
    strokeLinecap="round" strokeLinejoin="round" className={`icon ${className}`} aria-hidden="true"
    dangerouslySetInnerHTML={{ __html: iconPaths[name] || iconPaths['leaf'] }} />
}

export function Brand() {
  return <a className="brand-link" href="#/services" aria-label="Spearmint 服务工作区">
    <span className="brand-mark"><Icon name="sprout" size={25} /></span>
    <span className="brand-type"><strong>spearmint</strong><small>GROVE CONSOLE</small></span>
  </a>
}

export function PageHeading({ eyebrow, title, description, children }: {
  eyebrow: string; title: ReactNode; description: ReactNode; children?: ReactNode
}) {
  return <header className="page-heading"><div><span className="eyebrow">{eyebrow}</span>
    <h1 tabIndex={-1} id="page-title">{title}</h1><p>{description}</p></div>
    {children && <div className="heading-actions">{children}</div>}</header>
}

export function Panel({ title, action, children, className = '' }: {
  title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string
}) {
  return <section className={`panel ${className}`}>{(title || action) && <div className="panel-head">
    {title && <h3>{title}</h3>}{action}</div>}{children}</section>
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge badge-${tone}`}>{children}</span>
}

export const stateNames: Record<string, string> = {
  online: '已连接', offline: '离线', unreachable: '不可达', disabled: '已停用', quarantined: '本机已隔离', probing: '探测中',
  connecting: '连接中', reconnecting: '等待重连', backoff: '等待重连', listening: '监听中', error: '连接异常', idle: '按需连接',
  unconfigured: '未配置互联',
  running: '运行中', stopped: '已停止', starting: '启动中', stopping: '停止中', failed: '失败',
  missing: '目标缺失', unknown: '状态未知', queued: '排队中', succeeded: '已完成', uncertain: '结果待确认',
}

export function StateBadge({ state, stale = false }: { state: string; stale?: boolean }) {
  const tone = stale ? 'amber' : ['online', 'running', 'succeeded'].includes(state) ? 'green'
    : ['failed', 'error', 'missing', 'offline', 'unreachable'].includes(state) ? 'red'
    : ['queued', 'starting', 'stopping', 'probing', 'uncertain', 'backoff', 'reconnecting', 'connecting', 'quarantined'].includes(state) ? 'amber' : 'neutral'
  return <Badge tone={tone}>{stale ? '数据陈旧' : stateNames[state] || state}</Badge>
}

export function ServiceHealthBadge({ health }: { health: ServiceHealth }) {
  return <Badge tone={health === 'unhealthy' ? 'red' : health === 'starting' ? 'amber' : 'green'}>{serviceHealthLabels[health]}</Badge>
}

export function ServiceStatusFilters({ value, onChange }: { value: ServiceFilter; onChange: (filter: ServiceFilter) => void }) {
  return <div className="filter-pills" role="group" aria-label="服务状态筛选">
    {(Object.keys(serviceFilters) as ServiceFilter[]).map((filter) => <button key={filter} type="button"
      className={`pill ${filter === value ? 'active' : ''}`} aria-pressed={filter === value} onClick={() => onChange(filter)}>
      {serviceFilters[filter]}
    </button>)}
  </div>
}

export function nodeConnectionLabel(node: Parameters<typeof nodeConnectionGroup>[0]) {
  const group = nodeConnectionGroup(node)
  return group === 'observed' || group === 'unreachable' ? connectionLabels[group] : stateNames[node.status] || node.status
}

export function NodeConnectionBadge({ node }: { node: Parameters<typeof nodeConnectionGroup>[0] }) {
  const group = nodeConnectionGroup(node)
  if (group === 'observed' || group === 'unreachable') {
    return <Badge tone={group === 'observed' ? 'amber' : 'red'}>{nodeConnectionLabel(node)}</Badge>
  }
  return <StateBadge state={node.status} />
}

export function Metric({ label, value, unit, detail, icon, hint }: {
  label: string; value: ReactNode; unit?: string; detail: ReactNode; icon: string; hint?: ReactNode
}) {
  return <section className="metric-card"><div className="metric-top"><span>{label}</span><Icon name={icon} className="metric-icon" /></div>
    <div className="metric-main">{value}{unit && <> <small>{unit}</small></>}</div>
    <div className="metric-bottom"><span>{detail}</span>{hint && <span className="trend">{hint}</span>}</div></section>
}

export function EmptyState({ icon = 'sprout', title, children, action }: {
  icon?: string; title: string; children?: ReactNode; action?: ReactNode
}) {
  return <div className="empty-state"><span className="empty-symbol"><Icon name={icon} size={28} /></span>
    <h3>{title}</h3>{children && <p>{children}</p>}{action}</div>
}

export function Notice({ title, children, tone = '', icon = 'info' }: {
  title?: string; children: ReactNode; tone?: string; icon?: string
}) {
  return <div className={`notice ${tone ? `notice-${tone}` : ''}`}><Icon name={icon} />
    <div>{title && <strong>{title}</strong>}<p>{children}</p></div></div>
}

export function Loading({ label = '正在读取最新状态…' }: { label?: string }) {
  return <div className="loading-state" role="status"><span className="loading-leaf"><Icon name="sprout" size={24} /></span>{label}</div>
}

export function CopyValue({ value, short = false }: { value: string; short?: boolean }) {
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => clearTimeout(timer.current), [])
  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true); setError(false)
      clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 2000)
    } catch { setError(true) }
  }
  return <span className="copy-value"><code title={value}>{short ? shortId(value) : value}</code>
    <button type="button" className="icon-button" aria-label={copied ? '已复制' : `复制 ${shortId(value)}`} onClick={() => void copy()}>
      <Icon name={copied ? 'check' : 'copy'} size={14} /></button>
    {error && <small role="status">请选中标识手动复制</small>}</span>
}

export function shortId(value: string) { return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-6)}` : value }
export function bytes(size: number) {
  if (size < 1024) return `${Math.round(size)} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']; let number = size / 1024; let index = 0
  while (number >= 1024 && index < units.length - 1) { number /= 1024; index++ }
  return `${number.toFixed(1)} ${units[index]}`
}
export function duration(seconds: number | null | undefined) {
  if (seconds == null) return '等待采样'
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)} 天 ${Math.floor(seconds % 86400 / 3600)} 小时`
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分钟`
}

export function Tabs({ items, current, onChange, label }: {
  items: { id: string; label: string; icon?: string }[]; current: string; onChange: (value: string) => void; label: string
}) {
  return <div className="tabs" role="tablist" aria-label={label}>{items.map((item) => <button key={item.id}
    className={`tab ${current === item.id ? 'active' : ''}`} type="button" role="tab" id={`${label}-${item.id}`}
    aria-selected={current === item.id} tabIndex={current === item.id ? 0 : -1}
    onKeyDown={(event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
      event.preventDefault()
      const index = items.findIndex((entry) => entry.id === current)
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1
        : (index + (event.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length
      onChange(items[next].id)
      document.getElementById(`${label}-${items[next].id}`)?.focus()
    }} onClick={() => onChange(item.id)}>{item.icon && <Icon name={item.icon} size={15} />}{item.label}</button>)}</div>
}

export function Modal({ title, children, onClose, className = '', dismissOnEscape = true }: {
  title: string; children: ReactNode; onClose: () => void; className?: string; dismissOnEscape?: boolean
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const close = useRef(onClose); close.current = onClose
  useEffect(() => {
    const dialog = ref.current; dialog?.showModal()
    dialog?.querySelector<HTMLElement>('[autofocus], input:not([type="hidden"])')?.focus()
    return () => dialog?.close()
  }, [])
  return <dialog ref={ref} className={`console-modal ${className}`} aria-label={title}
    onCancel={event => { event.preventDefault(); if (dismissOnEscape) close.current() }} onClick={(event) => { if (event.target === event.currentTarget) close.current() }}>
    <div className="modal-inner"><div className="modal-heading"><h2>{title}</h2>
      <button className="icon-button" onClick={onClose} aria-label="关闭对话框"><Icon name="x" /></button></div>{children}</div>
  </dialog>
}

export function GardenArt() {
  return <div className="garden-art" aria-hidden="true"><svg viewBox="0 0 530 230" className="garden-svg">
    <defs><linearGradient id="leafGradient" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#a5d1ac" /><stop offset="1" stopColor="#2f806c" /></linearGradient></defs>
    <circle cx="278" cy="114" r="92" fill="none" stroke="#d6e9d9" strokeWidth="1" /><circle cx="278" cy="114" r="66" fill="none" stroke="#d6e9d9" strokeWidth="1" />
    <path d="M85 145 C150 100 205 75 275 121 S395 174 472 80" stroke="#7fbb9a" strokeWidth="2" strokeDasharray="5 6" fill="none" />
    <path d="M145 72 Q230 50 280 121 T444 164" stroke="#b4cdbd" strokeWidth="1.6" fill="none" />
    <g transform="translate(278 132)"><path d="M0 72V-58" stroke="#1f7359" strokeWidth="4" strokeLinecap="round" />
      <path d="M0 13C-62 12-73-25-72-48-33-48-4-23 0 13Z" fill="url(#leafGradient)" />
      <path d="M0-4C42 1 69-35 64-62 28-63 2-40 0-4Z" fill="#62a984" />
      <path d="M0 45C-41 37-61 10-59-8-28-7-5 8 0 45Z" fill="#9cca9a" />
      <path d="M0-57C-18-75-20-94 0-109 20-94 17-76 0-57Z" fill="#b0cf8f" /></g>
    <g fill="#fff" stroke="#4f9673" strokeWidth="2"><circle cx="145" cy="72" r="8" /><circle cx="85" cy="145" r="7" /><circle cx="443" cy="164" r="9" /><circle cx="472" cy="80" r="6" /></g>
    <g fill="#7ab18b"><circle cx="197" cy="157" r="3" /><circle cx="392" cy="44" r="3" /><circle cx="103" cy="56" r="3" /></g>
  </svg></div>
}

export function AuthStory() {
  return <div className="auth-story"><div className="auth-brand"><Icon name="sprout" size={30} />spearmint</div>
    <div className="auth-paint"><svg viewBox="0 0 420 400" aria-hidden="true"><circle cx="210" cy="190" r="142" stroke="#ffffff44" fill="none" />
      <circle cx="210" cy="190" r="95" stroke="#ffffff22" fill="none" />
      <path d="M204 339V120M204 248C101 230 91 154 100 119c70 1 102 44 104 129Zm0-73c61-68 120-78 148-71-6 72-67 91-148 100Zm0 112c-81-9-117-52-107-92 61 3 103 39 107 92Z" fill="#addab5" stroke="#3b836e" strokeWidth="4" />
      <path d="M204 124c-31-37-31-80 0-111 33 32 32 77 0 111" fill="#c7e6a9" /></svg></div>
    <div className="auth-story-copy"><div className="eyebrow">EVERYTHING IS CONNECTED</div><h2>Welcome back<br />to your Grove.</h2><p>你的基础设施，始终在你身边。</p></div>
  </div>
}

const connectionColors: Record<ConnectionGroup, string> = {
  connected: 'green', idle: 'amber', pending: 'violet', unconfigured: 'neutral', observed: 'amber', unreachable: 'red', restricted: 'neutral', unknown: 'neutral',
}

export function HealthRing({ connections, total }: {
  connections: Record<ConnectionGroup, number>; total: number
}) {
  const percent = total ? Math.round(connections.connected / total * 100) : 0
  const groups = (Object.keys(connectionLabels) as ConnectionGroup[]).filter((group) =>
    ['connected', 'idle', 'unreachable'].includes(group) || connections[group] > 0)
  return <div className="health-summary"><div className="health-ring" style={{ background: `conic-gradient(#5caa7a 0% ${percent}%, #e7ece5 ${percent}% 100%)` } as CSSProperties}>
    <div><b>{connections.unknown === total ? '—' : `${percent}%`}</b><span>远程节点已连接</span></div></div>
    <div className="health-legend">{groups.map((group) => <div key={group}><span className={`dot ${connectionColors[group]}`} />
      {connectionLabels[group]}<b>{connections[group]}</b></div>)}</div></div>
}
