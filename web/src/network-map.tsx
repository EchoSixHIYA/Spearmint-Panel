import { useLayoutEffect, useRef, useState, type CSSProperties } from 'react'
import { type NodeView } from './console-data'
import { reachabilityLabel } from './connection-status'
import { Icon, nodeConnectionLabel, shortId } from './ui'
import { NetworkCanvas } from './network-canvas'
import { useNetworkMemory } from './network-memory'
import './network-map.css'

type Link = { id: string; from: string; to: string; kind: 'active' | 'selected' | 'alternative'; shared?: boolean; pending?: boolean }

function reportedLinks(nodes: NodeView[], current: NodeView, paths: Map<string, string[]>, rememberedDepths: Map<string, number>, target?: string, alternative?: readonly string[]) {
  const destinations = new Map<string, number>()
  const positions = new Map<string, number>()
  const relayPositions = new Map<string, number>()
  const links = new Map<string, Link>()
  for (const node of nodes) {
    const path = node.activePath ?? paths.get(node.id)
    if (!path) continue
    positions.set(node.id, path.length - 1)
    if (node.activePath) destinations.set(node.id, path.length - 1)
    for (let depth = 1; depth < path.length; depth++) {
      const from = path[depth - 1], to = path[depth]
      if (depth < path.length - 1) relayPositions.set(to, Math.min(depth, relayPositions.get(to) ?? depth))
      const id = [from, to].sort().join('/')
      const previous = links.get(id)
      if (!previous || (previous.pending && node.activePath) || (node.id === target && (node.activePath || previous.pending))) {
        links.set(id, { id, from, to, kind: node.id === target ? 'selected' : 'active', pending: !node.activePath })
      }
    }
  }
  const depths = new Map([...relayPositions, ...positions, [current.id, 0]])
  for (const node of nodes) if (!depths.has(node.id)) depths.set(node.id, rememberedDepths.get(node.id) ?? 1)
  const alternativeOnly = new Set<string>()
  if (alternative) for (let depth = 1; depth < alternative.length; depth++) {
    const from = alternative[depth - 1], to = alternative[depth]
    if (!depths.has(to)) {
      depths.set(to, depth)
      alternativeOnly.add(to)
    }
    const id = [from, to].sort().join('/')
    const previous = links.get(id)
    links.set(id, previous ? { ...previous, shared: true }
      : { id, from, to, kind: 'alternative' })
  }
  return { depths, destinations, alternativeOnly, links: [...links.values()] }
}

function linkGeometry(from: DOMRect, to: DOMRect, bounds: DOMRect, vertical: boolean, radial: boolean, obstacles: DOMRect[], lane: number) {
  const ax = from.left + from.width / 2, ay = from.top + from.height / 2
  const bx = to.left + to.width / 2, by = to.top + to.height / 2
  if (radial) {
    const distance = Math.hypot(bx - ax, by - ay) || 1
    const dx = (bx - ax) / distance, dy = (by - ay) / distance
    const x1 = ax + dx * from.width / 2 - bounds.left, y1 = ay + dy * from.height / 2 - bounds.top
    const x2 = bx - dx * to.width / 2 - bounds.left, y2 = by - dy * to.height / 2 - bounds.top
    return { x1, x2, y1, y2, path: `M ${x1} ${y1} L ${x2} ${y2}` }
  }
  if (Math.abs(ax - bx) < 1 && obstacles.some(rect => rect.left < ax && rect.right > ax
    && rect.top > Math.min(ay, by) && rect.bottom < Math.max(ay, by))) {
    const x1 = from.right - bounds.left, x2 = to.right - bounds.left
    const y1 = ay - bounds.top, y2 = by - bounds.top
    const corridor = Math.max(x1, x2) + 10 + lane % 3 * 3
    return { x1, x2, y1, y2, path: `M ${x1} ${y1} H ${corridor} V ${y2} H ${x2}` }
  }
  const across = vertical ? Math.abs(ay - by) < 1 : Math.abs(ax - bx) >= 1
  const direction = (across ? bx - ax : by - ay) >= 0 ? 1 : -1
  const x1 = (across ? ax + direction * from.width / 2 : ax) - bounds.left
  const x2 = (across ? bx - direction * to.width / 2 : bx) - bounds.left
  const y1 = (across ? ay : ay + direction * from.height / 2) - bounds.top
  const y2 = (across ? by : by - direction * to.height / 2) - bounds.top
  if (across && obstacles.some(rect => rect.left > Math.min(x1, x2) + bounds.left
    && rect.right < Math.max(x1, x2) + bounds.left)) {
    const corridor1 = x1 + direction * 14, corridor2 = x2 - direction * 14
    const top = Math.max(6, Math.min(from.top, to.top, ...obstacles.map(rect => rect.top)) - bounds.top - 12 - lane % 4 * 4)
    return { x1, x2, y1, y2, path: `M ${x1} ${y1} H ${corridor1} V ${top} H ${corridor2} V ${y2} H ${x2}` }
  }
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2
  const controls = across ? `${mx} ${y1} ${mx} ${y2}` : `${x1} ${my} ${x2} ${my}`
  return { x1, x2, y1, y2, path: `M ${x1} ${y1} C ${controls} ${x2} ${y2}` }
}

function Connections({ links, radial = false }: { links: Link[]; radial?: boolean }) {
  const overlay = useRef<SVGSVGElement>(null)
  const [lines, setLines] = useState<Array<ReturnType<typeof linkGeometry> & Pick<Link, 'id' | 'kind' | 'shared' | 'from' | 'to' | 'pending'>>>([])
  useLayoutEffect(() => {
    const graph = overlay.current?.parentElement
    if (!graph) return
    const cards = new Map(Array.from(graph.querySelectorAll<HTMLElement>('[data-mesh-node]'), (card) => [card.dataset.meshNode, card]))
    function draw() {
      if (!graph) return
      const visibleBounds = graph.getBoundingClientRect()
      const scaleX = visibleBounds.width / graph.offsetWidth || 1
      const scaleY = visibleBounds.height / graph.offsetHeight || 1
      const bounds = new DOMRect(0, 0, graph.offsetWidth, graph.offsetHeight)
      const vertical = getComputedStyle(graph).gridAutoFlow === 'row'
      const rects = new Map(Array.from(cards, ([id, card]) => {
        const rect = card.getBoundingClientRect()
        return [id, new DOMRect((rect.left - visibleBounds.left) / scaleX, (rect.top - visibleBounds.top) / scaleY,
          rect.width / scaleX, rect.height / scaleY)]
      }))
      setLines(links.filter(({ from, to }) => rects.has(from) && rects.has(to)).map(({ id, from, to, kind, shared, pending }, lane) => ({
        id, kind, shared, pending, from, to, ...linkGeometry(rects.get(from)!, rects.get(to)!, bounds, vertical, radial,
          [...rects].filter(([node]) => node !== from && node !== to).map(([, rect]) => rect), lane),
      })))
    }
    draw()
    const observer = new ResizeObserver(draw)
    observer.observe(graph)
    cards.forEach((card) => observer.observe(card))
    return () => observer.disconnect()
  }, [links, radial])
  return <svg ref={overlay} className="mesh-connections" aria-hidden="true">
    {lines.map(({ id, x1, x2, y1, y2, path, kind, shared, from, to, pending }) => <g key={id} className={`mesh-link-${kind}${pending ? ' mesh-link-pending' : ''}`} data-from={from} data-to={to}>
      <path d={path} className="mesh-wire-halo" /><path d={path} className="mesh-wire" />
      {shared && <path d={path} className="mesh-wire-shared" />}
      <circle cx={x1} cy={y1} r="3.5" /><circle cx={x2} cy={y2} r="3.5" />
    </g>)}
  </svg>
}

function NetworkPreview({ current, levels, byId, links, paths }: {
  current: NodeView; levels: Map<number, string[]>; byId: Map<string, NodeView>; links: Link[]; paths: Map<string, string[]>
}) {
  const angles = new Map<string, number>()
  const positions = [{ id: current.id, x: 0, y: 0 }]
  const startAngle = -5 * Math.PI / 6
  const turn = 2 * Math.PI
  // Geometric rings group nearby nodes without implying a hop count; exact hops remain in the detailed map.
  // A 120px separation clears every complete 80 × 70 node-and-label box, including between rings.
  const spacing = 120
  const remaining = [...levels].filter(([depth]) => depth > 0).flatMap(([, members]) => [...members].sort())
  let radius = 0
  while (remaining.length) {
    radius += spacing
    const capacity = Math.floor(Math.PI / Math.asin(spacing / (2 * radius)) + 1e-9)
    const members = remaining.splice(0, capacity)
    const ringSize = members.length
    const slotCount = angles.size === 0 ? ringSize
      : Math.max(ringSize, Math.floor(Math.PI / Math.asin(spacing / (2 * radius))))
    const slots = Array.from({ length: slotCount }, (_, index) => startAngle + index * turn / slotCount)
    for (const [index, id] of members.entries()) {
      const parent = paths.get(id)?.at(-2) ?? links.find((link) => link.to === id && angles.has(link.from))?.from
      const preferred = angles.get(parent ?? '') ?? startAngle + index * turn / ringSize
      const best = slots.reduce((closest, angle, i) =>
        Math.cos(angle - preferred) > Math.cos(slots[closest] - preferred) ? i : closest, 0)
      const [angle] = slots.splice(best, 1)
      angles.set(id, angle)
      positions.push({ id, x: Math.cos(angle) * radius, y: Math.sin(angle) * radius })
    }
  }
  const extent = positions.reduce((bounds, { x, y }) => ({ left: Math.min(bounds.left, x), right: Math.max(bounds.right, x),
    top: Math.min(bounds.top, y), bottom: Math.max(bounds.bottom, y) }), { left: 0, right: 0, top: 0, bottom: 0 })
  const width = extent.right - extent.left + 128, height = extent.bottom - extent.top + 118

  return <div className="mesh-preview" role="group" aria-label={`已报告的网络拓扑，${positions.length} 个节点，${links.length} 条链路`}
    style={{ width, height }}>
    <Connections links={links} radial />
    {positions.map(({ id, x, y }) => {
      const node = byId.get(id)
      const name = node?.name ?? shortId(id)
      const status = node ? nodeConnectionLabel(node) : '路径中继'
      const latency = node?.status === 'online' ? node.peer?.rtt_ms : null
      const label = [name, node?.local && '当前节点', status, latency != null && `${latency.toFixed(1)} ms`].filter(Boolean).join(' · ')
      const marker = <>
        <span className="mesh-preview-marker" data-mesh-node={id}>
          <Icon name={node?.local ? 'monitor' : node ? 'server' : 'route'} size={18} />
        </span>
        <span className="mesh-preview-name">{name}</span>
      </>
      const props = {
        className: `mesh-preview-node${node?.local ? ' is-local' : ''}${node?.status === 'online' ? ' is-online' : ''}`,
        style: { left: x - extent.left + 64, top: y - extent.top + 59 },
        title: label,
      }
      return node ? <a key={id} {...props} href={`#/nodes/${id}`} aria-label={label}>{marker}</a>
        : <div key={id} {...props}>{marker}</div>
    })}
  </div>
}

function MapNode({ node, plotted = false, hops, selected = false, alternative = false, selectTarget = false, onPick }: {
  node: NodeView; plotted?: boolean; hops?: number; selected?: boolean; alternative?: boolean; selectTarget?: boolean
  onPick?: (id: string) => void
}) {
  const online = node.status === 'online'
  const awaitingPath = online && !node.local && hops === undefined
  const latency = online ? node.peer?.rtt_ms : null
  const evidence = reachabilityLabel(node)
  const relayOnly = plotted && online && !node.local && hops === undefined
  const props = { className: `mesh-node${node.local ? ' is-local' : ''}${online ? ' is-online' : ''}${selected ? ' is-target' : ''}`,
    'data-mesh-node': plotted ? node.id : undefined, title: node.name }
  const card = <>
    <span className="mesh-node-icon"><Icon name={node.local ? 'monitor' : 'server'} size={21} /></span>
    <span className="mesh-node-info">
      <strong>{node.name}</strong>
      <small><span className="mesh-status-dot" />{nodeConnectionLabel(node)}{latency != null && <span className="mesh-latency" title="心跳往返时间">{latency.toFixed(1)} ms</span>}</small>
      {hops !== undefined && <small>{hops === 1 ? '直连' : `活动路径 ${hops} 跳`}</small>}
      {awaitingPath && <small>路径待报告</small>}
      {!online && plotted && <small>连接待确认</small>}
      {!online && node.idlePath && <small>上次连接 {node.idlePath.path.length - 1} 跳</small>}
      {relayOnly && <small>{alternative ? '备路经过' : '中继经过'}</small>}
      {evidence && <small>{evidence}</small>}
    </span>
    <Icon name={onPick ? selected ? 'check' : 'arrow-right' : 'arrow-up-right'} className="mesh-node-arrow" size={15} />
  </>
  if (onPick) return <button {...props} type="button" aria-pressed={selected}
    disabled={node.local ? !online : !node.peer?.enabled || ['disabled', 'quarantined'].includes(node.status)}
    onClick={() => onPick(node.id)}>{card}</button>
  return <a {...props} href={`#/${selectTarget && !node.local ? 'topology' : 'nodes'}/${node.id}`}
    aria-current={selectTarget && selected ? 'location' : undefined}>{card}</a>
}

function MapRelay({ id, alternative }: { id: string; alternative: boolean }) {
  return <div className="mesh-node mesh-relay" data-mesh-node={id} title={id}>
    <span className="mesh-node-icon"><Icon name="route" size={21} /></span>
    <span className="mesh-node-info"><strong>{shortId(id)}</strong><small>{alternative ? '备路经过' : '中继经过'}</small></span>
  </div>
}

export function NetworkMap({ mini = false, compact = false, target, alternative, onPick }: {
  mini?: boolean; compact?: boolean; target?: string; alternative?: readonly string[]; onPick?: (id: string) => void
}) {
  const { nodes, current, paths, depths: rememberedDepths } = useNetworkMemory()
  if (!current) return <div className="mesh-map"><p className="mesh-map-message">正在读取本机节点…</p></div>

  const { depths, destinations, alternativeOnly, links } = reportedLinks(nodes, current, paths, rememberedDepths, target, alternative)
  const levels = new Map<number, string[]>()
  const byId = new Map(nodes.map((node) => [node.id, node]))
  for (const [id, depth] of [...depths].sort(([, a], [, b]) => a - b)) {
    const level = levels.get(depth)
    if (level) level.push(id)
    else levels.set(depth, [id])
  }
  return <div className={`mesh-map${mini ? ' mesh-map-mini' : ''}${compact ? ' mesh-map-compact' : ''}`}>
    {alternative && <div className="mesh-map-legend"><span><i />活动路径</span><span><i className="is-alternative" />已验证备路</span></div>}
    <NetworkCanvas mini={mini} compact={compact} current={current.id}
      label={mini ? '节点关系画布' : compact ? '节点连接拓扑画布' : '网络拓扑画布'}>
      {mini ? <NetworkPreview current={current} levels={levels} byId={byId} links={links} paths={paths} />
        : <div className="mesh-graph" role="group" aria-label={`已报告的网络拓扑，${depths.size} 个节点，${links.length} 条链路`}
          style={compact ? { '--mesh-level-count': levels.size } as CSSProperties : undefined}>
          <Connections links={links} />
          {[...levels].map(([depth, members]) => <section className="mesh-level" key={depth}>
            <h4>{depth === 0 ? '当前节点' : `${depth} 跳`}</h4>
            <div className="mesh-level-nodes">{members.map((id) => {
              const node = byId.get(id)
              return node ? <MapNode key={id} node={node} plotted hops={destinations.get(id)} selected={id === target}
                alternative={alternativeOnly.has(id)} selectTarget={!compact} onPick={onPick} />
                : <MapRelay key={id} id={id} alternative={alternativeOnly.has(id)} />
            })}</div>
          </section>)}
        </div>}
    </NetworkCanvas>
  </div>
}
