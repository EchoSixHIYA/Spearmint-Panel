import { useLayoutEffect, useRef, useState } from 'react'
import { useConsole, type NodeView } from './console-data'
import { reachabilityLabel, reachabilityReports } from './connection-status'
import { Icon, nodeConnectionLabel, shortId } from './ui'
import './network-map.css'

type Link = { id: string; from: string; to: string; kind: 'active' | 'selected' | 'alternative'; shared?: boolean }

function reportedLinks(nodes: NodeView[], current: NodeView, target?: string, alternative?: readonly string[]) {
  const destinations = new Map<string, number>()
  const relayPositions = new Map<string, number>()
  const links = new Map<string, Link>()
  for (const node of nodes) {
    const path = node.activePath
    if (!path) continue
    destinations.set(node.id, path.length - 1)
    for (let depth = 1; depth < path.length; depth++) {
      const from = path[depth - 1], to = path[depth]
      if (depth < path.length - 1) relayPositions.set(to, Math.min(depth, relayPositions.get(to) ?? depth))
      const id = [from, to].sort().join('/')
      const previous = links.get(id)
      if (!previous || node.id === target) links.set(id, { id, from, to, kind: node.id === target ? 'selected' : 'active' })
    }
  }
  const depths = new Map([...relayPositions, ...destinations, [current.id, 0]])
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

function linkGeometry(from: DOMRect, to: DOMRect, bounds: DOMRect, vertical: boolean) {
  const ax = from.left + from.width / 2, ay = from.top + from.height / 2
  const bx = to.left + to.width / 2, by = to.top + to.height / 2
  const across = vertical ? Math.abs(ay - by) < 1 : Math.abs(ax - bx) >= 1
  const direction = (across ? bx - ax : by - ay) >= 0 ? 1 : -1
  const x1 = (across ? ax + direction * from.width / 2 : ax) - bounds.left
  const x2 = (across ? bx - direction * to.width / 2 : bx) - bounds.left
  const y1 = (across ? ay : ay + direction * from.height / 2) - bounds.top
  const y2 = (across ? by : by - direction * to.height / 2) - bounds.top
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2
  const controls = across ? `${mx} ${y1} ${mx} ${y2}` : `${x1} ${my} ${x2} ${my}`
  return { x1, x2, y1, y2, path: `M ${x1} ${y1} C ${controls} ${x2} ${y2}` }
}

function Connections({ links }: { links: Link[] }) {
  const overlay = useRef<SVGSVGElement>(null)
  const [lines, setLines] = useState<Array<ReturnType<typeof linkGeometry> & Pick<Link, 'id' | 'kind' | 'shared'>>>([])
  useLayoutEffect(() => {
    const graph = overlay.current?.parentElement
    if (!graph) return
    const cards = new Map(Array.from(graph.querySelectorAll<HTMLElement>('[data-mesh-node]'), (card) => [card.dataset.meshNode, card]))
    function draw() {
      if (!graph) return
      const bounds = graph.getBoundingClientRect()
      const vertical = getComputedStyle(graph).gridAutoFlow === 'row'
      const rects = new Map(Array.from(cards, ([id, card]) => [id, card.getBoundingClientRect()]))
      setLines(links.map(({ id, from, to, kind, shared }) => ({ id, kind, shared, ...linkGeometry(rects.get(from)!, rects.get(to)!, bounds, vertical) })))
    }
    draw()
    const observer = new ResizeObserver(draw)
    observer.observe(graph)
    cards.forEach((card) => observer.observe(card))
    return () => observer.disconnect()
  }, [links])
  return <svg ref={overlay} className="mesh-connections" aria-hidden="true">
    {lines.map(({ id, x1, x2, y1, y2, path, kind, shared }) => <g key={id} className={`mesh-link-${kind}`}>
      <path d={path} className="mesh-wire-halo" /><path d={path} className="mesh-wire" />
      {shared && <path d={path} className="mesh-wire-shared" />}
      <circle cx={x1} cy={y1} r="3.5" /><circle cx={x2} cy={y2} r="3.5" />
    </g>)}
  </svg>
}

function MapNode({ node, plotted = false, hops, selected = false, alternative = false, selectTarget = false, onPick }: {
  node: NodeView; plotted?: boolean; hops?: number; selected?: boolean; alternative?: boolean; selectTarget?: boolean
  onPick?: (id: string) => void
}) {
  const online = node.status === 'online'
  const awaitingPath = online && !node.local && hops === undefined
  const latency = online ? node.peer?.rtt_ms : null
  const evidence = reachabilityLabel(node)
  const relayOnly = plotted && !node.local && hops === undefined
  const props = { className: `mesh-node${node.local ? ' is-local' : ''}${online ? ' is-online' : ''}${selected ? ' is-target' : ''}`,
    'data-mesh-node': plotted ? node.id : undefined, title: node.name }
  const card = <>
    <span className="mesh-node-icon"><Icon name={node.local ? 'monitor' : 'server'} size={21} /></span>
    <span className="mesh-node-info">
      <strong>{node.name}</strong>
      <small><span className="mesh-status-dot" />{nodeConnectionLabel(node)}{latency != null && <span className="mesh-latency" title="心跳往返时间">{latency.toFixed(1)} ms</span>}</small>
      {hops !== undefined && <small>{hops === 1 ? '直连' : `活动路径 ${hops} 跳`}</small>}
      {awaitingPath && <small>路径待报告</small>}
      {!online && node.idlePath && <small>上次连接 {node.idlePath.path.length - 1} 跳</small>}
      {relayOnly && <small>{alternative ? '备路经过' : '中继经过'}</small>}
      {evidence && <small>{evidence}</small>}
    </span>
    <Icon name={onPick ? selected ? 'check' : 'arrow-right' : 'arrow-up-right'} className="mesh-node-arrow" size={15} />
  </>
  if (onPick) return <button {...props} type="button" aria-pressed={selected}
    disabled={!node.local && (!node.peer?.enabled || ['disabled', 'quarantined'].includes(node.status))}
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

export function NetworkMap({ mini = false, target, alternative, onPick }: {
  mini?: boolean; target?: string; alternative?: readonly string[]; onPick?: (id: string) => void
}) {
  const { listedNodes: nodes } = useConsole()
  const current = nodes.find((node) => node.local)
  if (!current) return <div className="mesh-map"><p className="mesh-map-message">正在读取本机节点…</p></div>

  const { depths, destinations, alternativeOnly, links } = reportedLinks(nodes, current, target, alternative)
  const levels = new Map<number, string[]>()
  const byId = new Map(nodes.map((node) => [node.id, node]))
  for (const [id, depth] of depths) {
    const level = levels.get(depth)
    if (level) level.push(id)
    else levels.set(depth, [id])
  }
  const unplaced: NodeView[] = []
  const observed: NodeView[] = []
  const withoutMesh: NodeView[] = []
  for (const node of nodes) {
    const depth = depths.get(node.id)
    if (depth === undefined && node.status === 'unconfigured') withoutMesh.push(node)
    else if (depth === undefined) (reachabilityReports(node) ? observed : unplaced).push(node)
  }
  const withoutPaths = [
    { members: observed, title: '邻居观测可达 · 本机暂无活动路径' },
    { members: unplaced, title: '暂无活动路径' },
    { members: withoutMesh, title: '本机未配置 Mesh 互联' },
  ]
  return <div className={`mesh-map${mini ? ' mesh-map-mini' : ''}`}>
    {alternative && <div className="mesh-map-legend"><span><i />活动路径</span><span><i className="is-alternative" />已验证备路</span></div>}
    <div className="mesh-map-scroll">
      <div className="mesh-graph" role="group" aria-label={`已报告的网络拓扑，${depths.size} 个节点，${links.length} 条链路`}>
        <Connections links={links} />
        {[...levels].sort(([a], [b]) => a - b).map(([depth, members]) => <section className="mesh-level" key={depth}>
          <h4>{depth === 0 ? '当前节点' : `${depth} 跳`}</h4>
          <div className="mesh-level-nodes">{members.map((id) => {
            const node = byId.get(id)
            return node ? <MapNode key={id} node={node} plotted hops={destinations.get(id)} selected={id === target}
              alternative={alternativeOnly.has(id)} selectTarget={!mini} onPick={onPick} />
              : <MapRelay key={id} id={id} alternative={alternativeOnly.has(id)} />
          })}</div>
        </section>)}
      </div>
    </div>
    {withoutPaths.filter(({ members }) => members.length > 0).map(({ members, title }) => <section className="mesh-unplaced" key={title}>
        <h4>{title} · {members.length} 个节点</h4>
        <div>{members.map((node) => <MapNode key={node.id} node={node} selected={node.id === target} selectTarget={!mini} onPick={onPick} />)}</div>
      </section>)}
  </div>
}
