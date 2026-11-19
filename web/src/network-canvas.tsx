import { useLayoutEffect, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from 'react'
import { Icon } from './ui'

type Camera = { x: number; y: number; scale: number }
type Point = { x: number; y: number }
type Drag = { pointer: number; start: Point; camera: Camera; moved: boolean }
type Pinch = { distance: number; center: Point; camera: Camera }
const limits = { min: .001, max: 2.5 }
const clamp = (scale: number) => Math.max(limits.min, Math.min(limits.max, scale))

export function NetworkCanvas({ children, mini, compact, current, label }: {
  children: ReactNode; mini: boolean; compact: boolean; current: string; label: string
}) {
  const viewport = useRef<HTMLDivElement>(null)
  const stage = useRef<HTMLDivElement>(null)
  const camera = useRef<Camera>({ x: 0, y: 0, scale: 1 })
  const [view, setView] = useState(camera.current)
  const [dragging, setDragging] = useState(false)
  const [overflow, setOverflow] = useState(false)
  const drag = useRef<Drag | null>(null)
  const pinch = useRef<Pinch | null>(null)
  const pointers = useRef(new Map<number, Point>())
  const suppressClick = useRef(false)
  const touched = useRef(false)
  const controls = !mini && !compact

  function move(next: Camera) { camera.current = next; setView(next) }
  function bounds() {
    const outer = viewport.current, inner = stage.current
    return outer && inner ? { width: outer.clientWidth, height: outer.clientHeight, contentWidth: inner.offsetWidth, contentHeight: inner.offsetHeight } : null
  }
  function centered(scale: number, focusCurrent = false) {
    const size = bounds()
    if (!size) return
    let x = size.contentWidth / 2, y = size.contentHeight / 2
    if (focusCurrent) {
      const node = stage.current?.querySelector<HTMLElement>('[data-mesh-node].is-local, .is-local [data-mesh-node]')
      if (node && stage.current) {
        const rect = node.getBoundingClientRect(), parent = stage.current.getBoundingClientRect()
        x = (rect.left + rect.width / 2 - parent.left) / camera.current.scale
        y = (rect.top + rect.height / 2 - parent.top) / camera.current.scale
      }
    }
    move({ scale, x: size.width / 2 - x * scale, y: size.height / 2 - y * scale })
  }
  function fit() {
    const size = bounds()
    if (!size?.width || !size.contentWidth || !size.contentHeight) return
    const scale = Math.min(1, (size.width - 16) / size.contentWidth, (size.height - 16) / size.contentHeight)
    centered(clamp(scale))
  }
  function zoom(scale: number, point?: Point) {
    const size = bounds()
    if (!size) return
    const before = camera.current, after = clamp(scale), ratio = after / before.scale
    const anchor = point ?? { x: size.width / 2, y: size.height / 2 }
    move({ scale: after, x: anchor.x - (anchor.x - before.x) * ratio, y: anchor.y - (anchor.y - before.y) * ratio })
  }
  useLayoutEffect(() => {
    const outer = viewport.current, inner = stage.current
    if (!outer || !inner) return
    touched.current = false
    function resize() {
      const size = bounds()
      if (!size) return
      setOverflow(size.contentWidth > size.width || size.contentHeight > size.height - 32)
      if (!touched.current) {
        if (mini) centered(1, true)
        else fit()
      }
    }
    resize()
    const observer = new ResizeObserver(resize)
    observer.observe(outer)
    observer.observe(inner)
    function wheel(event: WheelEvent) {
      if (!event.ctrlKey && !event.metaKey) return
      event.preventDefault()
      touched.current = true
      const rect = outer!.getBoundingClientRect()
      zoom(camera.current.scale * Math.exp(-Math.max(-100, Math.min(100, event.deltaY)) * .008), { x: event.clientX - rect.left, y: event.clientY - rect.top })
    }
    outer.addEventListener('wheel', wheel, { passive: false })
    return () => { observer.disconnect(); outer.removeEventListener('wheel', wheel) }
  }, [current, mini])

  function localPoint(event: PointerEvent): Point {
    const rect = viewport.current!.getBoundingClientRect()
    return { x: event.clientX - rect.left, y: event.clientY - rect.top }
  }
  function onPointerDown(event: PointerEvent<HTMLDivElement>) {
    suppressClick.current = false
    if ((event.button !== 0 && event.button !== 1) || (event.target as HTMLElement).closest('.mesh-canvas-controls')) return
    const point = localPoint(event)
    pointers.current.set(event.pointerId, point)
    if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()]
      pinch.current = { camera: camera.current, distance: Math.max(1, Math.hypot(b.x - a.x, b.y - a.y)), center: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } }
      drag.current = null
      suppressClick.current = true
    } else if (pointers.current.size === 1) drag.current = { pointer: event.pointerId, start: point, camera: camera.current, moved: false }
    if (event.button === 1) event.preventDefault()
  }
  function onPointerMove(event: PointerEvent<HTMLDivElement>) {
    if (!pointers.current.has(event.pointerId)) return
    if (event.pointerType === 'mouse' && event.buttons === 0) { endPointer(event); return }
    const point = localPoint(event)
    pointers.current.set(event.pointerId, point)
    const gesture = pinch.current
    if (gesture && pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()]
      const center = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }
      const scale = clamp(gesture.camera.scale * Math.hypot(b.x - a.x, b.y - a.y) / gesture.distance)
      const ratio = scale / gesture.camera.scale
      move({ scale, x: center.x - (gesture.center.x - gesture.camera.x) * ratio, y: center.y - (gesture.center.y - gesture.camera.y) * ratio })
      touched.current = true
      setDragging(true)
      return
    }
    const active = drag.current
    if (!active || active.pointer !== event.pointerId) return
    const dx = point.x - active.start.x, dy = point.y - active.start.y
    if (!active.moved && Math.hypot(dx, dy) < 6) return
    active.moved = true
    touched.current = true
    suppressClick.current = true
    event.currentTarget.setPointerCapture(event.pointerId)
    setDragging(true)
    move({ ...active.camera, x: active.camera.x + dx, y: active.camera.y + dy })
  }
  function endPointer(event: PointerEvent<HTMLDivElement>) {
    pointers.current.delete(event.pointerId)
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId)
    pinch.current = null
    drag.current = null
    setDragging(false)
    const remaining = [...pointers.current.entries()][0]
    if (remaining) drag.current = { pointer: remaining[0], start: remaining[1], camera: camera.current, moved: true }
  }
  function keyboard(event: KeyboardEvent<HTMLDivElement>) {
    if (event.target !== event.currentTarget) return
    const next = camera.current
    switch (event.key) {
      case 'ArrowLeft': move({ ...next, x: next.x + 48 }); break
      case 'ArrowRight': move({ ...next, x: next.x - 48 }); break
      case 'ArrowUp': move({ ...next, y: next.y + 48 }); break
      case 'ArrowDown': move({ ...next, y: next.y - 48 }); break
      case '+': case '=': zoom(next.scale * 1.2); break
      case '-': zoom(next.scale / 1.2); break
      case '0': fit(); break
      case 'Home': centered(1, true); break
      default: return
    }
    event.preventDefault()
    touched.current = true
  }
  function control(action: () => void) { touched.current = true; action() }
  return <div className={`mesh-canvas-shell${mini ? ' is-mini' : ''}${compact ? ' is-compact' : ''}`} role="region" aria-label={label}>
    {controls && <div className="mesh-canvas-controls" role="group" aria-label="画布视图">
      <button type="button" aria-label="缩小拓扑" title="缩小" disabled={view.scale <= limits.min} onClick={() => control(() => zoom(camera.current.scale / 1.2))}>−</button>
      <output aria-label="画布缩放比例">{view.scale < .1 ? (view.scale * 100).toFixed(1) : Math.round(view.scale * 100)}%</output>
      <button type="button" aria-label="放大拓扑" title="放大" disabled={view.scale >= limits.max} onClick={() => control(() => zoom(camera.current.scale * 1.2))}>+</button>
      <button type="button" aria-label="适配画布" title="适配全部节点（0）" onClick={() => control(() => fit())}><Icon name="maximize" size={14} /></button>
      <button type="button" aria-label="回到当前节点" title="回到当前节点（Home）" onClick={() => control(() => centered(1, true))}><Icon name="monitor" size={14} /></button>
    </div>}
    <div ref={viewport} className={`mesh-canvas${dragging ? ' is-dragging' : ''}`} tabIndex={0} aria-label="拖动和缩放画布" onKeyDown={keyboard}
      onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={endPointer} onPointerCancel={endPointer}
      onLostPointerCapture={(event) => { if (pointers.current.has(event.pointerId)) endPointer(event) }}
      onDragStart={(event) => event.preventDefault()}
      onClickCapture={(event) => { if (suppressClick.current && event.detail > 0) { event.preventDefault(); event.stopPropagation() } }}>
      <div ref={stage} className="mesh-canvas-stage" style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.scale})` }}>{children}</div>
      {overflow && controls && <span className="mesh-canvas-hint">拖动画布 · Ctrl + 滚轮缩放</span>}
    </div>
  </div>
}
