/** Display layers describe the combined graph, never an individual RPC route's hop count. */
export function graphLayers(current: string, nodes: Iterable<string>, links: readonly { from: string; to: string }[], remembered: ReadonlyMap<string, number>) {
  const neighbors = new Map<string, Set<string>>()
  for (const { from, to } of links) {
    if (!neighbors.has(from)) neighbors.set(from, new Set())
    if (!neighbors.has(to)) neighbors.set(to, new Set())
    neighbors.get(from)!.add(to); neighbors.get(to)!.add(from)
  }
  const depths = new Map([[current, 0]]), queue = [current]
  for (let index = 0; index < queue.length; index++) {
    const id = queue[index]
    for (const next of neighbors.get(id) ?? []) if (!depths.has(next)) {
      depths.set(next, depths.get(id)! + 1); queue.push(next)
    }
  }
  for (const id of nodes) if (!depths.has(id)) depths.set(id, remembered.get(id) || 1)
  // Cached disconnected components may have been several layers away. Keep their
  // relative order without drawing empty columns or inventing intermediate nodes.
  const layers = [...new Set(depths.values())].sort((a, b) => a - b)
  return new Map([...depths].map(([id, depth]) => [id, layers.indexOf(depth)]))
}

type Box = { left: number; top: number; right: number; bottom: number; width: number; height: number }
type Point = { x: number; y: number }
const padding = 7

function segmentBlocked(a: Point, b: Point, box: Box) {
  // Slab intersection, including diagonals of a sampled Bezier. Padding keeps
  // both the wire and its halo outside a card even between adjacent samples.
  let low = 0, high = 1
  for (const [start, delta, min, max] of [[a.x, b.x - a.x, box.left - padding, box.right + padding],
    [a.y, b.y - a.y, box.top - padding, box.bottom + padding]]) {
    if (Math.abs(delta) < 1e-8) { if (start < min || start > max) return false; continue }
    const first = (min - start) / delta, last = (max - start) / delta
    low = Math.max(low, Math.min(first, last)); high = Math.min(high, Math.max(first, last))
    if (low > high) return false
  }
  return true
}

export function linkGeometry(from: Box, to: Box, bounds: Box, vertical: boolean, radial: boolean, obstacles: Box[], lane: number) {
  const ax = from.left + from.width / 2, ay = from.top + from.height / 2
  const bx = to.left + to.width / 2, by = to.top + to.height / 2
  const local = (x: number, y: number) => ({ x: x - bounds.left, y: y - bounds.top })
  function result(points: Point[], path: string) {
    return { x1: points[0].x, y1: points[0].y, x2: points.at(-1)!.x, y2: points.at(-1)!.y, path }
  }
  if (radial) {
    const distance = Math.hypot(bx - ax, by - ay) || 1
    const dx = (bx - ax) / distance, dy = (by - ay) / distance
    const a = local(ax + dx * from.width / 2, ay + dy * from.height / 2)
    const b = local(bx - dx * to.width / 2, by - dy * to.height / 2)
    return result([a, b], `M ${a.x} ${a.y} L ${b.x} ${b.y}`)
  }
  const across = vertical ? Math.abs(ay - by) < 1 : Math.abs(ax - bx) >= 1
  const direction = (across ? bx - ax : by - ay) >= 0 ? 1 : -1
  const a = { x: across ? ax + direction * from.width / 2 : ax, y: across ? ay : ay + direction * from.height / 2 }
  const b = { x: across ? bx - direction * to.width / 2 : bx, y: across ? by : by - direction * to.height / 2 }
  const c = { x: across ? (a.x + b.x) / 2 : a.x, y: across ? a.y : (a.y + b.y) / 2 }
  const d = { x: across ? c.x : b.x, y: across ? b.y : c.y }
  const curve = Array.from({ length: 49 }, (_, index) => {
    const t = index / 48, u = 1 - t
    return { x: u ** 3 * a.x + 3 * u ** 2 * t * c.x + 3 * u * t ** 2 * d.x + t ** 3 * b.x,
      y: u ** 3 * a.y + 3 * u ** 2 * t * c.y + 3 * u * t ** 2 * d.y + t ** 3 * b.y }
  })
  const clear = (points: Point[]) => points.slice(1).every((point, index) =>
    obstacles.every(box => !segmentBlocked(points[index], point, box)))
  if (clear(curve)) {
    const [start, control1, control2, end] = [a, c, d, b].map(p => local(p.x, p.y))
    return result([start, end], `M ${start.x} ${start.y} C ${control1.x} ${control1.y} ${control2.x} ${control2.y} ${end.x} ${end.y}`)
  }
  const offset = 12 + lane % 4 * 3
  const candidates: Point[][] = []
  if (across) {
    const x1 = a.x + direction * 12, x2 = b.x - direction * 12
    const lanes = new Set([ay, by, ...[from, to, ...obstacles].flatMap(box => [box.top - offset, box.bottom + offset])])
    for (const y of lanes) candidates.push([a, { x: x1, y: a.y }, { x: x1, y }, { x: x2, y }, { x: x2, y: b.y }, b])
  } else {
    // Same-column edges leave through side ports instead of entering the cards
    // above/below them. Try both sides and use the shortest clear corridor.
    for (const side of [-1, 1]) {
      const start = { x: side > 0 ? from.right : from.left, y: ay }
      const end = { x: side > 0 ? to.right : to.left, y: by }
      const x = side > 0 ? Math.max(from.right, to.right) + offset : Math.min(from.left, to.left) - offset
      candidates.push([start, { x, y: ay }, { x, y: by }, end])
    }
  }
  const length = (points: Point[]) => points.slice(1).reduce((sum, p, index) =>
    sum + Math.abs(p.x - points[index].x) + Math.abs(p.y - points[index].y), 0)
  const points = candidates.filter(clear).sort((left, right) => length(left) - length(right))[0]
  if (!points) return null // Never draw an unverified straight line through a card.
  const route = points.map(p => local(p.x, p.y))
  return result(route, route.map((p, index) => `${index ? 'L' : 'M'} ${p.x} ${p.y}`).join(' '))
}
