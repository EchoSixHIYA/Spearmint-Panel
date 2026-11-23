import assert from 'node:assert/strict'
import { test } from 'node:test'
import { graphLayers, linkGeometry } from '../web/src/network-geometry.ts'

const box = (left, top, width = 250, height = 78) => ({ left, top, width, height, right: left + width, bottom: top + height })
const bounds = box(0, 0, 1600, 1100)
const edge = (from, to) => ({ from, to })

test('shared and cyclic routes have consistent graph layers without missing intermediate columns', () => {
  const links = [edge('local', 'us'), edge('local', 'shanghai'), edge('shanghai', 'us'),
    edge('us', 'ii'), edge('shanghai', 'ii'), edge('ii', 'hk')]
  const saved = new Map([['local', 0], ['us', 1], ['shanghai', 1], ['ii', 2], ['hk', 4]])
  const levels = graphLayers('local', saved.keys(), links, saved)
  assert.equal(levels.get('us'), 1); assert.equal(levels.get('shanghai'), 1)
  assert.equal(levels.get('ii'), 2); assert.equal(levels.get('hk'), 3)
  assert.deepEqual([...new Set(levels.values())], [0, 1, 2, 3])
  assert.deepEqual(graphLayers('local', saved.keys(), [...links].reverse(), saved), levels)
})

test('cards outside the actual curve do not force a detour above the entire map', () => {
  const from = box(20, 480), to = box(960, 480)
  const wire = linkGeometry(from, to, bounds, false, false, [box(340, 40), box(650, 40)], 0)
  assert.ok(wire); assert.match(wire.path, / C /)
  assert.equal(wire.y1, 519); assert.equal(wire.y2, 519)
})

function assertClear(wire, obstacles) {
  assert.ok(wire)
  const points = [...wire.path.matchAll(/[ML] (-?[\d.]+) (-?[\d.]+)/g)].map(match => ({ x: +match[1], y: +match[2] }))
  assert.ok(points.length >= 4)
  for (let index = 1; index < points.length; index++) {
    const a = points[index - 1], b = points[index]
    assert.ok(a.x === b.x || a.y === b.y)
    for (const obstacle of obstacles) {
      const intersects = a.x === b.x
        ? a.x > obstacle.left && a.x < obstacle.right && Math.max(a.y, b.y) > obstacle.top && Math.min(a.y, b.y) < obstacle.bottom
        : a.y > obstacle.top && a.y < obstacle.bottom && Math.max(a.x, b.x) > obstacle.left && Math.min(a.x, b.x) < obstacle.right
      assert.equal(intersects, false, `wire crosses card ${JSON.stringify(obstacle)}`)
    }
  }
}

test('same-layer links go around intervening cards and terminate on side ports', () => {
  const from = box(340, 40), to = box(340, 400), obstacles = [box(340, 130), box(340, 220), box(340, 310)]
  const wire = linkGeometry(from, to, bounds, false, false, obstacles, 1)
  assertClear(wire, obstacles)
  assert.equal(wire.y1, 79); assert.equal(wire.y2, 439)
  assert.equal(wire.x1, wire.x2)
})

test('skip-layer links take the nearest clear corridor instead of crossing cards', () => {
  const from = box(20, 480), to = box(960, 480)
  const obstacles = [box(340, 40), box(340, 480), box(650, 480)]
  const wire = linkGeometry(from, to, bounds, false, false, obstacles, 0)
  assertClear(wire, obstacles)
  const coordinates = [...wire.path.matchAll(/[ML] (-?[\d.]+) (-?[\d.]+)/g)].map(match => +match[2])
  assert.ok(Math.min(...coordinates) >= 468, 'unrelated top card must not pull the wire to the top')
})

test('a dense 200-member graph retains every node and edge endpoint at fractional scale', () => {
  const ids = Array.from({ length: 200 }, (_, index) => `node-${index}`)
  const links = ids.slice(1).map((id, index) => edge(ids[Math.floor(index / 3)], id))
  const levels = graphLayers(ids[0], ids, links, new Map())
  assert.equal(levels.size, 200)
  for (const { from, to } of links) assert.equal(levels.get(to), levels.get(from) + 1)
  const source = box(30.2, 121.6), target = box(344.2, 214.3)
  const wire = linkGeometry(source, target, bounds, false, false, [], 0)
  assert.ok(wire); assert.equal(wire.x1, source.right); assert.equal(wire.x2, target.left)
})
