import assert from 'node:assert/strict'
import { test } from 'node:test'
import { resourcePoll } from '../../web/src/node-resource-poll.ts'

const settle = async () => { for (let i = 0; i < 12; i++) await Promise.resolve() }
function fixture(read, limit = 4) {
  let now = 0, sequence = 0, visible = true
  const timers = new Map()
  const clock = { now: () => now, later(run, delay) { const id = ++sequence; timers.set(id, { run, at: now + delay }); return id }, cancel: id => timers.delete(id) }
  const poll = resourcePoll(read, () => visible, clock, limit)
  return { poll, hide() { visible = false }, show() { visible = true; poll.resume() },
    async advance(to) {
      await settle()
      while (true) {
        const entry = [...timers].filter(([, timer]) => timer.at <= to).sort((a, b) => a[1].at - b[1].at)[0]
        if (!entry) break
        now = entry[1].at; timers.delete(entry[0]); entry[1].run(); await settle()
      }
      now = to; await settle()
    } }
}

test('a stalled remote does not delay another node past its eight second sample lifetime', async () => {
  const calls = [], held = []
  const f = fixture(async id => { calls.push(id); if (id === 'slow') await new Promise(resolve => held.push(resolve)); return 5000 })
  f.poll.setTargets(['slow', 'thor', 'orin', 'rtx', 'nas'])
  await f.advance(12000)
  for (const id of ['thor', 'orin', 'rtx', 'nas']) assert.equal(calls.filter(value => value === id).length, 3)
  assert.equal(calls.filter(value => value === 'slow').length, 1)
  f.poll.close(); held.forEach(resolve => resolve())
})

test('a topology change preserves unrelated in-flight reads and starts only new targets', async () => {
  const requests = []
  const f = fixture((id, signal) => new Promise(resolve => requests.push({ id, signal, resolve })))
  f.poll.setTargets(['thor', 'orin']); await settle()
  f.poll.setTargets(['thor', 'orin', 'beijing']); await settle()
  assert.deepEqual(requests.map(row => row.id), ['thor', 'orin', 'beijing'])
  assert.ok(requests.every(row => !row.signal.aborted))
  f.poll.setTargets(['thor', 'beijing']); assert.equal(requests[1].signal.aborted, true)
  assert.equal(requests[0].signal.aborted, false)
  f.poll.close(); requests.forEach(row => row.resolve(5000)); await settle()
})

test('reads stop while hidden and resume without duplicate requests', async () => {
  const calls = []
  const f = fixture(async id => { calls.push(id); return 5000 })
  f.poll.setTargets(['thor']); await settle()
  f.hide(); await f.advance(20000); assert.equal(calls.length, 1)
  f.show(); await settle(); assert.equal(calls.length, 2)
  f.poll.close(); await f.advance(40000); assert.equal(calls.length, 2)
})

test('failures use their own backoff without slowing healthy nodes', async () => {
  const calls = []
  const f = fixture(async id => { calls.push(id); return id === 'offline' ? 15000 : 5000 })
  f.poll.setTargets(['offline', 'thor']); await f.advance(12000)
  assert.equal(calls.filter(id => id === 'thor').length, 3)
  assert.equal(calls.filter(id => id === 'offline').length, 1)
  f.poll.close()
})
