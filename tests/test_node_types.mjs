import assert from 'node:assert/strict'
import { test } from 'node:test'
import { nodeIcon, nodeIcons, nodeTypes } from '../web/src/node-types.ts'
import { iconPaths } from '../web/src/icons.ts'

test('every node type has a concrete icon, including PC, workstation, NAS and edge devices', () => {
  for (const [nodeType, type] of Object.entries(nodeTypes)) {
    const icon = nodeIcon({ nodeType, icon: 'auto' })
    assert.ok(iconPaths[icon], nodeType)
    if (nodeType !== 'generic') assert.equal(icon, type.icon)
  }
  assert.notEqual(nodeIcon({ nodeType: 'pc' }), nodeIcon({ nodeType: 'workstation' }))
  assert.notEqual(nodeIcon({ nodeType: 'nas' }), nodeIcon({ nodeType: 'edge' }))
})

test('custom icons take precedence; automatic mode restores type defaults on local and remote nodes', () => {
  for (const local of [false, true]) {
    for (const icon of Object.keys(nodeIcons).filter(icon => icon !== 'auto')) {
      assert.equal(nodeIcon({ local, nodeType: 'workstation', icon }), icon)
      assert.ok(iconPaths[icon])
    }
    assert.equal(nodeIcon({ local, nodeType: 'edge', icon: 'auto' }), 'cpu')
    assert.equal(nodeIcon({ local, nodeType: 'workstation', icon: 'auto' }), 'workstation')
  }
})

test('older display snapshots preserve their existing fallback before a type is chosen', () => {
  assert.equal(nodeIcon({ local: true }), 'monitor')
  assert.equal(nodeIcon({ local: false }), 'server')
})
