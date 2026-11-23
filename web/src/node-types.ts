export const nodeTypes = {
  generic: { label: '通用节点', icon: 'server' }, pc: { label: 'PC', icon: 'monitor' },
  laptop: { label: '笔记本', icon: 'laptop' }, workstation: { label: '工作站', icon: 'workstation' },
  server: { label: '服务器', icon: 'server' }, nas: { label: 'NAS', icon: 'hard-drive' },
  edge: { label: '边缘设备', icon: 'cpu' }, vm: { label: '虚拟机', icon: 'layers' },
} as const
export const nodeIcons = {
  auto: '跟随类型', monitor: '显示器', laptop: '笔记本', workstation: '工作站', server: '服务器',
  'hard-drive': '存储设备', cpu: '芯片', layers: '虚拟机', cloud: '云节点', smartphone: '移动设备',
} as const
export type NodeType = keyof typeof nodeTypes
export type NodeIcon = keyof typeof nodeIcons
export type NodeAppearance = { node_type: NodeType; icon: NodeIcon }
export type NodeProfile = NodeAppearance & { note: string }
export const isNodeType = (value: unknown): value is NodeType => typeof value === 'string' && Object.hasOwn(nodeTypes, value)
export const isNodeIcon = (value: unknown): value is NodeIcon => typeof value === 'string' && Object.hasOwn(nodeIcons, value)
export function nodeIcon(node: { local?: boolean; nodeType?: NodeType; icon?: NodeIcon }) {
  if (node.icon && node.icon !== 'auto' && isNodeIcon(node.icon)) return node.icon
  return !node.nodeType || node.nodeType === 'generic' ? node.local ? 'monitor' : 'server' : nodeTypes[node.nodeType].icon
}
