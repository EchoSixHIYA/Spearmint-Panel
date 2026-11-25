export type UpdateRelease = { tag: string; commit: string }
export type NodeUpdate = { status: string; reason?: string; package_source_node?: string }
export type UpdateBatch = { job: string; release: UpdateRelease; nodes: Record<string, NodeUpdate>; expires: number }
export type GroveUpdate = { job: null } | UpdateBatch

const terminal = new Set(['succeeded', 'failed', 'unsupported', 'expired'])
const labels: Record<string, string> = {
  queued: '等待更新', downloading: '正在获取安装包', waiting_package: '等待安装包', waiting_grove: '等待权限同步',
  installing: '正在更新并重启', succeeded: '已更新', failed: '更新失败', unsupported: '需要手动处理', expired: '任务已过期',
}
const reasons: Record<string, string> = {
  waiting_node: '节点离线，上线后会自动继续', updater_missing: '此节点需要先手动安装支持群组更新的版本',
  native_install_required: '需先通过原生安装器接管现有面板', schema_change: '此版本需要先迁移数据',
  already_current_unmanaged: '版本已一致；自动更新功能尚未配置',
  installer_failed: '安装未完成，请检查该节点的安装日志后重试', installer_interrupted: '安装中断，请核对节点状态后重试',
  installer_unavailable: '无法启动安装器，请检查该节点的安装环境', update_unavailable: '暂时无法启动更新，可稍后重试',
  authorization_changed: '管理员权限已变化，完成 Grove 同步后可重试',
  authorization_denied: '目标节点未认可当前 Grove 管理员，完成同步后可重试',
  update_conflict: '目标节点正在处理其他更新，结束后可重试',
  grove_sync_pending: '正在同步成员和管理员信息，将自动重试',
  legacy_peer_unverified: '正在同步发起端的 Grove 成员身份', legacy_revision_mismatch: '正在同步管理员信息',
  another_update: '等待该节点的另一项更新结束', running_commit_mismatch: '重启后的版本不符，请核对该节点后重试',
  checking_package_sources: '正在查找 GitHub 和 Grove 安装包', fetching_from_grove: '正在从 Grove 节点接收安装包',
  source_unavailable: '暂未找到可用来源，将自动重试',
}

export function updateProgress(row: NodeUpdate, expires: number, now = Date.now() / 1000): NodeUpdate {
  return expires <= now && !terminal.has(row.status) ? { status: 'expired' } : row
}

export function updatePresentation(row: NodeUpdate, packageSourceName?: string) {
  if (row.reason === 'older_release') return { label: '版本较新，已跳过', tone: 'neutral', detail: '' }
  if (row.reason === 'member_removed') return { label: '已离开 Grove', tone: 'neutral', detail: '' }
  return { label: row.reason === 'already_current' || row.reason === 'already_current_unmanaged' ? '已是目标版本' : labels[row.status] ?? '等待确认',
    tone: row.status === 'succeeded' ? 'green' : terminal.has(row.status) ? 'red' : 'amber',
    detail: row.status === 'downloading' && row.reason === 'fetching_from_grove' && packageSourceName
      ? `正在从${packageSourceName}接收安装包`
      : terminal.has(row.status) && ['grove_sync_pending', 'legacy_peer_unverified', 'legacy_revision_mismatch'].includes(row.reason ?? '')
      ? '权限同步未完成，连接恢复后可重试' : reasons[row.reason ?? ''] ?? '' }
}

export function updateNeedsAttention(row: NodeUpdate) {
  return ['failed', 'unsupported', 'expired'].includes(row.status) && !['older_release', 'member_removed'].includes(row.reason ?? '')
}

export function updateCounts(rows: readonly NodeUpdate[]) {
  return { succeeded: rows.filter(row => row.status === 'succeeded').length,
    attention: rows.filter(updateNeedsAttention).length,
    retryable: rows.filter(row => ['failed', 'expired'].includes(row.status)).length,
    pending: rows.filter(row => !terminal.has(row.status)).length }
}

export function updateCoversMembers(batch: UpdateBatch | undefined, members: readonly string[], release?: UpdateRelease) {
  return !!(batch && release && members.length && batch.release.commit === release.commit
    && members.every(id => batch.nodes[id]?.status === 'succeeded' || batch.nodes[id]?.reason === 'older_release'))
}
