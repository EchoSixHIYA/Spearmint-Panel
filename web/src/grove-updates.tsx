import { useState } from 'react'
import { ApiError, api, usePoll } from './api'
import { useConsole, refreshConsole } from './console-data'
import { Notice, Panel, shortId } from './ui'

type Candidate = { tag: string; commit: string }
type NodeProgress = { status: string; reason?: string }
type Update = { job: null } | { job: string; release: Candidate; nodes: Record<string, NodeProgress>; expires: number }

const statusLabels: Record<string, string> = {
  queued: '已排队', downloading: '正在获取安装包', waiting_package: '等待可用安装包', waiting_grove: '正在等待 Grove 同步', installing: '正在更新并重启',
  succeeded: '已更新', failed: '更新失败', unsupported: '需要手动升级', expired: '更新任务已过期',
}
const reasons: Record<string, string> = {
  waiting_node: '等待节点上线', updater_missing: '此节点尚未安装群组更新功能',
  native_install_required: '需由原生安装器接管现有面板', schema_change: '此版本需要手动迁移数据',
  already_current_unmanaged: '需由原生安装器接管后才能自动升级',
  older_release: '当前版本较新', installer_failed: '安装未完成，查看节点本机的安装日志',
  installer_interrupted: '安装进程中断，查看本机安装日志', installer_unavailable: '无法启动本机安装器',
  authorization_changed: '管理员权限变更', member_removed: '已离开 Grove',
  authorization_denied: '目标节点拒绝当前 Grove 管理员身份', update_conflict: '目标节点的更新任务发生冲突',
  grove_sync_pending: '目标节点尚未同步 Grove 成员或管理员信息',
  legacy_peer_unverified: '目标节点未认可发起端的 Grove 成员身份', legacy_revision_mismatch: '目标节点的 Grove 管理员信息与发起端不一致',
  another_update: '正在处理另一项更新', running_commit_mismatch: '重启后的版本与目标版本不一致',
  checking_package_sources: '正在查找 GitHub 和 Grove 来源', fetching_from_grove: '正在从 Grove 节点接收安装包',
  source_unavailable: '暂未找到可用来源，将自动重试',
}

export function GroveUpdatePanel() {
  const { session, onUnauthorized, memberNodes, nodes } = useConsole()
  const [candidate, setCandidate] = useState<Candidate>()
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState(false)
  const status = usePoll<Update>('/grove/updates', onUnauthorized, 4000)
  const batch = status.data?.job ? status.data : undefined
  const active = batch && Object.values(batch.nodes).some(row => !['succeeded', 'failed', 'unsupported', 'expired'].includes(row.status))
  const names = new Map((memberNodes ?? nodes).map(node => [node.id, node.name]))

  async function perform(action: () => Promise<void>) {
    if (busy) return
    setBusy(true)
    setMessage('')
    setError(false)
    try {
      await action()
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) onUnauthorized()
      else {
        setError(true)
        setMessage(error instanceof Error ? error.message : '暂时无法读取更新状态')
      }
    } finally {
      setBusy(false)
    }
  }

  return <Panel title="Grove 群组更新" action={<button type="button" className="btn btn-secondary" disabled={busy}
    onClick={() => void perform(async () => {
      setCandidate(undefined)
      const result = await api<{ release: Candidate | null }>('/grove/updates/release', { signal: AbortSignal.timeout(90_000) })
      if (result.release) setCandidate({ tag: result.release.tag, commit: result.release.commit })
      else setMessage('暂未找到可用的已签名发布。可稍后重试。')
    })}>{busy ? '处理中…' : '检查更新'}</button>}>
    {message && <Notice tone={error ? 'amber' : undefined}>{message}</Notice>}
    {candidate && <div className="stack">
      <p>可用发布 {candidate.tag} · {candidate.commit.slice(0, 8)}</p>
      <button type="button" className="btn btn-primary" disabled={busy || !!active} onClick={() => void perform(async () => {
        await api<Update>('/grove/updates', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
          body: JSON.stringify(candidate),
        })
        setCandidate(undefined)
        refreshConsole()
      })}>更新当前 Grove 节点</button>
    </div>}
    {batch && <div className="stack">
      <p>更新目标 {batch.release.tag} · {batch.release.commit.slice(0, 8)}</p>
      <dl className="facts">{Object.entries(batch.nodes).map(([node, row]) => <div key={node}>
        <dt>{names.get(node) ?? shortId(node)}</dt>
        <dd>{row.reason && ['already_current', 'already_current_unmanaged'].includes(row.reason) ? '已是此版本' : statusLabels[row.status] ?? row.status}
          {row.reason && reasons[row.reason] ? ' · ' + reasons[row.reason] : ''}</dd>
      </div>)}</dl>
    </div>}
    {status.error && <Notice tone="amber">正在等待面板恢复连接。</Notice>}
  </Panel>
}
