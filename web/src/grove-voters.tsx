import { useState } from 'react'
import { api, ApiError, usePoll } from './api'
import { useConsole } from './console-data'
import { Badge, Modal, Notice } from './ui'

export type VoterJob = { id: string; node_id: string; desired: number; status: string; reason?: string }
export type VoterStatus = { available: boolean; voters: string[]; version: number; required: number;
  min_voters: number; max_voters: number; jobs: VoterJob[] }

export function VoterDialog({ node, close }: { node: { id: string; name: string }; close: () => void }) {
  const { session, onUnauthorized } = useConsole()
  const status = usePoll<VoterStatus>('/grove/voters', onUnauthorized)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [submitted, setSubmitted] = useState<string>()
  const data = status.data
  const voting = !!data?.voters.includes(node.id)
  const job = data?.jobs.find(item => submitted ? item.id === submitted : item.node_id === node.id)
  const pending = job?.status === 'pending'
  const limit = !!data && (voting ? data.voters.length <= data.min_voters : data.voters.length >= data.max_voters)
  async function change() {
    setBusy(true); setError('')
    try {
      const result = await api<{ id: string }>(`/grove/voters/${node.id}`, { method: 'POST', headers: { 'X-CSRF-Token': session.csrf_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ voting: !voting, request_id: crypto.randomUUID().replaceAll('-', '') }) })
      setSubmitted(result.id)
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof ApiError ? failure.message : '暂时无法提交，请连接恢复后重试。')
    } finally { setBusy(false) }
  }
  return <Modal title={`${node.name} · 投票资格`} onClose={close}>
    <div className="stack">
      <div><Badge tone={voting ? 'green' : undefined}>{voting ? '投票节点' : '普通成员'}</Badge>
        {data && <span className="muted">　{data.voters.length} 台投票节点 · 多数确认需 {data.required} 票</span>}</div>
      <p>投票节点参与 Grove 身份确认、成员加入及节点证书签发。调整资格保留此节点的服务和普通成员身份。</p>
      <p className="muted">新节点会先同步权限，再由新旧投票名单的多数节点自动确认。无需逐台审批；离线节点重新连接后自动同步。</p>
      {(pending || submitted && !job) && <Notice title="正在自动处理投票资格">{job?.reason || '正在等待节点同步和多数确认。关闭此窗口后仍会继续。'}</Notice>}
      {job?.status === 'succeeded' && submitted && <Notice>投票资格已同步到 Grove。</Notice>}
      {job?.status === 'failed' && <p className="error" role="alert">{job.reason || '未能调整投票资格。'}</p>}
      {limit && <p className="muted">当前支持 {data?.min_voters} 至 {data?.max_voters} 台投票节点。建议保持 3 或 5 台长期在线设备。</p>}
      {error && <p className="error" role="alert">{error}</p>}
      {status.error && <p className="muted">正在等待 Grove 投票名单。</p>}
      <div className="modal-actions"><button className="btn btn-secondary" onClick={close}>关闭</button>
        {session.role === 'node_admin' && <button className="btn btn-primary" disabled={!data?.available || busy || pending || !!submitted && !job || limit}
          onClick={() => void change()}>{busy ? '正在提交…' : voting ? '取消投票资格' : '设为投票节点'}</button>}</div>
    </div>
  </Modal>
}
