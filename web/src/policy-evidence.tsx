import { useState } from 'react'
import { ApiError, api, timestamp, usePoll } from './api'
import { refreshConsole, useConsole } from './console-data'
import { Notice, Panel } from './ui'

type Entry = { term: string; recorded_at: number; shared_until: number | null }
type Page = { conflicts: Entry[]; next_before: string | null; can_share: boolean }
type RemotePage = { reports: Entry[]; next_before: string | null }
type Inbox = { observer: string; proof_id: string; term: string; kind: string; received_at: number }

const kinds: Record<string, string> = {
  delegation_conflict: '委托不一致', snapshot_conflict: '同序号声明冲突', chain_conflict: '前驱摘要不一致',
}

export function PolicyEvidence({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { nodes, session } = useConsole()
  const [cursors, setCursors] = useState<string[]>([])
  const [pending, setPending] = useState<string>()
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [selected, setSelected] = useState('')
  const [selectedReports, setRemote] = useState<{ nodeId: string; page: RemotePage }>()
  const before = cursors.at(-1)
  const { data } = usePoll<Page>(before === undefined ? '/security/evidence' : `/security/evidence?before=${encodeURIComponent(before)}`, onUnauthorized)
  const next = data?.next_before
  const { data: inbox } = usePoll<Inbox[]>(data ? '/security/evidence/inbox' : null, onUnauthorized)
  const peers = nodes.filter((node) => !node.local && node.status !== 'quarantined' && node.peer?.enabled)
  const source = peers.some((node) => node.id === selected) ? selected : peers[0]?.id
  const remote = selectedReports?.nodeId === source ? selectedReports?.page : undefined
  const sourcePath = source ? `/peers/${encodeURIComponent(source)}/evidence` : ''
  const writeHeaders = { 'X-CSRF-Token': session.csrf_token }

  async function perform(key: string, action: () => Promise<void>) {
    setPending(key)
    setError('')
    setMessage('')
    try {
      await action()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof Error ? failure.message : '证据暂时不可用')
    } finally {
      setPending(undefined)
    }
  }

  async function download(path: string, filename: string) {
    return perform(path, async () => {
      const payload = await api<object>(path)
      const url = URL.createObjectURL(new Blob([JSON.stringify(payload)], { type: 'application/json' }))
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      anchor.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    })
  }

  async function toggle(entry: Entry) {
    const path = `/security/evidence/${encodeURIComponent(entry.term)}/share`
    return perform(path, async () => {
      await api(path, { method: entry.shared_until ? 'DELETE' : 'POST', headers: writeHeaders })
      setMessage(entry.shared_until ? '已停止共享。' : '本 Grove 的活动成员可在七天内获取这份报告。')
      refreshConsole()
    })
  }

  async function loadReports(cursor?: string) {
    if (!source) return
    return perform(sourcePath, async () => {
      const page = await api<RemotePage>(sourcePath + (cursor ? `?before=${encodeURIComponent(cursor)}` : ''))
      setRemote({ nodeId: source, page })
    })
  }

  async function receive(term: string) {
    const path = `${sourcePath}/${encodeURIComponent(term)}`
    return perform(path, async () => {
      const receipt = await api<{ stored: boolean }>(path, { method: 'POST', headers: writeHeaders })
      setMessage(receipt.stored ? '已核验并保存到本机收件箱。' : '本机已保留同一份证据。')
      refreshConsole()
    })
  }

  if (!data?.conflicts.length && !cursors.length && !error && !inbox?.length && !(data?.can_share && peers.length)) return null
  return <Panel title="签名策略冲突">
    <p className="muted">下载原始签名声明，在独立工作站使用受信根公钥核验。</p>
    {data?.can_share && !!data.conflicts.length && <p className="muted">共享后，本 Grove 的活动成员可以获取这两份历史策略。</p>}
    {error && <Notice tone="amber">{error}</Notice>}
    {message && <p role="status">{message}</p>}
    <ul className="service-list">{data?.conflicts.map((entry) => <li key={entry.term}>
      <strong>本机记录 · 任期 {entry.term}</strong><span>{timestamp(entry.recorded_at)}</span>
      {entry.shared_until && <span>共享至 {timestamp(entry.shared_until)}</span>}
      <button className="btn btn-secondary btn-small" disabled={pending !== undefined}
        onClick={() => void download(`/security/evidence/${encodeURIComponent(entry.term)}`, `spearmint-policy-conflict-${entry.term}.json`)}>下载证据</button>
      {data.can_share && <button className="btn btn-secondary btn-small" disabled={pending !== undefined}
        onClick={() => void toggle(entry)}>{entry.shared_until ? '停止共享' : '共享到 Grove'}</button>}
    </li>)}</ul>
    {(cursors.length > 0 || next != null) && <div className="button-row">
      {cursors.length > 0 && <button className="btn btn-secondary btn-small" onClick={() => setCursors(cursors.slice(0, -1))}>上一页</button>}
      {next != null && <button className="btn btn-secondary btn-small"
        onClick={() => setCursors([...cursors, next])}>更早的记录</button>}
    </div>}
    {data?.can_share && source && <section aria-label="获取共享证据">
      <div className="button-row">
        <label className="field-label">记录节点<select value={source} disabled={pending !== undefined}
          onChange={(event) => { setSelected(event.target.value); setRemote(undefined) }}>
          {peers.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}
        </select></label>
        <button className="btn btn-secondary btn-small" disabled={pending !== undefined}
          onClick={() => void loadReports()}>查询共享报告</button>
      </div>
      {remote && !remote.reports.length && <p className="muted">此节点当前没有共享报告。</p>}
      {remote && <ul className="service-list">{remote.reports.map((entry) => <li key={entry.term}>
        <strong>任期 {entry.term}</strong><span>{timestamp(entry.recorded_at)}</span>
        <button className="btn btn-secondary btn-small" disabled={pending !== undefined}
          onClick={() => void receive(entry.term)}>核验并接收</button>
      </li>)}</ul>}
      {remote?.next_before && <button className="btn btn-secondary btn-small" disabled={pending !== undefined}
        onClick={() => void loadReports(remote.next_before!)}>更早的共享报告</button>}
    </section>}
    {!!inbox?.length && <section aria-label="证据收件箱">
      <h4>证据收件箱</h4>
      <ul className="service-list">{inbox.map((entry) => <li key={`${entry.observer}/${entry.proof_id}`}>
        <strong>{kinds[entry.kind] || entry.kind} · 任期 {entry.term}</strong>
        <span>{nodes.find((node) => node.id === entry.observer)?.name || entry.observer}</span>
        <span>{timestamp(entry.received_at)}</span>
        <button className="btn btn-secondary btn-small" disabled={pending !== undefined}
          onClick={() => void download(`/security/evidence/inbox/${encodeURIComponent(entry.observer)}/${encodeURIComponent(entry.proof_id)}`,
            `spearmint-${entry.proof_id}.json`)}>下载证据</button>
      </li>)}</ul>
    </section>}
  </Panel>
}
