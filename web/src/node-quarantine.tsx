import { useEffect, useState } from 'react'
import { ApiError, api, timestamp, type Session } from './api'
import { refreshConsole, type LocalQuarantine } from './console-data'
import { Modal, Notice, Panel } from './ui'

export function NodeQuarantine({ nodeId, isolation, session, onUnauthorized }: {
  nodeId: string; isolation: LocalQuarantine | null; session: Session; onUnauthorized: () => void
}) {
  const [recent, setRecent] = useState<LocalQuarantine | null>()
  const [confirm, setConfirm] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const current = recent === undefined ? isolation : recent
  useEffect(() => setRecent(undefined), [isolation?.recorded_at, isolation?.reason])

  async function update(hold: boolean) {
    setBusy(true)
    setError('')
    try {
      const data = await api<{ local_quarantine: LocalQuarantine | null }>(`/peers/${encodeURIComponent(nodeId)}/quarantine`, {
        method: hold ? 'POST' : 'DELETE',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
        body: hold ? JSON.stringify({ reason: reason.trim() }) : undefined,
      })
      setRecent(data.local_quarantine)
      setConfirm(false)
      setReason('')
      refreshConsole()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof Error ? failure.message : '隔离状态暂时无法更新')
    } finally {
      setBusy(false)
    }
  }

  return <Panel title="本机隔离">
    {current ? <><p>{current.reason}</p><p className="muted">隔离时间 {timestamp(current.recorded_at)}</p>
      <button className="btn btn-secondary" disabled={busy} onClick={() => void update(false)}>解除本机隔离</button></>
      : <><p className="muted">隔离会从当前节点断开此成员，并停止使用经过它的 Mesh 路径。</p>
        <button className="btn btn-secondary" disabled={busy} onClick={() => { setError(''); setConfirm(true) }}>在本机隔离</button></>}
    {error && !confirm && <Notice tone="amber">{error}</Notice>}
    {confirm && <Modal title="在本机隔离此节点？" onClose={() => { if (!busy) setConfirm(false) }}>
      <form onSubmit={(event) => { event.preventDefault(); if (reason.trim() && !busy) void update(true) }}>
        <label className="field-label">隔离原因<input autoFocus required maxLength={160} value={reason}
          onChange={(event) => setReason(event.target.value)} /></label>
        {error && <Notice tone="amber">{error}</Notice>}
        <div className="modal-actions"><button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setConfirm(false)}>取消</button>
          <button className="btn btn-danger" disabled={!reason.trim() || busy}>确认隔离</button></div>
      </form>
    </Modal>}
  </Panel>
}
