import { useState } from 'react'
import { ApiError, api, type Session, timestamp, usePoll } from './api'
import { Badge, EmptyState, Icon, Loading, Modal, Notice, Panel } from './ui'

type SessionEntry = { id: string; created_at: number; last_seen: number; current: boolean }

export function Sessions({ session, onUnauthorized }: { session: Session; onUnauthorized: () => void }) {
  const { data, error } = usePoll<SessionEntry[]>('/sessions', onUnauthorized)
  const [pending, setPending] = useState<string>()
  const [failure, setFailure] = useState('')
  const [confirm, setConfirm] = useState<SessionEntry>()

  async function revoke(entry: SessionEntry) {
    setConfirm(undefined)
    setPending(entry.id)
    setFailure('')
    try {
      await api(`/sessions/${entry.id}`, {
        method: 'DELETE', headers: { 'X-CSRF-Token': session.csrf_token },
      })
      if (entry.current) onUnauthorized()
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) onUnauthorized()
      else if (reason instanceof ApiError && reason.code === 'REAUTHENTICATION_REQUIRED') {
        setFailure('请先用 Passkey 或动态验证码重新登录，再撤销会话。')
      } else setFailure('暂时无法撤销该会话。')
    } finally {
      setPending(undefined)
    }
  }

  return (
    <Panel title="登录中的会话" action={<Badge tone="sage">{data?.length ?? '—'} 个会话</Badge>}>
      {(failure || error) && <Notice tone="amber">{failure || error}</Notice>}
      {!data && !error && <Loading label="正在读取会话…" />}
      {data?.length === 0 && <EmptyState icon="monitor" title="没有其他会话" />}
      <ul className="session-list">
        {data?.map((entry) => (
          <li className="session-row" key={entry.id}>
            <span className={`session-device ${entry.current ? 'current' : ''}`}><Icon name="monitor" size={24} /></span>
            <div className="session-information"><div><strong>{entry.current ? '当前浏览器会话' : '其他登录会话'}</strong>{entry.current && <Badge tone="green">正在使用</Badge>}</div><p>登录于 {timestamp(entry.created_at)}</p><small>最近活动 {timestamp(entry.last_seen)}</small></div>
            <button className="btn btn-secondary btn-small" disabled={pending !== undefined} onClick={() => setConfirm(entry)}>
              {pending === entry.id ? '撤销中…' : '撤销'}
            </button>
          </li>
        ))}
      </ul>
      <Notice icon="shield-check">撤销会话需要最近 5 分钟内通过 Passkey 或动态验证码验证身份。无法确认的会话，请在重新验证后及时撤销。</Notice>
      {confirm && <Modal title={confirm.current ? '退出当前会话？' : '撤销这个登录会话？'} onClose={() => setConfirm(undefined)}><p className="muted">{confirm.current ? '你会退出当前控制台，需要重新登录才能继续。' : '该会话将立即失去访问权限。其他登录会话不会受到影响。'}</p><div className="modal-actions"><button className="btn btn-secondary" onClick={() => setConfirm(undefined)}>取消</button><button className="btn btn-danger" onClick={() => void revoke(confirm)}>确认撤销</button></div></Modal>}
    </Panel>
  )
}
