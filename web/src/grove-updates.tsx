import { useEffect, useRef, useState } from 'react'
import { ApiError, api, usePoll } from './api'
import { useConsole, refreshConsole } from './console-data'
import { Badge, Icon, Panel, shortId } from './ui'
import { updateCounts, updateCoversMembers, updateNeedsAttention, updatePresentation, updateProgress,
  type GroveUpdate, type UpdateRelease } from './grove-update-state'

type Action = 'checking' | 'starting' | 'retrying' | 'refreshing'
type Feedback = { text: string; error?: boolean }
const actionLabels: Record<Action, string> = { checking: '正在检查…', starting: '正在提交…', retrying: '正在重试…', refreshing: '正在刷新…' }

function failureMessage(error: unknown, action: Action) {
  if (error instanceof ApiError) {
    if (error.code === 'GROVE_SYNCHRONIZING') return 'Grove 权限正在同步，完成后可重试。'
    if (error.code === 'CONFLICT') return '更新状态已变化，请刷新进度或重新检查更新。'
    if (error.code === 'DENIED' || error.status === 403) return '请使用 Grove 管理员账号发起更新。'
    if (error.code === 'OFFLINE') return 'Grove 暂时不可达，连接恢复后可重试。'
  }
  return action === 'checking' || action === 'retrying' ? '暂时无法检查更新，请稍后重试。' : '暂时无法刷新更新状态，稍后会自动重试。'
}

export function GroveUpdatePanel() {
  const { session, onUnauthorized, listedNodes, memberNodes, local, localName, grove } = useConsole()
  const realmId = grove.data?.realm?.id
  const status = usePoll<GroveUpdate>(realmId ? '/grove/updates' : null, onUnauthorized, 4000, undefined, realmId)
  const [candidate, setCandidate] = useState<UpdateRelease>()
  const [action, setAction] = useState<Action>()
  const [feedback, setFeedback] = useState<Feedback>()
  const [attentionOnly, setAttentionOnly] = useState(false)
  const [accepted, setAccepted] = useState<{ data: GroveUpdate; receivedAt: number }>()
  const [awaiting, setAwaiting] = useState<{ release: UpdateRelease; previousJob?: string }>()
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => request.current?.abort(), [])
  const data = accepted && (status.requestedAt ?? -Infinity) < accepted.receivedAt ? accepted.data : status.data
  const batch = data?.job ? data : undefined
  const names = new Map(listedNodes.map(node => [node.id, node.name]))
  const members = (memberNodes ?? []).map(node => node.id)
  const rows = Object.entries(batch?.nodes ?? {}).map(([id, row]) => [id, updateProgress(row, batch!.expires)] as const)
    .sort(([a], [b]) => Number(b === local.data?.node_id) - Number(a === local.data?.node_id)
      || (names.get(a) ?? a).localeCompare(names.get(b) ?? b, 'zh-CN') || a.localeCompare(b))
  const counts = updateCounts(rows.map(([, row]) => row))
  const active = counts.pending > 0
  const visibleRows = attentionOnly && counts.attention ? rows.filter(([, row]) => updateNeedsAttention(row)) : rows
  const completedBefore = !active && updateCoversMembers(batch, members, candidate)
  const currentCommit = local.data?.build?.commit
  const currentVersion = candidate && candidate.commit === currentCommit ? candidate.tag
    : batch && batch.release.commit === currentCommit ? batch.release.tag
      : local.data?.build?.version ? `v${local.data.build.version}` : '—'
  const scope = members.length ? `全部 ${members.length} 个 Grove 节点` : '全部 Grove 节点'

  useEffect(() => {
    if (awaiting && status.data?.job && status.data.job !== awaiting.previousJob
      && status.data.release.commit === awaiting.release.commit) {
      setAwaiting(undefined)
      setCandidate(undefined)
      setFeedback({ text: '已确认更新任务，进度会自动刷新。' })
    }
  }, [awaiting, status.data])

  async function perform(kind: Action, work: (signal: AbortSignal) => Promise<void>) {
    if (request.current) return
    const controller = new AbortController()
    request.current = controller
    setAction(kind)
    setFeedback(undefined)
    try { await work(AbortSignal.any([controller.signal, AbortSignal.timeout(90_000)])) }
    catch (error) {
      if (controller.signal.aborted) return
      if (error instanceof ApiError && error.status === 401) onUnauthorized()
      else setFeedback({ text: failureMessage(error, kind), error: true })
    } finally {
      if (request.current === controller) request.current = null
      setAction(undefined)
    }
  }

  async function refresh(signal: AbortSignal) {
    const value = await api<GroveUpdate>('/grove/updates', { signal })
    setAccepted({ data: value, receivedAt: performance.now() })
    refreshConsole()
    return value
  }

  async function check(signal: AbortSignal) {
    if (awaiting) {
      const value = await refresh(signal)
      if (value.job && value.job !== awaiting.previousJob && value.release.commit === awaiting.release.commit) {
        setAwaiting(undefined)
        setCandidate(undefined)
        setFeedback({ text: '已确认更新任务，进度会自动刷新。' })
        return
      }
    }
    const result = await api<{ release: UpdateRelease | null }>('/grove/updates/release', { signal })
    setAwaiting(undefined)
    setCandidate(result.release ?? undefined)
    if (!result.release) setFeedback({ text: '暂未找到可用版本，可稍后重新检查。' })
  }

  async function start(release: UpdateRelease, signal: AbortSignal) {
    try {
      const value = await api<GroveUpdate>('/grove/updates', { method: 'POST', signal,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(release) })
      if (!value.job) throw new Error('Missing update receipt')
      setAccepted({ data: value, receivedAt: performance.now() })
      setCandidate(undefined)
      setAttentionOnly(false)
      setFeedback(undefined)
      refreshConsole()
    } catch (error) {
      if (error instanceof ApiError && error.status < 500 && ![408, 429].includes(error.status)) throw error
      setAwaiting({ release, previousJob: batch?.job })
      setFeedback({ text: '提交结果暂未确认，正在查询进度。请先核对任务，避免重复发起。' })
      refreshConsole()
    }
  }

  async function retry(signal: AbortSignal) {
    if (!batch) return
    const result = await api<{ release: UpdateRelease | null }>('/grove/updates/release', { signal })
    if (!result.release) {
      setFeedback({ text: '暂时无法取得本次更新版本，请稍后重试。', error: true })
      return
    }
    if (result.release.commit !== batch.release.commit || result.release.tag !== batch.release.tag) {
      setCandidate(result.release)
      setFeedback({ text: '发现了较新版本，请查看目标版本后再发起更新。' })
      return
    }
    await start(result.release, signal)
  }

  return <Panel className="maintenance-update" title="Grove 群组更新" action={<button type="button" className="btn btn-secondary" disabled={!!action || !realmId}
    onClick={() => void perform('checking', check)}><Icon name="refresh" size={14} />{action === 'checking' ? actionLabels.checking : '检查更新'}</button>}>
    <div className="maintenance-installed"><span>当前面板 <strong>{localName}</strong></span><span>已安装 <strong>{currentVersion}</strong></span></div>
    {!realmId ? <p className="maintenance-feedback muted">{grove.data ? '加入或创建 Grove 后可使用群组更新。' : '正在读取 Grove 信息…'}</p> : <>
      {candidate && !awaiting && <div className={`maintenance-offer ${completedBefore ? 'is-current' : ''}`}>
        <div><span className="muted">更新版本</span><strong>{candidate.tag}</strong><span className="muted">
          {active ? '当前任务完成后可发起下一次更新' : `更新范围：${scope}`}</span></div>
        <div className="maintenance-offer-actions">{completedBefore && <Badge tone="green"><Icon name="check" size={12} />上次已完成</Badge>}
          <button type="button" className={`btn ${completedBefore ? 'btn-secondary' : 'btn-primary'}`} disabled={!!action || active || !!status.error || !status.data}
            title={completedBefore ? '重新核对全组节点，已是目标版本的节点会自动跳过' : undefined}
            onClick={() => void perform('starting', signal => start(candidate, signal))}><Icon name="download" size={14} />
            {action === 'starting' ? actionLabels.starting : completedBefore ? '重新检查并更新' : `更新${scope}`}</button></div>
      </div>}
      {candidate && !awaiting && !active && <p className="maintenance-footnote muted">节点更新后会自动重启，已是目标版本的节点会跳过。</p>}
      {feedback && <p className={`maintenance-feedback ${feedback.error ? 'error' : 'muted'}`} role={feedback.error ? 'alert' : 'status'}>{feedback.text}</p>}
      {awaiting && <div className="maintenance-inline-actions"><button className="btn btn-secondary btn-small" disabled={!!action}
        onClick={() => void perform('refreshing', async signal => { await refresh(signal) })}>{action === 'refreshing' ? actionLabels.refreshing : '查询提交结果'}</button>
        <span className="muted tiny">若未找到任务，可重新检查后再发起。</span></div>}
      {batch ? <div className="maintenance-progress">
        <div className="maintenance-batch"><div><strong>{active ? '正在更新' : counts.attention ? '更新需要处理' : '最近更新'} <span>{batch.release.tag}</span></strong>
          <p className="maintenance-summary muted">{counts.succeeded} / {rows.length} 已更新{counts.pending > 0 && ` · ${counts.pending} 个进行中`}
            {counts.attention > 0 && ` · ${counts.attention} 个需处理`}{status.error && ' · 连接恢复后继续刷新'}</p></div>
          <div className="maintenance-inline-actions">{counts.attention > 0 && <button type="button" className="btn btn-secondary btn-small" aria-pressed={attentionOnly}
            onClick={() => setAttentionOnly(value => !value)}>{attentionOnly ? '查看全部节点' : `只看需处理 (${counts.attention})`}</button>}
            {(active || status.error) && <button type="button" className="btn btn-secondary btn-small" disabled={!!action}
              onClick={() => void perform('refreshing', async signal => { await refresh(signal) })}>{action === 'refreshing' ? actionLabels.refreshing : '刷新进度'}</button>}
            {!active && counts.retryable > 0 && !candidate && !awaiting && <button type="button" className="btn btn-primary btn-small" disabled={!!action || !!status.error}
              title="重新发起群组更新，已是目标版本的节点会自动跳过" onClick={() => void perform('retrying', retry)}>
              {action === 'retrying' ? actionLabels.retrying : '重试本次更新'}</button>}
          </div></div>
        <div className="table-wrap"><table className="data-table maintenance-table"><thead><tr><th>节点</th><th>更新状态</th></tr></thead>
          <tbody>{visibleRows.map(([id, row]) => {
            const view = updatePresentation(row)
            return <tr key={id}><td><a className="text-link" href={`#/nodes/${id}`}>{names.get(id) ?? shortId(id)}</a>
              {id === local.data?.node_id && <span className="maintenance-local">本机</span>}</td>
              <td><Badge tone={view.tone}>{view.label}</Badge>{view.detail && <span className="maintenance-reason">{view.detail}</span>}</td></tr>
          })}</tbody></table></div>
        {!active && counts.retryable > 0 && !candidate && <p className="maintenance-footnote muted">重试会重新发起群组更新，已是目标版本的节点会自动跳过。</p>}
      </div> : !candidate && !feedback && <p className="maintenance-feedback muted">{status.error ? '暂时无法读取更新记录，可重新检查更新。'
        : status.data ? '暂无更新记录。点击「检查更新」查看可用版本。' : '正在读取更新记录…'}</p>}
      {!batch && status.error && <div className="maintenance-inline-actions"><span className="muted tiny">连接恢复后会继续刷新更新状态。</span>
        <button className="text-link plain-button" disabled={!!action} onClick={() => void perform('refreshing', async signal => { await refresh(signal) })}>刷新状态</button></div>}
    </>}
  </Panel>
}
