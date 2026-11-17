import { useEffect, useState } from 'react'
import { ApiError, api, type Session, timestamp, usePoll } from './api'
import { actions as actionNames, type Action, statuses } from './services'
import { Badge, CopyValue, Icon, Notice, StateBadge } from './ui'

type Envelope = { challenge: string; issuer_signature: string }
type Prepared = { request_id: string; expires_at: number; envelope: Envelope }
const receiptReasons: Partial<Record<string, string>> = {
  POLICY_CHANGED: '执行前，所属节点的管理授权已变更。',
  PANEL_RESTARTED: '所属面板重启，执行结果待确认。请查看服务当前状态。',
  RUNTIME_NOT_READY: '执行时服务状态尚未就绪。',
  STATE_NOT_REACHED: '服务未进入请求的运行状态。',
  OUTCOME_UNCONFIRMED: '所属节点未能确认执行后的服务状态。',
  HOST_TIMEOUT: '所属节点的主机命令超时。',
  HOST_ERROR: '所属节点执行出错。可在该节点查看操作记录。',
}
export type Receipt = {
  request_id: string
  operation_id: string
  accepted: true
  operation?: { status: string; updated_at: number; reason?: string }
}
export type History = { request_id: string; action: Action; updated_at: number; receipt?: Receipt | null }

export function ReceiptBadge({ receipt }: { receipt?: Receipt | null }) {
  return receipt?.operation ? <StateBadge state={receipt.operation.status} />
    : <Badge tone="outline">{receipt ? '已受理' : receipt === null ? '结果待确认' : '待查询'}</Badge>
}

export function ReceiptHistory({ history, selected, onSelect }: {
  history: History[]; selected?: string; onSelect: (requestId: string) => void
}) {
  return <ul className="service-list" aria-label="远程操作记录">{history.map((item) => <li key={item.request_id}>
    <button className="secondary" aria-pressed={selected === item.request_id} onClick={() => onSelect(item.request_id)}>
      查看{actionNames[item.action]}回执
    </button>
    <ReceiptBadge receipt={item.receipt} />
    <span>{timestamp(item.updated_at)}</span>
    <code>{item.request_id}</code>
  </li>)}</ul>
}

export function receiptFinished(receipt?: Receipt) {
  return receipt?.operation?.status === 'succeeded' || receipt?.operation?.status === 'failed'
    || receipt?.operation?.status === 'uncertain'
}

function receiptProgress(receipt: Receipt) {
  if (receiptFinished(receipt)) return 3
  if (receipt.operation?.status === 'running') return 2
  if (receipt.operation?.status === 'queued') return 1
  return 0
}

export function latestReceipt(previous?: Receipt, incoming?: Receipt) {
  if (!previous || !incoming) return incoming ?? previous
  if (previous.request_id !== incoming.request_id) return incoming
  const progress = receiptProgress(incoming) - receiptProgress(previous)
  const updatedAt = (incoming.operation?.updated_at ?? 0) - (previous.operation?.updated_at ?? 0)
  const hasNewReason = updatedAt === 0 && incoming.operation?.status === previous.operation?.status
    && !!incoming.operation?.reason && !previous.operation?.reason
  return progress > 0 || (progress === 0 && (updatedAt > 0 || hasNewReason))
    ? incoming : previous
}

export function ReceiptStatus({ path, onUnauthorized, initial, onReceipt, stale = false, connectionId }: {
  path: string; onUnauthorized: () => void; initial?: Receipt; onReceipt?: (receipt: Receipt) => void; stale?: boolean; connectionId?: string
}) {
  const [lastReceipt, setLastReceipt] = useState<Receipt>()
  const current = latestReceipt(lastReceipt, initial)
  const missingReason = !!current?.operation && ['failed', 'uncertain'].includes(current.operation.status) && !current.operation.reason
  const [attemptedReason, setAttemptedReason] = useState<string>()
  const reasonScope = JSON.stringify([path, connectionId, current?.operation?.updated_at])
  const shouldRead = !receiptFinished(current) || (missingReason && attemptedReason !== reasonScope)
  const { data, error } = usePoll<Receipt>(stale || !shouldRead ? null : path, onUnauthorized, 3000, undefined, connectionId)
  useEffect(() => {
    if (data?.accepted) onReceipt?.(data)
  }, [data, onReceipt])
  useEffect(() => {
    setLastReceipt((previous) => latestReceipt(latestReceipt(previous, initial), data?.accepted ? data : undefined))
  }, [data, initial])
  useEffect(() => {
    if (missingReason && (error || receiptFinished(data))) setAttemptedReason(reasonScope)
  }, [data, error, missingReason, reasonScope])
  const reason = current?.operation?.reason
  return <div role="status">
    {current ? <p>{current.operation ? statuses[current.operation.status] || current.operation.status : '已受理'} · <code>{current.operation_id}</code></p>
      : stale ? <p>结果待确认 · 等待连接恢复</p>
      : error ? <p>结果待确认 · {error}</p>
      : <p>正在查询回执…</p>}
    {reason && Object.hasOwn(receiptReasons, reason) && <p>{receiptReasons[reason]}</p>}
    {current && !receiptFinished(current) && (stale || error) && <p>{stale ? '等待连接恢复' : '暂时无法更新回执。'}</p>}
  </div>
}

export function RemoteOperations({ path, actions, version, stale, session, onUnauthorized, keyIds }: {
  path: string; actions: Action[]; version: number; stale: boolean; session: Session; onUnauthorized: () => void
  keyIds: string[]
}) {
  const [keyId, setKeyId] = useState('')
  const [prepared, setPrepared] = useState<Prepared>()
  const [approval, setApproval] = useState<string>()
  const [receipt, setReceipt] = useState<Receipt>()
  const [selected, setSelected] = useState<string>()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const [fileName, setFileName] = useState('')
  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    if (!prepared) return
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(timer)
  }, [prepared])
  const historyPath = `${path}/operations`
  const { data: history } = usePoll<History[]>(historyPath, onUnauthorized)
  const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }
  const selectedKey = keyIds.includes(keyId) ? keyId : keyIds[0] || ''

  function showError(failure: unknown) {
    if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
    else if (failure instanceof ApiError && failure.code === 'APPROVAL_VERSION_REQUIRED') {
      setError('目标服务要求 M003 批准，请从 Mesh 签名操作入口发起。')
    } else setError(failure instanceof Error ? failure.message : '请求失败')
  }

  async function prepare(action: Action) {
    if (stale || pending || !actions.includes(action) || !selectedKey) return
    setPending(true)
    setError('')
    setPrepared(undefined)
    setApproval(undefined)
    setFileName('')
    try {
      setPrepared(await api<Prepared>(`${path}/operation-prepare`, {
        method: 'POST', headers, body: JSON.stringify({ action, service_version: version, operator_key_id: selectedKey }),
      }))
    } catch (failure) {
      showError(failure)
    } finally {
      setPending(false)
    }
  }

  function download() {
    if (!prepared) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(prepared.envelope)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `spearmint-challenge-${prepared.request_id}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  async function importFile(file?: File) {
    setApproval(undefined)
    setFileName('')
    setError('')
    if (!file) return
    try {
      if (file.size > 16384) throw new Error('批准文件超过 16 KiB')
      const raw = await file.text()
      const data = JSON.parse(raw)
      if (!data || Object.keys(data).length !== 3 ||
        !['challenge', 'issuer_signature', 'operator_signature'].every((key) => typeof data[key] === 'string')) {
        throw new Error('批准文件格式无效')
      }
      setApproval(raw)
      setFileName(file.name)
    } catch (failure) {
      showError(failure)
    }
  }

  async function submit() {
    if (stale || pending || !actions.length || !approval) return
    setPending(true)
    setError('')
    setReceipt(undefined)
    if (prepared) setSelected(prepared.request_id)
    try {
      const accepted = await api<Receipt>(`${path}/operation-submit`, {
        method: 'POST', headers, body: approval,
      })
      setReceipt(accepted)
      setSelected(accepted.request_id)
      setApproval(undefined)
    } catch (failure) {
      if (failure instanceof ApiError && failure.code === 'RESULT_PENDING') {
        setError('结果待确认。连接恢复后可按原请求 ID 查询回执。')
      } else showError(failure)
    } finally {
      setPending(false)
    }
  }

  if (actions.length === 0 && !history?.length && !receipt && !prepared && !selected) return null
  return <section className="remote-operation" aria-label="远程操作">
    {actions.length > 0 && <>
      <div className="operation-step-heading"><span className="step-index">1</span><div><h4>选择操作，获取挑战</h4><p>挑战中包含目标、服务、动作和有效期，交由独立工作站核对。</p></div></div>
      <label className="field-label">用于签署的公钥<select className="input" value={selectedKey} onChange={(event) => setKeyId(event.target.value)}>
        {keyIds.map((id) => <option key={id} value={id}>{id}</option>)}
      </select></label>
      <div className="button-row">
        {actions.map((action) => <button className="btn btn-secondary" key={action} disabled={stale || pending || !/^op1-[a-f0-9]{64}$/.test(selectedKey)}
          onClick={() => prepare(action)}>申请{actionNames[action]}批准</button>)}
        {prepared && <button className="btn btn-primary" disabled={now >= prepared.expires_at} onClick={download}><Icon name="download" size={15} />下载挑战文件</button>}
      </div>
      {prepared && <Notice tone={now >= prepared.expires_at ? 'amber' : ''} title={now >= prepared.expires_at ? '挑战已到期，请重新申请' : '挑战已准备好'}>到期时间 {timestamp(prepared.expires_at)}<br /><CopyValue value={prepared.request_id} /></Notice>}
      <div className="operation-step-heading"><span className="step-index">2</span><div><h4>导入独立工作站的批准</h4><p>在工作站核对并签署后，将生成的 JSON 文件带回这里。</p></div></div>
      <label className="approval-upload"><Icon name="upload" size={24} /><strong>{fileName || '选择批准文件'}</strong><small>JSON 文件 · 最大 16 KiB</small><input aria-label="导入批准文件" type="file" accept=".json,application/json" disabled={stale || pending}
        onChange={(event) => void importFile(event.target.files?.[0])} /></label>
      {approval && <p className="approval-file-ready"><Icon name="check-circle" size={15} />文件已读取，提交后由执行节点核验签名。</p>}
      <button className="btn btn-primary" disabled={stale || pending || !approval} onClick={submit}><Icon name="shield-check" size={16} />{pending ? '正在提交…' : '提交批准并执行'}</button>
    </>}
    {error && <Notice tone="amber">{error}</Notice>}
    {receipt && <div className="receipt-summary"><Badge tone="green">目标已受理</Badge><CopyValue value={receipt.operation_id} /></div>}
    {!!history?.length && <ReceiptHistory history={history} selected={selected} onSelect={setSelected} />}
    {selected && <ReceiptStatus key={selected} path={`${historyPath}/${selected}`} onUnauthorized={onUnauthorized} stale={stale}
      initial={latestReceipt(receipt?.request_id === selected ? receipt : undefined, history?.find((item) => item.request_id === selected)?.receipt ?? undefined)} />}
  </section>
}
