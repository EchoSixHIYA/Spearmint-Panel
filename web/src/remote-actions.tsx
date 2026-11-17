import { useCallback, useEffect, useEffectEvent, useMemo, useRef, useState } from 'react'
import { ApiError, api, type Session, usePoll } from './api'
import { refreshConsole } from './console-data'
import { uncertainSubmission, usePendingSubmission } from './pending-submission'
import { directoryQuery, directoryScope } from './remote-directory'
import { latestReceipt, receiptFinished, type History, type Receipt, ReceiptHistory, ReceiptStatus } from './remote-operations'
import { actions as actionNames, ServiceActionConfirmation, type Action } from './services'
import { Icon, Notice } from './ui'

type Submission = Receipt | { request_id: string; pending: true }
type PendingAction = { key: string; action: Action; version: number; requestId?: string; accepted?: true }

const unavailableReasons = {
  observe: '此服务处于观察模式。可在所属节点核对管理条件。',
  'no-grant': '当前面板没有此服务的操作授权，或授权已过期。',
  'approval-required': '此服务需要独立签名审批。',
  'host-unavailable': '所属节点暂时无法执行已授权的操作。请查看其管理模式检查结果。',
  'registration-changed': '服务登记在检查期间发生了变化。目录同步后可重新核对。',
}

// Preparation, reconnect, and submission each have their own Mesh deadline.
const SUBMISSION_TIMEOUT_MS = 50_000

function decodeAction({ key, action, version, requestId, accepted }: Record<string, unknown> & { key: string }): PendingAction | undefined {
  if (typeof action !== 'string' || !Object.hasOwn(actionNames, action)
      || typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return
  if (requestId !== undefined && (typeof requestId !== 'string' || !/^[a-f0-9]{32}$/.test(requestId))) return
  if (accepted !== undefined && (accepted !== true || requestId === undefined)) return
  return { key, action: action as Action, version, requestId, accepted }
}

export function RemoteActions({ path, name, version, stale, receiptOffline, advertised, visibleService, session, onUnauthorized, requestId,
  onSelectReceipt, onOperationFinished, ownerAccess, connectionId, directoryGeneration, onSyncDirectory, onRouteLost }: {
  path: string; name: string; version: number; stale: boolean; advertised: readonly Action[]; visibleService: boolean
  receiptOffline: boolean
  session: Session; onUnauthorized: () => void; requestId?: string; ownerAccess?: string; connectionId?: string
  directoryGeneration?: number
  onSelectReceipt: (requestId?: string) => void
  onOperationFinished: (requestId: string) => void
  onSyncDirectory: () => void
  onRouteLost: (scope: string) => void
}) {
  const [confirm, setConfirm] = useState<{ action: 'stop' | 'restart'; scope: string }>()
  const [submitting, setSubmitting] = useState<Action>()
  const [selected, setSelected] = useState<string>()
  const [receipt, setReceipt] = useState<Receipt>()
  const [error, setError] = useState('')
  const [permissionRefresh, setPermissionRefresh] = useState(0)
  const inFlight = useRef(false)
  const syncedRegistration = useRef<string>(undefined)
  const actionsPath = `${path}/actions`
  const historyPath = `${path}/operations`
  const { pending, ready, remember, update, clear } = usePendingSubmission(
    'spearmint-operation', actionsPath, session.csrf_token, decodeAction,
  )
  const lookupKey = !submitting && !pending?.requestId ? pending?.key : undefined
  const lookupHeaders = useMemo(() => lookupKey ? { 'Idempotency-Key': lookupKey } : undefined, [lookupKey])
  const { data: recovered } = usePoll<Submission | null>(lookupKey ? `${actionsPath}/request` : null,
    onUnauthorized, 3000, lookupHeaders)
  const publication = directoryScope(connectionId, directoryGeneration)
  const scope = `${version}/${advertised.join(',')}/${permissionRefresh}/${publication ?? ''}`
  const query = directoryQuery(connectionId, directoryGeneration)
  const availabilityPath = `${actionsPath}?explain=true&service_version=${version}${query ? '&' + query : ''}`
  const submitPath = query ? `${actionsPath}?${query}` : actionsPath
  const { data: available, error: availabilityError, errorCode } = usePoll<{ actions: Action[]; reason?: keyof typeof unavailableReasons }>(
    visibleService && !stale ? availabilityPath : null, onUnauthorized, 3000, undefined, scope,
  )
  const { data: history } = usePoll<History[]>(requestId ? `${historyPath}?request_id=${encodeURIComponent(requestId)}` : historyPath,
    onUnauthorized)
  const routeLost = errorCode === 'ROUTE_LOST'
  const directoryChanged = !availabilityError && (available?.reason === 'registration-changed'
    || available?.actions.some(action => !advertised.includes(action)))
  const actions = stale || availabilityError || directoryChanged ? [] : available?.actions ?? []
  const directoryNeedsSync = visibleService && !stale && (routeLost || directoryChanged)
  const unavailableReason = available?.reason && Object.hasOwn(unavailableReasons, available.reason)
    ? unavailableReasons[available.reason] : undefined
  const confirmedAction = confirm?.scope === scope && actions.includes(confirm.action) ? confirm.action : undefined
  const canSubmit = ready && !pending && !submitting
  const receiptId = requestId ?? selected ?? pending?.requestId
  const historyReceipt = history?.find((item) => item.request_id === receiptId)?.receipt ?? undefined
  const pendingReceipt = history?.find((item) => item.request_id === pending?.requestId)?.receipt
  // The selected receipt can change while the submitted operation is still running.
  const pendingRequestId = pending?.requestId
  const { data: backgroundReceipt } = usePoll<Receipt>(
    pendingRequestId && pendingRequestId !== receiptId && !receiptOffline && !receiptFinished(pendingReceipt ?? undefined)
      ? `${historyPath}/${pendingRequestId}` : null, onUnauthorized, 3000, undefined, connectionId,
  )

  useEffect(() => {
    if (!confirmedAction) setConfirm(undefined)
  }, [confirmedAction])

  const recoverRoute = useEffectEvent(onRouteLost)
  useEffect(() => {
    if (routeLost && visibleService && !stale && publication) recoverRoute(publication)
  }, [routeLost, visibleService, stale, publication])

  const syncRegistration = useEffectEvent(onSyncDirectory)
  useEffect(() => {
    if (!visibleService || stale || !directoryChanged || !publication) return
    const registration = `${publication}/${version}`
    if (syncedRegistration.current === registration) return
    syncedRegistration.current = registration
    syncRegistration()
  }, [publication, directoryChanged, stale, version, visibleService])

  const track = useCallback((request: PendingAction, result: Submission) => {
    setSelected((previous) => previous ?? result.request_id)
    setError('')
    if ('accepted' in result) setReceipt((previous) => latestReceipt(previous, result))
    if ('accepted' in result && receiptFinished(result)) {
      clear(request.key)
      onOperationFinished(result.request_id)
    } else update({ ...request, requestId: result.request_id, accepted: 'accepted' in result ? true : undefined })
  }, [clear, update, onOperationFinished])

  useEffect(() => {
    if (pending && lookupKey === pending.key && recovered && /^[a-f0-9]{32}$/.test(recovered.request_id)) {
      track(pending, recovered)
      refreshConsole()
    }
  }, [lookupKey, pending, recovered, track])

  async function submit(intent: PendingAction) {
    if (inFlight.current || !actions.includes(intent.action)) return
    const request = remember(intent)
    if (!request || request.requestId) return
    inFlight.current = true
    setConfirm(undefined)
    setSubmitting(request.action)
    setSelected(undefined)
    if (requestId) onSelectReceipt()
    setReceipt(undefined)
    setError('')
    const deadline = AbortSignal.timeout(SUBMISSION_TIMEOUT_MS)
    try {
      const result = await api<Submission>(submitPath, {
        method: 'POST',
        signal: deadline,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token, 'Idempotency-Key': request.key },
        body: JSON.stringify({ action: request.action, service_version: request.version }),
      })
      track(request, result)
      refreshConsole()
    } catch (failure) {
      if (failure instanceof ApiError && failure.code === 'DIRECTORY_CHANGED') {
        clear(request.key)
        setError('服务目录已变化，本次操作未提交。同步后请重新发起。')
        setPermissionRefresh((revision) => revision + 1)
        if (publication) onRouteLost(publication)
        refreshConsole()
        return
      }
      if (!pending && !deadline.aborted && !uncertainSubmission(failure)) clear(request.key)
      if (failure instanceof ApiError && [403, 404, 409].includes(failure.status)) {
        setPermissionRefresh((revision) => revision + 1)
        refreshConsole()
      }
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(deadline.aborted ? '提交响应超时，正在查询原请求的回执。' : failure instanceof Error ? failure.message : '请求失败')
    } finally {
      inFlight.current = false
      setSubmitting(undefined)
    }
  }

  const received = useCallback((current: Receipt) => {
    if (pending?.requestId !== current.request_id) return
    setReceipt((previous) => latestReceipt(previous, current))
    setSelected((selectedRequest) => selectedRequest ?? current.request_id)
    setError('')
    if (receiptFinished(current)) {
      clear(pending.key)
      onOperationFinished(current.request_id)
    } else if (!pending.accepted) update({ ...pending, accepted: true })
  }, [pending, clear, update, onOperationFinished])

  useEffect(() => {
    if (pendingReceipt && receiptFinished(pendingReceipt)) received(pendingReceipt)
    else if (backgroundReceipt?.accepted) received(backgroundReceipt)
  }, [backgroundReceipt, pendingReceipt, received])

  function begin(action: Action) {
    if (canSubmit) void submit({ key: crypto.randomUUID(), action, version })
  }

  if (!visibleService && !history?.length && !receiptId && !pending && !error && !confirm && !availabilityError) return null
  const accepted = pending?.accepted === true
  return <section className="remote-operation" aria-label="远程操作">
    {visibleService && <h4>远程操作</h4>}
    {visibleService && !actions.length && !directoryNeedsSync && <Notice tone={availabilityError ? 'amber' : ''}>
      {stale ? '目录同步后会重新检查可用操作。'
        : availabilityError ? <>暂时无法从服务所属节点核对可用操作。{availabilityError}</>
        : !available ? '正在向服务所属节点检查可用操作…'
        : unavailableReason ?? (session.grove ? '当前没有可用的远程操作，请核对服务的托管模式和主机执行条件。'
          : '当前没有可用的远程操作，请核对服务的管理设置。')}
      {!stale && !availabilityError && available?.reason === 'approval-required' &&
        <> <a className="text-link" href="#/operations/approvals">打开独立签名审批<Icon name="arrow-right" size={14} /></a></>}
      {ownerAccess && !stale && (availabilityError || available) &&
        <> <a className="text-link" href={ownerAccess}>打开所属节点的访问权限<Icon name="arrow-up-right" size={14} /></a></>}
    </Notice>}
    {directoryNeedsSync && <div className="stack-small">
      <Notice tone="amber">{routeLost ? '检查操作权限时服务目录已变化。同步后可继续。'
        : available?.reason === 'registration-changed' ? unavailableReasons['registration-changed']
        : '所属节点报告的操作权限比当前目录更新。同步目录后可核对新增操作。'}</Notice>
      <div><button type="button" className="btn btn-secondary btn-small" onClick={onSyncDirectory}>
        <Icon name="refresh" size={14} />同步目录并核对操作
      </button></div>
    </div>}
    {!!actions.length && <div className="button-row">
      {actions.map((action) => <button key={action} className={`btn ${action === 'start' ? 'btn-primary' : 'btn-secondary'}`}
        disabled={!canSubmit} onClick={() => action === 'start' ? begin(action) : setConfirm({ action, scope })}>
        {submitting === action ? '正在提交…' : actionNames[action]}
      </button>)}
    </div>}
    {confirmedAction && <ServiceActionConfirmation action={confirmedAction} name={name} disabled={!canSubmit}
      onClose={() => setConfirm(undefined)} onConfirm={() => begin(confirmedAction)} />}
    {(error || (!visibleService && availabilityError)) && <Notice tone="amber">{error || availabilityError}</Notice>}
    {pending && !submitting && <div className="stack">
      <Notice tone="amber" title={`${actionNames[pending.action]}${accepted ? '已受理' : '请求待确认'}`}>
        {accepted ? '正在等待执行结果。' : '核对执行节点的实际结果后，可结束跟踪。'}
      </Notice>
      {(!accepted || receiptId !== pending.requestId) && <div className="button-row">
        {pending.requestId ? receiptId !== pending.requestId && <button className="btn btn-secondary btn-small"
          onClick={() => onSelectReceipt(pending.requestId)}>查看待确认回执</button>
          : <button className="btn btn-secondary btn-small" disabled={!actions.includes(pending.action)}
            onClick={() => void submit(pending)}>重试同一请求</button>}
        {!accepted && <button className="btn btn-secondary btn-small" onClick={() => {
          clear(pending.key)
          if (pending.requestId && pending.requestId === requestId) onSelectReceipt()
          if (selected === pending.requestId) setSelected(undefined)
          setError('')
        }}>结束跟踪</button>}
      </div>}
    </div>}
    {!!history?.length && <ReceiptHistory history={history} selected={receiptId} onSelect={onSelectReceipt} />}
    {receiptId && <ReceiptStatus key={receiptId} path={`${historyPath}/${receiptId}`} onUnauthorized={onUnauthorized} onReceipt={received}
      initial={latestReceipt(receipt?.request_id === receiptId ? receipt : undefined, historyReceipt)} stale={receiptOffline} connectionId={connectionId} />}
  </section>
}
