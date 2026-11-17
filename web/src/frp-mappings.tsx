import { useEffect, useRef, useState } from 'react'
import { ApiError, api, READ_TIMEOUT_MS, timestamp, type Session, usePoll } from './api'
import { refreshConsole, useConsole } from './console-data'
import { uncertainSubmission, usePendingSubmission } from './pending-submission'
import { Badge, CopyValue, EmptyState, Icon, Loading, Modal, Notice, PageHeading, Panel } from './ui'

type Target = { address: string; domain?: string; port?: number }
type Option = { provider: string; protocol: 'http' | 'https' | 'tcp'; targets: Target[] }
type Mapping = { id: string; provider: string; public_address: string; expires_at: number; status: string; health: string | null }
type LocalMapping = Mapping & { service_id: string; service_name: string | null; protocol: Option['protocol'] }
type View = { options: Option[]; mappings: Mapping[]; can_start: boolean }
type Receipt = { mapping?: Mapping; pending?: boolean }
type Submission = { key: string } & ({ body: string; exposure?: never } | { exposure: string; body?: never })

const active = ['starting', 'running', 'revoking']
const labels: Record<string, string> = {
  starting: '正在启动', running: '进程已启动', revoking: '正在撤销', revoked: '已撤销',
  expired: '已到期', failed: '启动或运行失败', ready: '入口已注册', connecting: '正在连接 Provider',
  backend_unavailable: '服务端口不可达', provider_rejected: 'Provider 拒绝了映射',
}

function MappingStatus({ mapping }: { mapping: Mapping }) {
  return <Badge tone={mapping.health === 'ready' ? 'green' : 'outline'}>
    {labels[mapping.health || mapping.status] || mapping.status}
  </Badge>
}

export function ExposuresPage() {
  const { onUnauthorized } = useConsole()
  const { data, error } = usePoll<LocalMapping[]>('/frp/exposures', onUnauthorized, 10000)
  return <>
    <PageHeading eyebrow="INFRASTRUCTURE / EXPOSURES" title="公网映射" description="查看当前节点管理的公网入口和最近的映射记录。">
      <button className="btn btn-secondary" onClick={refreshConsole}><Icon name="refresh" size={15} />刷新列表</button>
    </PageHeading>
    <Panel>
      {error && <Notice tone="amber" title="暂时无法更新映射状态">{data ? '下方显示上次读取的记录。' : error}</Notice>}
      {!data && !error && <Loading label="正在读取公网映射…" />}
      {data?.length === 0 && !error && <EmptyState icon="globe" title="当前节点暂无公网映射"
        action={<a href="#/services/local" className="btn btn-primary">打开本机服务</a>} />}
      {!!data?.length && <div className="table-wrap"><table className="data-table">
        <thead><tr><th scope="col">公网入口</th><th scope="col">所属服务</th><th scope="col">Provider</th>
          <th scope="col">状态</th><th scope="col">到期时间</th></tr></thead>
        <tbody>{data.map((mapping) => <tr key={mapping.id}>
          <td><CopyValue value={mapping.public_address} /></td>
          <td>{mapping.service_name === null ? <span className="muted">服务已取消登记</span>
            : <a className="text-link" href={`#/services/${encodeURIComponent(mapping.service_id)}`}>
              {mapping.service_name}<Icon name="arrow-right" size={14} /></a>}</td>
          <td>{mapping.provider} · {mapping.protocol.toUpperCase()}</td>
          <td><MappingStatus mapping={mapping} /></td>
          <td className="time-cell">{timestamp(mapping.expires_at)}</td>
        </tr>)}</tbody>
      </table></div>}
    </Panel>
  </>
}

const optionKey = (option: Option) => `${option.provider}/${option.protocol}`
function decodeSubmission({ key, body, exposure }: Record<string, unknown> & { key: string }): Submission | undefined {
  if (typeof body === 'string' && body.length <= 2048 && exposure === undefined) return { key, body }
  if (typeof exposure === 'string' && /^[a-f0-9]{32}$/.test(exposure) && body === undefined) return { key, exposure }
}

export function FrpMappings({ path, session, onUnauthorized, stale = false, connectionId }: {
  path: string; session: Session; onUnauthorized: () => void; stale?: boolean; connectionId?: string
}) {
  const url = `${path}/frp`
  const { data, error, requestedAt } = usePoll<View>(url, onUnauthorized, 3000, undefined, connectionId)
  const [choice, setChoice] = useState('')
  const [address, setAddress] = useState('')
  const [minutes, setMinutes] = useState('60')
  const [confirmation, setConfirmation] = useState<{ option: Option; target: Target; ttl: number }>()
  const { pending, ready, remember, clear } = usePendingSubmission('spearmint-frp', url, session.csrf_token, decodeSubmission)
  const [latest, setLatest] = useState<{ mapping: Mapping; receivedAt: number }>()
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const inFlight = useRef(false)
  const lookupKey = !busy && !stale ? pending?.key : undefined
  const { data: recovered, error: lookupError } = usePoll<Receipt>(
    lookupKey ? `${url}/requests/${encodeURIComponent(lookupKey)}` : null, onUnauthorized, 10000,
  )
  const option = data?.options.find((item) => optionKey(item) === choice) ?? data?.options[0]
  const target = option?.targets.find((item) => item.address === address) ?? option?.targets[0]
  const duration = Number(minutes)
  const validDuration = Number.isInteger(duration) && duration >= 1 && duration <= 1440
  const canStart = !!data?.can_start && !error && !stale
  const canSubmit = ready && !pending && !busy
  const confirmed = confirmation && canStart && canSubmit && data?.options.some((current) =>
    optionKey(current) === optionKey(confirmation.option) && current.targets.some((entry) =>
      entry.address === confirmation.target.address && entry.domain === confirmation.target.domain
      && entry.port === confirmation.target.port))
    ? confirmation : undefined

  useEffect(() => {
    if (!confirmed) setConfirmation(undefined)
  }, [confirmed])

  useEffect(() => {
    if (!lookupKey || !recovered?.mapping) return
    setLatest({ mapping: recovered.mapping, receivedAt: performance.now() })
    setMessage('')
    clear(lookupKey)
    refreshConsole()
  }, [clear, lookupKey, recovered])

  async function send(intent: Submission) {
    if (inFlight.current) return
    const request = remember(intent)
    if (!request) return
    inFlight.current = true
    setBusy(true)
    setMessage('')
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      const receipt = await api<Receipt>(request.exposure ? `${url}/${encodeURIComponent(request.exposure)}/revoke` : url, {
        method: 'POST', body: request.body, signal: deadline,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token, 'Idempotency-Key': request.key },
      })
      if (receipt.mapping) {
        setLatest({ mapping: receipt.mapping, receivedAt: performance.now() })
        clear(request.key)
        refreshConsole()
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      if (!pending && !deadline.aborted && !uncertainSubmission(failure)) clear(request.key)
      setMessage(deadline.aborted ? '提交响应超时。'
        : failure instanceof Error ? failure.message : '请求结果尚未确认')
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  const mappings = data?.mappings ?? []
  const receiptMapping = latest && (requestedAt === undefined || requestedAt < latest.receivedAt) ? latest.mapping : undefined
  const rows = receiptMapping ? [receiptMapping, ...mappings.filter(({ id }) => id !== receiptMapping.id)] : mappings
  if (!option && !rows.length && !pending && !message) return null

  return <Panel title="公网映射">
    {option && <form className="stack" onSubmit={(event) => {
      event.preventDefault()
      if (canStart && canSubmit && target && validDuration) setConfirmation({ option, target, ttl: duration * 60 })
    }}>
      <div className="button-row">
        <label className="field-label">Provider 与协议
          <select value={optionKey(option)} onChange={(event) => { setChoice(event.target.value); setAddress('') }}>
            {data?.options.map((item) => <option key={optionKey(item)} value={optionKey(item)}>{item.provider} · {item.protocol.toUpperCase()}</option>)}
          </select>
        </label>
        <label className="field-label">公网入口
          <select value={target?.address || ''} onChange={(event) => setAddress(event.target.value)}>
            {option.targets.map((item) => <option key={item.address} value={item.address}>{item.address}</option>)}
          </select>
        </label>
        <label className="field-label">有效期（分钟）
          <input type="number" min="1" max="1440" step="1" value={minutes} onChange={(event) => setMinutes(event.target.value)} />
        </label>
      </div>
      {canStart ? <div><button className="btn btn-primary" disabled={!canSubmit || !target || !validDuration}>建立公网映射</button></div>
        : <p className="muted">{stale || error ? '请等待执行节点的状态更新。' : '服务所属节点需要配置 frpc。'}</p>}
    </form>}
    {rows.length > 0 && <ul className="service-list">{rows.map((mapping) => <li key={mapping.id}>
      <div><strong>{mapping.public_address}</strong><br /><small>{mapping.provider} · {timestamp(mapping.expires_at)} 到期</small></div>
      <MappingStatus mapping={mapping} />
      {active.includes(mapping.status) && mapping.status !== 'revoking' && <button className="btn btn-secondary btn-small"
        disabled={!canSubmit || stale || !!error || !mappings.some((entry) => entry.id === mapping.id)} onClick={() => void send({
          key: crypto.randomUUID(), exposure: mapping.id,
        })}>撤销</button>}
    </li>)}</ul>}
    {error && <Notice tone="amber">{error}</Notice>}
    {message && <Notice tone="amber">{message}</Notice>}
    {pending && !busy && <p className="muted" role="status">{stale ? '连接恢复后会查询原请求的回执。'
      : lookupError ? '暂未读到回执，稍后会继续查询。' : '正在查询原请求的回执。'}</p>}
    {pending && <div className="button-row">
      <button className="btn btn-secondary btn-small" disabled={busy || stale} onClick={refreshConsole}>查询回执</button>
      <button className="btn btn-secondary btn-small" disabled={busy || stale || !!error} onClick={() => void send(pending)}>重试同一请求</button>
    </div>}
    {confirmed && <Modal title="公开此服务？" onClose={() => setConfirmation(undefined)}>
      <p>{confirmed.target.address} 将开放 {confirmed.ttl / 60} 分钟。对外访问权限由服务本身控制。</p>
      <div className="modal-actions">
        <button className="btn btn-secondary" onClick={() => setConfirmation(undefined)}>取消</button>
        <button className="btn btn-primary" onClick={() => {
          setConfirmation(undefined)
          void send({ key: crypto.randomUUID(), body: JSON.stringify({
            provider: confirmed.option.provider, protocol: confirmed.option.protocol, ttl: confirmed.ttl,
            domain: confirmed.target.domain ?? null, public_port: confirmed.target.port ?? null,
          }) })
        }}>确认公开</button>
      </div>
    </Modal>}
  </Panel>
}
