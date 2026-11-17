import { useEffect, useEffectEvent, useRef, useState } from 'react'
import { ApiError, api, READ_TIMEOUT_MS, timestamp } from './api'
import { refreshConsole, useConsole } from './console-data'
import { useGroveDirectorySync } from './grove-auth'
import { seedProgress } from './seed-progress'
import { useRemoteCatalog, type NodeDirectory } from './remote-catalog'
import { Icon } from './ui'

const seedProgressLabels = {
  'directory-unavailable': '等待当前 Grove 的成员目录更新。',
  'ambiguous-origin': '多个已启用成员使用这个地址，请到节点管理核对 Node ID。',
  'identity-mismatch': '成员目录中的地址与安装回执的 Node ID 不匹配，请在签发节点核对加入记录。',
  'awaiting-member': '等待 Grove 同步新节点的成员身份。',
  'member-disabled': '当前 Grove 目录显示该成员已停用，请在签发节点核对成员状态。',
  local: '这是当前面板所在的节点，已加入 Grove。',
  'mesh-unavailable': 'Grove 已批准此目标，连接状态暂时无法读取。',
  'mesh-unconfigured': 'Grove 已批准此目标，正在等待自动配对。',
  'mesh-restricted': 'Grove 已批准此目标，当前面板上的 Mesh 连接已停用或隔离。',
  'mesh-idle': 'Grove 已批准此目标，Mesh 会在读取服务目录时按需建立连接。',
  'awaiting-path': 'Grove 已批准此目标，等待当前面板建立活动路径。',
  'awaiting-catalog': '已发现活动路径，正在等待该连接同步服务目录。',
  ready: 'Grove 已批准此目标，活动路径与服务目录均已就绪。',
}

export function SeedConnectionProgress({ origin, nodeId, syncOnJoin = false }: { origin: string; nodeId?: string; syncOnJoin?: boolean }) {
  const { directoryCurrent, members, directoryRequestedAt, directoryMeshRequestedAt, listedNodes, memberPanelOrigins,
    grove, groveDetails } = useConsole()
  const { directories, error } = useRemoteCatalog()
  const attempted = useRef<{ target: string; connectionId?: string }>(undefined)
  const progress = seedProgress(origin, { directoryCurrent, members }, listedNodes, directories, !!error, nodeId)
  const memberId = progress.status !== 'local' ? progress.id : undefined
  const node = listedNodes.find(node => node.id === memberId)
  const requestedAt = memberId ? directoryRequestedAt?.[memberId] : undefined
  const meshRequestedAt = memberId ? directoryMeshRequestedAt?.[memberId] : undefined
  const canCheck = (progress.status === 'mesh-idle' || progress.status === 'awaiting-path' || progress.status === 'awaiting-catalog')
    && node?.peer?.enabled === true
  const target = syncOnJoin && nodeId && memberId === nodeId ? `${nodeId}/${origin}` : undefined
  const connectionId = node?.status === 'online' ? node.peer?.connection_id : undefined
  const autoCheckKey = target ? JSON.stringify([target, connectionId]) : undefined
  const waitingForDirectory = progress.status === 'directory-unavailable' || progress.status === 'awaiting-member'
  const syncRealmId = !grove.error && groveDetails?.local_issuer === false
    && !groveDetails.frozen && !groveDetails.issuer_paused ? groveDetails.realm?.id : undefined
  const memberOrigin = memberId ? memberPanelOrigins.get(memberId) : undefined

  function noteAttempt(connectionId?: string) {
    if (!target) return false
    if (attempted.current?.target === target && (connectionId === undefined || attempted.current.connectionId === connectionId)) return false
    attempted.current = { target, connectionId }
    return true
  }

  return <div role="status" className="stack-small">
    <p>{seedProgressLabels[progress.status]}</p>
    {requestedAt !== undefined && <p>签发节点首次收到目标的 HTTPS 身份目录请求 · {timestamp(requestedAt)}</p>}
    {meshRequestedAt !== undefined && <p>签发节点首次收到目标的 Mesh 身份目录请求 · {timestamp(meshRequestedAt)}</p>}
    {memberId && (directoryRequestedAt || directoryMeshRequestedAt) && requestedAt === undefined && meshRequestedAt === undefined &&
      <p>签发节点尚未记录来自该目标的身份目录请求。目标也可从其他 Mesh 邻居获取目录。</p>}
    {'hops' in progress && <p>{progress.hops === 1 ? '当前面板与目标直连' : `当前面板经 ${progress.hops} 跳到达目标`}
      {progress.status === 'ready' && ` · 已同步 ${progress.services} 项授权服务`}</p>}
    {syncRealmId && <SeedMembershipSync key={JSON.stringify([syncRealmId, origin, nodeId])}
      realmId={syncRealmId} waiting={waitingForDirectory} />}
    {memberId && <div className="button-row">
      <a className="text-link" href={`#/nodes/${memberId}`}>查看节点<Icon name="arrow-right" size={15} /></a>
      {memberOrigin === origin && <a className="text-link" href={`${memberOrigin}/`}
        target="_blank" rel="noopener noreferrer">打开目标面板<Icon name="arrow-up-right" size={15} /></a>}
      {progress.status === 'awaiting-path' && <a className="text-link" href={`#/topology/${memberId}`}>查看路径与观测<Icon name="arrow-right" size={15} /></a>}
      {'hops' in progress && <a className="text-link" href={`#/topology/${memberId}`}>查看活动路径<Icon name="arrow-right" size={15} /></a>}
      {'hops' in progress && <a className="text-link" href={`#/deployments/${memberId}`}>核对目标版本<Icon name="arrow-right" size={15} /></a>}
      {progress.status === 'ready' && <a className="text-link" href={`#/services/remote/${memberId}`}>查看服务目录<Icon name="arrow-right" size={15} /></a>}
    </div>}
    {memberId && canCheck && <SeedDirectoryCheck key={`${memberId}/${origin}`} nodeId={memberId}
      autoCheckKey={autoCheckKey} connectionId={connectionId} noteAttempt={noteAttempt} />}
  </div>
}

function SeedMembershipSync({ realmId, waiting }: { realmId: string; waiting: boolean }) {
  const { session, onUnauthorized } = useConsole()
  const { checking, sync, message } = useGroveDirectorySync(realmId, session.csrf_token, onUnauthorized)
  if (!waiting && !message && !checking) return null
  return <div className="stack-small">
    {(waiting || checking) && <div><button type="button" className="btn btn-secondary btn-small" disabled={checking}
      onClick={() => void sync()}><Icon name="refresh" size={14} />
      {checking ? '正在同步成员目录…' : '同步成员目录'}</button></div>}
    {message && <p className={message.error ? 'error' : 'muted'}>{message.text}</p>}
  </div>
}

function SeedDirectoryCheck({ nodeId, autoCheckKey, connectionId, noteAttempt }: {
  nodeId: string; autoCheckKey?: string; connectionId?: string; noteAttempt: (connectionId?: string) => boolean
}) {
  const { onUnauthorized } = useConsole()
  const request = useRef<AbortController | null>(null)
  const [checking, setChecking] = useState(false)
  const [message, setMessage] = useState('')
  useEffect(() => () => request.current?.abort(), [])

  async function check(automatic = false) {
    if (request.current) return
    const firstAttempt = noteAttempt(connectionId)
    if (automatic && !firstAttempt) return
    const controller = new AbortController()
    request.current = controller
    setChecking(true)
    setMessage('')
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    try {
      const result = await api<NodeDirectory>(`/peers/${encodeURIComponent(nodeId)}/services?refresh=true`, {
        signal: AbortSignal.any([controller.signal, deadline]),
      })
      if (controller.signal.aborted) return
      if (result.node_id !== nodeId) {
        setMessage('返回的节点身份与当前目标不符。')
        return
      }
      if (!result.stale && result.connection_id) noteAttempt(result.connection_id)
      setMessage(result.stale ? '暂未取得当前连接的服务目录，可稍后重试。' : '已收到服务目录，正在核对当前连接。')
      refreshConsole()
    } catch (failure) {
      if (controller.signal.aborted) return
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setMessage(deadline.aborted ? '连接验证超时，可稍后重试。' : '暂时无法验证连接，可稍后重试。')
    } finally {
      if (!controller.signal.aborted) {
        request.current = null
        setChecking(false)
      }
    }
  }

  const checkAutomatically = useEffectEvent(() => check(true))
  useEffect(() => {
    if (!autoCheckKey || checking) return
    const timer = setTimeout(() => void checkAutomatically(), 0)
    return () => clearTimeout(timer)
  }, [autoCheckKey, checking])

  return <div className="stack-small">
    <div><button type="button" className="btn btn-secondary btn-small" disabled={checking} onClick={() => void check()}>
      <Icon name="refresh" size={14} />{checking ? '正在验证连接…' : '验证连接并同步目录'}
    </button></div>
    {message && <p>{message}</p>}
  </div>
}
