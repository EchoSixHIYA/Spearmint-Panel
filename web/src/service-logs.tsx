import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { ApiError, api, READ_TIMEOUT_MS, timestamp } from './api'
import { refreshConsole } from './console-data'
import { directoryQuery, directoryScope } from './remote-directory'
import { Icon, Notice, Panel } from './ui'

type LogSnapshot = { text: string; truncated: boolean; source: string; checked_at: number }
const lineCounts = [50, 200, 500] as const
type LineCount = typeof lineCounts[number]

export function ServiceLogs({ path, serviceId, onUnauthorized, active = true, remote = false, paused = false, connectionId,
  directoryGeneration, onRouteLost }: {
  path: string; serviceId: string; onUnauthorized: () => void; active?: boolean; remote?: boolean; connectionId?: string
  paused?: boolean; directoryGeneration?: number
  onRouteLost?: (scope: string) => void
}) {
  const scope = directoryScope(connectionId, directoryGeneration)
  const [sample, setSample] = useState<{ logs: LogSnapshot; scope?: string; path: string; tail: LineCount }>()
  const [busy, setBusy] = useState(false)
  const [auto, setAuto] = useState(false)
  const [tail, setTail] = useState<LineCount>(200)
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')
  const request = useRef<AbortController>(null)
  const terminal = useRef<HTMLPreElement>(null)
  const followLatest = useRef(true)
  const canRead = active && !paused
  const logs = canRead && sample?.scope === scope && sample?.path === path && sample.tail === tail ? sample.logs : undefined

  const read = useCallback(async () => {
    if (!canRead || request.current) return
    const controller = new AbortController()
    const deadline = AbortSignal.timeout(READ_TIMEOUT_MS)
    request.current = controller
    setBusy(true)
    setError('')
    try {
      const query = directoryQuery(connectionId, directoryGeneration)
      const result = await api<LogSnapshot>(`${path}/logs?tail=${tail}${query ? '&' + query : ''}`, {
        signal: AbortSignal.any([controller.signal, deadline]),
      })
      if (!controller.signal.aborted) setSample({ logs: result, scope, path, tail })
    } catch (failure) {
      if (controller.signal.aborted) return
      const unavailable = failure instanceof ApiError && [401, 403, 404].includes(failure.status)
      if (remote || unavailable) setSample(undefined)
      if (unavailable) setAuto(false)
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else if (remote && failure instanceof ApiError && failure.code === 'ROUTE_LOST') {
        setError('服务目录已变化，等待同步。')
        if (scope && onRouteLost) onRouteLost(scope)
        else refreshConsole()
      }
      else setError(deadline.aborted ? '日志读取超时，请重试。' : failure instanceof Error ? failure.message : '日志读取失败')
    } finally {
      if (request.current === controller) {
        request.current = null
        setBusy(false)
      }
    }
  }, [canRead, path, tail, onUnauthorized, remote, connectionId, directoryGeneration, scope, onRouteLost])

  useEffect(() => {
    if (!canRead) {
      setBusy(false)
      if (remote && !active) followLatest.current = true
      if (remote || paused) {
        setSample(undefined)
        setError('')
      }
      return
    }
    void read()
    return () => {
      request.current?.abort()
      request.current = null
    }
  }, [active, canRead, paused, read, remote])

  useEffect(() => {
    if (!canRead || !auto) return
    const timer = setInterval(() => { if (!document.hidden) void read() }, remote ? 10000 : 5000)
    return () => clearInterval(timer)
  }, [canRead, auto, read, remote])

  function download() {
    if (!logs) return
    const url = URL.createObjectURL(new Blob([logs.text], { type: 'text/plain;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `spearmint-${serviceId}.log`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const match = query.toLowerCase()
  const text = logs && (match ? logs.text.split('\n').filter((line) => line.toLowerCase().includes(match)).join('\n')
    || '没有匹配的日志。' : logs.text || '当前还没有日志。')
  function jumpToLatest() {
    followLatest.current = true
    const element = terminal.current
    if (element) element.scrollTop = element.scrollHeight
  }
  useLayoutEffect(() => {
    if (logs && followLatest.current) jumpToLatest()
  }, [logs, text])

  if (remote && !active) return null

  return <div hidden={!active}><Panel className={remote ? 'logs-panel remote-logs-panel' : 'logs-panel'}
    title={remote ? '远程服务日志' : '运行日志'} action={
    <div className="button-row">
      <label className="inline-checkbox"><input type="checkbox" checked={auto} onChange={(event) => setAuto(event.target.checked)} />自动刷新</label>
      <button className="btn btn-secondary btn-small" disabled={!canRead || busy} onClick={() => void read()}>
        <Icon name="refresh" size={14} />{busy ? '读取中…' : '刷新'}
      </button>
      <button className="btn btn-secondary btn-small" disabled={!logs} onClick={download}>
        <Icon name="download" size={14} />下载
      </button>
    </div>}>
    <div className="log-filters">
      <label className="search-box log-search"><Icon name="search" size={16} />
        <input placeholder="在日志中筛选关键词…" aria-label="筛选日志" value={query} onChange={(event) => setQuery(event.target.value)} />
      </label>
      <select className="input" aria-label="读取日志行数" value={tail}
        onChange={(event) => {
          const count = lineCounts.find((value) => String(value) === event.target.value)
          if (count === undefined || count === tail) return
          followLatest.current = true
          setSample(undefined)
          setTail(count)
        }}>
        {lineCounts.map((count) => <option key={count} value={count}>最近 {count} 行</option>)}
      </select>
      <button className="btn btn-secondary btn-small" disabled={!logs} onClick={jumpToLatest}>跳到最新</button>
    </div>
    {!paused && error && <Notice tone="amber">{error}</Notice>}
    <div className="log-caption"><span>{logs?.truncated ? '部分日志已截断' : '日志快照'}</span>
      <span>{logs ? timestamp(logs.checked_at) : '等待日志'}</span></div>
    <pre className="log-terminal" tabIndex={0} ref={terminal} onScroll={({ currentTarget }) => {
      if (logs) followLatest.current = currentTarget.scrollHeight - currentTarget.clientHeight - currentTarget.scrollTop <= 8
    }}>{text ?? (paused ? '等待服务目录同步。' : busy ? '正在读取日志…' : '日志暂不可用。')}</pre>
  </Panel></div>
}
