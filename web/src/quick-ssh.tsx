import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { ApiError, api, type Session } from './api'
import { useConsole } from './console-data'
import { NetworkMap } from './network-map'
import { bytes, Icon, Notice, PageHeading, Panel } from './ui'
import '@xterm/xterm/css/xterm.css'
import './quick-ssh.css'

type Connection = { target: string; id: string; name: string }
type Exchange = { data: string; offset: number; sequence: number; ended: boolean }
type FileEntry = { name: string; path: string; directory: boolean; size: number; modified: number; version: string }
type Directory = { path: string; parent: string | null; items: FileEntry[]; next_offset: number | null; drives: string[] }
type FileChunk = { data: string; size: number; offset: number; version: string }

function encode(data: Uint8Array) {
  return btoa(String.fromCharCode(...data)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}
function decode(data: string) {
  return Uint8Array.from(atob(data.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0))
}
function terminalError(failure: unknown) {
  if (failure instanceof ApiError) {
    if (failure.code === 'UNSUPPORTED_METHOD' || failure.status === 404) return '目标节点需要先通过 Grove 群组更新升级，才能打开快速 SSH。'
    if (failure.code === 'TERMINAL_CLOSED') return '终端会话已结束，请重新连接。'
    if (failure.code === 'HOST_PERMISSION') return '目标节点的运行账号没有访问该文件的权限。'
    if (failure.code === 'CONFLICT') return '文件或会话状态已变化，请刷新后重试。'
    if (failure.code === 'DENIED') return '请使用当前 Grove 的管理员账号，并确认目标节点仍在 Grove 中。'
    if (['OFFLINE', 'NO_ROUTE', 'ROUTE_LOST', 'TIMEOUT'].includes(failure.code ?? '')) return '到目标节点的 Mesh 连接暂时不可用。'
  }
  return '暂时无法完成操作，请检查节点连接后重试。'
}

function request<T>(connection: Connection, session: Session, action: string, body: object, signal?: AbortSignal) {
  return api<T>(`/peers/${connection.target}/terminal/${connection.id}/${action}`, {
    method: 'POST', headers: { 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body),
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000),
  })
}

export default function QuickSSH({ targetId }: { targetId?: string }) {
  const { listedNodes, session, onUnauthorized } = useConsole()
  const [target, setTarget] = useState(targetId)
  const [connection, setConnection] = useState<Connection>()
  const [opening, setOpening] = useState(false)
  const [error, setError] = useState('')
  const selected = listedNodes.find(node => node.id === target)
  const openingController = useRef<AbortController | null>(null)
  useEffect(() => () => openingController.current?.abort(), [])

  async function connect() {
    if (!selected || opening) return
    setOpening(true); setError('')
    const controller = new AbortController()
    openingController.current = controller
    const next = { target: selected.id, id: crypto.randomUUID().replaceAll('-', ''), name: selected.name }
    try {
      await request(next, session, 'open', { columns: 100, rows: 28 }, controller.signal)
      if (!controller.signal.aborted) setConnection(next)
      else void request(next, session, 'close', {}).catch(() => {})
    } catch (failure) {
      if (!controller.signal.aborted) {
        if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
        else setError(terminalError(failure))
      }
      void request(next, session, 'close', {}).catch(() => {})
    } finally {
      if (!controller.signal.aborted) setOpening(false)
    }
  }

  return <>
    <PageHeading eyebrow="INFRASTRUCTURE / SSH" title="快速 SSH" description="从拓扑图选择节点，在当前面板打开终端和文件目录。" />
    {error && <Notice tone="amber">{error}</Notice>}
    {!connection ? <Panel title="选择目标节点">
      <NetworkMap target={target} onPick={setTarget} />
      <div className="button-row quick-ssh-connect">
        {selected && <strong>{selected.name}</strong>}
        <button className="btn btn-primary" disabled={!selected || opening} onClick={() => void connect()}>
          <Icon name="terminal" size={16} />{opening ? '正在连接…' : '打开终端'}
        </button>
      </div>
    </Panel> : <SSHWorkspace key={connection.id} connection={connection} close={() => setConnection(undefined)} />}
  </>
}

function SSHWorkspace({ connection, close }: { connection: Connection; close: () => void }) {
  const { session, onUnauthorized } = useConsole()
  const container = useRef<HTMLDivElement>(null)
  const terminal = useRef<Terminal | null>(null)
  const [error, setError] = useState('')
  const [ended, setEnded] = useState(false)

  useEffect(() => {
    const term = new Terminal({ cursorBlink: true, fontFamily: '"Courier Prime", Consolas, monospace', fontSize: 14,
      scrollback: 5000, theme: { background: '#102a24', foreground: '#e5f1e8', cursor: '#9dd7b5', selectionBackground: '#427661' } })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(container.current!)
    fit.fit(); term.focus(); terminal.current = term
    let stopped = false, offset = 0, sequence = 0, pending = '', inflight = '', failures = 0
    let timer: number | undefined
    let running = false
    const controller = new AbortController()
    const observer = new ResizeObserver(() => { if (!stopped) fit.fit() })
    observer.observe(container.current!)
    const input = term.onData(data => {
      pending += data
      if (!running) schedule(0)
    })
    function schedule(delay: number) {
      window.clearTimeout(timer)
      if (!stopped) timer = window.setTimeout(() => void exchange(), delay)
    }
    async function exchange() {
      if (stopped || running) return
      running = true
      if (!inflight && pending) {
        inflight = Array.from(pending).slice(0, 1000).join('')
        pending = pending.slice(inflight.length)
        sequence += 1
      }
      try {
        const output = await request<Exchange>(connection, session, 'exchange', { offset, sequence,
          data: encode(new TextEncoder().encode(inflight)), columns: Math.max(2, Math.min(500, term.cols)),
          rows: Math.max(2, Math.min(250, term.rows)) }, controller.signal)
        if (stopped) return
        failures = 0
        inflight = ''
        if (output.data) await new Promise<void>(resolve => term.write(decode(output.data), resolve))
        offset = output.offset
        if (output.ended) {
          stopped = true; setEnded(true)
          void request(connection, session, 'close', {}).catch(() => {})
        } else schedule(pending || output.data ? 0 : 80)
      } catch (failure) {
        if (stopped) return
        if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
        if (++failures < 3 && (!(failure instanceof ApiError) || failure.status >= 500)) schedule(500)
        else { setError(terminalError(failure)); stopped = true; setEnded(true) }
      } finally { running = false }
    }
    function disconnect() {
      const path = `/api/v1/peers/${connection.target}/terminal/${connection.id}/close`
      void fetch(path, { method: 'POST', credentials: 'same-origin', keepalive: true,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }, body: '{}' }).catch(() => {})
    }
    window.addEventListener('pagehide', disconnect)
    schedule(0)
    return () => {
      stopped = true; controller.abort(); window.clearTimeout(timer)
      input.dispose(); observer.disconnect(); terminal.current = null; term.dispose()
      window.removeEventListener('pagehide', disconnect); disconnect()
    }
  }, [connection, session, onUnauthorized])

  return <div className="quick-ssh-workspace">
    <Panel className="quick-ssh-console" title={`${connection.name} · 终端`} action={<div className="button-row">
      <button className="btn btn-secondary" onClick={() => { terminal.current?.clear(); terminal.current?.focus() }}>清屏</button>
      <button className="btn btn-secondary" onClick={close}>{ended ? '重新选择节点' : '断开连接'}</button>
    </div>}>
      {error && <Notice tone="amber">{error}</Notice>}
      {ended && !error && <p className="muted">终端会话已结束。</p>}
      <div className="quick-ssh-terminal" ref={container} aria-label={`${connection.name} 交互终端`} />
    </Panel>
    {!ended && <FileBrowser connection={connection} />}
  </div>
}

function FileBrowser({ connection }: { connection: Connection }) {
  const { session, onUnauthorized } = useConsole()
  const [listing, setListing] = useState<Directory>()
  const [path, setPath] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [editor, setEditor] = useState<{ file: FileEntry; text: string }>()
  const active = useRef(true)
  const uploadInput = useRef<HTMLInputElement>(null)
  useEffect(() => { active.current = true; return () => { active.current = false } }, [])

  async function files<T>(body: object) { return request<T>(connection, session, 'files', body) }
  async function perform(work: () => Promise<void>) {
    if (busy) return
    setBusy(true); setError('')
    try { await work() } catch (failure) {
      if (active.current) {
        if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
        else setError(terminalError(failure))
      }
    } finally { if (active.current) { setBusy(false); setProgress('') } }
  }
  async function browse(next: string, offset = 0) {
    const result = await files<Directory>({ operation: 'list', path: next, offset })
    if (active.current) { setListing(result); setPath(result.path); setEditor(undefined) }
  }
  useEffect(() => { void perform(() => browse('')) }, [connection.id])
  async function download(file: FileEntry, editing: boolean) {
    if (editing && file.size > 512 * 1024) { setError('文件较大，请下载后编辑并重新上传。'); return }
    const chunks: Uint8Array<ArrayBuffer>[] = []
    let offset = 0
    do {
      if (!active.current) return
      const part = await files<FileChunk>({ operation: 'read', path: file.path, version: file.version, offset })
      const data = decode(part.data)
      chunks.push(data); offset = part.offset
      setProgress(`正在读取 ${file.name} · ${bytes(offset)} / ${bytes(file.size)}`)
      if (!data.length) break
    } while (offset < file.size)
    const blob = new Blob(chunks)
    if (editing) {
      const data = await blob.arrayBuffer()
      try { setEditor({ file, text: new TextDecoder('utf-8', { fatal: true }).decode(data) }) }
      catch { setError('文件不是 UTF-8 文本，请下载后使用对应工具编辑。') }
    } else {
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = file.name; anchor.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 30_000)
    }
  }
  async function upload(name: string, data: Blob, target?: FileEntry) {
    if (!listing) return
    const transfer = crypto.randomUUID().replaceAll('-', '')
    const separator = listing.path.includes('\\') ? '\\' : '/'
    const destination = target?.path ?? listing.path.replace(/[\\/]$/, '') + separator + name
    let result = await files<{ offset: number }>({ operation: 'begin', transfer, path: destination,
      size: data.size, version: target?.version ?? null })
    while (result.offset < data.size) {
      if (!active.current) return
      const offset = result.offset
      const chunk = new Uint8Array(await data.slice(offset, offset + 8192).arrayBuffer())
      result = await files({ operation: 'write', transfer, offset, data: encode(chunk) })
      setProgress(`正在保存 ${name} · ${bytes(result.offset)} / ${bytes(data.size)}`)
    }
    await files({ operation: 'finish', transfer })
    await browse(listing.path)
  }
  function navigate(event: FormEvent) { event.preventDefault(); void perform(() => browse(path)) }
  const entries = [...(listing?.items ?? [])].sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name))
  return <Panel className="quick-ssh-files" title="文件" action={<div className="button-row">
    <button className="btn btn-secondary" disabled={busy || !listing?.parent} onClick={() => void perform(() => browse(listing!.parent!))}>上一级</button>
    <button className="btn btn-secondary" disabled={busy} onClick={() => void perform(() => browse(listing?.path ?? ''))}>刷新</button>
    <button className="btn btn-secondary" disabled={busy || !listing} onClick={() => uploadInput.current?.click()}>上传文件</button>
    <input ref={uploadInput} type="file" hidden onChange={event => {
      const file = event.target.files?.[0]; event.target.value = ''
      if (file) void perform(async () => {
        const previous = listing?.items.find(item => item.name === file.name)
        if (previous && !window.confirm(`覆盖 ${file.name}？`)) return
        await upload(file.name, file, previous)
      })
    }} />
  </div>}>
    <form className="quick-ssh-path" onSubmit={navigate}>
      <input className="input" aria-label="目标目录路径" value={path} onChange={event => setPath(event.target.value)} />
      <button className="btn btn-secondary" disabled={busy}>打开目录</button>
    </form>
    {!!listing?.drives.length && <div className="button-row quick-ssh-drives">{listing.drives.map(drive => <button key={drive} className="btn btn-secondary btn-small" disabled={busy}
      onClick={() => void perform(() => browse(drive))}>{drive}</button>)}</div>}
    {error && <Notice tone="amber">{error}</Notice>}
    {progress && <p className="muted" role="status">{progress}</p>}
    {editor ? <div className="stack-small">
      <strong>{editor.file.path}</strong>
      <textarea className="input quick-ssh-editor" aria-label="文件内容" value={editor.text} disabled={busy}
        onChange={event => setEditor({ ...editor, text: event.target.value })} spellCheck={false} />
      <div className="button-row"><button className="btn btn-primary" disabled={busy}
        onClick={() => void perform(() => upload(editor.file.name, new Blob([editor.text]), editor.file))}>保存文件</button>
        <button className="btn btn-secondary" disabled={busy} onClick={() => setEditor(undefined)}>关闭编辑</button></div>
    </div> : <div className="table-wrap quick-ssh-list"><table className="data-table"><thead><tr><th>名称</th><th>大小</th><th>操作</th></tr></thead>
      <tbody>{entries.map(file => <tr key={file.path}>
        <td>{file.directory ? <button className="text-link quick-ssh-folder" disabled={busy}
          onClick={() => void perform(() => browse(file.path))}><Icon name="folder" size={16} />{file.name}</button> : file.name}</td>
        <td>{file.directory ? '—' : bytes(file.size)}</td>
        <td>{!file.directory && <div className="button-row">
          <button className="btn btn-secondary btn-small" disabled={busy} onClick={() => void perform(() => download(file, true))}>编辑</button>
          <button className="btn btn-secondary btn-small" disabled={busy} onClick={() => void perform(() => download(file, false))}>下载</button>
          <button className="btn btn-secondary btn-small" onClick={() => void navigator.clipboard.writeText(file.path).catch(() => setError('浏览器未允许复制路径。'))}>复制路径</button>
        </div>}</td>
      </tr>)}</tbody></table>
      {listing && !entries.length && <p className="muted">当前目录为空。</p>}
      {listing?.next_offset != null && <button className="btn btn-secondary" disabled={busy}
        onClick={() => void perform(() => browse(listing.path, listing.next_offset!))}>下一页</button>}
    </div>}
  </Panel>
}
