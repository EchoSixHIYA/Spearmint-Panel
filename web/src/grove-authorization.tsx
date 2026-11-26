import { useState, type FormEvent } from 'react'
import { ApiError, api, type Session } from './api'
import { CopyValue, Modal, Notice } from './ui'

const scopes = [
  ['services', '远程服务管理'], ['terminal', '远程终端与文件'], ['deployment', '部署与更新服务代码'],
  ['seed', '节点播种'], ['accounts', 'Grove 账号管理'], ['identity', '角色与权限变更'],
  ['self', '绑定本人登录设备与恢复码'], ['voters', '调整投票资格'], ['updates', 'Grove 群组更新'], ['join', '批准指定节点加入'],
]

export function GroveAuthorizationDialog({ session, nodes, onClose, onUnauthorized, selfOnly = false }: {
  session: Session; nodes: { id: string; name: string }[]; onClose: () => void; onUnauthorized: () => void; selfOnly?: boolean
}) {
  const [request, setRequest] = useState<Record<string, unknown>>()
  const [selection, setSelection] = useState<string[]>(selfOnly ? ['self'] : [])
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<{ expires_at: number }>()
  const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setPending(true); setError('')
    try {
      if (!request) {
        const executor = String(form.get('seed_executor') || '')
        const joining = selection.includes('join') ? { node_id: String(form.get('node_id')).trim(), origin: String(form.get('origin')).trim() } : undefined
        setRequest(await api<Record<string, unknown>>('/grove/authorization/challenge', { method: 'POST', headers,
          body: JSON.stringify({ scopes: selection, seed_executor: executor || undefined, joining }) }))
      } else {
        const signed = String(form.get('authorization') || '').trim()
        try { JSON.parse(signed) } catch { throw new Error('请粘贴完整的授权文件内容。') }
        setResult(await api<{ expires_at: number }>('/grove/authorization', { method: 'POST', headers, body: signed }))
        window.dispatchEvent(new Event('spearmint:refresh'))
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(failure instanceof Error ? failure.message : '暂时无法验证授权。')
    } finally { setPending(false) }
  }

  function downloadRequest() {
    const path = URL.createObjectURL(new Blob([JSON.stringify(request, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = path
    link.download = 'grove-authorization-request.json'
    link.click()
    setTimeout(() => URL.revokeObjectURL(path), 1000)
  }

  return <Modal title="授权当前面板" onClose={onClose}>
    {result ? <div className="grove-account-form">
      <Notice tone="green">已授权，有效至 {new Date(result.expires_at * 1000).toLocaleTimeString()}。</Notice>
      <button className="btn btn-primary" onClick={onClose}>完成</button>
    </div> : <form className="grove-account-form" onSubmit={submit}>
      {!request ? <>
        <p>选择允许当前面板执行的操作。授权由你持有的独立密钥签发，有效期 5 分钟。</p>
        <div className="grove-authorization-scopes">{scopes.filter(([id]) => !selfOnly || id === 'self').map(([id, name]) =>
          <label key={id}><input type="checkbox" checked={selection.includes(id)} onChange={event =>
            setSelection(event.target.checked ? [...selection, id] : selection.filter(item => item !== id))} />{name}</label>)}</div>
        {selection.includes('seed') && <label className="field-label">播种发起节点<select className="input" name="seed_executor">
          <option value="">当前面板</option>{nodes.map(node => <option key={node.id} value={node.id}>{node.name}</option>)}
        </select></label>}
        {selection.includes('join') && <>
          <label className="field-label">待加入节点标识<input className="input" name="node_id" maxLength={69} required /></label>
          <label className="field-label">待加入节点 HTTPS 地址<input className="input" name="origin" type="url" maxLength={512} required /></label>
        </>}
      </> : <>
        <button type="button" className="btn btn-secondary" onClick={downloadRequest}>下载授权请求</button>
        <div className="grove-account-secret"><strong>当前面板标识</strong><CopyValue value={String(request.source)} /></div>
        <p>在持有独立密钥的设备上签名。{selection.includes('join') ? '节点加入时，使用为该节点签名的授权。' : '签名后将授权文件内容粘贴到下方。'}</p>
        <label className="field-label">签名授权<textarea className="input" name="authorization" maxLength={32768} autoComplete="off" required /></label>
      </>}
      {error && <Notice tone="red">{error}</Notice>}
      <div className="button-row">
        {request && <button type="button" className="btn btn-secondary" onClick={() => { setRequest(undefined); setError('') }}>重新选择</button>}
        <button className="btn btn-primary" disabled={pending || !selection.length}>
          {pending ? '正在核对…' : request ? '验证授权' : '生成授权请求'}
        </button>
      </div>
    </form>}
  </Modal>
}
