import { useEffect, useState, type FormEvent } from 'react'
import { ApiError } from './api'
import { refreshConsole, useConsole } from './console-data'
import { workspace, workspaceError } from './workspace-api'
import { Icon, Modal, Notice, StateBadge } from './ui'
import './service-groups.css'

export type GroupMember = { service_id: string; status_only: boolean }
type GroupOperation = { request_id: string; version: string; action: 'start' | 'stop'; status: string;
  completed: number; total: number; current_service_id: string | null; reason?: string }
export type ServiceGroup = { id: string; name: string; version: string; members: GroupMember[]; operation?: GroupOperation | null }
export type GroupTarget = { id: string; label: string; available: boolean;
  services: { id: string; name: string; actions: readonly string[] }[] }

function groupError(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === 'BUSY') return '此节点有整组操作正在执行，请等待回执。'
    if (error.code === 'CONFLICT') return /\p{Script=Han}/u.test(error.message) ? error.message : '服务组或成员状态已变化，请刷新后重试。'
  }
  return workspaceError(error)
}

export function ServiceGroupEditor({ targets, initialTarget, group, onClose }: {
  targets: GroupTarget[]; initialTarget: string; group?: ServiceGroup; onClose: () => void
}) {
  const { session, onUnauthorized } = useConsole()
  const [targetId, setTargetId] = useState(initialTarget)
  const [name, setName] = useState(group?.name || '')
  const [members, setMembers] = useState(group?.members || [])
  const [id] = useState(() => group?.id || crypto.randomUUID().replaceAll('-', ''))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const target = targets.find(item => item.id === targetId)
  const candidates = target?.services.filter(service => !members.some(member => member.service_id === service.id)) || []

  function add(serviceId: string) {
    const service = candidates.find(item => item.id === serviceId)
    if (service) setMembers([...members, { service_id: service.id, status_only: !service.actions.includes('start') }])
  }

  function move(index: number, offset: number) {
    const ordered = members.slice()
    const [member] = ordered.splice(index, 1)
    ordered.splice(index + offset, 0, member)
    setMembers(ordered)
  }

  async function save(event?: FormEvent, remove = false) {
    event?.preventDefault()
    if (busy || !target?.available || (!remove && (!name.trim() || !members.length))) return
    if (remove && !confirm(`解散「${group?.name}」？组内服务会保留。`)) return
    setBusy(true)
    setError('')
    try {
      await workspace(target.id, session, remove ? 'group-delete' : 'group-save', remove
        ? { id, version: group?.version } : { id, version: group?.version ?? null, name, members })
      refreshConsole()
      onClose()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(groupError(failure))
    } finally { setBusy(false) }
  }

  return <Modal title={group ? '编辑服务组' : '新建服务组'} onClose={() => { if (!busy) onClose() }} dismissOnEscape={!busy}>
    <form className="stack service-group-form" onSubmit={event => void save(event)}>
      {error && <Notice tone="amber">{error}</Notice>}
      <div className="service-group-fields">
        <label className="field-label">所属节点<select className="input" value={targetId} disabled={!!group || busy} onChange={event => {
          setTargetId(event.target.value)
          setMembers([])
        }}>{targets.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
        <label className="field-label">组名称<input className="input" required maxLength={80} value={name} disabled={busy}
          placeholder="输入服务组名称" onChange={event => setName(event.target.value)} /></label>
      </div>
      {target && !target.available && <Notice tone="amber">此节点的服务组暂时不可用。请核对节点连接和版本。</Notice>}
      {members.length > 0 && <div>
        <strong>启动顺序</strong>
        <p className="muted tiny">从上往下启动，前一项就绪后才继续。停止按相反顺序执行，状态成员会跳过。</p>
        <ol className="service-group-order">{members.map((member, index) => {
          const service = target?.services.find(item => item.id === member.service_id)
          const label = service?.name || '已取消登记的服务'
          return <li key={member.service_id}>
            <span className="service-group-member-name">{label}</span>
            <label className="service-group-observe"><input type="checkbox" checked={member.status_only}
              disabled={busy || !service?.actions.includes('start')}
              onChange={event => setMembers(members.map(item => item === member
                ? { ...item, status_only: event.target.checked } : item))} />仅显示状态</label>
            <div className="service-group-move">
              <button type="button" className="icon-button" title="上移" aria-label={`上移 ${label}`} disabled={busy || index === 0}
                onClick={() => move(index, -1)}><Icon name="chevron-down" size={15} className="service-group-up" /></button>
              <button type="button" className="icon-button" title="下移" aria-label={`下移 ${label}`} disabled={busy || index === members.length - 1}
                onClick={() => move(index, 1)}><Icon name="chevron-down" size={15} /></button>
              <button type="button" className="icon-button" title="从组中移除" aria-label={`从组中移除 ${label}`} disabled={busy}
                onClick={() => setMembers(members.filter(item => item !== member))}><Icon name="x" size={15} /></button>
            </div>
          </li>
        })}</ol>
      </div>}
      <label className="field-label">添加已登记服务<select className="input" value="" disabled={busy || !target?.available || !candidates.length}
        onChange={event => add(event.target.value)}>
        <option value="">{candidates.length ? '选择服务' : '没有更多可选服务'}</option>
        {candidates.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
      </select></label>
      <div className="modal-actions">
        {group && <button type="button" className="btn btn-secondary service-group-delete" disabled={busy || !target?.available}
          onClick={() => void save(undefined, true)}>解散服务组</button>}
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>取消</button>
        <button type="submit" className="btn btn-primary" disabled={busy || !target?.available || !name.trim() || !members.length}>
          {busy ? '保存中…' : '保存服务组'}</button>
      </div>
    </form>
  </Modal>
}

export function ServiceGroupActions({ group, target, onEdit }: { group: ServiceGroup; target: GroupTarget; onEdit: () => void }) {
  const { session, onUnauthorized } = useConsole()
  const [accepted, setAccepted] = useState<GroupOperation>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    if (accepted && (group.version !== accepted.version || group.operation?.request_id === accepted.request_id)) setAccepted(undefined)
  }, [accepted, group.operation?.request_id, group.version])
  const operation = group.operation?.request_id === accepted?.request_id ? group.operation : accepted ?? group.operation
  const current = operation?.version === group.version ? operation : undefined
  const blocked = !target.available || busy || current?.status === 'running'
  const canControl = group.members.some(member => !member.status_only)
  const memberName = target.services.find(service => service.id === current?.current_service_id)?.name
  const reason = current?.reason === 'SERVICE_NOT_READY' ? '成员未就绪，已停止后续操作'
    : current?.reason === 'PANEL_RESTARTED' ? '面板重启，请核对组内服务状态'
    : current?.status === 'failed' ? '该成员操作失败，已停止后续操作'
    : current?.status === 'uncertain' ? '回执待确认，请核对组内服务状态' : undefined

  async function run(action: 'start' | 'stop') {
    const label = action === 'start' ? '启动' : '停止'
    if (blocked || !confirm(`${label}「${group.name}」？`)) return
    setBusy(true)
    setError('')
    try {
      setAccepted(await workspace<GroupOperation>(target.id, session, 'group-run', {
        id: group.id, version: group.version, action, request_id: crypto.randomUUID().replaceAll('-', ''),
      }))
      refreshConsole()
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(groupError(failure))
    } finally { setBusy(false) }
  }

  return <div className="service-group-actions">
    <div className="service-action-icons">
      <button type="button" className="icon-button" disabled={blocked || !canControl} title="启动整组"
        aria-label={`启动整组 ${group.name}`} onClick={() => void run('start')}><Icon name="play" size={16} /></button>
      <button type="button" className="icon-button service-action-stop" disabled={blocked || !canControl} title="停止整组"
        aria-label={`停止整组 ${group.name}`} onClick={() => void run('stop')}><Icon name="stop" size={16} /></button>
      <button type="button" className="icon-button" disabled={blocked} title="编辑服务组"
        aria-label={`编辑服务组 ${group.name}`} onClick={onEdit}><Icon name="settings" size={16} /></button>
    </div>
    {current && <span className="service-group-progress" role="status"><StateBadge state={current.status} />
      {current.completed}/{current.total}{memberName && ` · ${memberName}`}{reason && ` · ${reason}`}</span>}
    {error && <span className="service-group-progress" role="alert">{error}</span>}
  </div>
}
