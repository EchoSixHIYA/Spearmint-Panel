import { useState } from 'react'
import { ApiError } from './api'
import { EmptyState, Icon, Modal, Notice, Panel } from './ui'
import { workspaceError } from './workspace-api'

export type AccessLink = { label: string; url: string }
type SavedLinks = { links: AccessLink[]; version: number }
type DraftLink = AccessLink & { id: string }
const maxLinks = 8

function webAddress(value: string) {
  if (!/^https?:\/\//i.test(value) || /[\s\\]/.test(value)) return undefined
  try {
    const address = new URL(value)
    if (address.hostname && !address.username && !address.password) return address.href
  } catch { /* An incomplete or invalid URL cannot be opened. */ }
}

function draftLink(link: AccessLink = { label: '', url: '' }): DraftLink {
  return { ...link, id: crypto.randomUUID() }
}

export function ServiceAccessLinks({ links, version, canEdit, onSave }: {
  links?: AccessLink[]; version: number; canEdit: boolean
  onSave: (links: AccessLink[], version: number) => Promise<SavedLinks>
}) {
  const [saved, setSaved] = useState<SavedLinks>()
  const [draft, setDraft] = useState<{ rows: DraftLink[]; version: number }>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const current = saved && saved.version > version ? saved : { links: links ?? [], version }
  const supported = links !== undefined

  function edit() {
    setError('')
    setDraft({ version: current.version, rows: current.links.length ? current.links.map(item => draftLink(item)) : [draftLink()] })
  }
  async function save() {
    if (!draft || busy) return
    const values = draft.rows.map(({ label, url }) => ({ label: label.trim(), url: url.trim() }))
    if (values.some(link => !link.label || !webAddress(link.url))) {
      setError('请填写链接名称和完整的 HTTP 或 HTTPS 地址。')
      return
    }
    setError('')
    setBusy(true)
    try {
      const result = await onSave(values, draft.version)
      setSaved(result)
      setDraft(undefined)
    } catch (failure) {
      setError(failure instanceof ApiError && failure.code === 'CONFLICT'
        ? '服务信息已变更。请关闭编辑，再打开以读取最新链接。'
        : workspaceError(failure))
    } finally {
      setBusy(false)
    }
  }
  function changeRow(id: string, field: keyof AccessLink, value: string) {
    setDraft(previous => previous && { ...previous, rows: previous.rows.map(row => row.id === id ? { ...row, [field]: value } : row) })
  }
  return <Panel title="访问链接" action={supported && <button type="button" className="btn btn-secondary btn-small"
    disabled={!canEdit} onClick={edit}>{current.links.length ? '编辑链接' : '添加链接'}</button>}>
    {!supported ? <Notice tone="amber">升级所属节点后即可配置访问链接。</Notice>
      : current.links.length ? <ul className="service-links-list">{current.links.map(({ label, url }, index) => {
        const href = webAddress(url)
        return <li key={index}><div><strong>{label}</strong><small>{url}</small></div>
          {href && <a className="btn btn-secondary btn-small" href={href} target="_blank" rel="noopener noreferrer"
            aria-label={`打开 ${label}（新标签页）`}>打开<Icon name="arrow-up-right" size={14} /></a>}</li>
      })}</ul> : <EmptyState title="还没有访问链接">可添加用户面板、管理后台或 API 地址。</EmptyState>}
    {draft && <Modal title="编辑访问链接" className="service-links-modal" onClose={() => { if (!busy) setDraft(undefined) }}>
      <form onSubmit={event => { event.preventDefault(); void save() }}>
        <fieldset className="service-link-fields" disabled={busy}>
          {draft.rows.map((row, index) => <div className="service-link-editor-row" key={row.id}>
            <label className="field-label">名称<input className="input" value={row.label} maxLength={60} required
              placeholder="如 管理后台" onChange={event => changeRow(row.id, 'label', event.target.value)} /></label>
            <label className="field-label">地址<input className="input" type="url" value={row.url} maxLength={400} required
              placeholder="https://example.com/admin" onChange={event => changeRow(row.id, 'url', event.target.value)} /></label>
            <button type="button" className="icon-button" aria-label={row.label ? `移除 ${row.label}` : `移除第 ${index + 1} 个链接`}
              onClick={() => setDraft(previous => previous && { ...previous, rows: previous.rows.filter(item => item.id !== row.id) })}><Icon name="x" size={16} /></button>
          </div>)}
          <button type="button" className="btn btn-secondary btn-small" disabled={draft.rows.length >= maxLinks}
            onClick={() => setDraft(previous => previous && { ...previous, rows: [...previous.rows, draftLink()] })}>
            <Icon name="plus" size={14} />添加一项
          </button>
        </fieldset>
        {error && <div role="alert"><Notice tone="amber">{error}</Notice></div>}
        <div className="modal-actions"><button type="button" className="btn btn-secondary" disabled={busy}
          onClick={() => setDraft(undefined)}>取消</button><button type="submit" className="btn btn-primary" disabled={busy}>{busy ? '正在保存…' : '保存'}</button></div>
      </form>
    </Modal>}
  </Panel>
}
