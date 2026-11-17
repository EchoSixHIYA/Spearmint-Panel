import { useState } from 'react'
import { ApiError, api } from './api'
import { isQuorumInvitation, isSignedGroveInvitation, MAX_GROVE_INVITATION_LENGTH, type GroveRealm } from './grove-invitation'
import { CopyValue, Icon } from './ui'

export function CopyGroveInvitation({ small = false }: { small?: boolean }) {
  const [status, setStatus] = useState<'loading' | 'copied' | 'manual' | 'failed'>()
  const [code, setCode] = useState('')
  const [error, setError] = useState('')

  async function copy() {
    setStatus('loading')
    let result: { code: string }
    try {
      result = await api<{ code: string }>('/grove/browser-invitation')
      setCode(result.code)
    } catch (failure) {
      const reason = failure instanceof ApiError ? failure.code : undefined
      setError(reason === 'GROVE_SIGNER_UPGRADE_REQUIRED'
        ? '当前 Grove 尚未启用多数接管。请升级原签发节点，或在完成多数交接后生成邀请码。'
        : reason === 'GROVE_SIGNER_REQUIRED'
          ? '当前 Grove 尚未启用多数接管，原签发节点的签发服务当前不可用。'
          : reason === 'GROVE_QUORUM_UNAVAILABLE'
            ? '多数成员授权暂时不可用，请等待续期后重新生成邀请码。'
            : '暂时无法生成邀请码，请稍后重试。')
      setStatus('failed')
      return
    }
    try {
      await navigator.clipboard.writeText(result.code)
      setStatus('copied')
    } catch {
      setStatus('manual')
    }
  }

  return <div className="grove-invitation-copy">
    <button type="button" className={`btn btn-secondary${small ? ' btn-small' : ''}`} disabled={status === 'loading'} onClick={() => void copy()}>
      <Icon name={status === 'copied' ? 'check' : 'copy'} size={16} />
      {status === 'copied' ? '已复制邀请代码' : status === 'loading' ? '正在生成邀请…' : '复制邀请代码'}
    </button>
    {status === 'failed' && <p className="error" role="alert">{error}</p>}
    {status === 'manual' && <label className="field-label">
      浏览器无法写入剪贴板，请手动复制
      <textarea className="input grove-invitation-code" rows={3} readOnly value={code} onFocus={(event) => event.currentTarget.select()} />
    </label>}
  </div>
}
export function GroveInvitationField({ code, realm, disabled, onChange }: {
  code: string; realm?: GroveRealm; disabled: boolean; onChange: (code: string) => void
}) {
  const invalid = Boolean(code.trim() && !realm && !isSignedGroveInvitation(code) && !isQuorumInvitation(code))
  return <div className="stack-small">
    <label className="field-label">邀请代码
      <textarea className="input grove-invitation-code" placeholder="粘贴从已有 Grove 复制的邀请代码"
        value={code} onChange={(event) => onChange(event.target.value)} maxLength={MAX_GROVE_INVITATION_LENGTH}
        rows={3} disabled={disabled} aria-invalid={invalid} autoComplete="off" spellCheck={false} />
    </label>
    {invalid && <p className="error" role="alert">邀请代码有误，请从已有 Grove 重新复制完整代码。</p>}
    {realm && <dl className="facts">
      <div><dt>Grove</dt><dd>{realm.name}</dd></div>
      <div><dt>稳定身份</dt><dd><CopyValue value={realm.id} short /></dd></div>
    </dl>}
  </div>
}
