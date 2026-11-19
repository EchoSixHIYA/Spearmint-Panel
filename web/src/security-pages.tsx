import { useState, type FormEvent } from 'react'
import { ApiError, api, type Session, usePoll } from './api'
import { useConsole } from './console-data'
import { MeshOperations, type MeshService } from './mesh-operations'
import { LocalOperationHistory, OperationHistory, SavedRemoteOperation } from './operation-history'
import { Badge, CopyValue, EmptyState, Icon, Modal, Notice, PageHeading, Panel, Tabs } from './ui'
import { GroveCard } from './grove-auth'
import { savedRemoteOperationTarget } from './grove-navigation'

export function OperationsPage({ section }: { section?: string }) {
  const { admin } = useConsole()
  const receipt = admin && savedRemoteOperationTarget(location.hash)
  if (receipt) return <SavedRemoteOperation key={location.hash} {...receipt} />
  const tab = !admin || section === 'approvals' ? 'approvals' : section === 'local' ? 'local' : 'history'
  return <><PageHeading eyebrow="OPERATIONS / APPROVALS" title="操作与审批" description={admin
    ? '查看本机和远程服务的操作结果，或为受保护的服务申请独立签名审批。' : '为获准操作的服务申请独立签名审批，并查询执行回执。'} />
    {admin && <Tabs label="操作与审批" current={tab} onChange={(value) => {
      location.hash = value === 'history' ? '#/operations' : `#/operations/${value}`
    }} items={[{ id: 'history', label: '远程操作记录', icon: 'activity' }, { id: 'local', label: '本机操作记录', icon: 'clock' },
      { id: 'approvals', label: '独立签名审批', icon: 'shield-check' }]} />}
    {tab === 'history' ? <OperationHistory filter={section === 'pending' || section === 'review' ? section : 'recent'} />
      : tab === 'local' ? <LocalOperationHistory /> : <MeshOperations />}
  </>
}

export function AccessPage({ onFactors, expectedJoinNode }: { onFactors: () => void; expectedJoinNode?: string }) {
  const { session, admin, local, onUnauthorized, groveDetails, groveError, members, listedNodes, directoryCurrent,
    directoryLoading, memberPanelOrigins } = useConsole()
  const { data, error } = usePoll<MeshService[]>('/mesh/services', onUnauthorized)
  const factor = usePoll<{ eligible: boolean; grove_totp?: boolean }>('/auth/first-factor', onUnauthorized)
  const password = usePoll<{ available: boolean }>(session.grove ? '/auth/grove/password' : null, onUnauthorized)
  const [showPassword, setShowPassword] = useState(false)
  const [query, setQuery] = useState('')
  const joinTargetMatches = !local.error && local.data?.node_id === expectedJoinNode
  const visible = data?.filter((entry) => `${entry.name} ${entry.node_id}`.toLowerCase().includes(query.toLowerCase()))
    .map((entry) => ({ ...entry, stale: entry.stale || !!error }))
  return <><PageHeading eyebrow="SECURITY / IDENTITY" title="用户与授权" description="本机登录身份和跨节点操作授权各司其职，每项权限都有明确的边界。" />
    <div className="columns-2"><Panel title="我的本机身份"><div className="identity-profile"><span className="avatar-circle">{session.username.slice(0, 1).toUpperCase()}</span><div><strong>{session.display_name || session.username}</strong><p>{admin ? '节点管理员' : '远程操作员'}</p></div><Badge tone="sage">当前账户</Badge></div><dl className="facts"><div><dt>本机角色</dt><dd>{admin ? '管理本机与节点配置' : '操作授权的远程服务'}</dd></div><div><dt>所属节点</dt><dd>{local.data ? <CopyValue value={local.data.node_id} short /> : '读取中…'}</dd></div><div><dt>登录会话</dt><dd><a className="text-link" href="#/sessions">查看我的会话<Icon name="arrow-right" size={14} /></a></dd></div></dl></Panel>
      <Panel title="验证器与恢复"><span className="security-symbol"><Icon name="shield-check" size={28} /></span><h3>让访问始终掌握在你手中</h3><p className="muted">{factor.data?.grove_totp ? '用已有 Passkey 登录后，可为 Grove 成员侧登录添加动态验证码。' : factor.data?.eligible ? '首次登记可直接在网页扫码或创建 Passkey。完成后保存恢复码。' : '登记 Passkey 或动态验证码验证器，并离线保存恢复码。更换已有验证器需要近期身份验证与本机登记令牌。'}</p>{session.grove ? password.data?.available ? <button className="btn btn-secondary" onClick={() => setShowPassword(true)}><Icon name="key" size={16} />修改 Grove 密码</button> : <span className="muted">请在下方的 Grove 身份节点管理验证器。</span> : <button className="btn btn-secondary" onClick={onFactors}><Icon name="key" size={16} />{factor.data?.grove_totp ? '为 Grove 添加动态验证码' : factor.data?.eligible ? '设置登录验证' : '更换或添加验证器'}</button>}</Panel></div>
    {showPassword && <GrovePasswordDialog session={session} onClose={() => setShowPassword(false)} onUnauthorized={onUnauthorized} />}
    {expectedJoinNode && !admin ? <Notice tone="amber">请用目标机的本机管理员账号登录后继续加入 Grove。</Notice>
      : expectedJoinNode && !joinTargetMatches && <Notice tone="amber">
        {local.error ? '暂时无法核对播种回执中的节点身份。'
          : local.data ? '当前面板与播种回执中的 Node ID 不同。请回到播种页核对目标。' : '正在核对播种回执中的节点身份…'}
      </Notice>}
    {admin && (!expectedJoinNode || joinTargetMatches) && <GroveCard key={expectedJoinNode || 'access'} openJoin={!!expectedJoinNode}
      session={session} data={groveDetails} error={groveError} members={members} names={new Map(listedNodes.map(node => [node.id, node.name]))}
      directoryCurrent={directoryCurrent} directoryLoading={directoryLoading} memberPanelOrigins={memberPanelOrigins}
      onUnauthorized={onUnauthorized} />}
    <Panel title="我获准操作的远程服务" action={<a href="#/operations/approvals" className="panel-link">进入独立签名审批<Icon name="arrow-up-right" size={14} /></a>}>
      <label className="search-box"><Icon name="search" size={16} /><input aria-label="搜索授权服务" placeholder="搜索服务或节点…" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
      {error && <Notice tone="amber">{error}</Notice>}{visible?.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>服务</th><th>目标节点</th><th>允许操作</th><th>授权状态</th></tr></thead><tbody>{visible.map((entry) => <tr key={`${entry.node_id}/${entry.service_id}`}><td><strong>{entry.name}</strong></td><td><CopyValue value={entry.node_id} short /></td><td>{entry.actions.map((action) => ({ start: '启动', stop: '停止', restart: '重启' }[action])).join('、') || '仅历史回执'}</td><td><Badge tone={entry.stale ? 'amber' : 'green'}>{entry.stale ? '等待状态恢复' : entry.actions.length ? '可申请批准' : '只读记录'}</Badge></td></tr>)}</tbody></table></div> : <EmptyState icon="shield" title={data ? '暂无匹配的远程授权' : '正在读取授权范围'}>由独立授权方签发策略，并将本机账户绑定到对应的集群用户后，授权服务会显示在这里。</EmptyState>}
    </Panel>
    {admin && <Notice icon="terminal" title="本机账号管理">添加账号、调整角色或恢复丢失的验证器，需要在当前节点终端以运行账号完成。你的本机管理员角色不会自动转换为其他节点的操作权限。</Notice>}
  </>
}

export function GrovePasswordDialog({ session, onClose, onUnauthorized }: { session: Session; onClose: () => void; onUnauthorized: () => void }) {
  const [pending, setPending] = useState(false)
  const [message, setMessage] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const current = fields.get('current')
    const replacement = fields.get('replacement')
    if (replacement !== fields.get('confirmation')) { setMessage('两次输入的新密码不一致。'); return }
    setPending(true); setMessage('')
    try {
      await api('/auth/grove/password', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token },
        body: JSON.stringify({ current_password: current, new_password: replacement }) })
      location.hash = '#/signin'
      onUnauthorized()
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) onUnauthorized()
      else setMessage(error instanceof ApiError && error.code === 'REAUTHENTICATION_REQUIRED' ? '请用当前 Grove 密码和验证码重新登录，再修改密码。'
        : error instanceof ApiError && error.status === 403 ? '请核对当前密码和登录状态。' : '无法修改密码，请使用至少 12 个字符且不同的新密码。')
    } finally { setPending(false) }
  }

  return <Modal title="修改 Grove 密码" onClose={() => { if (!pending) onClose() }}>
    <form className="auth-form" onSubmit={event => void submit(event)}>
      <p>保存后本机旧会话会退出，其他成员同步后也会要求重新登录。</p>
      <label className="field-label">当前密码<input className="input" name="current" type="password" autoComplete="current-password" required maxLength={256} /></label>
      <label className="field-label">新密码<input className="input" name="replacement" type="password" autoComplete="new-password" required minLength={12} maxLength={256} /></label>
      <label className="field-label">确认新密码<input className="input" name="confirmation" type="password" autoComplete="new-password" required minLength={12} maxLength={256} /></label>
      {message && <p className="error" role="alert">{message}</p>}
      <button className="btn btn-primary" disabled={pending}>{pending ? '正在保存…' : '保存新密码'}</button>
    </form>
  </Modal>
}
