import { useCallback, useEffect, useEffectEvent, useRef, useState } from 'react'
import { useConsole, refreshConsole, type NodeInfo, type NodeView } from './console-data'
import { ApiError, api, READ_TIMEOUT_MS, timestamp, usePoll } from './api'
import { pathLabel, reachabilityReports } from './connection-status'
import { DeploymentReportPanel } from './deployment-report-panel'
import { reportCandidate } from './deployment-report'
import { useGroveDirectorySync } from './grove-auth'
import { compareMemberDirectories, memberDirectoryDifferences, type DirectoryMember, type MemberDirectoryVersion } from './grove-directory'
import { compareDeploymentEvidence, deploymentWebDifference, MAX_BROWSER_ARCHIVE_SIZE, matchesUpgradePreflight, packageCandidate, parseDeploymentManifest, parseUpgradePreflight,
  parseUpgradeRecoveryStatus, recoveryPackageMismatch, recoveryStatusPrefix, releaseCompatibility, releaseDeploymentStatus, releaseInstallerCommand, releaseRecoveryCommand, releaseRolloutStatus, rolloutLabels, verifyReleaseArchive,
  upgradeRecoveryOrigin, type DeploymentHost, type PackageManifest, type ReleaseCandidate, type UpgradePreflight, type UpgradeRecoveryStatus } from './release-compatibility'
import { CopyValue, Icon, Modal, NodeConnectionBadge, Notice, PageHeading, Panel, shortId } from './ui'

const webStatus = {
  ready: '入口资源齐全',
  'missing-entry': '缺少前端入口文件',
  unbuilt: '前端入口未引用构建后的脚本',
  'missing-assets': '前端入口引用的资源缺失',
  unreadable: '无法读取前端入口或资源',
}

const comparisonLabels = {
  matched: '与当前节点一致', different: '与当前节点有差异', unhealthy: '该节点的前端检查异常', unverified: '证据不足',
}

const directoryComparisonLabels = {
  matched: '版本与成员均一致', 'same-members': '版本不同，成员一致', different: '成员有差异', unverified: '待确认',
}

type WebBundle = { status: keyof typeof webStatus; build: string | null; package_match?: boolean | null; package_web_sha256?: string | null }
type Deployment = { node_id: string; origin: string; build: NonNullable<NodeInfo['build']>; web: WebBundle;
  host?: DeploymentHost | null; connection_id?: string; member_directory?: MemberDirectoryVersion | null; package_checksums_sha256?: string }
type LocalDeploymentSample = WebBundle & { deployment?: Pick<Deployment, 'node_id' | 'origin' | 'build' | 'host' | 'package_checksums_sha256'> }
type Member = { id: string; name: string; origin?: string; eligible: boolean; connectionId?: string;
  mesh: Pick<NodeView, 'status' | 'activePath' | 'observations'> }
type Result = { origin?: string; requestedConnectionId?: string; receivedAt: number;
  state: Deployment | 'unsupported' | 'unavailable' | 'route-changed' }
type ReportSource = { node_id?: string; received_at?: string; build?: NodeInfo['build']; host?: DeploymentHost | null; web?: WebBundle;
  browser_web_build?: string; member_directory?: MemberDirectoryVersion; package_checksums_sha256?: string;
  directory_members?: DirectoryMember[];
  candidate_status?: ReturnType<typeof releaseRolloutStatus> }

function saveDeploymentReport(generatedAt: Date, source: ReportSource, groveId?: string, candidate?: ReleaseCandidate,
  nodes: object[] = []) {
  const { directory_members, ...metadata } = source
  const directoryCurrent = (source.member_directory?.valid_until ?? 0) * 1000 > generatedAt.getTime()
  const report = { version: 1, grove_id: groveId, generated_at: generatedAt.toISOString(),
    source: directoryCurrent && directory_members ? source : metadata,
    candidate: candidate && reportCandidate(candidate), nodes }
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + '\n'], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `spearmint-deployment-report-${generatedAt.toISOString().replace(/[:.]/g, '-')}.json`
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

// Leave time for the target's periodic Grove synchronization before the second read.
const DIRECTORY_RECHECK_DELAY_MS = 25_000
const candidateStorageKey = 'spearmint-deployment-candidate'
const manifestLimit = 1024 * 1024
const checksumLimit = 4096

type CandidateInput = { manifest: string; checksum?: string }

function loadCandidateInput(): CandidateInput | undefined {
  try {
    const saved = sessionStorage.getItem(candidateStorageKey)
    if (!saved || saved.length > 6 * (manifestLimit + checksumLimit) + 50) return
    const input = JSON.parse(saved)
    if (input && typeof input.manifest === 'string' && input.manifest.length <= manifestLimit
        && (input.checksum === undefined || typeof input.checksum === 'string' && input.checksum.length <= checksumLimit)) return input
  } catch { /* Storage is optional. */ }
}

function storeCandidateInput(input?: CandidateInput) {
  try {
    if (input) sessionStorage.setItem(candidateStorageKey, JSON.stringify(input))
    else sessionStorage.removeItem(candidateStorageKey)
  } catch { /* The candidate can still be used in the current view. */ }
}

export function DeploymentsPage({ targetId }: { targetId?: string }) {
  const { local, localName, webBuild, onUnauthorized, directoryCurrent, memberPanelOrigins, memberNodes, grove, groveDetails } = useConsole()
  const [candidate, setCandidate] = useState<ReleaseCandidate>()
  const [includeMembers, setIncludeMembers] = useState(false)
  const [packageManifest, setPackageManifest] = useState<PackageManifest>()
  const [manifestError, setManifestError] = useState('')
  const [receipts, setReceipts] = useState(new Map<string, UpgradePreflight>())
  const reading = useRef(0)
  const manifestInput = useRef<string | undefined>(undefined)
  useEffect(() => {
    const stored = loadCandidateInput()
    const request = ++reading.current
    if (stored) void parseDeploymentManifest(stored.manifest).then(value => {
      if (request !== reading.current) return
      if ('packages' in value) setCandidate(value)
      else {
        const restored = stored.checksum === undefined ? undefined : packageCandidate(value, stored.checksum)
        setPackageManifest(value)
        setCandidate(restored)
      }
      manifestInput.current = stored.manifest
    }).catch(() => { if (request === reading.current) storeCandidateInput() })
    return () => { reading.current += 1 }
  }, [])
  const web = usePoll<LocalDeploymentSample>('/node/web-bundle?include_deployment=true', onUnauthorized, 15_000)
  const response = web.error ? undefined : web.data
  const deployment = response?.deployment
  const info = local.error ? undefined : local.data
  const localNodeId = info?.node_id
  const newerBuild = deployment && info?.build && (info.build.commit !== deployment.build.commit
    || info.package_checksums_sha256 !== deployment.package_checksums_sha256)
    && (local.requestedAt ?? 0) > (web.requestedAt ?? 0)
  const sample = !newerBuild && deployment?.node_id === localNodeId && deployment?.origin === location.origin ? deployment : undefined
  const bundle = response && { status: response.status, build: response.build,
    package_match: response.package_match, package_web_sha256: response.package_web_sha256 }
  const build = sample?.build ?? info?.build
  const host = sample ? sample.host : info?.deployment_host
  const packageDigest = sample?.package_checksums_sha256
  const verifiedWeb = sample ? bundle : undefined
  const loadedBuild = webBuild === '开发模式' ? undefined : webBuild
  const localDirectory = directoryCurrent ? groveDetails?.member_directory : undefined
  const different = loadedBuild && bundle?.build && loadedBuild !== bundle.build
  const members = (memberNodes ?? []).filter(node => !node.local && node.id !== local.data?.node_id
    && (!targetId || node.id === targetId)).map(node => {
    const origin = memberPanelOrigins.get(node.id)
    return { id: node.id, name: node.name, origin, mesh: node, connectionId: node.status === 'online' ? node.peer?.connection_id : undefined,
      eligible: directoryCurrent && !!origin && node.peer?.enabled === true && node.peer.legacy === false
      && !['disabled', 'quarantined', 'unknown'].includes(node.status) }
  }).sort((a, b) => a.id.localeCompare(b.id))
  const scope = JSON.stringify([grove.data?.realm?.id, targetId, directoryCurrent])
  const reportSource: ReportSource = { node_id: localNodeId, build, host, web: verifiedWeb,
    received_at: sample && web.requestedAt !== undefined ? new Date(performance.timeOrigin + web.requestedAt).toISOString() : undefined,
    browser_web_build: loadedBuild, member_directory: localDirectory, package_checksums_sha256: packageDigest,
    directory_members: includeMembers && localDirectory && localNodeId && groveDetails?.realm ? groveDetails.members?.map(({ node_id, origin, enabled }) =>
      ({ node_id, origin, enabled })) : undefined,
    candidate_status: candidate && releaseRolloutStatus(candidate, host, build?.commit, verifiedWeb, packageDigest) }

  function clearCandidate() {
    reading.current += 1
    setManifestError('')
    setCandidate(undefined)
    setPackageManifest(undefined)
    setReceipts(new Map())
    manifestInput.current = undefined
    storeCandidateInput()
  }

  async function readManifest(file?: File) {
    if (!file) return
    clearCandidate()
    const request = reading.current
    try {
      if (file.size > manifestLimit) throw new Error('发布清单超过 1 MiB。')
      const manifest = await file.text()
      const value = await parseDeploymentManifest(manifest)
      if (request !== reading.current) return
      manifestInput.current = manifest
      storeCandidateInput({ manifest })
      if ('packages' in value) setCandidate(value)
      else setPackageManifest(value)
    } catch (error) {
      if (request === reading.current) setManifestError(error instanceof SyntaxError ? '无法读取发布清单 JSON。'
        : error instanceof Error ? error.message : '无法读取发布清单。')
    }
  }

  async function readChecksum(manifest: PackageManifest, file?: File) {
    const text = manifestInput.current
    if (!file || text === undefined) return
    const request = ++reading.current
    setManifestError('')
    setCandidate(undefined)
    setReceipts(new Map())
    storeCandidateInput({ manifest: text })
    try {
      if (file.size > checksumLimit) throw new Error('SHA-256 文件超过 4 KiB。')
      const checksum = await file.text()
      const value = packageCandidate(manifest, checksum)
      if (request !== reading.current) return
      setCandidate(value)
      storeCandidateInput({ manifest: text, checksum })
    } catch (error) {
      if (request === reading.current) setManifestError(error instanceof Error ? error.message : '无法读取 SHA-256 文件。')
    }
  }

  return <>
    {targetId && <a className="back-link" href="#/deployments"><Icon name="arrow-left" size={15} />查看全部节点版本</a>}
    <PageHeading eyebrow="SYSTEM / DEPLOYMENTS" title="应用部署" description={`查看 ${localName} 的面板版本和前端资源。`}>
      <button type="button" className="btn btn-secondary" onClick={refreshConsole}><Icon name="refresh" size={15} />刷新状态</button>
      {localDirectory && localNodeId && groveDetails?.realm && <label className="inline-checkbox"><input type="checkbox" checked={includeMembers}
        onChange={event => setIncludeMembers(event.target.checked)} />报告包含成员地址及启用状态</label>}
      <button type="button" className="btn btn-secondary" disabled={!sample || !verifiedWeb} onClick={() => {
        if (sample && verifiedWeb) saveDeploymentReport(new Date(), reportSource, groveDetails?.realm?.id, candidate)
      }}><Icon name="download" size={15} />下载本机核对报告</button>
    </PageHeading>
    <div className="columns-2">
      <Panel title="运行中的后端">
        {local.error && <Notice tone="amber">无法读取后端构建信息。{local.error}</Notice>}
        <dl className="facts">
          <div><dt>版本</dt><dd>{build?.version || (!local.data && !local.error ? '读取中…' : '未知')}</dd></div>
          <div><dt>运行方式</dt><dd>{build ? (build.runtime === 'native' ? '原生部署包' : 'Python 环境') : '未知'}</dd></div>
          <div><dt>构建提交</dt><dd>{build?.commit ? <CopyValue value={build.commit} short /> : '未知'}</dd></div>
          <div><dt>数据库 schema</dt><dd>{host?.schema ?? '未知'}</dd></div>
          {packageDigest && <div><dt>启动时的包内清单（SHA-256）</dt><dd><CopyValue value={packageDigest} short /></dd></div>}
          {local.data?.node_id && <div><dt>Node ID</dt><dd><CopyValue value={local.data.node_id} short /></dd></div>}
        </dl>
      </Panel>
      <Panel title="前端资源">
        <dl className="facts">
          <div><dt>浏览器已加载</dt><dd>{webBuild || '未知'}</dd></div>
          <div><dt>节点入口引用</dt><dd>{bundle?.build || (web.error || bundle ? '未知' : '读取中…')}</dd></div>
          <div><dt>节点资源状态</dt><dd>{bundle ? webStatus[bundle.status] : (web.error ? '无法读取' : '读取中…')}</dd></div>
          {build?.runtime === 'native' && <div><dt>原生包文件核对</dt><dd>{bundle?.package_match === true ? '与采样时的包内文件摘要一致'
            : bundle?.package_match === false ? '与采样时的包内文件摘要有差异'
              : bundle || web.error ? '无法核对' : '读取中…'}</dd></div>}
        </dl>
        {web.error && <Notice tone="amber">无法读取此节点的前端资源。{web.error}</Notice>}
        {response && !deployment && <Notice>本机面板未提供同一次读取的构建和前端校验结果，暂时无法导出本机报告。</Notice>}
        {newerBuild && <Notice>后端构建已更新，等待当前构建的前端校验结果。</Notice>}
        {different && <Notice tone="amber">浏览器加载的资源与节点当前入口不同。<button type="button"
          className="text-link" onClick={() => location.reload()}>重新加载页面</button></Notice>}
      </Panel>
    </div>
    <Panel title="核对部署包">
      <div className="stack">
        <label className="field-label">发布清单或原生包清单
          <input type="file" accept=".json,application/json" onChange={event => {
            const file = event.currentTarget.files?.[0]
            event.currentTarget.value = ''
            void readManifest(file)
          }} />
        </label>
        {packageManifest && <label className="field-label">选择 {packageManifest.archive}.sha256
          <input type="file" accept=".sha256,text/plain" onChange={event => {
            const file = event.currentTarget.files?.[0]
            event.currentTarget.value = ''
            void readChecksum(packageManifest, file)
          }} />
        </label>}
        {(candidate || packageManifest) && <div><button type="button" className="btn btn-secondary btn-small" onClick={clearCandidate}>清除候选清单</button></div>}
        {manifestError && <p role="alert" className="error">{manifestError}</p>}
        {candidate && <>
          <dl className="facts">
            <div><dt>候选版本</dt><dd>{candidate.version} · <CopyValue value={candidate.commit} short /></dd></div>
            <div><dt>数据库 schema</dt><dd>{candidate.schema}</dd></div>
            <div><dt>当前节点</dt><dd><CandidateCompatibility candidate={candidate}
              host={host} commit={build?.commit} web={verifiedWeb} packageDigest={packageDigest} nodeId={localNodeId} origin={location.origin}
              receipt={receipts.get(localNodeId ?? '')} /></dd></div>
          </dl>
          <CandidateArchives key={`archives:${JSON.stringify(candidate)}`} candidate={candidate} />
          <PreflightImport key={`preflight:${JSON.stringify(candidate)}`} candidate={candidate} onImport={receipt =>
            setReceipts(previous => new Map(previous).set(receipt.node_id, receipt))} />
        </>}
      </div>
    </Panel>
    <RecoveryStatusPanel candidate={candidate} receipts={receipts} />
    {targetId && !members.length && <Panel title="目标节点版本">
      <Notice>{targetId === local.data?.node_id ? '目标是当前节点，版本和前端状态见上方。'
        : directoryCurrent ? '当前 Grove 中没有可核对的目标节点。' : '正在等待当前 Grove 的成员目录。'}</Notice>
    </Panel>}
    {!!members.length && <GroveDeployments key={`members:${scope}`} members={members} directoryCurrent={directoryCurrent}
      reportSource={reportSource} candidate={candidate} receipts={receipts} singleTarget={!!targetId} />}
    <DeploymentReportPanel key={`reports:${scope}`} />
    <Panel title="部署入口">
      <div className="button-row">
        <a href="#/seeds" className="btn btn-primary">通过 SSH 播种<Icon name="arrow-right" size={15} /></a>
        <a href="#/nodes" className="btn btn-secondary">查看 Grove 节点</a>
      </div>
    </Panel>
  </>
}

function RecoveryStatusPanel({ candidate, receipts }: { candidate?: ReleaseCandidate; receipts: ReadonlyMap<string, UpgradePreflight> }) {
  const [input, setInput] = useState('')
  const [status, setStatus] = useState<UpgradeRecoveryStatus>()
  const [error, setError] = useState('')
  return <Panel title="中断升级恢复">
    <details>
      <summary>查看目标机的恢复记录</summary>
      <div className="stack-small">
        <p>在目标机以面板运行账号查询。Windows 如使用自定义安装目录或任务名，请沿用原来的参数。</p>
        <div><CopyValue value="sh deployment/install-linux.sh --upgrade-recovery-status" /></div>
        <div><CopyValue value={'.\\deployment\\install-windows.ps1 -UpgradeRecoveryStatus'} /></div>
        <form className="stack-small" onSubmit={event => {
          event.preventDefault()
          setError('')
          try {
            setStatus(parseUpgradeRecoveryStatus(input))
            setInput('')
          } catch (failure) {
            setStatus(undefined)
            setError(failure instanceof SyntaxError ? '恢复状态的 JSON 无法读取。'
              : failure instanceof Error ? failure.message : '无法读取恢复状态。')
          }
        }}>
          <label className="field-label">粘贴以 {recoveryStatusPrefix} 开头的一行
            <textarea className="input" rows={3} maxLength={8192} value={input} onChange={event => {
              setInput(event.target.value); setStatus(undefined); setError('')
            }} />
          </label>
          <div><button type="submit" className="btn btn-secondary" disabled={!input.trim()}>读取恢复状态</button></div>
        </form>
        {error && <p role="alert" className="error">{error}</p>}
        {status && <div className="stack-small" aria-live="polite">
          {'busy' in status ? <Notice tone="amber">目标机的安装器正在运行。请等它退出后重新查询恢复状态。</Notice>
            : status.pending ? <>
            <dl className="facts">
              <div><dt>目标 Node ID</dt><dd>{status.node_id ? <CopyValue value={status.node_id} short /> : '旧记录未包含节点身份'}</dd></div>
              <div><dt>将恢复到的提交</dt><dd><CopyValue value={status.previous_commit} short /></dd></div>
              <div><dt>执行恢复所需的包提交</dt><dd><CopyValue value={status.candidate_commit} short /></dd></div>
              {status.origin && <div><dt>目标 HTTPS 地址</dt><dd><CopyValue value={status.origin} /></dd></div>}
              {status.schema !== undefined && <div><dt>数据库 schema</dt><dd>{status.schema}</dd></div>}
              {status.target && <div><dt>目标平台</dt><dd>{status.target}</dd></div>}
              {status.package_checksums_sha256 && <div><dt>包内文件清单（SHA-256）</dt><dd><CopyValue value={status.package_checksums_sha256} short /></dd></div>}
              <div><dt>升级前的面板状态</dt><dd>{status.panel_was_running ? '运行中' : '已停止'}</dd></div>
            </dl>
            {!candidate ? <p>请选择恢复记录所列提交的包清单。</p>
              : candidate.commit !== status.candidate_commit ? <Notice tone="amber">所选清单的提交与恢复记录不一致。</Notice>
                : <RecoveryCommand key={JSON.stringify([candidate, status])} candidate={candidate} status={status}
                  receipt={status.node_id ? receipts.get(status.node_id) : undefined} />}
          </> : <p>这次查询没有发现待恢复的升级记录。</p>}
        </div>}
      </div>
    </details>
  </Panel>
}

function RecoveryCommand({ candidate, status, receipt }: {
  candidate: ReleaseCandidate; status: Extract<UpgradeRecoveryStatus, { pending: true }>; receipt?: UpgradePreflight
}) {
  const [selection, setSelection] = useState(candidate.singlePackage ? candidate.packages[0].target : '')
  const reportedTarget = status.target ?? (status.origin === undefined ? receipt?.target : undefined)
  const target = reportedTarget ?? selection
  if (!status.node_id) return <p>旧记录缺少 Node ID。请在目标机沿用原安装参数，按包内部署说明执行恢复。</p>
  if (!upgradeRecoveryOrigin(candidate, status, receipt)) return status.origin
    ? <Notice tone="amber">所选清单的数据库 schema 与恢复记录不一致。</Notice>
    : <p>旧记录缺少 HTTPS 地址。请在「核对部署包」导入本次中断升级的预检回执，或按包内部署说明在目标机恢复。</p>
  const recovery = releaseRecoveryCommand(candidate, status, target, receipt)
  const packageMismatch = recoveryPackageMismatch(candidate, status, target)
  if (reportedTarget && !recovery && !packageMismatch) {
    return <Notice tone="amber">所选清单或预检回执与目标平台 {reportedTarget} 不符。</Notice>
  }
  return <div className="stack-small">
    {!reportedTarget && <label className="field-label">目标平台
      <select className="input" value={selection} onChange={event => setSelection(event.target.value)}>
        <option value="">选择目标机的平台</option>
        {candidate.packages.map(bundle => <option key={bundle.target} value={bundle.target}>{bundle.target}</option>)}
      </select>
    </label>}
    {packageMismatch && <Notice tone="amber">所选原生包的摘要与恢复记录不符。请选择中断升级时使用的归档清单。</Notice>}
    {recovery && <>
      <p>校验下列归档后，以目标机的面板运行账号在解包目录执行。若原安装使用自定义任务、目录或监听参数，请沿用原参数。</p>
      <CopyValue value={recovery.bundle.archive} />
      <CopyValue value={recovery.bundle.sha256} short />
      <CopyValue value={recovery.command} />
    </>}
  </div>
}

function CandidateArchives({ candidate }: { candidate: ReleaseCandidate }) {
  const [checked, setChecked] = useState<Record<string, 'match' | 'mismatch'>>({})
  const [checking, setChecking] = useState<string>()
  const [error, setError] = useState('')
  const busy = useRef(false)

  async function checkArchive(file?: File) {
    if (!file || busy.current) return
    setError('')
    const bundle = candidate.packages.find(item => item.archive === file.name)
    if (!bundle) {
      setError('所选文件名不在此发布清单中。')
      return
    }
    busy.current = true
    setChecking(bundle.archive)
    setChecked(previous => {
      const next = { ...previous }
      delete next[bundle.archive]
      return next
    })
    try {
      const match = await verifyReleaseArchive(bundle, file)
      setChecked(previous => ({ ...previous, [bundle.archive]: match ? 'match' : 'mismatch' }))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : '无法读取归档。')
    } finally {
      busy.current = false
      setChecking(undefined)
    }
  }

  return <div className="stack-small">
    <label className="field-label">选择归档核对 SHA-256
      <input type="file" accept=".zip,.gz" disabled={!!checking} onChange={event => {
        const file = event.currentTarget.files?.[0]
        event.currentTarget.value = ''
        void checkArchive(file)
      }} />
    </label>
    <p className="muted">清单和归档在浏览器中读取。超过 {MAX_BROWSER_ARCHIVE_SIZE / (1024 * 1024)} MiB 的归档可用命令行核对。</p>
    {error && <p role="alert" className="error">{error}</p>}
    <dl className="facts" aria-live="polite">
      {candidate.packages.map(bundle => <div key={bundle.target}>
        <dt>{bundle.target}</dt>
        <dd>{checking === bundle.archive ? '正在计算 SHA-256…' : checked[bundle.archive] === 'match' ? 'SHA-256 与清单一致'
          : checked[bundle.archive] === 'mismatch' ? 'SHA-256 与清单不一致' : '尚未核对'}</dd>
      </div>)}
    </dl>
    <p className="muted">维护前，用包内安装器预检目标机的运行配置和备份。</p>
  </div>
}

function PreflightImport({ candidate, onImport }: { candidate: ReleaseCandidate; onImport: (receipt: UpgradePreflight) => void }) {
  const [input, setInput] = useState('')
  const [error, setError] = useState('')
  const [imported, setImported] = useState(false)
  return <details>
    <summary>导入安装器预检回执</summary>
    <form className="stack-small" onSubmit={event => {
      event.preventDefault()
      setError('')
      setImported(false)
      try {
        const receipt = parseUpgradePreflight(input)
        if (receipt.candidate_commit !== candidate.commit || receipt.schema !== candidate.schema) {
          throw new Error('预检回执与当前候选提交或 schema 不符。')
        }
        if (receipt.target && !candidate.packages.some(bundle => bundle.target === receipt.target)) {
          throw new Error('所选清单没有预检回执对应的平台包。')
        }
        const expected = candidate.packages.find(bundle => bundle.target === receipt.target)?.checksumsSha256
        if (expected && receipt.package_checksums_sha256 && expected !== receipt.package_checksums_sha256) {
          throw new Error('预检使用的原生包与所选清单不符。请用对应归档重新预检。')
        }
        onImport(receipt)
        setImported(true)
        setInput('')
      } catch (failure) {
        setError(failure instanceof SyntaxError ? '预检回执的 JSON 无法读取。'
          : failure instanceof Error ? failure.message : '无法读取预检回执。')
      }
    }}>
      <label className="field-label">粘贴以 SPEARMINT_UPGRADE_PREFLIGHT= 开头的一行
        <textarea className="input" rows={3} maxLength={8192} value={input}
          onChange={event => { setInput(event.target.value); setError(''); setImported(false) }} />
      </label>
      <div><button type="submit" className="btn btn-secondary" disabled={!input.trim()}>导入回执</button></div>
      {error && <p role="alert" className="error">{error}</p>}
      {imported && <p role="status">已导入此节点的终端回执。可在对应节点的兼容性结果中查看核对情况。</p>}
    </form>
  </details>
}

function CandidateCompatibility({ candidate, host, commit, web, packageDigest, nodeId, origin, receipt }: {
  candidate: ReleaseCandidate; host?: DeploymentHost | null; commit?: string | null; nodeId?: string; origin?: string;
  web?: WebBundle; packageDigest?: string; receipt?: UpgradePreflight
}) {
  const result = releaseCompatibility(candidate, host, commit)
  const deployment = releaseDeploymentStatus(candidate, host, commit, web, packageDigest)
  const [backup, setBackup] = useState<{ scope: string; path: string }>()
  const [maintenance, setMaintenance] = useState<{ scope: string; keepStopped: boolean }>()
  const backupScope = JSON.stringify([nodeId, origin, commit, candidate.commit, host?.target, host?.schema, result.bundle?.sha256])
  const backupPath = backup?.scope === backupScope ? backup.path : ''
  const receiptMatches = receipt && matchesUpgradePreflight(receipt, candidate, host, nodeId, origin, commit)
  const keepStopped = maintenance?.scope === backupScope ? maintenance.keepStopped : !!receiptMatches && receipt?.keep_stopped === true
  const modeMatches = receiptMatches && (receipt.keep_stopped === true) === keepStopped
  const canPreflight = releaseInstallerCommand(candidate, host, nodeId, origin, commit)
  const command = releaseInstallerCommand(candidate, host, nodeId, origin, commit, undefined, backupPath, keepStopped)
  const packageMismatch = receipt?.package_checksums_sha256 && result.bundle?.checksumsSha256
    && receipt.package_checksums_sha256 !== result.bundle.checksumsSha256
  const upgrade = receipt && releaseInstallerCommand(candidate, host, nodeId, origin, commit, receipt, backupPath, keepStopped)
  const labels = {
    unknown: '节点未报告平台或数据库 schema', unsupported: '所选清单没有此平台的原生包',
    migration: '需迁移数据库', restore: '回退需恢复兼容备份', 'same-build': '已运行同一构建',
    compatible: '平台与 schema 匹配，可执行安装器预检',
  }
  const deploymentLabels = {
    'host-mismatch': '节点已报告候选提交，平台或 schema 与清单不符',
    'package-mismatch': 'Git 提交相同，运行的原生包清单与候选不符',
    'web-mismatch': '后端已切换到候选提交，节点前端资源核对未通过',
    'awaiting-web': '后端已切换到候选提交，等待核对平台、schema 和前端文件',
    'awaiting-package': '构建和前端已核对，节点尚未报告包内文件清单摘要',
    matched: result.bundle?.checksumsSha256 ? '构建、平台、schema、原生包清单和前端均与候选匹配'
      : '构建、平台、schema 和前端文件摘要均与候选匹配',
  }
  const awaitingRead = deployment === 'awaiting-web' && !web
  return <div className="stack-small">
    <span>{awaitingRead ? '后端已切换到候选提交，尚未读取前端状态'
      : deployment ? deploymentLabels[deployment] : labels[result.status]}</span>
    {host && <small className="muted">节点 schema {host.schema}{host.target ? ` · ${host.target}` : ''}</small>}
    {result.bundle && <div className="break-anywhere"><CopyValue value={result.bundle.archive} />
      <CopyValue value={result.bundle.sha256} short /></div>}
    {receipt && !deployment && (receiptMatches
      ? <p>终端回执显示预检通过 · {receipt.panel_running ? '预检时面板运行中' : '预检时面板已停止'}{receipt.keep_stopped && ' · 升级后保持停止'} · {receipt.backup_verified ? '备份已核验' : '未核验备份'}</p>
      : <p className="muted">{packageMismatch ? '预检使用的原生包与所选清单不符。请用对应归档重新预检。'
        : '导入的回执与节点当前状态不符。请刷新节点状态或重新预检。'}</p>)}
    {receiptMatches && receipt.backup_sha256 && <div>备份指纹（SHA-256） <CopyValue value={receipt.backup_sha256} short /></div>}
    {receiptMatches && receipt.package_checksums_sha256 && <div>预检包内文件清单（SHA-256） <CopyValue value={receipt.package_checksums_sha256} short /></div>}
    {receiptMatches && (!result.bundle?.checksumsSha256 || !receipt.package_checksums_sha256) &&
      <p className="muted">当前清单或回执缺少包内文件清单摘要。请核对所用归档的 SHA-256。</p>}
    {canPreflight && <details>
      <summary>复制目标机预检命令</summary>
      <p>核对归档后，以面板运行账号在新版解包目录执行。Windows 需沿用原安装时的任务、目录和监听参数。</p>
      {result.bundle?.checksumsSha256 && <p>命令会先核对解包目录中的包内文件清单。</p>}
      <label className="inline-checkbox"><input type="checkbox" checked={keepStopped}
        onChange={event => setMaintenance({ scope: backupScope, keepStopped: event.target.checked })} />升级后保持停止</label>
      {keepStopped && <p className="muted">先停止目标面板，再执行此预检。需要支持保持停止的新版安装器。</p>}
      <label className="field-label">目标机的备份目录（可选）
        <input className="input" value={backupPath}
          placeholder={host?.target === 'windows-amd64' ? 'D:\\pre-upgrade-backup' : '/path/to/pre-upgrade-backup'}
          onChange={event => setBackup({ scope: backupScope, path: event.target.value })} />
      </label>
      {command ? <CopyValue value={command} /> : <p role="alert" className="error">请输入目标机上的绝对备份路径。</p>}
    </details>}
    {receiptMatches && !modeMatches && <p>预检回执与当前所选运行方式不符。请执行上面的预检命令并导入新回执。</p>}
    {modeMatches && receipt.backup_verified && !backupPath && <p>请在「复制目标机预检命令」中填入预检时使用的备份路径，生成升级命令。</p>}
    {upgrade && <details>
      <summary>复制目标机升级命令</summary>
      <p>在维护窗口执行，并沿用预检时的安装参数。{receipt?.backup_sha256
        ? '安装器会在切换前核对这份备份的 SHA-256。' : backupPath && '安装器切换版本前会再次核验所填备份。'}</p>
      {receipt?.package_checksums_sha256 && <p>安装器会核对包内文件清单是否与预检时一致。</p>}
      {keepStopped && <p>切换完成后，手动启动目标面板并检查首页。</p>}
      <CopyValue value={upgrade} />
    </details>}
  </div>
}

function GroveDeployments({ members, directoryCurrent, reportSource, candidate, receipts, singleTarget }: {
  members: Member[]; directoryCurrent: boolean; reportSource: ReportSource; candidate?: ReleaseCandidate;
  receipts: ReadonlyMap<string, UpgradePreflight>; singleTarget: boolean
}) {
  const { onUnauthorized, members: localMembers, listedNodes, groveDetails } = useConsole()
  const { build: localBuild, host: localHost, web: localWeb, member_directory: localDirectory,
    package_checksums_sha256: localPackageDigest } = reportSource
  const localCommit = localBuild?.commit
  const localSchema = localHost?.schema
  const names = new Map(listedNodes.map(node => [node.id, node.name]))
  const [results, setResults] = useState(new Map<string, Result>())
  const [checkedAt, setCheckedAt] = useState<number>()
  const [checking, setChecking] = useState<ReadonlySet<string>>()
  const [details, setDetails] = useState<{ id: string; origin?: string; connectionId?: string }>()
  const [pendingOnly, setPendingOnly] = useState(false)
  const active = useRef<AbortController | null>(null)
  const directoryRechecks = useRef(new Map<string, { key: string; retryAfter?: number }>())
  const eligible = members.filter(node => node.eligible)
  useEffect(() => () => active.current?.abort(), [])
  const [clock, setClock] = useState(Date.now)
  const now = Math.max(clock, Date.now())
  const nextExpiry = Math.min(...[...results.values()].flatMap(({ state }) => {
    const expiry = typeof state === 'object' ? (state.member_directory?.valid_until ?? 0) * 1000 : 0
    return expiry > now ? [expiry] : []
  }))
  useEffect(() => {
    if (!Number.isFinite(nextExpiry)) return
    const timeout = setTimeout(() => setClock(Date.now()), Math.max(0, Math.min(nextExpiry - Date.now(), 2 ** 31 - 1)))
    return () => clearTimeout(timeout)
  }, [nextExpiry])

  const counts = { matched: 0, different: 0, unhealthy: 0, unverified: 0 }
  const rollout = { matched: 0, 'not-installed': 0, migration: 0, restore: 0, mismatch: 0, unverified: 0, unsupported: 0 }
  const rows = members.map(node => {
    const saved = results.get(node.id)
    const sample = saved?.origin === node.origin ? saved?.state : undefined
    const result = node.eligible && typeof sample === 'object' && sample.connection_id && sample.connection_id === node.connectionId
      ? sample : undefined
    const comparison: keyof typeof comparisonLabels = result ? compareDeploymentEvidence(
      { commit: localCommit, schema: localSchema, web: localWeb, target: localHost?.target, packageDigest: localPackageDigest },
      { commit: result.build.commit, schema: result.host?.schema, web: result.web, target: result.host?.target,
        packageDigest: result.package_checksums_sha256 }) : 'unverified'
    counts[comparison] += 1
    const candidateStatus = candidate && releaseRolloutStatus(candidate, result?.host, result?.build.commit, result?.web, result?.package_checksums_sha256)
    if (candidateStatus) rollout[candidateStatus] += 1
    const changed = saved && (saved.origin !== node.origin || (typeof sample === 'object'
      ? !!sample.connection_id && sample.connection_id !== node.connectionId
      : saved.requestedConnectionId !== node.connectionId))
    const status = result ? 'reported' : !node.eligible ? 'no-mesh' : changed ? 'route-changed'
      : typeof sample === 'string' ? sample : sample ? 'connection-unconfirmed' : 'not-queried'
    return { node, saved, sample, result, comparison, candidateStatus, status }
  })
  const visibleRows = candidate && !singleTarget && pendingOnly
    ? rows.filter(({ candidateStatus }) => candidateStatus !== 'matched' && candidateStatus !== 'unsupported') : rows
  const retryTargets = rows.filter(({ node, sample, result }) => node.eligible && !result && sample !== 'unsupported')
    .map(({ node }) => node)
  const changedTargets = rows.flatMap(({ node, saved, result }) => node.eligible && node.connectionId && saved && !result
    && (saved.origin !== node.origin || saved.requestedConnectionId !== node.connectionId) ? [node] : [])
  const changedTargetsKey = JSON.stringify(changedTargets.map(({ id, origin, connectionId }) => [id, origin, connectionId]))
  const refreshChangedTargets = useEffectEvent(() => {
    if (!checking && changedTargets.length) void compare(changedTargets)
  })
  useEffect(() => refreshChangedTargets(), [checking, changedTargetsKey])
  const selected = details && rows.find(({ node, result }) => node.id === details.id && node.origin === details.origin
    && result?.connection_id === details.connectionId)
  const selectedId = selected?.node.id
  useEffect(() => {
    if (details && !selectedId) setDetails(undefined)
  }, [details, selectedId])

  const rememberDirectory = useCallback(({ node_id, origin, connection_id, sequence, members_sha256, valid_until }: DirectoryDetails) => {
    setResults(previous => {
      const saved = previous.get(node_id)
      if (saved?.origin !== origin || typeof saved.state !== 'object' || saved.state.connection_id !== connection_id) return previous
      const current = saved.state.member_directory
      if (current && BigInt(sequence) <= BigInt(current.sequence)) return previous
      return new Map(previous).set(node_id, { ...saved, state: { ...saved.state,
        member_directory: { sequence, members_sha256, valid_until } } })
    })
  }, [])

  const directoryTargets = rows.flatMap(({ node, result }) => {
    const directory = result?.member_directory
    if (!localDirectory || !directory || directory.members_sha256 === localDirectory.members_sha256
        || BigInt(directory.sequence) >= BigInt(localDirectory.sequence) || !node.connectionId) return []
    return [{ node, localDirectory, key: JSON.stringify([node.origin, node.connectionId, localDirectory.members_sha256]) }]
  })
  const directoryConnections = JSON.stringify(eligible.map(({ id, origin, connectionId }) => [id, origin, connectionId]))
  const refreshDirectories = useEffectEvent(async (signal: AbortSignal) => {
    for (const id of directoryRechecks.current.keys()) {
      if (!members.some(node => node.id === id)) directoryRechecks.current.delete(id)
    }
    if (checking) return undefined
    const targets = directoryTargets.filter(({ node, key }) => {
      const previous = directoryRechecks.current.get(node.id)
      return previous?.key !== key || (previous.retryAfter !== undefined && previous.retryAfter <= Date.now())
    })
    const pending = targets.values()
    async function read() {
      for (const { node, key, localDirectory } of pending) {
        if (signal.aborted) return
        const firstRead = directoryRechecks.current.get(node.id)?.key !== key
        let retryAfter: number | undefined
        try {
          const value = await api<DirectoryDetails>(`/grove/deployments/${node.id}/member-directory`, {
            signal: AbortSignal.any([signal, AbortSignal.timeout(READ_TIMEOUT_MS)]),
          })
          if (signal.aborted || !directoryDetailsMatch(value, node, node.connectionId)) continue
          rememberDirectory(value)
          if (firstRead && BigInt(value.sequence) < BigInt(localDirectory.sequence)
              && value.members_sha256 !== localDirectory.members_sha256) retryAfter = Date.now() + DIRECTORY_RECHECK_DELAY_MS
        } catch (failure) {
          if (signal.aborted) return
          if (failure instanceof ApiError && failure.status === 401) {
            onUnauthorized()
            return
          }
        } finally {
          if (!signal.aborted) directoryRechecks.current.set(node.id, { key, retryAfter })
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(3, targets.length) }, read))
    return Math.min(...directoryTargets.map(({ node, key }) => {
      const previous = directoryRechecks.current.get(node.id)
      return (previous?.key === key ? previous.retryAfter : undefined) ?? Infinity
    }))
  })
  useEffect(() => {
    const request = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    async function refresh() {
      const retryAt = await refreshDirectories(request.signal)
      if (!request.signal.aborted && retryAt !== undefined && Number.isFinite(retryAt)) {
        timer = setTimeout(() => void refresh(), Math.max(0, retryAt - Date.now()))
      }
    }
    void refresh()
    return () => { request.abort(); clearTimeout(timer) }
  }, [checkedAt, checking, directoryConnections, localDirectory?.members_sha256])

  function downloadReport() {
    const generatedAt = new Date()
    const nodes = rows.map(({ node, saved, result, comparison, candidateStatus, status }) => ({
      node_id: node.id, name: node.name, status, comparison, candidate_status: candidateStatus,
      directory_comparison: compareMemberDirectories(localDirectory, result?.member_directory, generatedAt.getTime()),
      observation: result && saved && {
        received_at: new Date(saved.receivedAt).toISOString(), build: result.build, host: result.host, web: result.web,
        member_directory: result.member_directory, path: node.mesh.activePath, package_checksums_sha256: result.package_checksums_sha256,
      },
    }))
    saveDeploymentReport(generatedAt, reportSource, groveDetails?.realm?.id, candidate, nodes)
  }

  async function compare(targets: Member[]) {
    if (active.current || !targets.length) return
    const controller = new AbortController()
    active.current = controller
    const ids = new Set(targets.map(node => node.id))
    setDetails(previous => previous && ids.has(previous.id) ? undefined : previous)
    setResults(previous => new Map([...previous].filter(([id]) => !ids.has(id))))
    setChecking(ids)
    const pending = targets.values()
    async function read() {
      for (const node of pending) {
        if (controller.signal.aborted) return
        let result: Result['state'] = 'unavailable'
        try {
          const value = await api<Deployment>(`/grove/deployments/${node.id}`, {
            signal: AbortSignal.any([controller.signal, AbortSignal.timeout(READ_TIMEOUT_MS)]),
          })
          if (value.node_id === node.id && value.origin === node.origin) result = value
        } catch (failure) {
          if (controller.signal.aborted) return
          if (failure instanceof ApiError && failure.status === 401) {
            controller.abort()
            onUnauthorized()
            return
          }
          if (failure instanceof ApiError && failure.code === 'DEPLOYMENT_UNSUPPORTED') result = 'unsupported'
          if (failure instanceof ApiError && failure.code === 'ROUTE_LOST') result = 'route-changed'
        }
        if (!controller.signal.aborted) {
          const receivedAt = Date.now()
          setResults(previous => new Map(previous).set(node.id, {
            origin: node.origin, requestedConnectionId: node.connectionId, state: result, receivedAt,
          }))
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(3, targets.length) }, read))
    active.current = null
    if (!controller.signal.aborted) {
      setChecking(undefined)
      setCheckedAt(Date.now() / 1000)
      refreshConsole()
    }
  }

  return <Panel title={singleTarget ? '目标节点版本' : 'Grove 节点版本'} action={<div className="button-row">
    {checkedAt !== undefined && <button type="button" className="btn btn-secondary btn-small" disabled={!!checking}
      onClick={downloadReport}><Icon name="download" size={15} />下载版本核对报告</button>}
    {!singleTarget && checkedAt !== undefined && retryTargets.length > 0 && <button type="button" className="btn btn-secondary btn-small"
      disabled={!!checking} onClick={() => void compare(retryTargets)}>重查未读到的节点</button>}
    <button type="button" className="btn btn-secondary btn-small" disabled={!!checking || !eligible.length}
      onClick={() => void compare(eligible)}>{checking ? '正在核对…' : singleTarget ? '核对目标版本' : '核对节点版本'}</button>
  </div>}>
    <div className="stack">
      {!directoryCurrent && <Notice tone="amber">成员目录待同步，暂时无法核对节点版本。</Notice>}
      <p role="status" className="muted">{checking ? `本轮已查询 ${[...checking].filter(id => results.has(id)).length} / ${checking.size} 个节点`
        : checkedAt !== undefined ? `最近查询于 ${timestamp(checkedAt)}` : '通过 Mesh 读取节点的构建、前端文件和签名成员目录。'}</p>
      {!singleTarget && checkedAt !== undefined && <p role="status">
        与当前节点对比 · {counts.matched} 一致 · {counts.different} 有差异 · {counts.unhealthy} 前端异常 · {counts.unverified} 待确认
      </p>}
      {candidate && !singleTarget && <div className="button-row">
        <p role="status">{[
          '与所选候选对比', ...(['matched', 'not-installed', 'migration', 'restore', 'mismatch', 'unverified', 'unsupported'] as const)
            .filter(key => rollout[key] || !['migration', 'restore', 'unsupported'].includes(key))
            .map(key => `${rollout[key]} ${rolloutLabels[key]}`),
        ].join(' · ')}</p>
        <button type="button" className="btn btn-secondary btn-small" aria-pressed={pendingOnly}
          onClick={() => setPendingOnly(previous => !previous)}>仅显示待处理节点</button>
      </div>}
      {!visibleRows.length ? <p className="muted">当前没有待处理的节点。</p> : <div className="table-wrap"><table className="data-table">
        <thead><tr><th>节点</th><th>本机 Mesh</th><th>后端构建</th><th>前端资源</th><th>版本对比</th><th>成员目录</th>{candidate && <th>候选兼容性</th>}</tr></thead>
        <tbody>{visibleRows.map(({ node, sample, result, comparison, candidateStatus, status }) => {
          const webDifference = result && deploymentWebDifference(localWeb, result.web)
          const directory = result?.member_directory
          const directoryComparison = compareMemberDirectories(localDirectory, directory, now)
          const route = node.mesh.activePath
          const observers = reachabilityReports(node.mesh) ? [...new Set(node.mesh.observations.map(report => report.observer_node_id))] : []
          const readStatus = status === 'no-mesh' ? '暂无可用的 Mesh 配置'
            : status === 'route-changed' ? '正在核对 Mesh 连接，或连接已切换。可重新查询。'
            : status === 'connection-unconfirmed' ? '无法确认版本结果对应的 Mesh 连接。可重新查询。'
            : status === 'unsupported' ? '此版本未提供状态' : status === 'unavailable' ? '暂时无法读取'
            : checking?.has(node.id) ? '正在查询' : '尚未查询'
          return <tr key={node.id}>
            <td>
              {node.origin ? <a className="text-link" href={`${node.origin}/#/deployments`} target="_blank" rel="noopener noreferrer">{node.name}</a> : node.name}
              {!singleTarget && node.eligible && <div className="table-secondary">
                <button type="button" className="text-link" disabled={!!checking}
                  aria-label={`核对 ${node.name} 的版本`} onClick={() => void compare([node])}>
                  {checking?.has(node.id) ? '正在核对…' : sample === undefined ? '核对版本' : '重新核对版本'}
                </button>
              </div>}
            </td>
            <td>
              <NodeConnectionBadge node={node.mesh} />
              {route && <small className="table-secondary">{pathLabel(route)} · {route.map(id => names.get(id) ?? shortId(id)).join(' → ')}</small>}
              {!!observers.length && <small className="table-secondary">观测来自 {observers.map(id => names.get(id) ?? shortId(id)).join('、')}</small>}
              {(route || observers.length > 0) && <a className="text-link" href={`#/topology/${encodeURIComponent(node.id)}`}>查看路径与观测</a>}
            </td>
            {!result ? <td colSpan={candidate ? 5 : 4}>{readStatus}</td> : <>
              <td>{result.build.version ?? '版本未知'}{result.build.commit && <CopyValue value={result.build.commit} short />}
                {localCommit && result.build.commit && localCommit !== result.build.commit &&
                  <small className="table-secondary">与当前节点的构建提交不同</small>}
                {result.package_checksums_sha256 && <div className="table-secondary">包内清单 <CopyValue value={result.package_checksums_sha256} short /></div>}
                {result.host && <small className="table-secondary">数据库 schema {result.host.schema}
                  {localSchema !== undefined && result.host.schema !== localSchema && ' · 与当前节点不同'}</small>}</td>
              <td>{result.web.build ?? '资源标识未知'}<small className="table-secondary">{webStatus[result.web.status]}</small>
                {webDifference && <small className="table-secondary">{webDifference === 'files'
                  ? '与当前节点的前端文件摘要不同' : '与当前节点的资源标识不同'}</small>}</td>
              <td>{comparisonLabels[comparison]}<small className="table-secondary">{result.web.package_match === true ? '与此节点的包内文件一致'
                : result.web.package_match === false ? '与此节点的包内文件不一致' : '无法核对包内文件'}</small></td>
              <td>{directoryComparisonLabels[directoryComparison]}
                {directory && <small className="table-secondary">该节点第 {directory.sequence} 版{localDirectory && ` · 本机第 ${localDirectory.sequence} 版`}</small>}
                {result.member_directory === undefined && <small className="table-secondary">此版本未报告目录</small>}
                {localDirectory && (directoryComparison === 'different' || (directoryComparison === 'unverified' && directory !== undefined)) &&
                  <button type="button" className="text-link" disabled={!!checking}
                    onClick={() => setDetails({ id: node.id, origin: node.origin, connectionId: result.connection_id })}>
                    {directoryComparison === 'different' ? '查看成员差异' : '重查该节点目录'}</button>}
              </td>
              {candidate && <td>{candidateStatus === 'not-installed' && <p>运行其他构建</p>}
                <CandidateCompatibility candidate={candidate} host={result.host} commit={result.build.commit}
                web={result.web} packageDigest={result.package_checksums_sha256}
                nodeId={result.node_id} origin={result.origin} receipt={receipts.get(result.node_id)} /></td>}
            </>}
          </tr>
        })}</tbody>
      </table></div>}
      {selected?.result?.connection_id && localDirectory && localMembers && <MemberDirectoryDetails
        key={JSON.stringify([selected.node.id, selected.node.origin, selected.result.connection_id])}
        node={selected.node} connectionId={selected.result.connection_id} localDirectory={localDirectory} localMembers={localMembers}
        latestSequence={selected.result.member_directory?.sequence} onRead={rememberDirectory} onClose={() => setDetails(undefined)} />}
    </div>
  </Panel>
}

type DirectoryDetails = MemberDirectoryVersion & { node_id: string; origin: string; connection_id: string; members: DirectoryMember[] }

function directoryDetailsMatch(value: DirectoryDetails, node: Pick<Member, 'id' | 'origin'>, connectionId?: string) {
  return !!connectionId && value.node_id === node.id && value.origin === node.origin && value.connection_id === connectionId
    && value.valid_until * 1000 > Date.now()
}

function MemberDirectoryDetails({ node, connectionId, localDirectory, localMembers, latestSequence, onRead, onClose }: {
  node: Member; connectionId: string; localDirectory: MemberDirectoryVersion; localMembers: DirectoryMember[];
  latestSequence?: string; onRead: (snapshot: DirectoryDetails) => void; onClose: () => void
}) {
  const { onUnauthorized, session, groveDetails } = useConsole()
  const directorySync = useGroveDirectorySync(groveDetails?.realm?.id, session.csrf_token, onUnauthorized)
  const [snapshot, setSnapshot] = useState<DirectoryDetails>()
  const [error, setError] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [expectedSequence, setExpectedSequence] = useState<string>()
  const [now, setNow] = useState(Date.now)
  const { id, origin } = node
  useEffect(() => {
    const controller = new AbortController()
    void api<DirectoryDetails>(`/grove/deployments/${id}/member-directory`, {
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(READ_TIMEOUT_MS)]),
    }).then(value => {
      if (controller.signal.aborted) return
      if (!directoryDetailsMatch(value, { id, origin }, connectionId)) {
        setError(true)
        return
      }
      setSnapshot(value)
      onRead(value)
    }).catch(failure => {
      if (controller.signal.aborted) return
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized()
      else setError(true)
    })
    return () => controller.abort()
  }, [id, origin, connectionId, attempt, onUnauthorized, onRead])
  useEffect(() => {
    if (!snapshot) return
    const timer = setTimeout(() => setNow(Date.now()), Math.max(0, snapshot.valid_until * 1000 - Date.now()))
    return () => clearTimeout(timer)
  }, [snapshot])

  function retry() {
    setSnapshot(undefined)
    setError(false)
    setAttempt(value => value + 1)
  }

  async function syncLocalDirectory() {
    const result = await directorySync.sync()
    if (!result) return
    setExpectedSequence(result.sequence)
    retry()
  }

  const waitingForLocal = expectedSequence !== undefined && BigInt(localDirectory.sequence) < BigInt(expectedSequence)
  const comparison = compareMemberDirectories(localDirectory, snapshot, Math.max(now, Date.now()))
  const outdated = snapshot && latestSequence && BigInt(snapshot.sequence) < BigInt(latestSequence)
  const differences = snapshot && comparison === 'different' ? memberDirectoryDifferences(localMembers, snapshot.members) : []
  return <Modal title={`${node.name} 的成员目录`} onClose={onClose}>
    <div className="stack-small">
      {directorySync.message && <p className={directorySync.message.error ? 'error' : 'muted'} role="status">{directorySync.message.text}</p>}
      {directorySync.checking ? <p role="status">正在同步本机成员目录…</p>
        : waitingForLocal ? <p role="status">正在读取同步后的本机目录…</p>
        : error || outdated || (snapshot && comparison === 'unverified') ? <>
        <Notice tone="amber">无法读取当前连接上的有效成员目录。</Notice>
        <button type="button" className="btn btn-secondary" onClick={retry}>重查成员目录</button>
      </> : !snapshot ? <p role="status">正在读取并核对签名目录…</p> : <>
        <p>本机第 {localDirectory.sequence} 版 · 该节点第 {snapshot.sequence} 版</p>
        {!differences.length ? <p>两边的成员身份、地址和启用状态一致。</p> :
          <div className="table-wrap"><table className="data-table">
            <thead><tr><th>成员 Node ID</th><th>本机看到的成员</th><th>该节点看到的成员</th></tr></thead>
            <tbody>{differences.map(({ nodeId, here, there }) => <tr key={nodeId}>
              <td><CopyValue value={nodeId} short /></td>
              {[here, there].map((member, index) => <td key={index}>{member ? <>
                <span className="break-anywhere">{member.origin}</span>
                <small className="table-secondary">{member.enabled ? '已启用' : '已停用'}</small>
              </> : '目录中没有该成员'}</td>)}
            </tr>)}</tbody>
          </table></div>}
        {differences.length > 0 && groveDetails?.local_issuer === false && BigInt(localDirectory.sequence) < BigInt(snapshot.sequence) &&
          <div><button type="button" className="btn btn-secondary" onClick={() => void syncLocalDirectory()}>同步本机成员目录</button></div>}
      </>}
    </div>
  </Modal>
}
