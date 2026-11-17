import { memberPanelOrigin } from './grove-directory.ts'

const targets = ['linux-amd64', 'linux-arm64', 'windows-amd64'] as const
type Target = typeof targets[number]
export type DeploymentHost = { target: Target | null; schema: number }
type ReleasePackage = { target: Target; archive: string; sha256: string; schema: number; checksumsSha256?: string }
export type ReleaseCandidate = {
  version: string; commit: string; schema: number; packages: ReleasePackage[]; webBuild?: string; webSha256?: string;
  singlePackage?: true
}
export type PackageManifest = Omit<ReleaseCandidate, 'packages' | 'singlePackage'> & Pick<ReleasePackage, 'target' | 'archive' | 'checksumsSha256'>
export const MAX_BROWSER_ARCHIVE_SIZE = 128 * 1024 * 1024
const preflightPrefix = 'SPEARMINT_UPGRADE_PREFLIGHT='
export const recoveryStatusPrefix = 'SPEARMINT_UPGRADE_RECOVERY='
const nodeIdPattern = /^spm1-[a-f0-9]{64}$/
const commitPattern = /^[a-f0-9]{40}$/
const sha256Pattern = /^[a-f0-9]{64}$/
const entryAssetPattern = /^assets\/index-([\w-]{1,120})\.(js|css)$/

export type UpgradePreflight = {
  version: 1; node_id: string; origin: string; previous_commit: string; candidate_commit: string;
  schema: number; panel_running: boolean; backup_verified: boolean; backup_sha256?: string;
  target?: Target; package_checksums_sha256?: string; keep_stopped?: boolean
}

export type UpgradeRecoveryStatus = { busy: true } | { pending: false } | {
  pending: true; previous_commit: string; candidate_commit: string; panel_was_running: boolean; node_id?: string;
  origin?: string; schema?: number; target?: Target; package_checksums_sha256?: string
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function releaseWebBuild(web: [string, string][]) {
  const scripts: string[] = []
  const styles: string[] = []
  for (const [name] of web) {
    const match = entryAssetPattern.exec(name)
    if (!match || match[0] !== name) continue
    const ids = match[2] === 'js' ? scripts : styles
    ids.push(match[1])
  }
  return scripts.length === 1 && styles.length === 1 ? `${scripts[0]} / ${styles[0]}` : undefined
}

export function parseUpgradePreflight(text: string): UpgradePreflight {
  if (text.length > 8192) throw new Error('预检输出过长，请只粘贴回执所在的一行。')
  const lines = text.trim().split(/\r?\n/).filter(line => line.startsWith(preflightPrefix))
  if (lines.length !== 1) throw new Error('请粘贴一条安装器返回的预检回执。')
  const value: unknown = JSON.parse(lines[0].slice(preflightPrefix.length))
  if (!record(value)) throw new Error('预检回执格式无效。')
  const { version, node_id, origin, previous_commit, candidate_commit, schema, panel_running, backup_verified, backup_sha256,
    target, package_checksums_sha256, keep_stopped } = value
  const platform = targets.find(item => item === target)
  if (version !== 1 || typeof node_id !== 'string' || node_id.length !== 69 || !nodeIdPattern.test(node_id)
      || typeof origin !== 'string' || memberPanelOrigin(origin) !== origin
      || typeof previous_commit !== 'string' || previous_commit.length !== 40 || !commitPattern.test(previous_commit)
      || typeof candidate_commit !== 'string' || candidate_commit.length !== 40 || !commitPattern.test(candidate_commit)
      || typeof schema !== 'number' || !Number.isInteger(schema) || schema < 1 || schema > 2 ** 31 - 1
      || typeof panel_running !== 'boolean' || typeof backup_verified !== 'boolean'
      || (keep_stopped !== undefined && (typeof keep_stopped !== 'boolean' || (keep_stopped && panel_running)))
      || (target !== undefined && !platform)
      || (package_checksums_sha256 !== undefined && (typeof package_checksums_sha256 !== 'string'
        || package_checksums_sha256.length !== 64 || !sha256Pattern.test(package_checksums_sha256)))
      || (backup_sha256 !== undefined && (!backup_verified || typeof backup_sha256 !== 'string'
        || backup_sha256.length !== 64 || !sha256Pattern.test(backup_sha256)))) throw new Error('预检回执字段无效。')
  return { version, node_id, origin, previous_commit, candidate_commit, schema, panel_running, backup_verified,
    ...(backup_sha256 === undefined ? {} : { backup_sha256 }), ...(platform ? { target: platform } : {}),
    ...(keep_stopped === undefined ? {} : { keep_stopped }),
    ...(package_checksums_sha256 === undefined ? {} : { package_checksums_sha256 }) }
}

export function parseUpgradeRecoveryStatus(text: string): UpgradeRecoveryStatus {
  if (text.length > 8192) throw new Error('恢复状态输出过长，请只粘贴状态所在的一行。')
  const lines = text.trim().split(/\r?\n/).filter(line => line.startsWith(recoveryStatusPrefix))
  if (lines.length !== 1) throw new Error('请粘贴一条安装器返回的恢复状态。')
  const value: unknown = JSON.parse(lines[0].slice(recoveryStatusPrefix.length))
  if (record(value)) {
    const { pending, previous_commit, candidate_commit, panel_was_running, node_id, origin, schema, target,
      package_checksums_sha256 } = value
    if (Object.hasOwn(value, 'busy')) {
      if (value.busy === true && Object.keys(value).length === 1) return { busy: true }
      throw new Error('恢复状态字段无效。')
    }
    if (pending === false && Object.keys(value).length === 1) return { pending }
    const platform = targets.find(item => item === target)
    if (pending === true && (target === undefined || platform !== undefined)
        && typeof previous_commit === 'string' && previous_commit.length === 40 && commitPattern.test(previous_commit)
        && typeof candidate_commit === 'string' && candidate_commit.length === 40 && commitPattern.test(candidate_commit)
        && typeof panel_was_running === 'boolean'
        && (node_id === undefined || (typeof node_id === 'string' && node_id.length === 69 && nodeIdPattern.test(node_id)))) {
      const status = { pending, previous_commit, candidate_commit, panel_was_running,
        ...(node_id === undefined ? {} : { node_id }), ...(platform ? { target: platform } : {}) }
      if (origin === undefined && schema === undefined && package_checksums_sha256 === undefined) return status
      if (node_id && typeof origin === 'string' && memberPanelOrigin(origin) === origin
          && typeof schema === 'number' && Number.isInteger(schema) && schema >= 1 && schema <= 2 ** 31 - 1
          && (package_checksums_sha256 === undefined || (typeof package_checksums_sha256 === 'string'
            && package_checksums_sha256.length === 64 && sha256Pattern.test(package_checksums_sha256)))) {
        return { ...status, origin, schema, ...(package_checksums_sha256 === undefined ? {} : { package_checksums_sha256 }) }
      }
    }
  }
  throw new Error('恢复状态字段无效。')
}

export function matchesUpgradePreflight(receipt: UpgradePreflight, candidate: ReleaseCandidate,
  host: DeploymentHost | null | undefined, nodeId?: string, origin?: string, currentCommit?: string | null) {
  const compatibility = releaseCompatibility(candidate, host, currentCommit)
  return !!currentCommit && compatibility.status === 'compatible'
    && (!receipt.target || receipt.target === host?.target)
    && (!compatibility.bundle.checksumsSha256 || !receipt.package_checksums_sha256
      || receipt.package_checksums_sha256 === compatibility.bundle.checksumsSha256)
    && receipt.node_id === nodeId && receipt.origin === origin && receipt.previous_commit === currentCommit
    && receipt.candidate_commit === candidate.commit && receipt.schema === candidate.schema
}

export async function parseDeploymentManifest(text: string): Promise<ReleaseCandidate | PackageManifest> {
  const value: unknown = JSON.parse(text)
  if (!record(value)) throw new Error('清单格式无效。')
  if (Object.hasOwn(value, 'packages')) return releaseFromManifest(value)
  if (value.format !== 'native-executable-with-runtime-and-web') throw new Error('原生包清单格式无效。')
  const { version, commit, schema } = releaseMetadata(value)
  const target = targets.find(item => {
    const [os, architecture] = item.split('-')
    return os === value.os && architecture === value.architecture
  })
  if (!target) throw new Error('清单中的原生包平台无效。')
  const digest = value.package_checksums_sha256
  if (digest !== undefined && (typeof digest !== 'string' || digest.length !== 64 || !sha256Pattern.test(digest))) {
    throw new Error('原生包清单中的包内文件清单摘要无效。')
  }
  return { version, commit, schema, target, archive: archiveName(version, target, commit),
    ...(digest === undefined ? {} : { checksumsSha256: digest }),
    ...await releaseWebMetadata(value.web_files, '') }
}

async function releaseFromManifest(value: Record<string, unknown>): Promise<ReleaseCandidate> {
  const { version, commit, schema } = releaseMetadata(value)
  const { packages, package_checksums: checksums } = value
  if (!Array.isArray(packages) || packages.length !== targets.length) throw new Error('发布清单的平台列表无效。')
  if (checksums !== undefined && (!record(checksums) || Object.keys(checksums).length !== targets.length)) {
    throw new Error('发布清单中的包内文件清单摘要无效。')
  }
  const parsed = targets.map(target => {
    const matches = packages.filter(item => record(item) && item.target === target)
    const item = matches[0]
    const archive = archiveName(version, target, commit)
    if (matches.length !== 1 || item.archive !== archive || item.schema !== schema
        || typeof item.sha256 !== 'string' || item.sha256.length !== 64 || !/^[a-f0-9]{64}$/.test(item.sha256)) {
      throw new Error('清单中的归档信息无效。')
    }
    if (checksums === undefined) return { target, archive, sha256: item.sha256, schema }
    const digest = checksums[target]
    if (typeof digest !== 'string' || digest.length !== 64 || !sha256Pattern.test(digest)) {
      throw new Error('发布清单中的包内文件清单摘要无效。')
    }
    return { target, archive, sha256: item.sha256, schema, checksumsSha256: digest }
  })
  return { version, commit, schema, packages: parsed, ...await releaseWebMetadata(value.web, 'web/') }
}

export function packageCandidate(manifest: PackageManifest, checksum: string): ReleaseCandidate {
  const { target, archive, schema, checksumsSha256, ...metadata } = manifest
  const line = checksum.trim()
  if (line.length !== 66 + archive.length || line.slice(66) !== archive || line.slice(64, 66) !== '  '
      || !/^[a-f0-9]{64}$/.test(line.slice(0, 64))) throw new Error('SHA-256 文件与原生包清单中的归档名不符，或格式无效。')
  return { ...metadata, schema, singlePackage: true, packages: [{ target, archive, schema, sha256: line.slice(0, 64),
    ...(checksumsSha256 === undefined ? {} : { checksumsSha256 }) }] }
}

function releaseMetadata(value: Record<string, unknown>) {
  const { version, commit, schema } = value
  if (typeof version !== 'string' || version.length > 64 || !/^[a-zA-Z0-9][a-zA-Z0-9.+-]*$/.test(version)
      || version.trim() !== version || typeof commit !== 'string' || commit.length !== 40 || !commitPattern.test(commit)
      || typeof schema !== 'number' || !Number.isInteger(schema) || schema < 1 || schema > 2 ** 31 - 1) {
    throw new Error('清单版本、提交或 schema 无效。')
  }
  return { version, commit, schema }
}

function archiveName(version: string, target: Target, commit: string) {
  return `spearmint-${version}-${target}-${commit.slice(0, 8)}${target.startsWith('windows') ? '.zip' : '.tar.gz'}`
}

async function releaseWebMetadata(web: unknown, prefix: string) {
  if (web === undefined) return {}
  if (!record(web) || !Object.hasOwn(web, `${prefix}index.html`)) throw new Error('清单中的前端文件信息无效。')
  const webFiles = Object.keys(web).sort().map((name): [string, string] => {
    const digest = web[name]
    if (!name.startsWith(prefix) || typeof digest !== 'string' || digest.length !== 64 || !/^[a-f0-9]{64}$/.test(digest)) {
      throw new Error('清单中的前端文件信息无效。')
    }
    return [name.slice(prefix.length), digest]
  })
  const webSha256 = globalThis.crypto?.subtle ? await sha256(new TextEncoder().encode(JSON.stringify(webFiles))) : undefined
  return { webBuild: releaseWebBuild(webFiles), webSha256 }
}

async function sha256(data: BufferSource) {
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
}

export function releaseCompatibility(candidate: ReleaseCandidate, host?: DeploymentHost | null, commit?: string | null) {
  if (!host) return { status: 'unknown' } as const
  const bundle = candidate.packages.find(item => item.target === host.target)
  if (!bundle) return { status: 'unsupported' } as const
  if (host.schema < candidate.schema) return { status: 'migration', bundle } as const
  if (host.schema > candidate.schema) return { status: 'restore', bundle } as const
  return { status: commit === candidate.commit ? 'same-build' : 'compatible', bundle } as const
}

type DeploymentWeb = {
  status: string; build: string | null; package_match?: boolean | null; package_web_sha256?: string | null
}

type DeploymentEvidence = { commit?: string | null; schema?: number; web?: DeploymentWeb;
  target?: DeploymentHost['target']; packageDigest?: string }

export function compareDeploymentEvidence(local: DeploymentEvidence, remote: DeploymentEvidence) {
  const differentCommit = !!local.commit && !!remote.commit && local.commit !== remote.commit
  const differentSchema = local.schema !== undefined && remote.schema !== undefined && local.schema !== remote.schema
  const differentPackage = !!local.target && local.target === remote.target && !!local.packageDigest
    && !!remote.packageDigest && local.packageDigest !== remote.packageDigest
  if (differentCommit || differentSchema || differentPackage || deploymentWebDifference(local.web, remote.web)) return 'different'
  if (remote.web && (remote.web.status !== 'ready' || remote.web.package_match === false)) return 'unhealthy'
  if (local.commit && remote.commit && local.schema !== undefined && remote.schema !== undefined
      && local.web?.status === 'ready' && remote.web?.status === 'ready'
      && local.web.package_match === true && remote.web.package_match === true
      && local.web.package_web_sha256 && remote.web.package_web_sha256) return 'matched'
  return 'unverified'
}

export function deploymentWebDifference(local?: DeploymentWeb, remote?: DeploymentWeb) {
  if (!local || !remote) return undefined
  if (local.package_match === true && remote.package_match === true && local.package_web_sha256
      && remote.package_web_sha256 && local.package_web_sha256 !== remote.package_web_sha256) return 'files'
  if (local.build && remote.build && local.build !== remote.build) return 'entry'
  return undefined
}

export function releaseDeploymentStatus(candidate: ReleaseCandidate, host: DeploymentHost | null | undefined,
  commit: string | null | undefined, web?: DeploymentWeb, packageDigest?: string) {
  if (commit !== candidate.commit) return undefined
  const expected = candidate.packages.find(item => item.target === host?.target)
  if (candidate.singlePackage && host && !expected) return undefined
  if (host && releaseCompatibility(candidate, host, commit).status !== 'same-build') return 'host-mismatch'
  if (expected?.checksumsSha256 && packageDigest && packageDigest !== expected.checksumsSha256) return 'package-mismatch'
  if (web && (web.status !== 'ready' || web.package_match === false
      || (web.build && candidate.webBuild && web.build !== candidate.webBuild)
      || (web.package_web_sha256 && candidate.webSha256 && web.package_web_sha256 !== candidate.webSha256))) return 'web-mismatch'
  if (host && candidate.webSha256 && web?.package_web_sha256 === candidate.webSha256 && web.package_match === true
      && (!candidate.webBuild || web.build === candidate.webBuild)) {
    return expected?.checksumsSha256 && !packageDigest ? 'awaiting-package' : 'matched'
  }
  return 'awaiting-web'
}

export function releaseRolloutStatus(candidate: ReleaseCandidate, host?: DeploymentHost | null,
  commit?: string | null, web?: DeploymentWeb, packageDigest?: string) {
  const compatibility = releaseCompatibility(candidate, host, commit).status
  if (compatibility === 'unsupported') return 'unsupported'
  if (!commit || commit.length !== 40 || !commitPattern.test(commit) || !host) return 'unverified'
  if (commit !== candidate.commit) {
    if (compatibility === 'migration' || compatibility === 'restore') return compatibility
    return 'not-installed'
  }
  const deployment = releaseDeploymentStatus(candidate, host, commit, web, packageDigest)
  if (deployment === 'host-mismatch' || deployment === 'web-mismatch' || deployment === 'package-mismatch') return 'mismatch'
  return deployment === 'matched' ? 'matched' : 'unverified'
}

export const rolloutLabels = {
  matched: '已核对一致', 'not-installed': '可预检', migration: '需迁移数据库', restore: '需恢复兼容备份',
  mismatch: '核对异常', unverified: '待确认', unsupported: '无对应平台包',
} satisfies Record<ReturnType<typeof releaseRolloutStatus>, string>

function quoteWindows(value: string) { return "'" + value.replace(/['‘’‚‛]/g, '$&$&') + "'" }
function quoteLinux(value: string) { return "'" + value.replaceAll("'", "'\\''") + "'" }

export function upgradeRecoveryOrigin(candidate: ReleaseCandidate, status: UpgradeRecoveryStatus, receipt?: UpgradePreflight) {
  if ('busy' in status || !status.pending || !status.node_id || candidate.commit !== status.candidate_commit) return undefined
  if (status.origin !== undefined || status.schema !== undefined) {
    if (status.origin && memberPanelOrigin(status.origin) === status.origin && candidate.schema === status.schema) return status.origin
    return undefined
  }
  if (receipt && receipt.node_id === status.node_id && receipt.previous_commit === status.previous_commit
      && receipt.candidate_commit === status.candidate_commit && candidate.schema === receipt.schema
      && memberPanelOrigin(receipt.origin) === receipt.origin) return receipt.origin
}

export function releaseRecoveryCommand(candidate: ReleaseCandidate, status: UpgradeRecoveryStatus, target: string,
  receipt?: UpgradePreflight) {
  if ('busy' in status || !status.pending || (status.target && status.target !== target)) return undefined
  if (status.origin === undefined && receipt?.target && receipt.target !== target) return undefined
  const origin = upgradeRecoveryOrigin(candidate, status, receipt)
  if (!origin) return undefined
  const bundle = candidate.packages.find(item => item.target === target)
  if (!bundle || recoveryPackageMismatch(candidate, status, target)) return undefined
  const command = bundle.target === 'windows-amd64'
    ? `.\\deployment\\install-windows.ps1 -RecoverUpgrade -Origin ${quoteWindows(origin)}`
    : `sh deployment/install-linux.sh --recover-upgrade ${quoteLinux(origin)}`
  return { bundle, command }
}

export function recoveryPackageMismatch(candidate: ReleaseCandidate, status: Extract<UpgradeRecoveryStatus, { pending: true }>, target: string) {
  const digest = candidate.packages.find(item => item.target === target)?.checksumsSha256
  return !!digest && !!status.package_checksums_sha256 && digest !== status.package_checksums_sha256
}

export function releaseInstallerCommand(candidate: ReleaseCandidate, host: DeploymentHost | null | undefined,
  nodeId: string | undefined, origin: string | undefined, commit?: string | null, receipt?: UpgradePreflight,
  backupPath?: string, keepStopped = receipt?.keep_stopped === true) {
  const compatibility = releaseCompatibility(candidate, host, commit)
  if (compatibility.status !== 'compatible'
      || !nodeId || nodeId.length !== 69 || !nodeIdPattern.test(nodeId)
      || candidate.commit.length !== 40 || !commitPattern.test(candidate.commit)
      || !origin || memberPanelOrigin(origin) !== origin) return undefined
  if (commit && (commit.length !== 40 || !commitPattern.test(commit))) return undefined
  if (receipt && !matchesUpgradePreflight(receipt, candidate, host, nodeId, origin, commit)) return undefined
  if (receipt && ((receipt.keep_stopped === true) !== keepStopped || (keepStopped && receipt.panel_running))) return undefined
  const windows = host?.target === 'windows-amd64'
  if (receipt?.backup_verified && !backupPath) return undefined
  const backupDigest = receipt?.backup_sha256
  const packageDigest = receipt?.package_checksums_sha256
  // Older installers may predate the expected-package argument even when a release manifest includes the digest.
  const selectedDigest = packageDigest === undefined ? compatibility.bundle.checksumsSha256 : undefined
  if (backupDigest !== undefined && (!receipt?.backup_verified || backupDigest.length !== 64 || !sha256Pattern.test(backupDigest))) return undefined
  if (packageDigest !== undefined && (packageDigest.length !== 64 || !sha256Pattern.test(packageDigest))) return undefined
  if (selectedDigest !== undefined && (selectedDigest.length !== 64 || !sha256Pattern.test(selectedDigest))) return undefined
  if (backupPath && (/[\u0000-\u001f\u007f]/.test(backupPath) || (windows
    ? !/^(?:[A-Za-z]:[\\/]|\\\\[^\\/? .][^\\/]*\\[^\\/]+)/.test(backupPath)
    : !backupPath.startsWith('/')))) return undefined
  if (windows) {
    const mode = `${receipt ? '-Upgrade' : '-CheckUpgrade'}${keepStopped ? ' -KeepStopped' : ''}`
    const expectedCurrent = commit ? ` -ExpectedCurrentCommit ${commit}` : ''
    const backup = backupPath ? ` -VerifyBackup ${quoteWindows(backupPath)}` : ''
    const expectedBackup = backupDigest ? ` -ExpectedBackupSha256 ${backupDigest}` : ''
    const expectedPackage = packageDigest ? ` -ExpectedPackageSha256 ${packageDigest}` : ''
    const command = `.\\deployment\\install-windows.ps1 ${mode} -Origin ${quoteWindows(origin)} -ExpectedNode ${nodeId} -ExpectedCommit ${candidate.commit}${expectedCurrent}${backup}${expectedBackup}${expectedPackage}`
    return selectedDigest
      ? `if ((Get-FileHash -LiteralPath '.\\checksums.json' -Algorithm SHA256 -ErrorAction Stop).Hash -ine '${selectedDigest}') { throw 'Package checksum manifest does not match the selected archive.' } else { ${command} }`
      : command
  }
  const mode = `${receipt ? '--upgrade' : '--check-upgrade'}${keepStopped ? ' --keep-stopped' : ''}`
  const expectedCurrent = commit ? ` --expected-current-commit ${commit}` : ''
  const backup = backupPath ? ` --verify-backup ${quoteLinux(backupPath)}` : ''
  const expectedBackup = backupDigest ? ` --expected-backup-sha256 ${backupDigest}` : ''
  const expectedPackage = packageDigest ? ` --expected-package-sha256 ${packageDigest}` : ''
  const command = `sh deployment/install-linux.sh ${mode} --expected-node ${nodeId} --expected-commit ${candidate.commit}${expectedCurrent}${backup}${expectedBackup}${expectedPackage} ${quoteLinux(origin)}`
  return selectedDigest ? `printf '%s  checksums.json\\n' '${selectedDigest}' | sha256sum -c && ${command}` : command
}

export async function verifyReleaseArchive(bundle: ReleasePackage, file: File): Promise<boolean> {
  if (file.name !== bundle.archive) throw new Error('文件名与清单中的归档不符。')
  if (!file.size) throw new Error('所选归档是空文件。')
  if (file.size > MAX_BROWSER_ARCHIVE_SIZE) throw new Error('归档超过浏览器核对上限，请用命令行计算 SHA-256。')
  if (!globalThis.crypto?.subtle) throw new Error('当前浏览器无法计算 SHA-256，请用命令行核对。')
  return await sha256(await file.arrayBuffer()) === bundle.sha256
}
