import { useRef, useState } from 'react'
import { pathLabel } from './connection-status'
import { compareDeploymentReports, MAX_DEPLOYMENT_REPORT_SIZE, parseDeploymentReport, queryLabels, verifyReportDirectory } from './deployment-report'
import { rolloutLabels } from './release-compatibility'
import { CopyValue, Notice, Panel, shortId } from './ui'

const labels = { matched: '一致', different: '有差异', unhealthy: '核对异常', unverified: '待确认', 'same-members': '版本不同，成员一致' }
const dateLabel = (value: string) => new Date(value).toLocaleString()

type Slot = { report?: ReturnType<typeof parseDeploymentReport>; error?: string }

export function DeploymentReportPanel() {
  const [left, setLeft] = useState<Slot>({})
  const [right, setRight] = useState<Slot>({})
  const leftRequest = useRef(0)
  const rightRequest = useRef(0)

  async function read(side: 'left' | 'right', file?: File) {
    const request = side === 'left' ? leftRequest : rightRequest
    const set = side === 'left' ? setLeft : setRight
    const version = ++request.current
    set({})
    if (!file) return
    try {
      if (file.size > MAX_DEPLOYMENT_REPORT_SIZE) throw new Error('核对报告超过 1 MiB。')
      const report = await verifyReportDirectory(parseDeploymentReport(await file.text()))
      if (version === request.current) set({ report })
    } catch (failure) {
      if (version === request.current) set({ error: failure instanceof SyntaxError ? '无法读取报告 JSON。'
        : failure instanceof Error ? failure.message : '无法读取报告。' })
    }
  }

  const ready = left.report && right.report
  const comparison = left.report && right.report ? compareDeploymentReports(left.report, right.report) : undefined
  const showCandidate = !!(left.report?.candidate || right.report?.candidate)

  return <Panel title="对照版本核对报告">
    <details>
      <summary>选择两份核对报告</summary>
      <div className="stack-small">
        <div className="columns-2">
          {([['left', '报告 A', left], ['right', '报告 B', right]] as const).map(([side, label, { report, error }]) =>
            <div key={side} className="stack-small">
              <label className="field-label">{label}
                <input type="file" accept=".json,application/json" onChange={event => void read(side, event.target.files?.[0])} />
              </label>
              {error && <p className="error" role="alert">{error}</p>}
              {report && <div>{dateLabel(report.generatedAt)} {report.source && <CopyValue value={report.source} short />}</div>}
              {report?.directorySnapshot?.status === 'unverified' && <Notice tone="amber">成员目录快照的摘要未能核对。</Notice>}
              {report?.candidate && <div>候选 {report.candidate.version} · schema {report.candidate.schema} <CopyValue value={report.candidate.commit} short /></div>}
            </div>)}
        </div>
        {ready && !comparison && <Notice tone="amber">两份报告属于不同 Grove，请重新选择。</Notice>}
        {comparison && <>
          {!comparison.sameGrove && <Notice>有报告未记录 Grove ID，按 Node ID 对照。</Notice>}
          {comparison.sameSource && <Notice>两份报告来自同一面板。成员目录按各自导出时的有效期核对。</Notice>}
          {showCandidate && <Notice tone={comparison.candidateComparison === 'different' ? 'amber' : undefined}>
            {comparison.candidateComparison === 'matched' ? '两份报告记录的候选归档摘要一致。'
              : comparison.candidateComparison === 'different' ? '两份报告的候选不同，各列显示对应报告的结果。'
              : '报告中的候选信息不足，无法确认两份报告使用相同归档。'}
          </Notice>}
          {comparison.roster ? <details open>
            <summary>Grove 成员目录对照{comparison.roster.differences.length > 0 && ` · ${comparison.roster.differences.length} 项差异`}</summary>
            <p>报告 A 第 {comparison.roster.leftSequence} 版 · 报告 B 第 {comparison.roster.rightSequence} 版</p>
            {comparison.roster.differences.length === 0 ? <p>成员、地址和启用状态一致。</p> :
              <div className="table-wrap"><table className="data-table">
                <thead><tr><th>成员 Node ID</th><th>报告 A 的目录</th><th>报告 B 的目录</th></tr></thead>
                <tbody>{comparison.roster.differences.map(({ nodeId, here, there }) => <tr key={nodeId}>
                  <td><CopyValue value={nodeId} short /></td>
                  {[here, there].map((entry, index) => <td key={index}>{entry ? <>
                    <span className="break-anywhere">{entry.origin}</span>
                    <small className="table-secondary">{entry.enabled ? '已启用' : '已停用'}</small>
                  </> : '目录中没有该成员'}</td>)}
                </tr>)}</tbody>
              </table></div>}
          </details> : (left.report?.directorySnapshot || right.report?.directorySnapshot) &&
            <Notice>需要两份属于同一 Grove、有效期相符且通过摘要核对的目录快照，才能逐项对照成员。</Notice>}
          {!comparison.rows.length ? <p>报告没有可对照的节点。</p> : <div className="table-wrap"><table className="data-table">
            <thead><tr><th>节点</th><th>报告 A 采样</th><th>报告 B 采样</th><th>后端提交</th><th>数据库 schema</th>
              <th>原生包清单</th><th>前端资源</th><th>成员目录</th>{showCandidate && <><th>报告 A 候选状态</th><th>报告 B 候选状态</th></>}</tr></thead>
            <tbody>{comparison.rows.map(row => <tr key={row.id}>
              <td>{row.name && <div>{row.name}</div>}<CopyValue value={row.id} short /></td>
              {[row.left, row.right].map((side, index) => <td key={index}>
                {side?.observedAt ? dateLabel(side.observedAt) : side ? (side.query ? queryLabels[side.query] : '待确认') : '未列出'}
                {row.earlierSample === (index === 0 ? 'left' : 'right') && <small className="table-secondary">较早采样</small>}
                {side?.path && <small className="table-secondary" title={side.path.join(' → ')}>
                  {pathLabel(side.path)} · {side.path.map(id => shortId(id)).join(' → ')}
                </small>}
              </td>)}
              <td>{labels[row.commit]}{row.commit === 'different' && <small className="table-secondary">
                {row.left?.evidence?.commit?.slice(0, 8)} / {row.right?.evidence?.commit?.slice(0, 8)}</small>}</td>
              <td>{labels[row.schema]}{row.schema === 'different' && <small className="table-secondary">
                {row.left?.evidence?.schema} / {row.right?.evidence?.schema}</small>}</td>
              <td>{labels[row.packageDigest]}{row.packageDigest === 'different' && <small className="table-secondary">
                {row.left?.evidence?.packageDigest?.slice(0, 8)} / {row.right?.evidence?.packageDigest?.slice(0, 8)}</small>}</td>
              <td>{labels[row.web]}</td>
              <td>{labels[row.directory]}{row.left?.evidence?.directory && row.right?.evidence?.directory &&
                <small className="table-secondary">第 {row.left.evidence.directory.sequence} / {row.right.evidence.directory.sequence} 版</small>}</td>
              {showCandidate && [row.left, row.right].map((side, index) => <td key={index}>
                {side?.rollout ? rolloutLabels[side.rollout] : side ? '未记录' : '未列出'}
              </td>)}
            </tr>)}</tbody>
          </table></div>}
        </>}
      </div>
    </details>
  </Panel>
}
