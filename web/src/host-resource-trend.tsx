import { timestamp, usePoll } from './api'
import { refreshConsole, useConsole } from './console-data'
import { hostTrendSeries, resourceWarningPercent, type HostTrend } from './host-resources'
import { EmptyState, Icon, Loading, Notice, Panel } from './ui'

export function HostResourceTrend() {
  const { onUnauthorized } = useConsole()
  const { data, error, errorStatus } = usePoll<HostTrend>('/metrics/trend', onUnauthorized, 10_000)
  const series = data && hostTrendSeries(data)
  const clock = (seconds: number) => new Date(seconds * 1000).toLocaleTimeString()
  return <Panel title="最近 15 分钟" action={<button className="btn btn-secondary" onClick={refreshConsole}>
    <Icon name="refresh" size={15} />刷新趋势</button>}>
    {error && <Notice tone="amber">{errorStatus === 404 ? '所属节点的版本尚未提供资源趋势。' : `暂时无法刷新趋势。${error}`}</Notice>}
    {!data && !error && <Loading label="正在读取主机采样…" />}
    {data && series && (series.some((item) => item.peak) ? <>
      <p className="muted">{error ? '上次读取的采样' : '采样区间'} {clock(data.sampled_at - data.window_seconds)} – {clock(data.sampled_at)}</p>
      <div className="resource-trends">
        {series.map(({ label, segments, peak }) => <section className="resource-trend" key={label}>
          <h4>{label}</h4>
          {peak ? <>
            <p><strong>{peak.value.toFixed(1)}%</strong> <span>峰值 · {timestamp(peak.time)}</span></p>
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="resource-trend-chart" aria-hidden="true">
              <line x1="0" y1={100 - resourceWarningPercent} x2="100" y2={100 - resourceWarningPercent} className="resource-trend-threshold" />
              {segments.map((segment) => segment.length === 1
                ? <circle key={segment[0].x} cx={segment[0].x} cy={segment[0].y} r="1.1" />
                : <polyline key={segment[0].x} points={segment.map(({ x, y }) => `${x},${y}`).join(' ')} vectorEffect="non-scaling-stroke" />)}
            </svg>
          </> : <p className="muted">该时段暂无独立采样</p>}
        </section>)}
      </div>
      <p className="resource-trend-note">各图使用 0–100% 刻度，虚线为 {resourceWarningPercent}%。</p>
    </> : <EmptyState title="正在积累主机采样">趋势从当前 Spearmint 进程启动后开始记录。</EmptyState>)}
  </Panel>
}
