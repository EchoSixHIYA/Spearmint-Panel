export type DeploymentOptions = {
  runtime: 'auto' | 'none' | 'python'; prepare: string; prepare_timeout: number; data_paths: string[];
  readiness: { mode: 'process' | 'http' | 'tcp' | 'command'; timeout: number; stable: number; url: string; port: number; command: string }
}
export const defaultOptions = (): DeploymentOptions => ({ runtime: 'auto', prepare: '', prepare_timeout: 900, data_paths: ['data'],
  readiness: { mode: 'process', timeout: 120, stable: 2, url: '', port: 0, command: '' } })

export function DeploymentSettings({ value, onChange, docker }: { value: DeploymentOptions; onChange: (value: DeploymentOptions) => void; docker: boolean }) {
  const ready = value.readiness
  const setReady = (change: Partial<typeof ready>) => onChange({ ...value, readiness: { ...ready, ...change } })
  return <details className="deployment-settings"><summary>高级部署设置 <span className="muted tiny">可选，默认自动准备与检查</span></summary>
    <div className="stack">
      {!docker && <>
        <div className="deployment-fields"><label>运行环境<select aria-label="运行环境" className="input" value={value.runtime} onChange={event => onChange({ ...value, runtime: event.target.value as DeploymentOptions['runtime'] })}>
          <option value="auto">自动识别 Python / 使用已有环境</option><option value="python">独立 Python 虚拟环境</option><option value="none">使用目标节点现有环境</option></select></label>
          <label>准备超时（秒）<input className="input" type="number" min={10} max={3600} value={value.prepare_timeout} onChange={event => onChange({ ...value, prepare_timeout: Number(event.target.value) })} /></label></div>
        <label>依赖准备命令<textarea className="input" rows={3} maxLength={8192} placeholder="例如 npm ci；Python 的 requirements.txt / pyproject.toml 会自动安装" value={value.prepare} onChange={event => onChange({ ...value, prepare: event.target.value })} /></label>
        <label>持久化目录（相对路径，每行一个）<textarea className="input" rows={2} value={value.data_paths.join('\n')} onChange={event => onChange({ ...value, data_paths: event.target.value.replaceAll('\r', '').split('\n') })} /></label>
        <p className="muted tiny">默认将 data 连接到独立数据目录。可添加 uploads 等目录；这些目录与 SPMT_DATA_DIR 在更新和回滚时保留。依赖准备在停止旧服务前执行。</p>
      </>}
      <div className="deployment-fields"><label>就绪检查<select aria-label="就绪检查" className="input" value={ready.mode} onChange={event => setReady({ mode: event.target.value as typeof ready.mode })}>
        <option value="process">进程持续运行 / Docker 健康检查</option><option value="http">HTTP 请求</option><option value="tcp">TCP 端口</option><option value="command">检查命令</option></select></label>
        <label>等待就绪（秒）<input className="input" type="number" min={2} max={3600} value={ready.timeout} onChange={event => setReady({ timeout: Number(event.target.value) })} /></label>
        <label>持续通过（秒）<input className="input" type="number" min={1} max={30} value={ready.stable} onChange={event => setReady({ stable: Number(event.target.value) })} /></label></div>
      {ready.mode === 'http' && <label>目标节点本机 HTTP 地址<input className="input" type="url" placeholder="http://127.0.0.1:8080/health" value={ready.url} onChange={event => setReady({ url: event.target.value })} /></label>}
      {ready.mode === 'tcp' && <label>目标节点本机端口<input className="input" type="number" min={1} max={65535} value={ready.port || ''} onChange={event => setReady({ port: Number(event.target.value) })} /></label>}
      {ready.mode === 'command' && <label>{docker ? '容器内检查命令' : '就绪检查命令'}<textarea className="input" rows={2} maxLength={4096} value={ready.command} onChange={event => setReady({ command: event.target.value })} /></label>}
      <p className="muted tiny">检查通过后才确认更新成功。失败自动恢复上一版程序及启动配置；应用数据和数据库结构不会随代码回滚。</p>
    </div>
  </details>
}
