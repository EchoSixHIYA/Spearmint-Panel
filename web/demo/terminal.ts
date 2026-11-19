import { demoNodes, now } from './data'

const encoder = new TextEncoder(), decoder = new TextDecoder()
export const encode = (data: Uint8Array) => btoa(String.fromCharCode(...data)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
export const decode = (data: string) => Uint8Array.from(atob(data.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0))
type File = { path: string; directory?: boolean; text: string; modified: number; bytes?: Uint8Array }
const contents = (file: File) => file.bytes ?? encoder.encode(file.text)
type Terminal = { node: string; cwd: string; line: string; output: string; sequence: number; ended: boolean; windows: boolean }
const sessions = new Map<string, Terminal>()
const uploads = new Map<string, { path: string; parts: Uint8Array[]; offset: number }>()
const files = new Map<string, Map<string, File>>()

function fileSystem(node: string, windows: boolean) {
  if (files.has(node)) return files.get(node)!
  const map = new Map<string, File>()
  const root = windows ? 'C:\\Demo' : '/home/demo'
  function add(path: string, text: string, directory = false) { map.set(path, { path, text, directory, modified: now() }) }
  add(windows ? 'C:\\' : '/', '', true)
  if (!windows) add('/home', '', true)
  add(root, '', true)
  const sep = windows ? '\\' : '/'
  add(root + sep + 'projects', '', true)
  add(root + sep + 'logs', '', true)
  add(root + sep + 'README.txt', 'Spearmint 演示工作区\n这里可以浏览目录、编辑文本、上传下载文件。\n所有文件均为浏览器中的示例数据。\n')
  add(root + sep + 'projects' + sep + 'hello.py', 'from http.server import HTTPServer, SimpleHTTPRequestHandler\nHTTPServer(("0.0.0.0", 8080), SimpleHTTPRequestHandler).serve_forever()\n')
  add(root + sep + 'projects' + sep + 'config.json', '{\n  "name": "demo-api",\n  "port": 8080\n}\n')
  add(root + sep + 'logs' + sep + 'application.log', '[INFO] Demo API started on port 8080\n[INFO] GET /healthz 200\n')
  files.set(node, map)
  return map
}
function parent(path: string, windows: boolean) {
  const sep = windows ? '\\' : '/'
  const value = path.replace(/[\\/]+$/, '')
  const pos = value.lastIndexOf(sep)
  if (windows && value.length <= 2 || !windows && !value) return null
  return pos <= (windows ? 2 : 0) ? (windows ? value.slice(0, 2) + '\\' : '/') : value.slice(0, pos)
}
function fullPath(value: string, terminal: Terminal) {
  if (!value || value === '~') return terminal.windows ? 'C:\\Demo' : '/home/demo'
  if (value === '..') return parent(terminal.cwd, terminal.windows) || terminal.cwd
  const sep = terminal.windows ? '\\' : '/'
  return /^(?:[A-Za-z]:[\\/]|\/)/.test(value) ? value : terminal.cwd.replace(/[\\/]+$/, '') + sep + value
}
function list(path: string, terminal: Terminal) {
  const map = fileSystem(terminal.node, terminal.windows)
  return [...map.values()].filter(file => file.path !== path && parent(file.path, terminal.windows) === path)
}
function prompt(terminal: Terminal) {
  return terminal.windows ? `${terminal.cwd}>` : `\x1b[32mdemo@${demoNodes.find(node => node.id === terminal.node)?.name ?? 'node'}\x1b[0m:\x1b[34m${terminal.cwd}\x1b[0m$ `
}
function command(line: string, terminal: Terminal) {
  const [verb, ...args] = line.trim().split(/\s+/)
  const rest = args.join(' ')
  if (!verb) return ''
  if (['help', '?'].includes(verb)) return 'help · pwd · cd · ls / dir · cat / type · echo · whoami · hostname · date · uname -a · python --version · systemctl status · docker ps · clear · exit\r\n'
  if (['clear', 'cls'].includes(verb)) return '\x1b[2J\x1b[H'
  if (verb === 'pwd') return terminal.cwd + '\r\n'
  if (verb === 'cd') {
    const path = fullPath(rest.replace(/^"|"$/g, ''), terminal)
    if (fileSystem(terminal.node, terminal.windows).get(path)?.directory) { terminal.cwd = path; return '' }
    return '目录不存在。使用 ls 或 dir 查看当前目录。\r\n'
  }
  if (['ls', 'dir'].includes(verb)) return list(terminal.cwd, terminal).map(file => (file.directory ? '[DIR]  ' : '       ') + file.path.split(/[\\/]/).at(-1)).join('\r\n') + '\r\n'
  if (['cat', 'type'].includes(verb)) return (fileSystem(terminal.node, terminal.windows).get(fullPath(rest.replace(/^"|"$/g, ''), terminal))?.text || '文件不存在。').replace(/\r?\n/g, '\r\n') + '\r\n'
  if (verb === 'echo') return rest + '\r\n'
  if (verb === 'whoami') return 'demo-admin\r\n'
  if (verb === 'hostname') return (demoNodes.find(node => node.id === terminal.node)?.name || 'demo-node') + '\r\n'
  if (verb === 'date' || verb === 'time') return new Date().toLocaleString('zh-CN') + '\r\n'
  if (verb === 'uname') return 'Linux spearmint-demo 6.8.0 ' + (terminal.node === demoNodes[4].id ? 'aarch64' : 'x86_64') + ' GNU/Linux\r\n'
  if (verb.startsWith('python')) return 'Python 3.12.3\r\n'
  if (verb === 'systemctl') return '● nginx.service - A high performance web server\r\n   Loaded: loaded; enabled\r\n   Active: active (running)\r\n'
  if (verb === 'docker') return 'CONTAINER ID  IMAGE         STATUS       NAMES\r\nab12cd34ef56  postgres:16   Up 2 hours   demo-postgres\r\n'
  if (verb === 'ps' || verb === 'tasklist') return 'PID    NAME\r\n5024   demo-api\r\n5025   spearmint\r\n'
  if (verb === 'exit') { terminal.ended = true; return '会话已结束。\r\n' }
  return `已收到命令：${line}\r\n演示终端支持的命令请输入 help 查看。\r\n`
}
export function terminalRequest(node: string, id: string, action: string, body: any) {
  if (action === 'open') {
    if (!sessions.has(id)) {
      const windows = node === demoNodes[0].id || node === demoNodes[5].id
      const terminal: Terminal = { node, windows, cwd: windows ? 'C:\\Demo' : '/home/demo', line: '', sequence: 0, ended: false,
        output: 'Spearmint 交互终端\r\n输入 help 查看可用命令。\r\n\r\n' }
      fileSystem(node, windows)
      terminal.output += prompt(terminal)
      sessions.set(id, terminal)
    }
    return { session: id }
  }
  if (action === 'close') { sessions.delete(id); return { closed: true } }
  const terminal = sessions.get(id)
  if (!terminal) throw new Error('终端会话已结束，请重新连接。')
  if (action === 'exchange') {
    if (body.sequence > terminal.sequence) {
      terminal.sequence = body.sequence
      for (const character of decoder.decode(decode(body.data || ''))) {
        if (character === '\r' || character === '\n') {
          terminal.output += '\r\n' + command(terminal.line, terminal)
          terminal.line = ''
          if (!terminal.ended) terminal.output += prompt(terminal)
        } else if (character === '\x03') { terminal.line = ''; terminal.output += '^C\r\n' + prompt(terminal) }
        else if (character === '\x7f' || character === '\b') { terminal.line = terminal.line.slice(0, -1); terminal.output += '\b \b' }
        else if (character >= ' ') { terminal.line += character; terminal.output += character }
      }
    }
    const output = encoder.encode(terminal.output)
    const slice = output.slice(body.offset, body.offset + 32768)
    return { data: encode(slice), offset: body.offset + slice.length, sequence: terminal.sequence, ended: terminal.ended }
  }
  if (action === 'files') {
    const map = fileSystem(node, terminal.windows)
    const path = body.path || (terminal.windows ? 'C:\\Demo' : '/home/demo')
    const version = (file: File) => `${contents(file).length}:${file.modified}`
    if (body.operation === 'list') {
      if (!map.get(path)?.directory) throw new Error('目录不存在。')
      return { path, parent: parent(path, terminal.windows), drives: terminal.windows ? ['C:\\'] : [], next_offset: null,
        items: list(path, terminal).map(file => ({ path: file.path, directory: !!file.directory, modified: file.modified,
          name: file.path.split(/[\\/]/).at(-1), size: contents(file).length, version: version(file) })) }
    }
    if (body.operation === 'read') {
      const file = map.get(path)
      if (!file) throw new Error('文件不存在。')
      const content = contents(file)
      const chunk = content.slice(body.offset, body.offset + 8192)
      return { data: encode(chunk), size: content.length, offset: body.offset + chunk.length, version: version(file) }
    }
    if (body.operation === 'begin') { uploads.set(body.transfer, { path, parts: [], offset: 0 }); return { offset: 0 } }
    const transfer = uploads.get(body.transfer)
    if (!transfer) throw new Error('传输记录不存在。')
    if (body.operation === 'write') {
      if (body.offset === transfer.offset) { const chunk = decode(body.data); transfer.parts.push(chunk); transfer.offset += chunk.length }
      return { offset: transfer.offset }
    }
    if (body.operation === 'finish') {
      const all = new Uint8Array(transfer.offset)
      let cursor = 0
      for (const part of transfer.parts) { all.set(part, cursor); cursor += part.length }
      // Preserve uploaded binary bytes through the download path as well.
      map.set(transfer.path, { path: transfer.path, text: decoder.decode(all), bytes: all, modified: now() })
      uploads.delete(body.transfer)
      return { path: transfer.path, size: all.length }
    }
  }
  throw new Error('未知的终端操作。')
}
