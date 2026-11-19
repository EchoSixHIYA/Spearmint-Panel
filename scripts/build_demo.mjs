/** Build an offline file://-compatible demo; no backend or module loader required. */
import { build } from '../web/node_modules/vite/dist/node/index.js'
import { copyFile, mkdir, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve, join } from 'node:path'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const output = resolve(process.argv[2] || join(root, 'work/tmp/static-demo/package'))
await build({ root: join(root, 'web'), configFile: false, base: './',
  define: { 'process.env.NODE_ENV': JSON.stringify('production'), 'location.origin': JSON.stringify('https://workstation.demo.example:18443') },
  plugins: [{ name: 'demo-planned-status', enforce: 'pre', transform(code, id) {
    if (id.replaceAll('\\', '/').endsWith('/src/console-layout.tsx')) return code.replace('>规划</span>', '>未完成</span>')
  } }],
  build: { outDir: output, emptyOutDir: false, license: { fileName: 'THIRD_PARTY_LICENSES.md' },
    lib: { entry: join(root, 'web/demo/entry.tsx'), name: 'SpearmintDemo', formats: ['iife'], fileName: () => 'spearmint-demo.js', cssFileName: 'spearmint-demo' },
    rolldownOptions: { output: { codeSplitting: false } },
  },
})
await mkdir(output, { recursive: true })
await copyFile(join(root, 'web/src/favicon.svg'), join(output, 'favicon.svg'))
await copyFile(join(root, 'LICENSE'), join(output, 'LICENSE.txt'))
await copyFile(join(root, 'web/demo/功能说明.html'), join(output, '功能说明.html'))
await writeFile(join(output, 'index.html'), `<!doctype html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spearmint · 离线演示</title><link rel="icon" href="./favicon.svg"><link rel="stylesheet" href="./spearmint-demo.css">
<script defer src="./spearmint-demo.js"></script></head><body><div id="root"></div><noscript>请启用 JavaScript 后打开演示页面。</noscript></body></html>\n`, 'utf8')
await writeFile(join(output, '打开演示.txt'), '解压整个文件夹后，双击 index.html。无需安装、无需启动服务，支持离线演示。\r\n功能范围与演示步骤见「功能说明.html」。\r\n', 'utf8')
console.log('Offline demo:', output)
