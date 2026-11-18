<div align="center">

# Spearmint

**去中心化服务器集群管理面板**

在一个 Grove 中管理 Linux、Windows 和 NAS 上的服务。

[简体中文](README.md) · [English](README.en.md)<br>
[下载](https://github.com/EchoSixHIYA/Spearmint-Panel/releases) · [快速开始](#快速开始) · [问题反馈](https://github.com/EchoSixHIYA/Spearmint-Panel/issues)

</div>

## Spearmint 能做什么

每台设备运行自己的面板。加入同一 Grove 后，可以在任一可用面板使用 Grove 管理员账号管理成员节点上的服务。Mesh 可在成员之间建立直连或通过其他在线成员转发，支持纳管没有公网 IP 的设备。

| 功能 | 说明 |
| --- | --- |
| 服务管理 | 在本机或远程节点登记前台程序、系统服务和容器，查看状态及日志，并执行支持的启停和重启。 |
| Grove 与 Mesh | 用邀请码添加成员，同步成员目录，在拓扑图查看直连、转发和当前路径。 |
| 节点播种 | 在拓扑图选发起节点，测试 SSH 连接并逐层选择安装目录，交由发起节点安装、启动和接入。 |
| 运行维护 | 查看主机资源和操作记录，使用面板命令备份和恢复节点状态。 |

## 下载

在 [GitHub Releases](https://github.com/EchoSixHIYA/Spearmint-Panel/releases) 选择包。原生包包含程序、Python 运行时和 Web 界面。

| 平台 | 文件名包含 |
| --- | --- |
| Linux x86-64，glibc 2.39 或更新版本 | `linux-amd64` · `.tar.gz` |
| Linux ARM64，glibc 2.39 或更新版本 | `linux-arm64` · `.tar.gz` |
| Windows x64 | `windows-amd64` · `.zip` |

将归档与同名的 `.sha256` 文件放在一起。Linux 用 `sha256sum -c <归档名>.sha256` 校验。Windows 用 `Get-FileHash <归档名> -Algorithm SHA256`，将结果与校验文件中的值比较。解包后保留整个 `spearmint/` 目录。

## 快速开始

### 在本机打开面板

1. 安装 [Caddy](https://caddyserver.com/docs/install)。在解包后的 `spearmint/` 目录执行 `caddy run --config deployment/Caddyfile.local --adapter caddyfile`，保持窗口运行。将生成的 `caddy-data/pki/authorities/local/root.crt` 导入当前用户或浏览器的受信任证书库。
2. 在第二个终端进入同一目录，以普通用户启动面板。

   ```bash
   ./spearmint --origin https://127.0.0.1:18443 serve --bind 127.0.0.1 --port 8765 --open-setup
   ```

   ```powershell
   .\spearmint.exe --origin https://127.0.0.1:18443 serve --bind 127.0.0.1 --port 8765 --open-setup
   ```

3. 在浏览器打开首次配置向导，设置本机管理员及动态验证码。首次入口过期后，以运行面板的账号执行 `spearmint setup-link --recover-and-open`，Windows 使用 `spearmint.exe`。使用自定义状态目录时，命令需沿用同一配置。

### 后台部署

准备浏览器可访问的 HTTPS 地址，将本地反向代理指向 `127.0.0.1:8765`。仓库提供 [Nginx 配置示例](deploy/nginx.conf.example)，包内也包含该示例。将命令中的域名替换为实际面板地址。

- **Linux** 使用运行面板的普通用户执行 `sh deployment/install-linux.sh https://panel.example.net`。安装器需要 systemd 用户会话、`curl` 和 `ss`。如需退出登录后仍运行，可由系统管理员为该用户启用 linger。
- **Windows** 使用 PowerShell 执行 `.\deployment\install-windows.ps1 -Origin 'https://panel.example.net'`。安装器创建计划任务，首次配置入口由安装器打印。

### 添加节点并登记服务

1. 在首台面板创建 Grove。添加已有面板时，从 Grove 成员页面复制邀请码，在目标面板粘贴并使用 Grove 账号验证。接入后，在拓扑图查看连接状态。
2. 安装还没有面板的设备时，用 Grove 管理员账号打开「节点播种」。选一台能通过 SSH 到达目标的有效成员。SSH 测试成功后，发起节点识别目标系统和架构，自动从缓存、GitHub Releases 或其他 Grove 成员获取并校验签名部署包。随后逐层选择安装目录并安装。
3. 在「服务管理」选择本机或远程节点并登记服务。登记已有容器或系统服务时，可先选择观察模式核对状态及日志，再按需切换到管理模式。

### 更新 Grove 节点

安装支持群组更新的原生部署包后，使用 Grove 管理员账号打开「应用部署 → Grove 群组更新」。检查已签名的 GitHub 发布并发起更新。每个节点先尝试从 GitHub 下载适合自己平台的包，无法下载时会尝试通过 Mesh 从同一 Grove 的节点取得包。安装完成后面板自动重启，页面显示逐节点结果。离线节点在任务有效期内重新连线后会继续接收更新。

通过 Linux systemd 用户服务或 Windows 计划任务安装的面板可以自动升级。涉及数据库 schema 变更的发布仍需手动迁移。GitHub 仓库为私有时，至少让一台能访问 GitHub 的 Grove 节点的面板进程拥有只读的 `SPEARMINT_GITHUB_TOKEN`。

发布供群组更新使用的版本时，用 `python -m scripts.sign_update <原生包目录> --tag <发布标签> --commit <完整提交> --key <签名私钥路径>` 生成 `update-index.json`，将它与三个平台的归档一起上传到同一个 GitHub Release。签名私钥保留在发布机的私有目录。

### 状态与备份

默认状态目录为 Linux `~/.local/state/spearmint/`、Windows `%LOCALAPPDATA%\spearmint\`。用 `SPEARMINT_STATE_DIR` 指定独立绝对路径。以面板运行账号停止面板后执行 `spearmint backup <备份目录>`，使用 `spearmint verify-backup <备份目录>` 校验；恢复时保持面板停止并执行 `spearmint restore <备份目录>`。Windows 将命令名换成 `spearmint.exe`。

## 从源码运行

需要 Python 3.12，以及 `web/.node-version` 指定的 Node.js。先在仓库根目录创建 `.venv`，再安装依赖和构建前端。

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps .
npm --prefix web ci
npm --prefix web run build
spearmint --web-dir web/dist --origin https://127.0.0.1:18443 serve --bind 127.0.0.1 --port 8765 --open-setup
```

Windows 可用 `py -3.12 -m venv .venv`、`.\.venv\Scripts\Activate.ps1` 执行等效步骤。本机 HTTPS 沿用上文的 Caddy 示例，源码路径为 [deploy/package/Caddyfile.local](deploy/package/Caddyfile.local)。要在目标平台生成原生归档，在已准备好的环境中安装 `pyinstaller==6.22.3`，运行 `python scripts/build_package.py`。归档输出到 `work/tmp/package-build/artifacts/`。

## 许可证

Spearmint 使用 [GNU Affero 通用公共许可证第 3 版](LICENSE)（AGPL-3.0-only）。
