<div align="center">

# Spearmint

**去中心化服务器集群管理面板**

在一个 Grove 中管理 Linux、Windows 和 NAS 上的服务。

[简体中文](README.md) · [English](README.en.md)<br>
[下载](https://github.com/EchoSixHIYA/Spearmint-Panel/releases) · [快速开始](#快速开始) · [问题反馈](https://github.com/EchoSixHIYA/Spearmint-Panel/issues)

</div>

## Spearmint 能做什么

每台设备运行自己的面板。加入同一 Grove 后，可以在任一可用面板使用 Grove 管理员账号管理成员节点上的服务。Mesh 可在成员之间建立直连或通过其他在线成员转发，支持纳管没有公网 IP 的设备。

每个节点支持最多 128 条中继会话，单个发起节点也不再受原来的 4 条限制。已验证备路与正在采样的任务分别计数，后台探测为主路及故障切换保留容量。路径依据端到端实测延迟选择，已有双向会话会复用；空闲及重复会话在请求和回执完成后回收。途经节点仍使用旧版本时，会保留该节点原有的容量限制。

控制台分为总览、服务、节点、操作中心、身份与安全、平台维护。服务列表统一展示本机与远程程序；启停、日志、信息编辑和取消登记都在当前面板完成。节点内提供拓扑、资源、添加节点及「终端与文件」，个人会话和显示偏好收在账户菜单。移动节点与跨 Grove 连接保留可见的「未完成」入口。

| 功能 | 说明 |
| --- | --- |
| 服务管理 | 远程接管系统服务和容器，或上传程序包、填写 Docker 命令部署新服务。统一启停、日志、资源、代码更新与回滚。 |
| Grove 与 Mesh | 用邀请码添加成员，同步成员目录，在拓扑图查看直连、转发和当前路径。 |
| 节点播种 | 在拓扑图选发起节点，测试 SSH 连接并逐层选择安装目录，交由发起节点安装、启动和接入。 |
| 快速 SSH | 在拓扑图选目标节点，通过现有 Mesh 打开 xterm.js 交互终端，浏览、上传下载文件和编辑文本。终端使用目标面板的运行账号。 |
| 运行维护 | 查看主机资源和操作记录，使用面板命令备份和恢复节点状态。 |

## 网络分区与离线运维

已有 Grove 账号可按最后确认的权限继续登录并管理当前可达节点。离线窗口为最后一次有效身份确认后的 12 小时，登录和普通操作不会延长它；已有会话仍遵守自身的空闲与最长时限。页面在离线时显示截止时间。账号停用、改密、角色和新成员接入需要最近确认的投票名单中的多数成员同意，票数不会按分区中的在线人数重新计算。

恢复成员连接时先同步账号与权限；已停用账号的会话会退出，随后恢复正常运维。失败请求不会因为身份同步而重新执行。至少需要多数投票节点升级到新版，才能发起新的身份变更。

使用 root SSH 播种 Linux 时，发起节点会自动创建独立运行账号、准备 systemd 用户服务与开机保持，再以该普通账号安装和运行面板。默认从 /opt 选择安装位置，不会放开 /root 等私有父目录的权限。已有普通账号的播种方式保持可用。

播种时可勾选「加入后参与 Grove 投票」，也可在节点拓扑右键菜单的「投票资格」中调整已有成员。新节点先同步身份、权限和成员记录，再由新旧名单的多数节点自动确认；无需逐台审批或原签发节点在线。支持 3 至 7 个投票节点，建议使用 3 或 5 台长期在线设备。取消投票资格保留成员身份、服务与已有连接；为已有证书保留公开信任链，新签发审批只由当前投票名单执行。

名单变更与申请作为本机授权记录的私有扩展保存在节点数据库中，备份时一并保存，不改变现有群组更新器支持的数据库结构版本。支持发起节点离线后继续处理和离线成员追赶。变更期间普通服务运维继续可用，身份修改会等待名单确认。回滚旧程序时应同时恢复升级前备份。多数投票节点及拟晋升节点须先通过群组更新升级。

## 下载

在 [GitHub Releases](https://github.com/EchoSixHIYA/Spearmint-Panel/releases) 选择包。原生包包含程序、Python 运行时和 Web 界面。

| 平台 | 文件名包含 |
| --- | --- |
| Linux x86-64，glibc 2.17 或更新版本 | `linux-amd64` · `.tar.gz` |
| Linux ARM64，glibc 2.17 或更新版本 | `linux-arm64` · `.tar.gz` |
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
  Linux 系统服务接管使用一次性的节点主机授权，详见下方「接管 Linux 系统服务」；无需为每个服务配置允许列表。
- **Windows** 使用 PowerShell 执行 `.\deployment\install-windows.ps1 -Origin 'https://panel.example.net'`。安装器创建计划任务，首次配置入口由安装器打印。

### 添加节点并登记服务

1. 在首台面板的「节点 → 设置 Grove」创建 Grove。添加已有面板时，在「节点 → 邀请节点」复制邀请码，在目标面板的「节点 → 设置 Grove → 加入已有 Grove」粘贴并使用 Grove 账号验证。接入后，在拓扑图查看连接状态；账号和角色在「身份与安全」管理。
2. 安装还没有面板的设备时，用 Grove 管理员账号打开「节点播种」。选一台能通过 SSH 到达目标的有效成员。SSH 测试成功后，发起节点识别目标系统和架构，自动从缓存、GitHub Releases 或其他 Grove 成员获取并校验签名部署包。随后逐层选择安装目录并安装。
   Windows 目标需要启用 SSH 的 SFTP 子系统，且目标自带 `cmd.exe`、`certutil.exe` 和 `tar.exe`。部署账号需要能注册开机计划任务，面板任务以该账号的受限权限运行。
3. 在「服务管理」选择本机或远程节点并登记服务。登记已有容器或系统服务时，可先选择观察模式核对状态及日志，再按需切换到管理模式。

### 接管 Linux 系统服务

SSH 播种时默认勾选「启用节点系统服务管理」。发起节点会使用这次 SSH 会话安装一次主机管理服务；sudo 需要密码时，默认使用 SSH 登录密码，也可填写单独的 sudo 密码。凭据只在安装期间使用。无需给每个业务服务写允许列表，面板继续以普通用户和 `NoNewPrivileges=true` 运行。

已有节点升级后，在服务登记页或观察模式服务的「管理设置」点击「授权此节点」，填写主机管理员账号和密码（或 SSH 私钥）。目标节点通过自己的本机 SSH 完成授权，无需打开终端，也不依赖公网 IP。SSH 端口和独立 sudo 密码可在高级选项中填写。页面显示进度，完成后自动重新检查接管能力；已有观察服务会切换为托管。凭据仅在内存中用于这次操作，不写入任务记录、日志或浏览器存储。

如果需要通过命令行维护，也可在 Spearmint 安装目录执行：

```sh
sudo ./spearmint host-services enable --user "$(id -un)"
```

`host-services plan --user <面板用户>` 可先输出具体配置。启用命令会备份原有配置，在 `/usr/local/lib/spearmint/` 放置只由 root 写入的主机管理程序，并注册 `spearmint-host-<UID>.socket/.service`。仅该面板系统账号可请求对既有系统服务的启停、重启和日志读取，不提供任意命令执行接口。该服务使用主机已有的 `/usr/bin/python3`，不会自动安装系统软件。授权覆盖整个节点，业务服务不因授权操作而重启。

未授权时可先以「观察状态与日志」登记；能直接读取的日志会照常显示。界面分别显示启动、停止、重启和日志的可用情况。关闭播种中的系统服务管理选项，仍可安装用于自建程序及 Docker 的普通面板。

### 部署与更新服务

在「服务 → 登记服务」选择目标节点，再选择「一键部署新服务」「登记已有代码」或「接管运行中服务」。一键部署从独立的新目录开始，可上传 ZIP/TAR 程序包或填写用于初始化和启动的命令，也支持 `docker run …`。服务名称可留空自动生成。任务由目标节点执行，页面显示上传、准备、启动和登记结果；部署开始后关闭网页不影响任务。

一键部署默认使用 Spearmint 数据目录下的 `service-apps/`，也可选择目标机上的空目录存放代码版本和持久数据。Spearmint 自动进入代码目录后运行启动命令，例如 `python hello.py`，无需自行 `cd`。只有这类部署由 Spearmint 更新代码和回滚；后续更新沿用初始部署目录。

已经上传到目标机的代码选择「登记已有代码」，在完整启动命令中自行 `cd` 到代码目录。Spearmint 保存启动脚本并管理启停、日志和资源状态，不移动代码，不提供代码更新入口；原有代码由用户自行维护。

程序包从解压目录启动；包只有一层外部目录时会自动进入它。文件保存在所选部署目录。Windows 命令按 CMD 脚本执行，Linux 按 `/bin/sh` 脚本执行。自动识别 Python 启动命令或依赖文件，为每版代码创建目标机的独立虚拟环境，并在切换前安装 `requirements.txt` 或 `pyproject.toml`。其他依赖可在可选的「高级部署设置」填写准备命令，或选择使用已有环境；准备失败时旧服务继续运行。目标机需已有对应解释器或工具链。

单包上限 1 GiB，展开上限 4 GiB。浏览器按 256 KiB 分块、双路传输，并校验分块与整个文件的 SHA-256；断线后重选同一份包可续传。目标节点可找回未完成任务，并复用相同内容的本机缓存。上传完成、开始部署后无需保持浏览器在线。当前面板与目标节点都需升级到支持可续传部署的版本。

默认将代码中的 `data/` 连接到独立数据目录，也可在高级设置添加 `uploads/` 等相对目录。运行时可使用 `SPMT_APP_DIR` 指向代码目录、`SPMT_DATA_DIR` 指向持久化数据目录（Windows 写作 `%SPMT_DATA_DIR%`，Linux 写作 `$SPMT_DATA_DIR`）。目录中已有数据优先于新版包内默认文件；未纳入持久化目录的代码文件随版本清理。

在服务详情的「代码与更新」上传新版包、修改启动命令或更新 Docker 镜像配置。更新先准备文件、依赖或镜像，再短暂停止并切换服务；启动或就绪检查失败自动恢复旧版。服务登记保持不变，最多保留一份可手动回滚的旧版本；临时上传、准备缓存和过期代码环境自动清理。Docker 使用目标节点配置的本机引擎，按固定镜像 ID 创建容器，拉取失败时可使用已缓存镜像。保留显式挂载及原容器匿名卷，镜像声明的数据目录和 `/data` 自动使用稳定持久卷；容器内可用 `SPMT_DATA_DIR`。不支持 Compose 或多条 shell 命令，不会运行全局 prune。接管的 Windows/systemd 系统服务仍由原安装器更新。

默认就绪检查验证进程持续运行；容器若有 HEALTHCHECK，还会等待其健康状态。可选用目标机本地 HTTP、TCP 或检查命令，并设置等待与稳定时间；容器检查命令在容器中执行。页面显示检查结果、失败原因和恢复回执。回滚恢复代码、启动配置或旧容器，不恢复数据及数据库结构，升级前请备份业务数据。

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

Windows 可用 `py -3.12 -m venv .venv`、`.\.venv\Scripts\Activate.ps1` 执行等效步骤。本机 HTTPS 沿用上文的 Caddy 示例，源码路径为 [deploy/package/Caddyfile.local](deploy/package/Caddyfile.local)。要在目标平台生成原生归档，在已准备好的虚拟环境中运行 `python -m pip install --no-cache-dir -r requirements-build.lock`，再运行 `python -m scripts.build_package`。归档输出到 `work/tmp/package-build/artifacts/`。

Linux 两种架构的原生包统一以 glibc 2.17 为运行库下限；不包含 musl 系统（如 Alpine）。托管面板仍需要上文的 systemd 用户服务条件。这是运行库兼容范围，不代表对每一种旧发行版和内核组合均已验收。

发布构建使用 [固定版本的 CPython、glibc 2.17 基础镜像与 Argon2 源码](scripts/linux-runtime.json)，下载后核对 SHA-256。在隔离构建环境中用该 Python 创建仓库 `.venv`，准备锁定依赖对应的 manylinux2014 wheel，然后执行 `python -m scripts.prepare_linux_dependencies --wheelhouse <wheel目录> --argon2-source <源码归档>`；该步骤按 [额外构建依赖](requirements-linux-build.lock) 重编同版本 Argon2，避免其官方 wheel 抬高 glibc 下限。最后安装本项目并执行 `python -m scripts.build_package`。支持原生构建或本机 QEMU。打包和发布验包都会逐一检查全部 ELF 文件，拒绝高于 2.17 的符号依赖；必须同时在最低基线中启动完整安装包，验证登录、部署、更新和回滚，再在较新系统回归。

## 许可证

Spearmint 使用 [GNU Affero 通用公共许可证第 3 版](LICENSE)（AGPL-3.0-only）。
