<div align="center">

# Spearmint

**A decentralized server management panel**

Manage services on Linux, Windows, and NAS devices from a single Grove.

[简体中文](README.md) · [English](README.en.md)<br>
[Downloads](https://github.com/EchoSixHIYA/Spearmint-Panel/releases) · [Quick start](#quick-start) · [Issues](https://github.com/EchoSixHIYA/Spearmint-Panel/issues)

</div>

## What Spearmint does

Each device runs its own panel. Once devices join the same Grove, a Grove administrator can sign in to any available panel and manage services across member nodes. Mesh traffic can travel directly or through other online members, so devices without a public IP can still be managed.

Each node supports up to 128 relay sessions, including sessions from a single origin, replacing the previous four-session origin cap. Verified standbys no longer occupy measurement slots; background sampling reserves capacity for primary and failover connections. Selection uses measured end-to-end latency. Existing bidirectional sessions are reused, and idle or duplicate sessions are retired after outstanding requests and replies drain. Intermediate nodes on older versions retain their earlier capacity limits.

The console has six areas: overview, services, nodes, operations, identity, and maintenance. Local and remote services share one workspace for control, logs, metadata editing, and unregistration. Nodes include topology, resources, enrollment, and the xterm.js terminal/file workspace. Personal sessions and display preferences live in the account menu. Planned mobile-node and Grove-federation pages remain visible and marked unfinished.

| Feature | What it does |
| --- | --- |
| Service management | Adopt system services and containers, or deploy an archive or Docker command remotely. Manage lifecycle, logs, resources, code updates, and rollback. |
| Grove and Mesh | Add members by invitation, synchronize the member directory, and see direct connections, relays, and active paths in the topology view. |
| Node seeding | Choose an initiator in the topology, test SSH, browse one directory at a time, and let the initiator install, start, and enroll the target. |
| Quick SSH | Select a node in the topology to open an xterm.js terminal over the existing Mesh, browse and transfer files, and edit text. Commands run as the target panel's OS account. |
| Maintenance | View host resources and operation history, and back up or restore node state with the CLI. |

## Partitions and offline operation

Existing Grove accounts can sign in and manage reachable nodes using their last confirmed permissions for up to 12 hours after the last valid identity confirmation. Sign-ins and ordinary operations do not extend this deadline; sessions retain their own idle and maximum lifetimes. The console shows the offline deadline. Account suspension, password and role changes, and member admission require a majority of the last confirmed voter roster, never a majority recalculated from nodes visible in one partition.

After reconnecting, members synchronize accounts and permissions before returning to normal operation. Suspended accounts lose their sessions. Identity synchronization does not replay failed service requests. A majority of voters must run the new protocol before new identity changes can be committed.

Linux seeding over root SSH prepares a dedicated ordinary runtime account, a systemd user manager and boot persistence, then installs and runs the panel as that account. Directory selection starts at /opt; private parent directories such as /root are not made accessible. Seeding with an existing ordinary account remains available.

Select “Participate in Grove voting after joining” during seeding, or open “Voting membership” from a node's topology context menu. New voters first synchronize identity, permissions and membership, then both the old and new rosters automatically confirm the change with a majority. No separate panel approvals or original issuer are needed. Three to seven voters are supported; three or five always-on devices are recommended. Demotion preserves ordinary membership, services and existing connections. Public trust for existing certificates is retained; only current voters approve new enrollment.

Membership requests and certificates are stored as a private extension to the local authorization record and included in backups. The database schema remains compatible with existing group updaters. Another accepting member can resume an interrupted change and offline members can catch up. Ordinary service operations remain available while identity mutations wait for membership confirmation. Roll back an older binary together with a compatible pre-upgrade backup. Upgrade a majority of existing voters and the intended new voter through Grove group updates first.

## Downloads

Choose a platform in [GitHub Releases](https://github.com/EchoSixHIYA/Spearmint-Panel/releases). Each native package includes the panel, Python runtime, and web UI.

| Platform | Archive name contains |
| --- | --- |
| Linux x86-64 with glibc 2.17 or later | `linux-amd64` · `.tar.gz` |
| Linux ARM64 with glibc 2.17 or later | `linux-arm64` · `.tar.gz` |
| Windows x64 | `windows-amd64` · `.zip` |

Keep the archive and its matching `.sha256` file in the same directory. On Linux, run `sha256sum -c <archive>.sha256`. On Windows, run `Get-FileHash <archive> -Algorithm SHA256` and compare the result with the value in the checksum file. Extract the archive and keep the `spearmint/` directory intact.

## Quick start

### Open the panel locally

1. Install [Caddy](https://caddyserver.com/docs/install). From the extracted `spearmint/` directory, run `caddy run --config deployment/Caddyfile.local --adapter caddyfile` and leave it running. Import the generated `caddy-data/pki/authorities/local/root.crt` into your user or browser trust store.
2. In a second terminal, go to the same directory and start the panel as a regular user.

   ```bash
   ./spearmint --origin https://127.0.0.1:18443 serve --bind 127.0.0.1 --port 8765 --open-setup
   ```

   ```powershell
   .\spearmint.exe --origin https://127.0.0.1:18443 serve --bind 127.0.0.1 --port 8765 --open-setup
   ```

3. Complete the browser setup wizard and enroll the local administrator's authenticator. If the setup link expires, run `spearmint setup-link --recover-and-open` as the panel user, or use `spearmint.exe` on Windows. Use the same configuration if the panel has a custom state directory.

### Run in the background

Set up a browser-accessible HTTPS address and a local reverse proxy to `127.0.0.1:8765`. The [Nginx example](deploy/nginx.conf.example) is also bundled with the package. Replace the example hostname with your panel's actual address.

- **Linux** Run `sh deployment/install-linux.sh https://panel.example.net` as the panel's regular user. The installer needs a systemd user session, `curl`, and `ss`. An administrator can enable linger to keep the user service running after logout.
  Linux system-service adoption uses one-time node-level host authorization, described below. No per-service allowlist is required.
- **Windows** Run `.\deployment\install-windows.ps1 -Origin 'https://panel.example.net'` in PowerShell. The installer creates a scheduled task and prints the first-run setup path.

### Add nodes and register services

1. Create a Grove under Nodes → Set up Grove on the first panel. To enroll an existing panel, copy a code under Nodes → Invite node, paste it under Nodes → Set up Grove → Join existing Grove on the target panel, and authenticate with a Grove account. Check the resulting connection in the topology view; manage accounts and roles under Identity and security.
2. To install Spearmint on a new device, open node seeding as a Grove administrator and pick an active member that can reach the target over SSH. After the connection test, the initiator detects the target OS and architecture, then automatically fetches and verifies the signed deployment package from its cache, GitHub Releases, or another Grove member. Browse to the installation directory to continue.
   Windows targets need the SSH SFTP subsystem and the built-in `cmd.exe`, `certutil.exe`, and `tar.exe`. The deployment account must be able to register a startup task. The panel task runs with that account's limited privileges.
3. In service management, choose the local or remote node where the service runs and register it. For an existing container or system service, use observe mode to check its status and logs before switching to manage mode.

### Adopt Linux system services

SSH seeding enables node-wide system-service management by default. The initiator uses the existing SSH session for a one-time host installation. When sudo requires a password, it uses the SSH login password unless a separate sudo password is provided. Credentials are only used during installation. There is no per-service allowlist; the panel continues to run as its ordinary account with `NoNewPrivileges=true`.

After upgrading an existing node, select **Authorize this node** on the service registration page or an observed service's management settings. Enter a host administrator account and password or SSH private key. The target authorizes its panel account through its own loopback SSH service, so no terminal or public IP is required. Advanced options accept a different SSH port and sudo password. Progress appears in the page; completion refreshes adoption readiness and switches an existing observed service to managed mode. Credentials remain in memory for this operation and are not written to task records, logs, or browser storage.

For command-line maintenance, the installation directory also provides:

```sh
sudo ./spearmint host-services enable --user "$(id -un)"
```

`host-services plan --user <panel-account>` prints the exact configuration first. Installation backs up existing configuration, installs a root-owned helper under `/usr/local/lib/spearmint/`, and registers `spearmint-host-<UID>.socket/.service`. The panel's OS account can request lifecycle operations and journal reads for existing system services through this local socket. The helper uses the host's existing `/usr/bin/python3` and does not install system packages or offer an arbitrary-command interface. Authorization covers the node and does not restart business services.

Before authorization, register a service in observation mode; directly readable logs remain available. The UI reports start, stop, restart, and log access separately. Seeding can also leave this option off to install a panel for foreground programs and Docker without system-service management.

### Authorize Docker management

When container discovery reports a permission error, select **Authorize Docker management** in the current page and verify a host administrator once. Docker deployment and existing container settings expose the same entry. The owning node uses its loopback SSH service; Python 3, systemd and `systemd-socket-proxyd` must be available. Access becomes effective immediately while existing containers keep running. Grove administrators can then manage containers, logs, deployment and updates on this Docker engine.

The node-service management seeding option grants system-service access and also grants Docker access when the target already has a running daemon. Missing or stopped Docker does not prevent seeding. The panel account's own Rootless engine remains preferred; an authorized local channel stays bound to the originally selected Unix socket. Host credentials are used for this operation only and are not saved.

### Deploy and update services

Under Services → Register service, select a node and choose Deploy new service, Register existing code, or Take over a running service. New deployments start in an independent directory, with an optional ZIP/TAR archive or commands that initialize and start the application; `docker run …` is also supported. Service names can be generated automatically. The target owns the job and reports preparation, startup and registration. Closing the browser after launch does not cancel the job.

New deployments default to `service-apps/` inside Spearmint's state directory. An optional empty target directory can hold code versions and persistent data instead. Spearmint enters the code directory automatically, so a startup command such as `python hello.py` needs no `cd`. Only these deployments support Spearmint code updates and rollback. Updates retain the original deployment location.

For code already uploaded to the target, choose Register existing code and include `cd` in the full startup command. Spearmint saves the launch script and manages startup, shutdown, logs and resource status. The code stays in place and remains user-maintained, with no code-update tab.

Archive applications start in the extracted directory, automatically entering a single enclosing folder. Files live in the selected deployment directory. Commands run as CMD scripts on Windows and `/bin/sh` scripts on Linux. Python commands and dependency manifests are detected automatically: each code version gets a target-local virtual environment, and `requirements.txt` or `pyproject.toml` is installed before switching. Optional advanced settings provide preparation commands and an existing-environment mode. Failed preparation leaves the running service untouched. The corresponding interpreter or toolchain must already be installed on the target.

Uploads are limited to 1 GiB, with a 4 GiB expanded limit. Two concurrent 256 KiB chunks carry individual and whole-file SHA-256 verification. After a connection loss, select the same archive to resume. Unfinished jobs are discoverable on the target, and identical local cached archives can be reused. Jobs continue after upload and launch without the browser. Both panels need the resumable deployment interface.

By default, `data/` is linked to an independent persistent directory. Advanced settings can add relative directories such as `uploads/`. `SPMT_APP_DIR` points to code and `SPMT_DATA_DIR` to persistent data (`%SPMT_DATA_DIR%` on Windows, `$SPMT_DATA_DIR` on Linux). Existing data takes precedence over packaged defaults. Files outside persistent directories belong to their code version and are removed with that version.

Use Code and updates in service details to replace an archive, edit the startup command, or change a Docker image/configuration. Files, dependencies and images are prepared before stopping the current service. Failed startup or readiness restores the previous version. Registration stays intact and one rollback version is retained. Temporary uploads, preparation caches and obsolete code environments are removed. Docker uses the node's configured local engine and pins the image ID before creating a container; cached images remain usable when pulling fails. Explicit mounts and existing anonymous volumes are preserved. Image-declared data directories and `/data` get stable persistent volumes, with `SPMT_DATA_DIR` available inside the container. Compose and compound shell commands are not supported. No global Docker prune runs. Adopted Windows/systemd services remain the responsibility of their original installer.

Default readiness checks that the process remains running and waits for Docker HEALTHCHECK when present. Optional local HTTP, TCP and command checks have configurable timeouts and stability periods; container commands execute inside the container. The panel reports readiness, failure reasons and recovery. Rollback restores code, configuration or the old container, without reverting data or database schemas. Back up application data before upgrading.

### Update Grove nodes

Once the nodes run native packages with group update support, sign in as a Grove administrator and open **Deployments → Grove group update**. Check for a signed GitHub release and start the update. Each node first tries to download the archive for its platform from GitHub, then tries other members of the same Grove over Mesh. The installer restarts the panel, and the update page shows each node’s result. Offline nodes receive the update when they reconnect while the job is active.

Automatic updates support native panels installed as Linux systemd user services or Windows scheduled tasks. Releases with database schema changes require a manual migration. For a private GitHub repository, at least one GitHub-reachable Grove panel needs a read-only `SPEARMINT_GITHUB_TOKEN` in its process environment.

To publish a group update, run `python -m scripts.sign_update <archive-directory> --tag <release-tag> --commit <full-commit> --key <private-key-path>` and upload the resulting `update-index.json` alongside the three platform archives in the same GitHub release. Keep the signing key in a private directory on the release machine.

### State and backups

The default state directory is `~/.local/state/spearmint/` on Linux and `%LOCALAPPDATA%\spearmint\` on Windows. Set `SPEARMINT_STATE_DIR` to use a different absolute path. Stop the panel and run `spearmint backup <backup-directory>` as its service account, then verify it with `spearmint verify-backup <backup-directory>`. To restore, keep the panel stopped and run `spearmint restore <backup-directory>`. Use `spearmint.exe` on Windows.

## Run from source

You need Python 3.12 and the Node.js version in `web/.node-version`. Create `.venv` at the repository root, install dependencies, and build the frontend.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps .
npm --prefix web ci
npm --prefix web run build
spearmint --web-dir web/dist --origin https://127.0.0.1:18443 serve --bind 127.0.0.1 --port 8765 --open-setup
```

On Windows, use `py -3.12 -m venv .venv` and `.\.venv\Scripts\Activate.ps1` for the equivalent setup. For local HTTPS, use the same Caddy instructions with [deploy/package/Caddyfile.local](deploy/package/Caddyfile.local). To build a native package on its target platform, run `python -m pip install --no-cache-dir -r requirements-build.lock` in the prepared virtual environment, then run `python -m scripts.build_package`. Archives are written to `work/tmp/package-build/artifacts/`.

Both Linux native packages use glibc 2.17 as their runtime floor. Musl systems such as Alpine are outside this range. Managed panels still require the systemd user-service prerequisites above. This ABI range does not imply that every older distribution and kernel combination has been tested.

Release builds use [pinned CPython, glibc 2.17 base images and Argon2 source](scripts/linux-runtime.json), verified by SHA-256. Create the checkout `.venv` with that Python in the isolated build environment and collect manylinux2014 wheels for the locked dependencies. Run `python -m scripts.prepare_linux_dependencies --wheelhouse <wheels> --argon2-source <source archive>`; it uses the [additional build-tool lock](requirements-linux-build.lock) to rebuild the same Argon2 version rather than inheriting the newer ABI required by its official wheel. Install this project and run `python -m scripts.build_package`. Native builds and local QEMU are supported. Packaging and release verification inspect every ELF file and reject symbol requirements newer than 2.17. Run the full native package at the minimum baseline, checking login, deployment, update and rollback, followed by regression on newer systems.

## License

Spearmint is licensed under the [GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only).
