<div align="center">

# Spearmint

**A decentralized server management panel**

Manage services on Linux, Windows, and NAS devices from a single Grove.

[简体中文](README.md) · [English](README.en.md)<br>
[Downloads](https://github.com/EchoSixHIYA/Spearmint-Panel/releases) · [Quick start](#quick-start) · [Issues](https://github.com/EchoSixHIYA/Spearmint-Panel/issues)

</div>

## What Spearmint does

Each device runs its own panel. Once devices join the same Grove, a Grove administrator can sign in to any available panel and manage services across member nodes. Mesh traffic can travel directly or through other online members, so devices without a public IP can still be managed.

| Feature | What it does |
| --- | --- |
| Service management | Register foreground programs, system services, and containers locally or remotely. View status and logs and run supported start, stop, and restart operations. |
| Grove and Mesh | Add members by invitation, synchronize the member directory, and see direct connections, relays, and active paths in the topology view. |
| Node seeding | Choose an initiator in the topology, test SSH, browse one directory at a time, and let the initiator install, start, and enroll the target. |
| Maintenance | View host resources and operation history, and back up or restore node state with the CLI. |

## Downloads

Choose a platform in [GitHub Releases](https://github.com/EchoSixHIYA/Spearmint-Panel/releases). Each native package includes the panel, Python runtime, and web UI.

| Platform | Archive name contains |
| --- | --- |
| Linux x86-64 with glibc 2.39 or later | `linux-amd64` · `.tar.gz` |
| Linux ARM64 with glibc 2.39 or later | `linux-arm64` · `.tar.gz` |
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
  If the panel account already manages system services through scoped `sudoers` rules, add `--allow-delegated-systemd` when adopting the existing installation and preserve its `SPEARMINT_SYSTEMD_UNITS` setting. Later upgrades preserve this option.
- **Windows** Run `.\deployment\install-windows.ps1 -Origin 'https://panel.example.net'` in PowerShell. The installer creates a scheduled task and prints the first-run setup path.

### Add nodes and register services

1. Create a Grove on the first panel. To enroll an existing panel, copy an invitation from the Grove members page, paste it into the target panel, and authenticate with a Grove account. Check the resulting connection in the topology view.
2. To install Spearmint on a new device, open node seeding as a Grove administrator and pick an active member that can reach the target over SSH. After the connection test, the initiator detects the target OS and architecture, then automatically fetches and verifies the signed deployment package from its cache, GitHub Releases, or another Grove member. Browse to the installation directory to continue.
3. In service management, choose the local or remote node where the service runs and register it. For an existing container or system service, use observe mode to check its status and logs before switching to manage mode.

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

On Windows, use `py -3.12 -m venv .venv` and `.\.venv\Scripts\Activate.ps1` for the equivalent setup. For local HTTPS, use the same Caddy instructions with [deploy/package/Caddyfile.local](deploy/package/Caddyfile.local). To build a native package on its target platform, install `pyinstaller==6.22.3` in the prepared environment and run `python scripts/build_package.py`. Archives are written to `work/tmp/package-build/artifacts/`.

## License

Spearmint is licensed under the [GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only).
