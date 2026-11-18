from argparse import REMAINDER, ArgumentParser, BooleanOptionalAction, Namespace
from contextlib import contextmanager
from getpass import getpass
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
import json
import os
from pathlib import Path
from socket import socket
import sqlite3
import ssl
import sys
from threading import Thread
import time
from urllib.parse import urlsplit

import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import accounts, auth, factors, frp, frp_runtime, grove, grove_admission, grove_continuity, grove_metadata, onboarding, passkeys, seed_admission
from .app import create_app
from .catalog import list_services, process_spec, register
from .config import Config
from .control import ControlError
from .drivers import DockerDriver, ProcessDriver, SystemUnitDriver
from .windows_services import WindowsServiceDriver
from .host import HostError, check_docker, command
from .maintenance import backup, migrate_offline, migration_plan, rebuild_identity, restore, verify_backup
from .peer import discovery, evidence, mesh_policy, pairing, quarantine
from . import mesh_enrollment
from .peer import policy
from .peer.credentials import NODE_ID, make_csr, read_pem
from .peer.manager import read_runtime
from .peer.operation_policy import audit_export, protect_service
from .peer.projection import export_service
from .peer.policy_records import encoded, read_document, root_id
from .peer.policy_workstation import read_public
from .peer.protocol import PeerError
from .peer.workstation import configure_approve, sign_approval, write_new
from .seeding import TARGETS_FILE, SeedDeployments, load_deployment_config
from .service_mode import change_mode
from .service_removal import unregister
from .state import State, StateError
from .platforms import capabilities, systemd_available, WINDOWS
from .state import private_path
from .web_bundle import WebEntry, check_web_bundle


def read_password(label: str = "Administrator", *, allow_stdin: bool = False) -> str:
    if not allow_stdin and not sys.stdin.isatty():
        raise StateError("A terminal is required to enter an account password")
    password = sys.stdin.readline().rstrip("\r\n") if allow_stdin else getpass(f"{label} password: ")
    if not 12 <= len(password) <= 256:
        raise StateError("Account password must contain 12 to 256 characters")
    confirmation = sys.stdin.readline().rstrip("\r\n") if allow_stdin else getpass("Confirm password: ")
    if password != confirmation:
        raise StateError("Passwords did not match")
    return auth.PASSWORD.hash(password)


def validate_tls_paths(certificate: Path | None, key: Path | None) -> None:
    if (certificate is None) != (key is None):
        raise ValueError("Native HTTPS requires both --tls-cert and --tls-key")
    if key is not None:
        private_path(key, 0o600)


class DesktopSetupServer(uvicorn.Server):
    def __init__(self, config: uvicorn.Config, state: State) -> None:
        super().__init__(config)
        self.state = state

    async def startup(self, sockets: list[socket] | None = None) -> None:
        await super().startup(sockets=sockets)
        if self.started and not self.should_exit:
            Thread(target=self.open_setup, daemon=True).start()

    def open_setup(self) -> None:
        try:
            print(onboarding.handoff_status(self.state, open_browser=True), flush=True)
        except (StateError, OSError, sqlite3.Error) as exc:
            print(f"Could not open first-run setup: {exc}. Run spearmint setup-link --status.",
                  file=sys.stderr, flush=True)


def setup_factor(state: State, config: Config, method: str, username: str | None, *, recover: bool = False) -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise StateError("A local terminal is required to issue an enrollment token")
    if method == "passkey":
        passkeys.relying_party(config.origin)
    with state.lock("maintenance.lock"):
        state.verify()
        if recover:
            with state.connect() as db:
                account = auth.account_for(db, username)
                if account is None:
                    raise StateError("Account is unavailable")
                account_name = account["username"]
            print("Local recovery removes this account's factors and recovery codes and revokes its sessions.")
            if input(f"Type the account name ({account_name}) to continue: ") != account_name:
                raise StateError("Factor recovery cancelled")
        factors.initialize_vault(state)
        token = auth.issue_enrollment(state, method, username, recover=recover)
    print(f"Enter this single-use {method} enrollment token on the sign-in page within {auth.ENROLLMENT_SECONDS} seconds.")
    print(token)
    if not recover:
        print("For an account with an active factor, sign in with that factor, then open authenticator settings in the panel within five minutes.")


def account_parser(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="account_command", required=True)
    commands.add_parser("list", help="List local accounts")
    add = commands.add_parser("add", help="Create a named account requiring factor enrollment")
    add.add_argument("username")
    add.add_argument("--role", choices=accounts.ROLES, required=True)
    for verb in ("enable", "disable", "passwd"):
        commands.add_parser(verb).add_argument("username")
    role = commands.add_parser("role", help="Change a named account's role and revoke its sessions")
    role.add_argument("username")
    role.add_argument("role", choices=accounts.ROLES)


def account_cli(state: State, args: Namespace) -> None:
    with state.lock("maintenance.lock"):
        state.verify()
        match args.account_command:
            case "list":
                with state.connect() as db:
                    rows = db.execute("""
                        SELECT id, username, role, enabled, require_mfa FROM panel_account ORDER BY username
                    """).fetchall()
                print(json.dumps([dict(row) for row in rows], indent=2, ensure_ascii=False))
            case "add":
                print(accounts.add(state, args.username, read_password("New account"), args.role))
            case "enable" | "disable":
                accounts.set_enabled(state, args.username, args.account_command == "enable")
            case "role":
                accounts.set_role(state, args.username, args.role)
            case "passwd":
                accounts.reset_password(state, args.username, read_password("Named account"))


def security_parser(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="security_command", required=True)
    root = commands.add_parser("pin-root", help="Pin or rotate the offline policy root")
    root.add_argument("public_key", type=Path)
    root.add_argument("--fingerprint", required=True)
    root.add_argument("--replace", help="Currently pinned fingerprint for a root rotation")
    commands.add_parser("import", help="Import a signed Mesh policy bundle").add_argument("file", type=Path)
    commands.add_parser("status", help="Show policy cursor and execution state")
    commands.add_parser("resume-request", help="Export the nonce for policy recovery")
    commands.add_parser("resume", help="Apply an independently signed recovery confirmation").add_argument("file", type=Path)
    bind = commands.add_parser("bind-user", help="Bind a local account to an active signed Mesh user")
    bind.add_argument("username")
    bind.add_argument("user_id")
    commands.add_parser("protect-service", help="Require M003 approvals for new remote operations").add_argument("service_id")
    audit_command = commands.add_parser("audit-export", help="Export operation, local and policy conflict audit evidence")
    audit_command.add_argument("output", type=Path)
    audit_command.add_argument("--after", type=int, default=0)
    audit_command.add_argument("--local-after", type=int, default=0)
    audit_command.add_argument("--conflict-after", type=int, default=0)
    audit_command.add_argument("--limit", type=int, default=200)
    conflicts = commands.add_parser('evidence-list', help='List recorded Mesh policy conflicts')
    conflicts.add_argument('--before', type=int)
    conflicts.add_argument('--limit', type=int, default=20)
    export = commands.add_parser('evidence-export', help='Export the two signed statements for one recorded conflict')
    export.add_argument('--term', type=int, required=True)
    export.add_argument('--root-public', type=Path, help='Independently trusted historical policy root')
    export.add_argument('--root-id', help='Approved fingerprint of that historical policy root')
    export.add_argument('output', type=Path)


def security_cli(state: State, args: Namespace) -> None:
    with state.lock("maintenance.lock"):
        node_id = state.verify()
        match args.security_command:
            case "pin-root":
                mesh_policy.pin_root(state, read_public(args.public_key), args.fingerprint, args.replace)
            case "import":
                status = mesh_policy.apply(state, read_document(args.file))
                if status == "conflict":
                    raise StateError("Conflicting policy retained. Remote policy writes remain frozen")
                print(status)
            case "status":
                with state.connect() as db:
                    db.execute("BEGIN")
                    print(json.dumps(mesh_policy.policy_status(db, int(time.time()))))
            case "resume-request":
                print(json.dumps(mesh_policy.resume_request(state)))
            case "resume":
                mesh_policy.resume(state, read_document(args.file, 4096))
            case "bind-user":
                mesh_policy.bind_user(state, args.username, args.user_id)
            case "protect-service":
                with state.connect(write=True) as db:
                    protect_service(db, args.service_id)
            case "audit-export":
                if min(args.after, args.local_after, args.conflict_after) < 0 or not 1 <= args.limit <= 1000:
                    raise ValueError("Audit export requires a non-negative cursor and a limit of 1 through 1000")
                with state.connect() as db:
                    db.execute("BEGIN")
                    document = audit_export(db, node_id, args.after, args.limit,
                                            local_after=args.local_after, conflict_after=args.conflict_after)
                write_new(args.output, (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode())
            case 'evidence-list':
                if not 1 <= args.limit <= 100 or args.before is not None and not 1 <= args.before < 2**63:
                    raise ValueError('Evidence listing requires a positive term cursor and a limit of 1 through 100')
                print(json.dumps(evidence.list_conflicts(state, before=args.before, limit=args.limit)))
            case 'evidence-export':
                if not 1 <= args.term < 2**63 or (args.root_public is None) != (args.root_id is None):
                    raise ValueError('Provide a positive policy term and both historical root options when applicable')
                root = read_public(args.root_public) if args.root_public is not None else None
                if root is not None and root_id(root) != args.root_id:
                    raise ValueError('Historical policy root does not match the approved fingerprint')
                document = evidence.export_report(state, args.term, root)
                write_new(args.output, encoded(document) + b'\n')


def frp_parser(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="frp_command", required=True)
    commands.add_parser("providers", help="List the node's configured FRP providers")
    commands.add_parser("list", help="Show this node's FRP mappings")
    commands.add_parser("revoke", help="Revoke an FRP mapping").add_argument("id")
    plan = commands.add_parser("plan", help="Preview an FRP mapping without publishing it")
    start = commands.add_parser("start", help="Start a time-limited FRP mapping on this node")
    for mapping in (plan, start):
        mapping.add_argument("service_id")
        mapping.add_argument("--provider", required=True)
        mapping.add_argument("--protocol", choices=frp.PROTOCOLS, required=True)
        public = mapping.add_mutually_exclusive_group(required=True)
        public.add_argument("--domain")
        public.add_argument("--public-port", type=int)
    plan.add_argument("--frpc", type=Path, help="Path to an installed frpc for offline configuration validation")
    start.add_argument("--frpc", type=Path, required=True, help="Path to an installed frpc")
    start.add_argument("--ttl", type=int, required=True, help="Mapping duration in seconds")


def frp_cli(state: State, args: Namespace) -> int:
    state.verify()
    code = 0
    match args.frp_command:
        case "list":
            result = frp_runtime.list_exposures(state)
        case "revoke":
            result = frp_runtime.revoke(state, args.id)
        case "start":
            result = frp_runtime.start(state, args.provider, args.service_id, args.protocol,
                                       args.frpc.expanduser().absolute(), args.ttl,
                                       domain=args.domain, public_port=args.public_port)
            code = int(result["status"] == "failed")
        case "providers":
            settings = frp.Settings.load(state.directory / "frp.toml")
            result = [settings.providers[name].summary() for name in sorted(settings.providers)]
        case "plan":
            settings = frp.Settings.load(state.directory / "frp.toml")
            plan = settings.plan(state, args.provider, args.service_id, args.protocol,
                                 domain=args.domain, public_port=args.public_port)
            result = plan.summary()
            if args.frpc is not None:
                plan.verify(args.frpc.expanduser().absolute(), state.directory)
                result["config_verified"] = True
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return code


def check_linger() -> str:
    linger = command(["/usr/bin/loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"])
    if linger != "yes":
        raise HostError("Enable linger for the panel account")
    return linger


def check_journal() -> str:
    record = command(["/usr/bin/journalctl", "--user", "--no-pager", "-n", "1", "-o", "json"])
    if not record.startswith("{"):
        raise HostError("No readable user journal entries. Check persistent storage and per-UID splitting")
    return "readable"


def panel_check_address(value: str) -> str:
    address = ip_address(value)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("Specify a concrete local listen address")
    return str(address)


@contextmanager
def local_panel_response(config: Config, address: str, port: int, path: str, context: ssl.SSLContext | None):
    connection = HTTPConnection(address, port, timeout=1, source_address=(address, 0))
    try:
        connection.connect()
        if context is not None:
            connection.sock = context.wrap_socket(connection.sock, server_hostname=urlsplit(config.origin).hostname)
        connection.request("GET", path, headers={"Host": config.authority})
        with connection.getresponse() as response:
            if response.status != 200:
                raise HostError(f"{path} returned HTTP {response.status}")
            yield response
    except HTTPException as exc:
        raise HostError(f"Invalid or incomplete response from {path}") from exc
    except ssl.SSLCertVerificationError:
        raise
    except OSError as exc:
        raise HostError(f"{path}: {exc}") from exc
    finally:
        connection.close()


def check_local_panel(config: Config, port: int, *, https: bool, ca: Path | None,
                      bind: str = "127.0.0.1", check_web: bool = False) -> str:
    address = panel_check_address(bind)
    context = ssl.create_default_context(cafile=ca) if https else None
    with local_panel_response(config, address, port, "/healthz", context) as response:
        if response.read(129) != b'{"status":"ok"}':
            raise HostError("Unexpected response from the health endpoint")
    status = f"{'HTTPS' if https else 'HTTP'} 200"
    if not check_web:
        return status
    with local_panel_response(config, address, port, "/", context) as response:
        if response.headers.get_content_type() != 'text/html':
            raise HostError("Panel homepage did not return HTML")
        body = response.read(128 * 1024 + 1)
        if len(body) > 128 * 1024:
            raise HostError("Panel homepage exceeds 128 KiB")
        entry = WebEntry.parse(body.decode('utf-8'))
        assets = entry.served_assets()
    for path in assets:
        with local_panel_response(config, address, port, path, context) as response:
            content_type = response.headers.get_content_type()
            if (content_type in ('text/html', 'application/xhtml+xml')
                    or path.endswith('.js') and content_type not in ('text/javascript', 'application/javascript')
                    or path.endswith('.css') and content_type != 'text/css'):
                raise HostError(f"{path} returned unexpected content type {content_type}")
            if not response.read(1):
                raise HostError(f"{path} returned an empty response")
    return f"{status}; homepage served ({len(assets)} entry assets checked)"


def doctor(config: Config, state: State, port: int, *, https: bool = False, ca: Path | None = None,
           bind: str = "127.0.0.1", check_web: bool = False) -> int:
    print(f"INFO State directory  {state.directory}")
    print(f"INFO Web directory  {config.web_dir}")
    print(f"INFO Panel origin  {config.origin}")
    checks = [
        ("State identity", state.verify, True),
        ("Platform", lambda: json.dumps(capabilities()), True),
        ("Web bundle", lambda: check_web_bundle(config.web_dir), True),
        ("Local Docker", lambda: check_docker(config.docker_socket), False),
    ]
    if systemd_available():
        checks.extend([
            ("User manager", lambda: command(["/usr/bin/systemctl", "--user", "is-active", "default.target"]), True),
            ("Linger", check_linger, True),
            ("User journal", check_journal, True),
        ])
    ok = True
    for label, check, required in checks:
        try:
            result = check()
            if not result:
                raise HostError("Not available")
            print(f"OK   {label}  {result}")
        except (StateError, HostError, OSError, sqlite3.Error, ValueError) as exc:
            print(f"{'FAIL' if required else 'WARN'} {label}  {exc}")
            ok = ok and not required
    if ok:
        if WINDOWS:
            driver = WindowsServiceDriver(state)
            try:
                allowed = driver.allowed_services()
                print(f"INFO Windows service allowlist  {len(allowed)} configured")
                for service in list_services(state, "process"):
                    if service.existing_windows_service:
                        result = driver.management_status(service.target)
                        status = result.get("status", "unknown")
                        mode = "manage" if service.managed else "observe"
                        readiness = "control rights available" if result["ready"] else result["reason"]
                        print(f"{'OK  ' if result['ready'] else 'WARN'} Windows service {service.target}  "
                              f"{status}, {mode}, {readiness}")
            except HostError as error:
                print(f"WARN Windows service allowlist  {error}")
        with state.connect() as db:
            members = pairing.members(db)
        enabled = [pair for pair in members.values() if pair.enabled]
        live = read_runtime(state) or {}
        live_members = {item["node_id"]: item for item in live.get("neighbors", [])}
        for pair in enabled:
            try:
                pair.validate(state.identity()[0])
                print("OK   Peer certificates and SAN")
            except (ValueError, OSError) as exc:
                print(f"FAIL Peer certificates  {exc}")
                ok = False
            current = live_members.get(pair.node_id, {})
            status = current.get("status", "not connected" if live else "panel not running")
            print(f"{'OK  ' if status == 'online' else 'INFO'} Peer {pair.node_id}  {status}")
            if current.get("detail"):
                print(f"     {current['detail']}")
            ok = ok and status != "error"
        if not enabled:
            print("INFO Peer listener disabled")
    try:
        result = check_local_panel(config, port, https=https, ca=ca, bind=bind, check_web=check_web)
        print("OK   Local panel  " + result)
    except (HostError, OSError, ValueError) as exc:
        scheme = "https" if https else "http"
        host = f"[{bind}]" if ":" in bind else bind
        path = "" if check_web else "/healthz"
        print(f"{'FAIL' if https or check_web else 'INFO'} Local panel  {scheme}://{host}:{port}{path}: {exc}")
        ok = ok and not (https or check_web)
    return 0 if ok else 1


def peer_parser(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="peer_command", required=True)
    csr = commands.add_parser("csr", help="Create a CSR signed by this node's existing key")
    csr.add_argument("--address", required=True)
    csr.add_argument("output", type=Path)
    commands.add_parser("enrollment-key", help="Create this voter's independent enrollment authority")
    commands.add_parser("enrollment-activate", help="Activate the configured enrollment authority bundle")
    add = commands.add_parser("add", help="Import and verify a pairing, initially disabled")
    add.add_argument("--node-id", required=True)
    add.add_argument("--mesh-id", required=True)
    add.add_argument("--bind-ip", required=True)
    add.add_argument("--listen-port", type=int, default=8766)
    add.add_argument("--source-ip", required=True)
    add.add_argument("--host", required=True, help="The peer's DNS or IP SAN, using source IP for TCP")
    add.add_argument("--port", type=int, default=8766)
    add.add_argument("--fingerprint", required=True)
    add.add_argument("--ca", required=True, type=Path)
    add.add_argument("--certificate", required=True, type=Path)
    add.add_argument("--peer-certificate", required=True, type=Path)
    mesh = commands.add_parser("mesh-config", help="Configure the local Mesh identity and listener")
    mesh.add_argument("--mesh-id", required=True)
    mesh.add_argument("--bind-ip", required=True)
    mesh.add_argument("--allow-public-bind", action="store_true", help="Allow this exact public IP as the Mesh bind address")
    mesh.add_argument("--listen-port", type=int, default=8766)
    mesh.add_argument("--ca", required=True, type=Path)
    mesh.add_argument("--certificate", required=True, type=Path)
    options = commands.add_parser("mesh-options", help="Set Mesh discovery and forwarding permissions")
    options.add_argument("--discover", action=BooleanOptionalAction)
    options.add_argument("--forward", action=BooleanOptionalAction)
    member = commands.add_parser("member-add", help="Approve a member certificate, initially disabled")
    member.add_argument("--node-id", required=True)
    member.add_argument("--host", required=True, help="Approved DNS or IP SAN")
    member.add_argument("--fingerprint", required=True)
    member.add_argument("--peer-certificate", required=True, type=Path)
    member.add_argument("--routed", action="store_true", help="Allow this member to use separately granted access over a Mesh route")
    generation = commands.add_parser("member-generation", help="Approve the member's signed address generation")
    generation.add_argument("--node-id", required=True)
    generation.add_argument("--generation", required=True)
    neighbor = commands.add_parser("neighbor-set", help="Allow a fixed neighbor address")
    neighbor.add_argument("--node-id", required=True)
    neighbor.add_argument("--source-ip", required=True)
    neighbor.add_argument("--port", type=int, default=8766)
    neighbor.add_argument("--allow-public", action="store_true", help="Allow this exact public IP for the pinned member")
    network = commands.add_parser("neighbor-allow", help="Allow a member to connect using a discovered address within a private CIDR")
    network.add_argument("--node-id", required=True)
    network.add_argument("--network", required=True)
    network.add_argument("--port", type=int, default=8766)
    commands.add_parser("neighbor-clear", help="Remove a member's direct neighbor address").add_argument("--node-id", required=True)
    commands.add_parser("list", help="List local pairing and runtime status")
    commands.add_parser("enable", help="Activate a verified member or the M001 pairing").add_argument("--node-id")
    commands.add_parser("disable", help="Suspend a member or the M001 pairing").add_argument("--node-id")
    isolate = commands.add_parser("quarantine", help="Block this member locally without changing Grove membership")
    isolate.add_argument("--node-id", required=True)
    isolate.add_argument("--reason", required=True)
    commands.add_parser("unquarantine", help="Remove this member's local isolation").add_argument("--node-id", required=True)
    commands.add_parser("remove", help="Remove a member or the M001 pairing").add_argument("--node-id")
    export = commands.add_parser("export", help="Set the peer's read permissions for one local service")
    export.add_argument("service_id")
    export.add_argument("--node-id")
    export.add_argument("--directory", action="store_true")
    export.add_argument("--status", action="store_true")
    export.add_argument("--logs", action="store_true")
    unexport = commands.add_parser("unexport", help="Revoke the peer's read permissions")
    unexport.add_argument("service_id")
    unexport.add_argument("--node-id")
    commands.add_parser("operator-add", help="Import an operator's public Ed25519 key").add_argument("public_key", type=Path)
    grant = commands.add_parser("grant", help="Grant an operator actions for one exported service")
    account = commands.add_parser("grant-account", help="Grant signed-in administrators of one paired node service actions")
    for command in (grant, account):
        command.add_argument("service_id")
        command.add_argument("--node-id")
        command.add_argument("--action", choices=("start", "stop", "restart"), action="append", required=True)
        command.add_argument("--ttl", type=int, default=86400)
    grant.add_argument("operator_key_id")
    grant.add_argument("--results", action="store_true")
    commands.add_parser("revoke", help="Revoke an operator grant").add_argument("grant_id")


def peer_cli(state: State, args: Namespace) -> None:
    with state.lock("maintenance.lock"):
        state.verify()
        match args.peer_command:
            case "csr":
                write_new(args.output, make_csr(state.signing_key(), args.address))
                print(state.identity()[0])
            case "enrollment-key":
                print(mesh_enrollment.initialize_signer(state))
            case "enrollment-activate":
                policy = mesh_enrollment.load_policy(state)
                if policy is None:
                    raise StateError("Configure the approved Mesh enrollment policy first")
                mesh_enrollment.activate_voter(state, policy)
                print(state.identity()[0])
            case "add":
                pairing.add(state, pairing.Pair(
                    args.node_id, args.mesh_id, args.bind_ip, args.listen_port, args.source_ip, args.host, args.port,
                    args.fingerprint, read_pem(args.ca), read_pem(args.certificate), read_pem(args.peer_certificate),
                ))
            case "mesh-config":
                pairing.configure_mesh(state, args.mesh_id, args.bind_ip, args.listen_port,
                                       read_pem(args.ca), read_pem(args.certificate), allow_public_bind=args.allow_public_bind)
            case "mesh-options":
                discovery.set_options(state, discover=args.discover, forward=args.forward)
            case "member-add":
                pairing.add_member(state, args.node_id, args.host, args.fingerprint, read_pem(args.peer_certificate),
                                   routed=args.routed)
            case "member-generation":
                discovery.approve_generation(state, args.node_id, args.generation)
            case "neighbor-set":
                pairing.set_neighbor(state, args.node_id, args.source_ip, args.port, allow_public=args.allow_public)
            case "neighbor-allow":
                discovery.allow_network(state, args.node_id, args.network, args.port)
            case "neighbor-clear":
                pairing.set_neighbor(state, args.node_id, None)
            case "list":
                with state.connect() as db:
                    pair = pairing.configured(db)
                    quarantines = quarantine.entries(db)
                    entries = [{**member.public_data(), 'local_quarantine': quarantines.get(member.node_id)}
                               for member in pairing.members(db).values()]
                    mesh = discovery.public_config(db)
                print(json.dumps({"pairing": pair.public_data() if pair else None, "mesh": mesh, "members": entries,
                                  "runtime": read_runtime(state)}, indent=2))
            case "enable" | "disable":
                pairing.set_enabled(state, args.peer_command == "enable", args.node_id)
            case "quarantine" | "unquarantine":
                result = quarantine.set_state(state, args.node_id, args.reason if args.peer_command == 'quarantine' else None)
                print(json.dumps({'node_id': args.node_id, 'local_quarantine': result}, ensure_ascii=False))
            case "remove":
                pairing.remove(state, args.node_id)
            case "export":
                if not (args.directory or args.status or args.logs):
                    raise ValueError("Select one or more read permissions, or use peer unexport")
                export_service(state, args.service_id, directory=args.directory, status=args.status, logs=args.logs,
                               node_id=args.node_id)
            case "unexport":
                export_service(state, args.service_id, directory=False, status=False, logs=False, node_id=args.node_id)
            case "operator-add":
                public_key = load_pem_public_key(read_pem(args.public_key))
                if not isinstance(public_key, Ed25519PublicKey):
                    raise StateError("Expected an Ed25519 operator public key")
                print(policy.add_operator(state, public_key))
            case "grant" | "grant-account":
                if not 1 <= args.ttl <= 90 * 86400:
                    raise ValueError("Grant TTL must be between 1 second and 90 days")
                account = args.peer_command == "grant-account"
                print(policy.grant(state, args.service_id, None if account else args.operator_key_id, args.action,
                                   int(time.time()) + args.ttl, account or args.results, node_id=args.node_id))
            case "revoke":
                policy.revoke(state, args.grant_id)


def service_parser(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="service_command", required=True)
    commands.add_parser("list", help="List registered services")
    process = commands.add_parser("register-process", help="Register an existing foreground program")
    process.add_argument("--name", required=True)
    process.add_argument("--cwd", required=True)
    process.add_argument("--stop-timeout", type=int, default=8)
    process.add_argument("--endpoint")
    process.add_argument("argv", nargs=REMAINDER)
    system_unit = commands.add_parser("register-systemd-unit", help="Register an existing systemd system service")
    system_unit.add_argument("--name", required=True)
    system_unit.add_argument("unit")
    windows_service = commands.add_parser("register-windows-service", help="Register an existing Windows service")
    windows_service.add_argument("--name", required=True)
    windows_service.add_argument("service")
    windows_allowlist = commands.add_parser("windows-allowlist", help="Read or set the Windows service allowlist for this node")
    update_allowlist = windows_allowlist.add_mutually_exclusive_group()
    update_allowlist.add_argument("--set", nargs="+", metavar="SERVICE")
    update_allowlist.add_argument("--clear", action="store_true")
    docker = commands.add_parser("register-docker", help="Register an existing Rootless Docker container")
    docker.add_argument("--name", required=True)
    docker.add_argument("--mode", choices=("observe", "manage"), default="observe")
    docker.add_argument("--stop-timeout", type=int, default=8)
    docker.add_argument("container")
    mode = commands.add_parser("mode", help="Change an existing service's access mode")
    mode.add_argument("id")
    mode.add_argument("mode", choices=("observe", "manage"))
    commands.add_parser("remove", help="Unregister a service without deleting its workload").add_argument("id")


def service_cli(config: Config, state: State, args: Namespace) -> None:
    if args.service_command == "windows-allowlist":
        if not WINDOWS:
            raise HostError("Windows system services require a Windows node")
        driver = WindowsServiceDriver(state)
        if args.set is not None or args.clear:
            state.prepare_directory()
            with state.lock("maintenance.lock"):
                driver.set_allowlist(args.set or [])
        print(json.dumps(sorted(driver.allowed_services().values(), key=str.lower)))
        return
    with state.lock("maintenance.lock"):
        state.verify()
        match args.service_command:
            case "list":
                print(json.dumps([
                    {"id": item.id, "name": item.name, "driver": item.driver, "target": item.target, "managed": item.managed}
                    for item in list_services(state)
                ], indent=2, ensure_ascii=False))
            case "register-process":
                argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
                spec = process_spec(argv, args.cwd, args.stop_timeout, args.endpoint)
                print(register(state, "process", args.name, "", spec, managed=True).id)
            case "register-systemd-unit":
                print(SystemUnitDriver.register(state, args.name, args.unit).id)
            case "register-windows-service":
                print(WindowsServiceDriver(state).register(args.name, args.service).id)
            case "register-docker":
                service = DockerDriver(config.docker_socket).register(state, args.name, args.container,
                    stop_timeout=args.stop_timeout, managed=args.mode == "manage")
                print(service.id)
            case "mode":
                change_mode(state, args.id, args.mode, docker_socket=config.docker_socket)
            case "remove":
                unregister(state, args.id)


def main() -> int:
    parser = ArgumentParser(prog="spearmint")
    parser.add_argument("--state-dir", type=Path, help="Override SPEARMINT_STATE_DIR for this command")
    parser.add_argument("--web-dir", type=Path, help="Override SPEARMINT_WEB_DIR for this command")
    parser.add_argument("--origin", help="Override SPEARMINT_ORIGIN for this command")
    parser.add_argument("--grove-ca", type=Path, help="PEM trust bundle for HTTPS Grove directory synchronization")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Initialize the node and administrator").add_argument(
        "--password-stdin", action="store_true", help="Read password and confirmation from two stdin lines")
    subparsers.add_parser("passwd", help="Reset the administrator password and revoke sessions")
    for method in ("totp", "passkey"):
        setup = subparsers.add_parser(f"setup-{method}", help=f"Issue a short-lived {method} enrollment token from the local terminal")
        setup.add_argument("--account", help="Account name, defaults to the bootstrap administrator")
        setup.add_argument("--recover", action="store_true",
                           help="Recover lost factors locally: clear factors, recovery codes and sessions after confirmation")
    account_parser(subparsers.add_parser("account", help="Manage named local panel accounts"))
    security_parser(subparsers.add_parser("security", help="Manage signed M003 Mesh policy on this node"))
    passkey_commands = subparsers.add_parser("passkey", help="Manage local Passkey credentials").add_subparsers(
        dest="passkey_command", required=True,
    )
    passkey_commands.add_parser("list", help="List registered Passkey IDs and statuses")
    passkey_commands.add_parser("revoke", help="Revoke a Passkey and its account sessions").add_argument("id")
    diagnostics = subparsers.add_parser("doctor", help="Check local deployment prerequisites and Peer status")
    diagnostics.add_argument("--port", type=int, default=8765)
    diagnostics.add_argument("--bind", type=panel_check_address, default="127.0.0.1", metavar="IP",
                             help="Local address where the panel is listening (default: 127.0.0.1)")
    diagnostics.add_argument("--https", action="store_true", help="Verify TLS when checking the local listener")
    diagnostics.add_argument("--tls-ca", type=Path, help="PEM trust bundle for the native HTTPS health check")
    diagnostics.add_argument("--check-web", action="store_true", help="Also verify the homepage and its assets over the local listener")
    service_parser(subparsers.add_parser("service", help="Manage the local service catalog"))
    frp_parser(subparsers.add_parser("frp", help="Manage local FRP mappings"))
    peer_parser(subparsers.add_parser("peer", help="Manage the authenticated Peer link"))
    configure_approve(subparsers.add_parser("approve", help="Sign an operation challenge"))
    migrate = subparsers.add_parser("migrate", help="Back up and upgrade the SQLite schema with the panel stopped")
    migration = migrate.add_mutually_exclusive_group(required=True)
    migration.add_argument("--backup", type=Path, help="Directory for the verified pre-upgrade backup")
    migration.add_argument("--plan", action="store_true", help="Read the node identity and schema without migrating")
    backup_command = subparsers.add_parser("backup", help="Write a verified offline state backup")
    backup_command.add_argument("destination", type=Path)
    subparsers.add_parser("verify-backup", help="Check an existing backup and its restore compatibility").add_argument(
        "source", type=Path,
    )
    restore_command = subparsers.add_parser("restore", help="Restore a verified backup with the panel stopped")
    restore_command.add_argument("source", type=Path)
    restore_command.add_argument("--save-current", type=Path)
    rebuild = subparsers.add_parser("rebuild-identity", help="Create a replacement node identity from a verified backup")
    rebuild.add_argument("source", type=Path)
    rebuild.add_argument("--destination", type=Path, required=True, help="New state directory for the replacement")
    rebuild.add_argument("--password-stdin", action="store_true", help="Read password and confirmation from two stdin lines")
    setup_link = subparsers.add_parser("setup-link", help="Save the first-run browser handoff without using a console key")
    setup_link_action = setup_link.add_mutually_exclusive_group()
    setup_link_action.add_argument("--renew", action="store_true", help="Replace an unused or expired first-run link")
    setup_link_action.add_argument("--renew-if-expired", action="store_true",
                                   help="Replace the pending first-run link only if it has expired")
    setup_link_action.add_argument("--status", action="store_true", help="Show first-run status and the private file path without changing it")
    setup_link_action.add_argument("--open", action="store_true", help="Open the existing private first-run file in the desktop browser")
    setup_link_action.add_argument("--print-code", action="store_true", help="Print the current one-time code for the web setup form")
    setup_link_action.add_argument("--recover-and-open", action="store_true",
                                   help="Restore or renew the private first-run file at its saved HTTPS origin and open it")
    setup_link.add_argument("--join-grove", type=Path, help="Use a Grove invitation JSON file in the first-run handoff")
    setup_link.add_argument("--seed-receipt", action="store_true", help="Print the Node ID and first-run status for the native installer")
    setup_link.add_argument("--expected-node", help="Require the installed Node ID and original HTTPS origin when renewing")
    seed_enrollment = subparsers.add_parser('seed-enrollment', help='Enroll this SSH-installed node using its quorum approval')
    seed_enrollment.add_argument('action', choices=('request', 'finish', 'status'))
    grove_commands = subparsers.add_parser('grove', help='Inspect Grove identity or perform local owner recovery').add_subparsers(dest='grove_command', required=True)
    grove_commands.add_parser('status')
    grove_commands.add_parser('sync-directory', help='Refresh the signed member directory directly from the configured HTTPS issuer')
    continuity = grove_commands.add_parser('install-continuity', help='Enroll this member using its Grove retirement authorization')
    continuity.add_argument('authorization', type=Path)
    grove_commands.add_parser('approve-recovery', help='Approve Grove recovery using the current stored snapshot')
    grove_commands.add_parser('apply-departure', help='Import a member-signed Grove departure').add_argument('document', type=Path)
    grove_commands.add_parser('approve-existing-member', help='Sign this voter’s approval for an existing certified Grove member').add_argument('node_id')
    grove_commands.add_parser('apply-existing-member', help='Apply a majority of approvals for an existing Grove member').add_argument('document', type=Path)
    detach = grove_commands.add_parser('detach', help='Detach this node after an offline backup and explicit owner confirmation')
    detach.add_argument('--backup', type=Path, required=True)
    preflight = subparsers.add_parser("validate-config", help="Check the panel configuration without starting it")
    preflight.add_argument("--expected-origin", help="Require the effective HTTPS origin to match this value")
    preflight.add_argument("--expected-grove-ca", type=Path, help="Require the effective Grove CA path to match this file")
    preflight.add_argument("--check-web", action="store_true", help="Check the effective Web directory and the assets referenced by index.html")
    seed_preflight = preflight.add_mutually_exclusive_group()
    seed_preflight.add_argument("--check-seed-targets", action="store_true", help="Check the private SSH seed configuration without connecting")
    seed_preflight.add_argument("--probe-seed-target", metavar="ID", help="Check one configured target over SSH without sending an archive")
    preflight.add_argument("--tls-cert", type=Path, help="PEM certificate chain for native HTTPS")
    preflight.add_argument("--tls-key", type=Path, help="Unencrypted private PEM key for native HTTPS")
    preflight.add_argument("--join-grove", type=Path, help="Validate a Grove invitation without preparing a first-run link")
    serve = subparsers.add_parser("serve", help="Start the panel; fresh nodes open the web setup flow")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--bind", default="127.0.0.1", help="Listening address; non-loopback requires native TLS")
    serve.add_argument("--tls-cert", type=Path, help="PEM certificate chain for native HTTPS")
    serve.add_argument("--tls-key", type=Path, help="Private PEM key for native HTTPS")
    serve.add_argument("--open-setup", action="store_true", help="Open the private first-run file after the local listener starts")
    serve.add_argument("--join-grove", type=Path, help="Use a Grove invitation JSON file in the first-run handoff")
    args = parser.parse_args()
    if args.command == "setup-link" and args.join_grove is not None and (args.status or args.open or args.recover_and_open or args.print_code):
        parser.error("--join-grove prepares a first-run link and cannot be used with --status, --open or --recover-and-open")
    if args.command == "setup-link" and args.seed_receipt and args.join_grove is None:
        parser.error("--seed-receipt requires --join-grove")
    if args.command == "setup-link" and args.expected_node is not None:
        if NODE_ID.fullmatch(args.expected_node) is None:
            parser.error("--expected-node requires a full Node ID")
        if not args.renew_if_expired or args.join_grove is not None:
            parser.error("Use --expected-node with --renew-if-expired alone to preserve the existing invitation")
    os.umask(0o077)
    try:
        if args.command == "approve":
            sign_approval(args)
            return 0
        if not WINDOWS and os.getuid() == 0:
            raise StateError("Run Spearmint as its dedicated non-root account")
        if args.command == "verify-backup":
            print(json.dumps(verify_backup(args.source.expanduser().absolute()), indent=2))
            return 0
        config = Config.from_env(state_dir=args.state_dir, origin=args.origin, web_dir=args.web_dir, grove_ca=args.grove_ca)
        if config.grove_ca is not None and args.command in {"validate-config", "serve"}:
            try:
                grove.directory_tls_context(config)
            except (OSError, ValueError) as exc:
                raise ValueError(f"Cannot load the Grove HTTPS trust bundle: {exc}") from exc
        if args.command == "validate-config":
            if args.expected_origin is not None and config.origin != args.expected_origin:
                raise ValueError(f"Configured HTTPS origin {config.origin} does not match {args.expected_origin}")
            if args.expected_grove_ca is not None and config.grove_ca != args.expected_grove_ca.expanduser().absolute():
                raise ValueError("The configured Grove CA path does not match the requested file")
            if args.check_web:
                check_web_bundle(config.web_dir)
            if args.check_seed_targets:
                settings = load_deployment_config(config.state_dir, config.seed_targets)
                if settings is None:
                    raise ValueError(f"Create {TARGETS_FILE} in the state directory or set SPEARMINT_SEED_TARGETS")
                print(f"Validated {len(settings.targets)} SSH seed target(s)")
            if args.join_grove is not None:
                onboarding.read_invitation(args.join_grove)
            validate_tls_paths(args.tls_cert, args.tls_key)
            if args.tls_cert is not None:
                try:
                    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(args.tls_cert, args.tls_key, password="")
                except ssl.SSLError as exc:
                    raise ValueError(f"Cannot load the TLS certificate and unencrypted private key: {exc}") from exc
            if args.probe_seed_target is not None:
                seeds = SeedDeployments(State(config.state_dir), config.seed_targets)
                target = seeds.configured_target(args.probe_seed_target)
                result = seeds.check_prerequisites(target)
                print(json.dumps({"target_id": target.id, **result}))
                return 0 if result["ready"] else 1
            return 0
        state = State(config.state_dir)
        if args.command == "init":
            print(state.initialize(lambda: read_password(allow_stdin=args.password_stdin)))
        elif args.command == "setup-link":
            if args.print_code:
                print(onboarding.owner_code(state))
            elif args.recover_and_open:
                onboarding.recover_handoff(state, expected_origin=args.origin)
                print(onboarding.handoff_status(state, open_browser=True))
            elif args.status or args.open:
                print(onboarding.handoff_status(state, open_browser=args.open))
            else:
                try:
                    handoff = onboarding.prepare(state, config, renew=args.renew, renew_if_expired=args.renew_if_expired,
                                                 join_grove=args.join_grove, expected_node=args.expected_node)
                except onboarding.ExistingNodeNeedsGrove:
                    if not args.seed_receipt:
                        raise
                    setup = 'join-required'
                    print('Sign in to the target panel with its local administrator to join the Grove.')
                else:
                    setup = 'pending' if handoff is not None else 'complete'
                    print(f"Open this private file to configure the node: {handoff}" if handoff else "Initial setup is already complete")
                if args.seed_receipt:
                    print(f'SPEARMINT_SEED_NODE_ID={state.identity()[0]} {setup}')
        elif args.command == 'seed-enrollment':
            print(json.dumps(seed_admission.cli(state, config, args.action)))
        elif args.command == 'grove':
            if args.grove_command == 'status':
                state.verify()
                status = grove.describe(state, private=True)
                with state.connect(read_only=True) as db:
                    db.execute('BEGIN')
                    if recovery := grove_continuity.recovery_details(db):
                        status['recovery'] = recovery
                print(json.dumps(status, indent=2, ensure_ascii=False))
            elif args.grove_command == 'sync-directory':
                state.verify()
                result = grove.sync_http(state, config)
                if result == 'not-configured':
                    raise StateError('Join a Grove before synchronizing its identity directory')
                if result == 'conflict':
                    raise StateError('Conflicting Grove directory received; check the local Grove status')
                print(json.dumps({'status': result}))
            elif args.grove_command == 'install-continuity':
                state.verify()
                envelope = read_document(args.authorization, limit=grove.MAX_DOCUMENT)
                anchor = grove_continuity.install_document(state, envelope)
                print(json.dumps({'realm_id': anchor['realm_id'], 'voters': anchor['voters']}))
            elif args.grove_command == 'apply-departure':
                state.verify()
                node = grove_metadata.apply_departure(state, read_document(args.document, limit=4096))
                print(json.dumps({'removed':node}))
            elif args.grove_command == 'approve-existing-member':
                state.verify()
                print(json.dumps(grove_admission.existing_member_ballot(state, args.node_id)))
            elif args.grove_command == 'apply-existing-member':
                state.verify()
                document = read_document(args.document, limit=grove.MAX_DOCUMENT)
                if document.keys() != {'approvals'}:
                    raise StateError('Expected Grove member approvals')
                print(json.dumps({'node_id':grove_admission.apply_existing_member(state, document['approvals'])}))
            elif args.grove_command == 'approve-recovery':
                if not (sys.stdin.isatty() and sys.stdout.isatty()):
                    raise StateError('A local terminal is required for Grove recovery approval')
                state.verify()
                status = grove.describe(state)
                if not status['configured'] or status['local_issuer']:
                    raise StateError('Use an enrolled Grove member to approve recovery')
                with state.connect(read_only=True) as db:
                    db.execute('BEGIN')
                    recovery = grove_continuity.recovery_details(db)
                if recovery is None:
                    raise StateError('This node has no matching Grove recovery authorization')
                expected = status['realm']['id']
                print(f"This permanently approves Grove snapshot {recovery['sequence']}. "
                      f"Recovery requires {recovery['required']} of {recovery['voters']} members to approve this version.")
                if input(f'Type the Grove ID ({expected}) to continue: ') != expected:
                    raise StateError('Grove recovery cancelled')
                grove_continuity.recovery_ballot(state, expected, recovery['sequence'])
                print('Recovery approval recorded. The running panel exchanges it with the other members.')
            else:
                if not (sys.stdin.isatty() and sys.stdout.isatty()):
                    raise StateError('A local terminal is required for Grove trust recovery')
                with state.lock('server.lock', exclusive_now=True), state.lock('maintenance.lock'):
                    state.verify()
                    status = grove.describe(state)
                    if not status['configured']:
                        raise StateError('This node has no Grove to detach')
                    expected = status['realm']['id']
                    print('This detaches Grove login on this node and disables its imported Grove accounts.')
                    if input(f'Type the Grove ID ({expected}) to continue: ') != expected:
                        raise StateError('Grove detach cancelled')
                    backup(state, args.backup.expanduser().absolute())
                    grove.detach(state, expected)
                    print('Grove detached; local independent accounts are unchanged. Rebuild or join from the panel after local sign-in.')
        elif args.command == "passwd":
            with state.lock("maintenance.lock"):
                state.verify()
                auth.reset_password(state, read_password())
            print("Administrator password reset. Previous sessions revoked.")
        elif args.command in {"setup-totp", "setup-passkey"}:
            setup_factor(state, config, args.command.removeprefix("setup-"), args.account, recover=args.recover)
        elif args.command == "account":
            account_cli(state, args)
        elif args.command == "security":
            security_cli(state, args)
        elif args.command == "passkey":
            with state.lock("maintenance.lock"):
                state.verify()
                if args.passkey_command == "revoke":
                    passkeys.revoke(state, args.id)
                else:
                    with state.connect() as db:
                        rows = db.execute("""
                            SELECT p.id, a.username, p.origin, p.created_at, p.last_used_at, p.enabled
                            FROM panel_passkey p JOIN panel_account a ON a.id=p.account_id
                            ORDER BY p.created_at, p.id
                        """).fetchall()
                    print(json.dumps([dict(row) for row in rows], indent=2, ensure_ascii=False))
        elif args.command == "doctor":
            if not 1 <= args.port <= 65535:
                raise ValueError("Panel port must be in the range 1 through 65535")
            if args.tls_ca is not None and not args.https:
                raise ValueError("--tls-ca requires --https")
            return doctor(config, state, args.port, https=args.https, ca=args.tls_ca, bind=args.bind,
                          check_web=args.check_web)
        elif args.command == "service":
            service_cli(config, state, args)
        elif args.command == "frp":
            return frp_cli(state, args)
        elif args.command == "peer":
            peer_cli(state, args)
        elif args.command == "migrate" and args.plan:
            print(json.dumps(migration_plan(state), indent=2))
        elif args.command in {"migrate", "backup"}:
            with state.lock("server.lock", exclusive_now=True), state.lock("maintenance.lock"):
                destination = (args.backup if args.command == "migrate" else args.destination).expanduser().absolute()
                action = migrate_offline if args.command == "migrate" else backup
                node_id = action(state, destination)
                print(f"Verified backup at {destination} for {node_id}")
                if args.command == "migrate":
                    print(f"Schema verified for {node_id}")
        elif args.command == "restore":
            source = args.source.expanduser().absolute()
            save_current = args.save_current.expanduser().absolute() if args.save_current else None
            state.prepare_directory()
            with state.lock("server.lock", exclusive_now=True), state.lock("maintenance.lock"):
                print(f"Restore source {source}\nActive state {state.directory}", flush=True)
                node_id = restore(state, source, save_current)
                print(f"Restored {node_id}. Previous sessions revoked.")
        elif args.command == "rebuild-identity":
            source = args.source.expanduser().absolute()
            destination = args.destination.expanduser().absolute()
            result = rebuild_identity(source, destination, lambda: read_password(allow_stdin=args.password_stdin))
            print(json.dumps({**result, "state_directory": str(destination)}, indent=2))
        else:
            if not 1024 <= args.port <= 65535:
                raise ValueError("Serve port must be in the range 1024 through 65535")
            validate_tls_paths(args.tls_cert, args.tls_key)
            if args.bind not in {"127.0.0.1", "::1", "localhost"} and args.tls_cert is None:
                raise ValueError("A public listening address requires native HTTPS")
            if args.open_setup:
                check_web_bundle(config.web_dir)
            state.prepare_directory()
            with state.lock("server.lock", exclusive_now=True):
                handoff = onboarding.prepare(state, config, join_grove=args.join_grove)
                if handoff:
                    print(f"First-run setup is waiting at {config.origin}/", flush=True)
                native_loopback_setup = (args.tls_cert is not None and onboarding.loopback_host(args.bind)
                                         and onboarding.loopback_host(urlsplit(config.origin).hostname))
                app = create_app(config, native_loopback_setup=native_loopback_setup)
                options = dict(
                    host=args.bind, port=args.port, workers=1,
                    proxy_headers=args.tls_cert is None, forwarded_allow_ips="127.0.0.1", access_log=False,
                    ssl_certfile=str(args.tls_cert) if args.tls_cert else None,
                    ssl_keyfile=str(args.tls_key) if args.tls_key else None,
                    # A reset Windows HTTPS transport can otherwise stall application shutdown.
                    timeout_graceful_shutdown=20 if os.name == "nt" and args.tls_cert else None,
                )
                if WINDOWS:
                    from .windows_asyncio import loop_factory
                    options['loop'] = f'{loop_factory.__module__}:{loop_factory.__name__}'
                if args.open_setup and handoff:
                    server = DesktopSetupServer(uvicorn.Config(app, **options), state)
                    try:
                        server.run()
                    except KeyboardInterrupt:
                        pass
                    return 0 if server.started else 1
                uvicorn.run(app, **options)
    except (StateError, ControlError, HostError, PeerError, OSError, sqlite3.Error, ValueError, InvalidSignature, EOFError) as exc:
        print(f"Spearmint: {exc}", file=sys.stderr)
        return 1
    return 0
