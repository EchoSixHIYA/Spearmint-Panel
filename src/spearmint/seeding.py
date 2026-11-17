"""Manage SSH installations for deployment targets configured on this node."""

from collections.abc import Callable
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sqlite3
import stat
import subprocess
from tempfile import TemporaryDirectory
from threading import Lock
import time
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from . import auth, grove, onboarding, seed_transport
from .control import ControlError
from .peer.credentials import NODE_ID
from .platforms import secure_private
from .state import State, StateError, audit, private_path


CATALOG_METHOD = 'grove.seed.catalog'
CATALOG_RECEIPTS_METHOD = 'grove.seed.catalog.v2'
CATALOG_SETUP_METHOD = 'grove.seed.catalog.v3'
TARGETS_FILE = 'seed-targets.json'
logger = logging.getLogger(__name__)
TargetId = Annotated[str, Field(pattern=r'^[a-z0-9][a-z0-9-]{0,31}$')]
TargetPlatform = Literal['linux-amd64', 'linux-arm64', 'windows-amd64']


class TargetIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    id: TargetId
    name: str = Field(min_length=1, max_length=80)
    platform: TargetPlatform
    origin: str = Field(max_length=300)

    @model_validator(mode='after')
    def validate_display(self):
        try:
            grove.origin(self.origin)
        except grove.PeerError as error:
            raise ValueError('Use a canonical HTTPS origin for the target panel') from error
        if not self.name.strip() or not self.name.isprintable():
            raise ValueError('Use a printable target name')
        return self


class Target(TargetIdentity):
    host: str = Field(pattern='^' + seed_transport.HOST.pattern + '$')
    port: int = Field(default=8765, ge=1024, le=65535)
    archive: str | None = Field(default=None, min_length=1, max_length=2048)
    target_archive: str | None = Field(default=None, min_length=1, max_length=1024)
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    install_timeout_seconds: int = Field(default=seed_transport.DEFAULT_INSTALL_TIMEOUT,
                                         ge=seed_transport.MIN_INSTALL_TIMEOUT, le=seed_transport.MAX_INSTALL_TIMEOUT)
    windows: dict[str, str] = Field(default_factory=dict, max_length=len(seed_transport.WINDOWS_OPTIONS))
    linux_grove_ca: str | None = None
    linux_bind: str | None = None
    linux_certificate: str | None = None
    linux_private_key: str | None = None
    catalog_readers: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode='after')
    def validate_target(self):
        if (self.archive is None) == (self.target_archive is None):
            raise ValueError('Configure exactly one local archive or staged target archive')
        if self.archive is not None and not Path(self.archive).is_absolute():
            raise ValueError('Use an absolute path to the local native archive')
        if self.target_archive is not None:
            seed_transport.validate_target_archive(self.target_archive, self.platform)
        if any(NODE_ID.fullmatch(node) is None for node in self.catalog_readers):
            raise ValueError('Catalog readers must be full Node IDs')
        if self.windows and (self.platform != 'windows-amd64'
                             or not self.windows.keys() <= seed_transport.WINDOWS_OPTIONS.keys()
                             or any(not value or not value.isprintable() or len(value) > 1024
                                    for value in self.windows.values())):
            raise ValueError('Invalid Windows native installer options')
        seed_transport.validate_windows_options(self.windows_parameters())
        if self.linux_grove_ca is not None:
            if self.platform == 'windows-amd64':
                raise ValueError('The Linux Grove CA option requires a Linux target')
            seed_transport.validate_linux_grove_ca(self.linux_grove_ca)
        if any(value is not None for value in self.linux_listener()):
            if self.platform == 'windows-amd64':
                raise ValueError('The Linux listener option requires a Linux target')
            seed_transport.linux_listener_args(*self.linux_listener())
        return self

    def linux_listener(self) -> tuple[str | None, str | None, str | None]:
        return self.linux_bind, self.linux_certificate, self.linux_private_key

    def windows_parameters(self) -> dict[str, str]:
        return {seed_transport.WINDOWS_OPTIONS[key]: value for key, value in self.windows.items()}

    def archive_name(self) -> str:
        if self.archive is not None:
            return Path(self.archive).name
        path_type = PureWindowsPath if self.platform == 'windows-amd64' else PurePosixPath
        return path_type(self.target_archive or '').name


class DeploymentConfig(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    ssh_config: str = Field(min_length=1, max_length=2048)
    targets: list[Target] = Field(min_length=1, max_length=32)


class SeedConfigError(ValueError):
    pass


def load_deployment_config(state_directory: Path, path: Path | None) -> DeploymentConfig | None:
    if path is None:
        path = state_directory / TARGETS_FILE
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise SeedConfigError('Cannot read the private SSH seed target configuration') from None
    try:
        private_path(path, 0o600)
        with path.open('rb') as stream:
            raw = stream.read(128 * 1024 + 1)
    except (OSError, StateError, ValueError):
        raise SeedConfigError('Cannot read the private SSH seed target configuration') from None
    if len(raw) > 128 * 1024:
        raise SeedConfigError('SSH seed target configuration is too large')
    try:
        settings = DeploymentConfig.model_validate_json(raw)
    except ValidationError as error:
        first = error.errors(include_input=False, include_context=False, include_url=False)[0]
        location = first['loc']
        if first['type'] == 'json_invalid':
            message = 'SSH seed target configuration is not valid JSON'
        elif len(location) >= 2 and location[0] == 'targets' and type(location[1]) is int:
            message = f'Invalid SSH seed target at position {location[1] + 1}'
        else:
            message = 'Invalid SSH seed target configuration'
        raise SeedConfigError(message) from None
    ssh_config = Path(settings.ssh_config)
    if not ssh_config.is_absolute():
        raise SeedConfigError('Use an absolute path to the deployment OpenSSH configuration')
    try:
        private_path(ssh_config, 0o600)
    except (OSError, StateError, ValueError):
        raise SeedConfigError('Cannot access the private deployment OpenSSH configuration') from None
    if (len({target.id for target in settings.targets}) != len(settings.targets)
            or len({target.origin for target in settings.targets}) != len(settings.targets)):
        raise SeedConfigError('Seed targets must have distinct IDs and panel origins')
    return settings


def fingerprint(target: Target, realm: dict) -> str:
    # Transport timing does not change which installation a receipt describes.
    original_fields = ('id', 'name', 'host', 'platform', 'origin', 'port', 'archive', 'sha256', 'windows')
    profile = {key: getattr(target, key) for key in original_fields}
    if target.target_archive is not None:
        profile['target_archive'] = target.target_archive
    # Keep receipts for existing profiles that do not specify the new option.
    if target.linux_grove_ca is not None:
        profile['linux_grove_ca'] = target.linux_grove_ca
    if listener := seed_transport.linux_listener_args(*target.linux_listener()):
        profile['linux_listener'] = listener
    return hashlib.sha256((json.dumps(profile, ensure_ascii=False, separators=(',', ':')) + realm['id']).encode()).hexdigest()


def destination_fingerprint(target: Target, realm: dict, ssh_config: Path | None) -> str:
    # Tie historical receipts to the configured destination and Grove independently of package selection.
    destination = (target.id, target.host, target.platform, target.origin, target.port, str(ssh_config),
                   {key: value for key, value in target.windows.items() if key != 'staging_directory'},
                   target.linux_grove_ca, target.linux_listener(), realm['id'], realm['public_key'], realm['issuer_node'])
    return hashlib.sha256(json.dumps(destination, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def startup_detail(receipt: seed_transport.InstallReceipt | None) -> str | None:
    if receipt is None:
        return None
    linger = f'linger-{receipt.linger}' if receipt.linger else None
    return '.'.join(filter(None, (receipt.node_id, receipt.setup, linger))) or None


class CatalogTarget(TargetIdentity):
    status: Literal['ready', 'running', 'started', 'checksum', 'failed', 'uncertain']
    updated_at: int | None


class SeedCatalog(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    targets: list[CatalogTarget] = Field(max_length=32)


class CatalogReceiptTarget(CatalogTarget):
    node_id: str | None = Field(default=None, pattern=f'^{NODE_ID.pattern}$')

    @model_validator(mode='after')
    def validate_receipt(self):
        if self.node_id is not None and self.status != 'started':
            raise ValueError('Node ID requires a confirmed startup receipt')
        return self


class SeedReceiptCatalog(SeedCatalog):
    targets: list[CatalogReceiptTarget] = Field(max_length=32)


class CatalogSetupTarget(CatalogReceiptTarget):
    setup: Literal['pending', 'complete', 'join-required'] | None = None

    @model_validator(mode='after')
    def validate_setup(self):
        if self.setup is not None and self.node_id is None:
            raise ValueError('Setup status requires an identified startup receipt')
        return self


class SeedSetupCatalog(SeedCatalog):
    targets: list[CatalogSetupTarget] = Field(max_length=32)


class SeedDeployments:
    def __init__(self, state: State, path: Path | None):
        self.state = state
        self.targets: dict[str, Target] = {}
        self.ssh_config: Path | None = None
        self.ssh = None
        self.config_invalid = False
        self.lock = Lock()
        self.checking = False
        self.running: dict[str, Path | None] = {}
        try:
            settings = load_deployment_config(state.directory, path)
        except SeedConfigError as error:
            self.config_invalid = True
            logger.warning('SSH seeding unavailable: %s', error)
            return
        if settings is None:
            return
        self.ssh_config = Path(settings.ssh_config)
        self.targets = {target.id: target for target in settings.targets}
        if executable := shutil.which('ssh'):
            self.ssh = str(Path(executable).absolute())

    @staticmethod
    def realm(db) -> dict | None:
        row = db.execute('SELECT * FROM grove_realm').fetchone()
        if row is None or row['frozen'] or row['issuer_paused']:
            return None
        return grove.realm_data(row)

    def interrupted_work(self, attempt: str) -> Path | None:
        if len(attempt) != 32 or any(char not in '0123456789abcdef' for char in attempt):
            return None
        try:
            work, = self.state.directory.glob(f'.ssh-seed-{attempt}-*')
            private_path(work, 0o700, directory=True)
            private_path(work / seed_transport.PROGRESS_FILE, 0o600)
        except (OSError, StateError, ValueError):
            return None
        return work

    def recover_confirmed_starts(self) -> None:
        if not self.targets or not any(self.state.directory.glob('.ssh-seed-*-*')):
            return
        completed = []
        with self.lock, self.state.connect(write=True) as db:
            if (realm := self.realm(db)) is None:
                return
            for target in self.targets.values():
                row = self.last_install(db, target.id, fingerprint(target, realm))
                if row is None or target.id in self.running or not row['event'].startswith('seed.ssh.running.'):
                    continue
                attempt_data = row['event'].removeprefix('seed.ssh.running.')
                attempt, _, destination = attempt_data.partition('.')
                if destination != destination_fingerprint(target, realm, self.ssh_config):
                    continue
                work = self.interrupted_work(attempt)
                if work is None:
                    continue
                output = seed_transport.read_install_output(work)
                if seed_transport.confirmed_before_disconnect(output):
                    receipt = seed_transport.install_receipt(output, target.platform)
                    self.record(db, row['actor'], row['source'], target, realm, 'started', startup_detail(receipt))
                    completed.append(work)
        for work in completed:
            self.clean_recovered_work(work)

    @staticmethod
    def clean_recovered_work(work: Path) -> None:
        # Remove only the files produced by the transport. Keep unfamiliar files
        # and any open or non-regular entries for inspection.
        try:
            private_path(work, 0o700, directory=True)
        except (OSError, StateError, ValueError):
            return
        for name in (seed_transport.TRANSFER_FILE, seed_transport.CLIENT_LOG_FILE, seed_transport.PROGRESS_FILE):
            path = work / name
            try:
                info = path.lstat()
                if stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400:
                    path.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning('Could not remove a recovered SSH seed temporary file')
        try:
            work.rmdir()
        except OSError:
            pass

    def last_check(self, db, target_id: str, revision: str) -> dict | None:
        row = db.execute("""SELECT event, recorded_at FROM audit
                           WHERE target=? AND reason=? AND event LIKE 'seed.preflight.%'
                           ORDER BY id DESC LIMIT 1""", (target_id, revision)).fetchone()
        if row is None:
            return None
        status, _, detail = row['event'].removeprefix('seed.preflight.').partition('.')
        receipt = {'ready': status == 'passed', 'recorded_at': row['recorded_at']}
        if status == 'passed' and detail in ('yes', 'no', 'unknown'):
            receipt['linger'] = detail
        elif status == 'failed' and detail in seed_transport.FAILURE_STAGES:
            receipt['stage'] = detail
        return receipt

    def last_install(self, db, target_id: str, profile: str) -> sqlite3.Row | None:
        return db.execute("""SELECT id, event, recorded_at, actor, source FROM audit
                           WHERE target=? AND reason=? AND event LIKE 'seed.ssh.%' ORDER BY id DESC LIMIT 1""",
                          (target_id, profile)).fetchone()

    def view(self, db, target: Target, realm: dict, *, local_details: bool = False) -> dict:
        profile = fingerprint(target, realm)
        row = self.last_install(db, target.id, profile)
        status, _, detail = row['event'].removeprefix('seed.ssh.').partition('.') if row else ('ready', '', '')
        interrupted = status == 'running' and target.id not in self.running
        if interrupted:
            status = 'uncertain'
        install_revision = hashlib.sha256(f"{profile}:{row['id'] if row else 0}".encode()).hexdigest()
        # Reuse the existing preflight audit key so stored checks remain readable.
        revision = hashlib.sha256(f'{install_revision}:{self.ssh_config}'.encode()).hexdigest()
        view = {'id': target.id, 'name': target.name, 'origin': target.origin, 'platform': target.platform,
                'status': status, 'revision': revision, 'updated_at': row['recorded_at'] if row else None,
                'archive_source': 'transfer' if target.archive is not None else 'target'}
        if local_details:
            name = target.archive_name()
            view['archive_sha256'] = target.sha256
            if 0 < len(name) <= 255 and name.isprintable():
                view['archive_name'] = name
            if checked := self.last_check(db, target.id, revision):
                view['last_check'] = checked
        if local_details and status == 'running' and (work := self.running[target.id]) is not None:
            if checkpoint := seed_transport.last_checkpoint(seed_transport.read_install_output(work)):
                view['checkpoint'] = checkpoint
        if status == 'started':
            fields = detail.split('.')
            if target.platform.startswith('linux-') and fields[-1] in ('linger-yes', 'linger-no', 'linger-unknown'):
                view['linger'] = fields.pop().removeprefix('linger-')
            detail = '.'.join(fields)
            node_id, _, setup = detail.partition('.')
            if NODE_ID.fullmatch(node_id):
                view['node_id'] = node_id
                if setup in ('pending', 'complete', 'join-required'):
                    view['setup'] = setup
        else:
            stage, _, remaining = detail.partition('.')
            checkpoint, _, reported_node_id = remaining.partition('.')
            if stage in seed_transport.FAILURE_STAGES:
                view['stage'] = stage
            if local_details and status == 'failed' and checkpoint in seed_transport.INSTALL_CHECKPOINTS:
                view['checkpoint'] = checkpoint
            if status == 'uncertain':
                if interrupted and local_details:
                    attempt, _, destination = detail.partition('.')
                    if ((not destination or destination == destination_fingerprint(target, realm, self.ssh_config))
                            and (work := self.interrupted_work(attempt)) is not None):
                        output = seed_transport.read_install_output(work)
                        checkpoint = seed_transport.last_checkpoint(output)
                        reported_node_id, _ = seed_transport.node_receipt(output)
                if checkpoint in seed_transport.INSTALL_CHECKPOINTS:
                    view['checkpoint'] = checkpoint
                if reported_node_id and NODE_ID.fullmatch(reported_node_id):
                    view['reported_node_id'] = reported_node_id
        if local_details and row and status in ('running', 'failed', 'uncertain', 'checksum') and 'reported_node_id' not in view:
            previous = db.execute("""SELECT event, recorded_at FROM audit
                                     WHERE target=? AND reason=? AND id<? AND
                                       (event LIKE 'seed.ssh.started%' OR event GLOB 'seed.ssh.uncertain.*.*.spm1-*')
                                     ORDER BY id DESC LIMIT 1""", (target.id, profile, row['id'])).fetchone()
            if previous and previous['event'].startswith('seed.ssh.uncertain.'):
                node_id = previous['event'].rsplit('.', 1)[-1]
                if NODE_ID.fullmatch(node_id):
                    view['last_report'] = {'node_id': node_id, 'recorded_at': previous['recorded_at']}
        if local_details and 'node_id' not in view:
            destination = destination_fingerprint(target, realm, self.ssh_config)
            last_start = db.execute("""SELECT event, reason, recorded_at FROM audit WHERE target=? AND (
                                          (reason=? AND event LIKE 'seed.ssh.started.spm1-%') OR
                                          (reason=? AND event LIKE 'seed.destination.started.spm1-%'))
                                      ORDER BY id DESC LIMIT 1""", (target.id, profile, destination)).fetchone()
            if last_start:
                last_node, _, setup = last_start['event'].split('.', 3)[3].partition('.')
                if NODE_ID.fullmatch(last_node):
                    view['last_start'] = {'node_id': last_node, 'recorded_at': last_start['recorded_at']}
                    last_setup = setup.partition('.')[0]
                    if last_setup in ('complete', 'join-required'):
                        view['last_start']['setup'] = last_setup
                    # Older receipts only bind the digest when the current package still matches the profile hash.
                    digest = target.sha256 if last_start['reason'] == profile else last_start['event'].partition('.sha256.')[2]
                    if re.fullmatch(r'[a-f0-9]{64}', digest):
                        view['last_start']['archive_sha256'] = digest
        if (local_details and target.platform == 'windows-amd64' and status != 'running'
                and view.get('setup') not in ('complete', 'join-required')
                and view.get('last_start', {}).get('setup') not in ('complete', 'join-required')
                and (status == 'started' or 'reported_node_id' in view or 'last_report' in view or 'last_start' in view)):
            directory = target.windows.get('state_directory')
            if directory is None:
                view['setup_task'] = target.windows.get('task_name', 'Spearmint')
            elif (path := PureWindowsPath(directory)).is_absolute():
                view['setup_path'] = str(path / onboarding.HANDOFF)
                view['setup_task'] = target.windows.get('task_name', 'Spearmint')
        return view

    def list(self) -> dict:
        if self.config_invalid:
            return {'targets': [], 'availability': 'config'}
        if not self.targets:
            return {'targets': [], 'availability': 'disabled'}
        with self.lock, self.state.connect(read_only=True) as db:
            realm = self.realm(db)
            if realm is None:
                return {'targets': [], 'availability': 'grove'}
            return {'targets': [self.view(db, target, realm, local_details=True) for target in self.targets.values()],
                    'availability': 'ready' if self.ssh else 'ssh'}

    def catalog(self, requester: str, authorize: Callable[[sqlite3.Connection], None], model: type[CatalogTarget]) -> dict:
        with self.lock, self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            authorize(db)
            realm = self.realm(db)
            if realm is None or not self.ssh:
                return {'targets': []}
            targets = [self.view(db, target, realm) for target in self.targets.values()
                       if requester in target.catalog_readers]
        return {'targets': [model.model_validate({key: target[key] for key in model.model_fields if key in target})
                            .model_dump(exclude_unset=True) for target in targets]}

    def configured_target(self, target_id: str) -> Target:
        if self.config_invalid:
            raise ControlError(503, 'SSH seed target configuration is unavailable')
        target = self.targets.get(target_id)
        if target is None:
            raise ControlError(404, 'SSH seed target is unavailable')
        if not self.ssh:
            raise ControlError(503, 'OpenSSH is unavailable on this node')
        return target

    def check(self, target_id: str, actor: auth.Actor, expected_revision: str | None = None) -> dict:
        target = self.configured_target(target_id)
        with self.lock:
            if self.checking or self.running:
                raise ControlError(409, 'An SSH target check or installation is already in progress on this node', code='seed_busy')
            with self.state.connect(read_only=True) as db:
                realm = self.realm(db)
                revision = self.view(db, target, realm)['revision'] if realm is not None else None
            if expected_revision is not None and revision != expected_revision:
                raise ControlError(409, 'Seed target changed. Refresh its status before proceeding', code='seed_stale')
            self.checking = True
        try:
            result = self.check_prerequisites(target)
            if revision is not None:
                if result['ready']:
                    event = 'seed.preflight.passed'
                    if linger := result.get('linger'):
                        event += f'.{linger}'
                else:
                    event = f"seed.preflight.failed.{result['stage']}"
                with self.lock, self.state.connect(write=True) as db:
                    audit(db, actor.operation_actor, actor.address, event, target.id, reason=revision)
            return result
        finally:
            with self.lock:
                self.checking = False

    def check_prerequisites(self, target: Target) -> dict:
        try:
            with TemporaryDirectory(prefix='.ssh-seed-check-', dir=self.state.directory) as directory:
                work = Path(directory)
                secure_private(work, 0o700)
                private_path(self.ssh_config, 0o600)
                archive_size = None
                if target.archive is not None:
                    with Path(target.archive).open('rb') as stream:
                        archive_size = os.fstat(stream.fileno()).st_size
                        if hashlib.file_digest(stream, 'sha256').hexdigest() != target.sha256:
                            return {'ready': False, 'stage': 'archive-checksum'}
                linger = seed_transport.check_target(work, host=target.host, target=target.platform, windows=target.windows_parameters(),
                                                     ssh=self.ssh, config=self.ssh_config, target_archive=target.target_archive,
                                                     digest=target.sha256 if target.target_archive is not None else '',
                                                     archive_size=archive_size, linux_grove_ca=target.linux_grove_ca,
                                                     linux_listener=target.linux_listener())
        except subprocess.SubprocessError as error:
            return {'ready': False, 'stage': seed_transport.failure(error)[1]}
        except (OSError, StateError, ValueError):
            return {'ready': False, 'stage': 'local'}
        return {'ready': True, 'linger': linger} if linger is not None else {'ready': True}

    def submit(self, actor: auth.Actor, target_id: str, revision: str, *, retry_started: bool = False) -> tuple[dict, Target, dict, str]:
        target = self.configured_target(target_id)
        with self.lock:
            with self.state.connect(write=True) as db:
                current = auth.active_session(db, actor.token_hash, int(time.time()))
                if current is None or current['id'] != actor.account_id or current['role'] != 'node_admin':
                    raise ControlError(403, 'Node administrator required')
                realm = self.realm(db)
                if realm is None:
                    raise ControlError(409, 'Grove invitation is unavailable')
                view = self.view(db, target, realm, local_details=True)
                if view['revision'] != revision or (view['status'] == 'started') != retry_started:
                    raise ControlError(409, 'Seed target changed. Refresh its status before proceeding')
                if view.get('setup') == 'complete':
                    raise ControlError(409, 'The installed node already completed Grove setup')
                if view.get('setup') == 'join-required':
                    raise ControlError(409, 'Sign in to the installed node to join the Grove')
                if self.checking or self.running:
                    raise ControlError(409, 'An SSH target check or installation is already in progress on this node', code='seed_busy')
                attempt = uuid4().hex
                if view['status'] == 'uncertain' and 'stage' not in view and view.get('reported_node_id'):
                    self.record(db, actor.operation_actor, actor.address, target, realm, 'uncertain',
                                f"receipt.{view.get('checkpoint', '')}.{view['reported_node_id']}")
                destination = destination_fingerprint(target, realm, self.ssh_config)
                self.record(db, actor.operation_actor, actor.address, target, realm, 'running', f'{attempt}.{destination}')
                view = self.view(db, target, realm, local_details=True) | {'status': 'running'}
            self.running[target_id] = None
            return view, target, realm, attempt

    def record(self, db, actor: str, source: str, target: Target, realm: dict, status: str, detail: str | None = None) -> None:
        if status == 'started' and detail:
            node_id = detail.partition('.')[0]
            if NODE_ID.fullmatch(node_id):
                audit(db, actor, source, f'seed.destination.started.{detail}.sha256.{target.sha256}', target.id,
                      reason=destination_fingerprint(target, realm, self.ssh_config))
        event = f'seed.ssh.{status}' + (f'.{detail}' if detail else '')
        audit(db, actor, source, event, target.id, reason=fingerprint(target, realm))

    def install(self, actor: auth.Actor, target: Target, realm: dict, attempt: str) -> None:
        status = 'failed'
        detail = 'local'
        failed_checkpoint = None
        temporary = None
        try:
            temporary = TemporaryDirectory(prefix=f'.ssh-seed-{attempt}-', dir=self.state.directory, delete=False)
            with temporary as directory:
                work = Path(directory)
                secure_private(work, 0o700)
                archive = Path(target.archive) if target.archive is not None else None

                def authorize_transfer() -> None:
                    with self.state.connect(read_only=True) as db:
                        current = auth.active_session(db, actor.token_hash, int(time.time()))
                        if (current is None or current['id'] != actor.account_id or current['role'] != 'node_admin'
                                or self.realm(db) != realm):
                            raise StateError('SSH seed authorization is no longer valid')
                    private_path(self.ssh_config, 0o600)

                with self.lock:
                    self.running[target.id] = work
                try:
                    receipt = seed_transport.install(
                        archive, work, host=target.host, target=target.platform, digest=target.sha256,
                        invitation_data=json.dumps(realm).encode(), origin=target.origin, port=target.port,
                        windows=target.windows_parameters(),
                        ssh=self.ssh, config=self.ssh_config, quiet=True, linux_grove_ca=target.linux_grove_ca,
                        target_archive=target.target_archive, linux_listener=target.linux_listener(),
                        timeout=target.install_timeout_seconds, capture_progress=True, before_connect=authorize_transfer,
                    )
                except subprocess.CalledProcessError:
                    failed_checkpoint = seed_transport.last_checkpoint(seed_transport.read_install_output(work))
                    raise
                finally:
                    # Stop readers before the temporary directory is removed on Windows.
                    with self.lock:
                        self.running[target.id] = None
                status, detail = 'started', startup_detail(receipt)
        except seed_transport.LocalArchiveMismatch:
            status, detail = 'checksum', None
        except subprocess.SubprocessError as error:
            status, detail, _ = seed_transport.failure(error)
            if isinstance(error, seed_transport.UnconfirmedInstall):
                if error.reported_node_id is not None:
                    detail = f'{detail}.{error.checkpoint or ""}.{error.reported_node_id}'
                elif error.checkpoint is not None:
                    detail = f'{detail}.{error.checkpoint}'
            elif status == 'failed' and failed_checkpoint is not None:
                detail = f'{detail}.{failed_checkpoint}'
        except (OSError, StateError, ValueError):
            pass
        finally:
            with self.lock:
                try:
                    with self.state.connect(write=True) as db:
                        self.record(db, actor.operation_actor, actor.address, target, realm, status, detail)
                finally:
                    self.running.pop(target.id, None)
            if temporary is not None:
                temporary.cleanup()
