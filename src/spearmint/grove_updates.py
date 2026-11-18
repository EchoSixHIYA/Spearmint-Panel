"""Coordinate a Grove update and exchange verified release archives over Mesh."""
import asyncio
from collections import Counter
from contextlib import suppress
from hashlib import sha256
import logging
from pathlib import Path
from secrets import token_hex
import sqlite3
from subprocess import SubprocessError
from tempfile import NamedTemporaryFile
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import grove, seed_packages, update_release as release, update_worker as worker
from .peer.grove_endpoints import trusted_members
from .peer.grove_service_admin import GroveServiceAdmin, admin_revision, require_member
from .peer.outbound import account_admin
from .peer.pairing import configured
from .peer.protocol import PeerError, parse_b64, wire_b64
from .platforms import WINDOWS, secure_private
from .state import StateError, audit


METHOD = 'grove.update.v1'
JOB_TTL = 24 * 60 * 60
TERMINAL = {'succeeded', 'failed', 'unsupported', 'expired'}
LOG = logging.getLogger(__name__)
IO_ERRORS = (OSError, ValueError, RuntimeError, sqlite3.Error, StateError, SubprocessError)
STATUSES = TERMINAL | {'queued', 'downloading', 'waiting_package', 'installing'}


class Offer(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

    job: str = Field(pattern=r'^[a-f0-9]{32}$')
    release: release.Release
    expires: int = Field(gt=0, lt=2**53)
    target: str = Field(pattern=r'^spm1-[a-f0-9]{64}$')
    identity: list


class StartUpdate(BaseModel):
    tag: str = Field(pattern=release.RELEASE_PATTERN, max_length=64)
    commit: str = Field(pattern=r'^[a-f0-9]{40}$')


class UpdateCoordinator:
    method = METHOD

    def __init__(self, state, remote, config, build: dict, host: dict):
        self.state = state
        self.remote = remote
        self.config = config
        self.local_id = remote.local_id
        self.build = build
        self.target = host['target']
        self.schema = host['schema']
        self.root = state.directory / 'grove-updates'
        self.root.mkdir(mode=0o700, exist_ok=True)
        secure_private(self.root, 0o700)
        self.group_path = self.root / 'group.json'
        self.local_path = self.root / 'local.json'
        self.seed_release_path = self.root / 'seed-release.json'
        self.catalog: release.Release | None = None
        self.github_checked = 0.0
        self.github_catalog: release.Release | None = None
        self.check_task: asyncio.Task | None = None
        self.downloads: dict[str, tuple[asyncio.Task, float]] = {}
        self.seed_downloads: dict[str, asyncio.Task] = {}
        self.seed_readers: Counter[str] = Counter()
        self.node_task: asyncio.Task | None = None
        self.node_retry = 0.0

    def members(self) -> list[str]:
        with self.state.connect() as db:
            trust = trusted_members(db, self.local_id)
            return sorted(trust.origins) if trust else []

    def identity(self, actor) -> list:
        with self.state.connect() as db:
            trust = trusted_members(db, self.local_id)
            if trust is None:
                raise PeerError('UNAVAILABLE', 'The Grove member directory is not current')
            account = account_admin(db, actor)
            user = account['grove_user']
            if user is None and db.execute('SELECT 1 FROM grove_realm WHERE is_issuer=1').fetchone():
                user = grove.user_id(trust.realm_id, actor.account_id)
            if user is None or account['mfa_at'] is None or account['mfa_at'] > int(time.time()):
                raise PeerError('DENIED', 'Sign in with a verified Grove administrator account')
            return admin_revision(db, trust.realm_id, user)

    async def verify_source(self, offer: Offer, pair=None, source: str | None = None) -> None:
        def check():
            with self.state.connect() as db:
                if pair is not None:
                    GroveServiceAdmin.from_wire(self.local_id, pair, offer.identity).require(db)
                    return
                if source is not None and source != self.local_id:
                    paired_source = configured(db, source)
                    if paired_source is None:
                        raise PeerError('DENIED', 'The update origin is no longer paired')
                    GroveServiceAdmin.from_wire(self.local_id, paired_source, offer.identity).require(db)
                    return
                trust = trusted_members(db, self.local_id)
                if trust is None or offer.identity != admin_revision(db, trust.realm_id, offer.identity[1]):
                    raise PeerError('DENIED', 'Grove administrator authorization changed')
        await self.remote.work(check, rpc=pair is not None)

    def audit_event(self, actor: str, source: str, event: str, job: str) -> None:
        with self.state.connect(write=True) as db:
            audit(db, actor, source, 'grove.update.' + event, job)

    async def check_github(self) -> None:
        try:
            self.github_catalog = await asyncio.to_thread(release.latest_release)
        except (*IO_ERRORS, KeyError, TypeError) as error:
            LOG.debug('Could not check GitHub Releases: %s', type(error).__name__)
            self.github_catalog = None
        finally:
            self.github_checked = time.monotonic()

    def check_in_background(self) -> asyncio.Task | None:
        if self.check_task is not None and not self.check_task.done():
            return self.check_task
        if self.github_checked and time.monotonic() - self.github_checked < 45:
            return None
        self.check_task = asyncio.create_task(self.check_github())
        return self.check_task

    async def discover_release(self) -> tuple[release.Release | None, str | None]:
        task = self.check_in_background()
        if task is not None:
            await asyncio.shield(task)
        if self.github_catalog is not None:
            return self.github_catalog, 'github'
        peers = [node for node in await self.remote.work(self.members) if node != self.local_id]
        for start in range(0, len(peers), 8):
            candidates = peers[start:start + 8]
            for attempt in range(4):
                responses = await asyncio.gather(*(self.ask(node, {'action': 'catalog'}) for node in candidates))
                available = []
                for node, response in zip(candidates, responses, strict=True):
                    if response and response.get('release'):
                        with suppress(ValidationError):
                            available.append((node, release.Release.model_validate(response['release'])))
                if available:
                    node, catalog = max(available, key=lambda item: item[1].sequence)
                    return catalog, node
                if not any(response and response.get('pending') for response in responses):
                    break
                if attempt < 3:
                    await asyncio.sleep(2)
        return None, None

    async def find_release(self) -> dict:
        self.catalog, source = await self.discover_release()
        return {'release': self.catalog.model_dump(), 'source': source} if self.catalog is not None else {'release': None}

    def cached_seed_release(self) -> release.Release | None:
        with suppress(OSError, ValueError, TypeError):
            cached = worker.read_record(self.seed_release_path)
            if cached is not None:
                return release.Release.model_validate(cached)
        return None

    async def seed_package(self, target: str) -> seed_packages.SeedArchive:
        if target not in release.TARGETS:
            raise PeerError('SEED_SYSTEM', 'No native deployment package supports this platform')
        catalog, _ = await self.discover_release()
        cached = self.cached_seed_release()
        if cached is not None and cached.database_schema == self.schema and (
                catalog is None or catalog.database_schema != self.schema or cached.sequence > catalog.sequence):
            catalog = cached
        if catalog is None or catalog.database_schema != self.schema:
            raise PeerError('SEED_PACKAGE_RELEASE', 'No compatible signed deployment release is available')
        asset = catalog.packages[target]
        digest = asset.sha256
        task = self.seed_downloads.get(digest)
        if task is None:
            task = asyncio.create_task(self.download_for_seed(asset))
            self.seed_downloads[digest] = task
            task.add_done_callback(lambda done: self.finish_seed_download(digest, done))
        self.seed_readers[digest] += 1
        try:
            if not await asyncio.shield(task):
                raise PeerError('SEED_PACKAGE_FETCH', 'Could not fetch a verified deployment archive from GitHub or another Grove member')
            package = await asyncio.to_thread(seed_packages.retain, self.state, self.archive(asset), catalog, target)
            with suppress(OSError):
                previous = self.cached_seed_release()
                if previous is None or previous.sequence < catalog.sequence:
                    worker.write_record(self.seed_release_path, catalog.model_dump())
            return package
        except OSError as error:
            raise PeerError('SEED_PACKAGE_FETCH', 'Could not cache the verified deployment archive') from error
        finally:
            self.seed_readers[digest] -= 1
            if not self.seed_readers[digest]:
                del self.seed_readers[digest]

    async def download_for_seed(self, asset: release.Asset) -> bool:
        try:
            async with asyncio.timeout(600):
                return await self.acquire(asset, wait_for_sources=True)
        except (PeerError, *IO_ERRORS):
            return False

    def finish_seed_download(self, digest: str, task: asyncio.Task) -> None:
        if self.seed_downloads.get(digest) is task:
            self.seed_downloads.pop(digest)
        if not task.cancelled():
            task.exception()

    async def ask(self, node: str, params: dict) -> dict | None:
        try:
            return await self.remote.call(node, METHOD, params, diagnostic=True)
        except PeerError as error:
            if error.code == 'UNSUPPORTED_METHOD':
                return {'status': 'unsupported', 'reason': 'updater_missing'}
            if params['action'] == 'offer' and error.code in {'DENIED', 'CONFLICT'}:
                return {'status': 'failed', 'reason': 'authorization_changed'}
            LOG.debug('Grove update RPC %s deferred for %s: %s', params['action'], node, error.code)
            return None

    async def start(self, intent: StartUpdate, actor) -> dict:
        identity = await self.remote.work(self.identity, actor)
        members = await self.remote.work(self.members)
        if not members:
            raise PeerError('UNAVAILABLE', 'The Grove member directory is not current')
        candidate = self.catalog
        if candidate is None or (candidate.tag, candidate.commit) != (intent.tag, intent.commit):
            raise PeerError('CONFLICT', 'Check for an update again before starting')
        if set(candidate.packages) != set(release.TARGETS):
            raise PeerError('UNAVAILABLE', 'Release does not contain all supported platforms')
        current = worker.read_record(self.group_path)
        now = int(time.time())
        if current and current['expires'] > now and any(row['status'] not in TERMINAL for row in current['nodes'].values()):
            if current['release'] == candidate.model_dump():
                return self.group_status()
            raise PeerError('CONFLICT', 'A Grove update is already in progress')
        job = token_hex(16)
        worker.write_record(self.group_path, {'job': job, 'release': candidate.model_dump(), 'identity': identity,
                                             'expires': now + JOB_TTL, 'nodes': {node: {'status': 'queued'} for node in members}})
        await self.remote.work(self.audit_event, identity[1], actor.address, 'started', job)
        return self.group_status()

    def group_status(self) -> dict:
        batch = worker.read_record(self.group_path)
        if not batch:
            return {'job': None}
        return {key: batch[key] for key in ('job', 'release', 'nodes', 'expires')}

    def local_status(self, offer: Offer, source: str) -> dict | None:
        job = worker.read_record(self.local_path)
        if not job or job['job'] != offer.job:
            return None
        if job['release'] != offer.release.model_dump() or (job['source'], job['source_node']) != (offer.identity, source):
            raise PeerError('CONFLICT', 'Update job ID was reused')
        return {key: job[key] for key in ('status', 'reason', 'source_node') if key in job}

    async def accept(self, offer: Offer, pair=None) -> dict:
        if offer.target != self.local_id or set(offer.release.packages) != set(release.TARGETS):
            raise PeerError('INVALID_REQUEST', 'Update is addressed to another node or has an invalid release')
        now = int(time.time())
        if offer.expires > now + JOB_TTL + 120:
            return {'status': 'expired'}
        await self.verify_source(offer, pair)
        source = pair.node_id if pair is not None else self.local_id
        if existing := self.local_status(offer, source):
            return existing
        if offer.expires <= now:
            return {'status': 'expired'}
        if self.build['commit'] == offer.release.commit:
            return {'status': 'succeeded', 'reason': 'already_current'}
        if self.target is None or not worker.supported():
            return {'status': 'unsupported', 'reason': 'native_install_required'}
        if offer.release.database_schema != self.schema:
            return {'status': 'unsupported', 'reason': 'schema_change'}
        if self.build['version'] and self.build['version'].count('.') == 2:
            version = self.build['version'].split('.')
            if all(part.isdecimal() for part in version) and tuple(map(int, version)) > tuple(map(int, offer.release.version.split('.'))):
                return {'status': 'unsupported', 'reason': 'older_release'}
        previous = worker.read_record(self.local_path)
        if previous and previous['status'] not in TERMINAL:
            return {'status': 'queued', 'reason': 'another_update'}
        if previous and previous['status'] == 'succeeded' and previous['release']['sequence'] > offer.release.sequence:
            return {'status': 'unsupported', 'reason': 'older_release'}
        config = {'origin': self.config.origin}
        if WINDOWS:
            config['windows'] = worker.windows_settings(self.config)
        worker.write_record(self.local_path, {'job': offer.job, 'release': offer.release.model_dump(), 'source': offer.identity,
                                             'source_node': source,
                                             'expires': offer.expires, 'node': self.local_id, 'target': self.target,
                                             'previous': self.build['commit'], 'config': config, 'status': 'queued'})
        await self.remote.work(self.audit_event, offer.identity[1], source, 'accepted', offer.job)
        return {'status': 'queued'}

    def archive(self, asset: release.Asset) -> Path:
        return self.root / (asset.sha256 + '.archive')

    def cleanup_cache(self) -> None:
        protected = self.downloads.keys() | self.seed_downloads.keys() | self.seed_readers.keys()
        local = worker.read_record(self.local_path)
        if local and local['status'] not in TERMINAL:
            protected.update(asset['sha256'] for asset in local['release']['packages'].values())
        files = sorted(self.root.glob('*.archive'), key=lambda item: item.stat().st_mtime, reverse=True)
        for file in files[6:]:
            if file.stem not in protected:
                file.unlink(missing_ok=True)

    async def from_github(self, asset: release.Asset) -> bool:
        try:
            await asyncio.to_thread(release.download, asset, self.archive(asset))
            return True
        except (*IO_ERRORS, KeyError, TypeError):
            return False

    def prepare(self, asset: release.Asset) -> asyncio.Task | None:
        now = time.monotonic()
        for digest, (task, until) in list(self.downloads.items()):
            if task.done() and until < now:
                self.downloads.pop(digest)
        if asset.sha256 in self.downloads:
            return self.downloads[asset.sha256][0]
        if sum(not task.done() for task, _ in self.downloads.values()) >= 3:
            return None
        self.cleanup_cache()
        task = asyncio.create_task(self.from_github(asset))
        self.downloads[asset.sha256] = (task, now + 30)
        return task

    def has_archive(self, asset: release.Asset) -> bool:
        path = self.archive(asset)
        return path.is_file() and path.stat().st_size == asset.size

    def read_chunk(self, asset: release.Asset, offset: int) -> dict:
        if not self.has_archive(asset):
            raise PeerError('UNAVAILABLE', 'Update package is not cached')
        with self.archive(asset).open('rb') as stream:
            stream.seek(offset)
            return {'data': wire_b64(stream.read(min(release.CHUNK, asset.size - offset)))}

    async def dispatch(self, pair, params: dict) -> dict:
        try:
            action = params.get('action')
            if action == 'offer' and set(params) == {'action', 'intent'}:
                return await self.accept(Offer.model_validate(params['intent']), pair)
            def authorize():
                with self.state.connect() as db:
                    require_member(db, self.local_id, pair)
            await self.remote.work(authorize, rpc=True)
            if action == 'catalog' and set(params) == {'action'}:
                pending = self.check_in_background() is not None
                catalog = self.github_catalog or self.cached_seed_release()
                return {'pending': pending, 'release': catalog.model_dump() if catalog else None}
            if action == 'prepare' and set(params) == {'action', 'asset'}:
                asset = release.Asset.model_validate(params['asset'])
                if self.has_archive(asset):
                    return {'ready': True}
                task = self.prepare(asset)
                return {'ready': False, 'pending': task is not None and not task.done()}
            if action == 'chunk' and set(params) == {'action', 'asset', 'offset'}:
                asset = release.Asset.model_validate(params['asset'])
                offset = params['offset']
                if type(offset) is int and 0 <= offset < asset.size and offset % release.CHUNK == 0:
                    return await self.remote.work(self.read_chunk, asset, offset, rpc=True)
        except (ValueError, OSError) as error:
            raise PeerError('INVALID_REQUEST', 'Invalid request for a Grove update') from error
        raise PeerError('INVALID_REQUEST', 'Unknown Grove update request')

    async def transfer(self, node: str, asset: release.Asset) -> bool:
        with NamedTemporaryFile(dir=self.root, delete=False) as stream:
            intermediate = Path(stream.name)
        try:
            digest = sha256()
            with intermediate.open('wb') as stream:
                for start in range(0, asset.size, 4 * release.CHUNK):
                    offsets = range(start, min(asset.size, start + 4 * release.CHUNK), release.CHUNK)
                    payloads = await asyncio.gather(*(self.ask(node, {'action': 'chunk', 'asset': asset.model_dump(),
                                                                     'offset': offset}) for offset in offsets))
                    for offset, payload in zip(offsets, payloads, strict=True):
                        block = parse_b64(payload.get('data'), release.CHUNK) if payload else b''
                        if len(block) != min(release.CHUNK, asset.size - offset):
                            return False
                        digest.update(block)
                        stream.write(block)
            if digest.hexdigest() != asset.sha256:
                return False
            intermediate.replace(self.archive(asset))
            return True
        except (OSError, ValueError):
            return False
        finally:
            intermediate.unlink(missing_ok=True)

    async def acquire(self, asset: release.Asset, *, wait_for_sources: bool = False) -> bool:
        if await asyncio.to_thread(release.correct_archive, self.archive(asset), asset):
            return True
        task = self.prepare(asset)
        if task is not None:
            done, _ = await asyncio.wait({task}, timeout=7)
            if done and task.result():
                return True
        peers = [node for node in await self.remote.work(self.members) if node != self.local_id]
        while True:
            pending = False
            for start in range(0, len(peers), 8):
                candidates = peers[start:start + 8]
                responses = await asyncio.gather(*(self.ask(node, {'action': 'prepare', 'asset': asset.model_dump()})
                                                   for node in candidates))
                for node, response in zip(candidates, responses, strict=True):
                    if response and response.get('ready') and await self.transfer(node, asset):
                        return True
                    pending = pending or bool(response and response.get('pending'))
            if task is not None and task.done() and task.result():
                return True
            if not wait_for_sources or (not pending and (task is None or task.done())):
                return False
            await asyncio.sleep(2)

    async def run_node(self, job: dict) -> None:
        candidate = release.Release.model_validate(job['release'])
        offer = Offer(job=job['job'], release=candidate, expires=job['expires'], target=self.local_id, identity=job['source'])
        try:
            if job['expires'] <= int(time.time()):
                self.write_status(job, 'expired')
                return
            self.write_status(job, 'downloading')
            if not await self.acquire(candidate.packages[self.target]):
                self.write_status(job, 'waiting_package', reason='source_unavailable')
                self.node_retry = time.monotonic() + 15
                return
            await self.verify_source(offer, source=job['source_node'])
            if job['expires'] <= int(time.time()):
                self.write_status(job, 'expired')
                return
            self.write_status(job, 'installing', started_at=int(time.time()))
            await asyncio.to_thread(worker.launch, self.state.directory, job['job'])
        except (PeerError, *IO_ERRORS) as error:
            LOG.warning('Grove update could not start: %s', type(error).__name__)
            status = 'waiting_package' if isinstance(error, PeerError) and error.code in {'BUSY', 'UNAVAILABLE'} else 'failed'
            self.write_status(job, status, reason='installer_unavailable' if job['status'] == 'installing' else 'update_unavailable')
            self.node_retry = time.monotonic() + 15

    def write_status(self, job: dict, status: str, **extra) -> None:
        job.pop('reason', None)
        job.update(status=status, **extra)
        worker.write_record(self.local_path, job)

    async def tick_node(self) -> None:
        if self.node_task and not self.node_task.done():
            return
        job = worker.read_record(self.local_path)
        if not job or job['status'] in TERMINAL:
            return
        if job['status'] == 'installing':
            result = worker.read_record(self.root / f"{job['job']}.result.json")
            if result is None and int(time.time()) - job['started_at'] > 920:
                success = job['release']['commit'] == self.build['commit']
                result = {'status': 'succeeded' if success else 'failed', 'reason': 'installer_interrupted'}
            if result is not None:
                if self.build['commit'] != job['release']['commit'] and result['status'] == 'succeeded':
                    result = {'status': 'failed', 'reason': 'running_commit_mismatch'}
                self.write_status(job, **result)
                await self.remote.work(self.audit_event, job['source'][1], job['source_node'], result['status'], job['job'])
            return
        if self.node_retry <= time.monotonic():
            self.node_task = asyncio.create_task(self.run_node(job))

    async def tick_group(self) -> None:
        batch = worker.read_record(self.group_path)
        if not batch or all(row['status'] in TERMINAL for row in batch['nodes'].values()):
            return
        expires = batch['expires']
        nodes = batch['nodes']
        before = {node: dict(row) for node, row in nodes.items()}
        if expires <= int(time.time()):
            for node, row in nodes.items():
                if row['status'] not in TERMINAL:
                    nodes[node] = {'status': 'expired'}
        else:
            members = await self.remote.work(self.members)
            if not members:
                return
            def intent(node):
                return {'job': batch['job'], 'release': batch['release'], 'identity': batch['identity'],
                        'expires': expires, 'target': node}
            targets = [node for node, row in nodes.items() if node != self.local_id and row['status'] not in TERMINAL]
            for start in range(0, len(targets), 8):
                candidates = targets[start:start + 8]
                results = await asyncio.gather(*(self.ask(node, {'action': 'offer', 'intent': intent(node)})
                                                 if node in members else asyncio.sleep(0, result={'status': 'unsupported', 'reason': 'member_removed'})
                                                 for node in candidates))
                for node, result in zip(candidates, results, strict=True):
                    if result and result.get('status') in STATUSES:
                        nodes[node] = {'status': result['status'], **({'reason': result['reason']}
                                       if isinstance(result.get('reason'), str) and len(result['reason']) <= 64 else {})}
                    elif nodes[node]['status'] == 'queued':
                        nodes[node] = {'status': 'queued', 'reason': 'waiting_node'}
            if nodes.get(self.local_id, {}).get('status') not in TERMINAL:
                try:
                    nodes[self.local_id] = await self.accept(Offer.model_validate(intent(self.local_id)))
                except PeerError as error:
                    if error.code not in {'BUSY', 'UNAVAILABLE'}:
                        nodes[self.local_id] = {'status': 'failed', 'reason': 'authorization_changed'}
        if nodes != before:
            latest = worker.read_record(self.group_path)
            if latest and latest['job'] == batch['job']:
                worker.write_record(self.group_path, batch)

    async def run(self) -> None:
        try:
            while True:
                try:
                    await self.tick_node()
                    await self.tick_group()
                except IO_ERRORS as error:
                    LOG.warning('Grove update check deferred: %s', type(error).__name__)
                await asyncio.sleep(4)
        finally:
            tasks = [task for task, _ in self.downloads.values()] + list(self.seed_downloads.values())
            tasks.extend(task for task in (self.node_task, self.check_task) if task is not None)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
