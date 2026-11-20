import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import partial
import json
import logging
from secrets import randbelow, token_hex
import sqlite3
import time
from typing import Callable, NamedTuple
from weakref import WeakKeyDictionary
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from ..auth import Actor
from .. import grove, grove_admission, grove_continuity, grove_login, grove_metadata, grove_password, grove_revocation, grove_roles, grove_web_join, seed_admission
from ..build_info import (DEPLOYMENT_DIRECTORY_METHOD, DEPLOYMENT_HOST_METHOD, DEPLOYMENT_METHOD,
                          DEPLOYMENT_PACKAGE_METHOD, DEPLOYMENT_WEB_METHOD, DeploymentStatus)
from ..catalog import Service, get_service
from ..control import OBSERVATION_TTL, Controller, ControlError
from ..drivers import LOG_LIMIT
from ..seeding import (
    CATALOG_METHOD as SEED_CATALOG, CATALOG_RECEIPTS_METHOD as SEED_RECEIPT_CATALOG, CATALOG_SETUP_METHOD as SEED_SETUP_CATALOG,
    CatalogReceiptTarget, CatalogSetupTarget, CatalogTarget, SeedCatalog, SeedDeployments, SeedReceiptCatalog, SeedSetupCatalog,
)
from ..state import State, StateError
from .approval_format import ACTIONS, operator_id
from .credentials import NODE_ID, RANDOM_ID
from .directory import (
    CATALOG_HEALTH_METHOD, DRIVERS, MAX_REVISION, STATUS_HEALTH_METHOD, apply_result, catalog_result, mirror_row,
    observation, valid_observation, validate_result,
)
from .discovery import INTERVAL as PEX_INTERVAL, METHOD as PEX_METHOD, Discovery
from .grove_endpoints import METHOD as GROVE_ENDPOINT_METHOD, GroveEndpoints, literal_endpoint, trusted_members
from .grove_service_admin import GroveServiceAdmin, source_identity
from .manager import Neighbor, PeerManager, diagnostic_rpc
from . import evidence_exchange, frp_access, grove_pairing, mesh_policy, quarantine
from .operations import (
    ACCOUNT_ACTIONS, ACCOUNT_ACTIONS_EXPLAIN, ACCOUNT_ACTIONS_VERSION, ACCOUNT_ACTION_REASONS, OPERATIONS,
    RECEIPT_REASON_METHODS, PeerOperations, grove_service_for,
)
from .observations import INTERVAL as OBSERVE_INTERVAL, METHOD as OBSERVE_METHOD, Observations
from .neighbors import Neighbors
from .outbound import OutboundOperations, account_request_id
from .pairing import Pair, members
from .policy import clean_expired, require_pair
from .protocol import IN_FLIGHT, RELAY_FRAMES, REQUEST, PeerError, matches, parse_b64, wire_b64
from .relay import Relay
from .reputation import GROUPS as OPTIONAL_RPC, Reputation
from .routing import Route, Routing
from .session import Session
from .adaptive import IDLE, AdaptiveRoutes, Binding, SwitchDeferred


logger = logging.getLogger(__name__)
LOCAL_WORKERS = 4
LOCAL_SLOTS = 8
RECOVERABLE = {"NO_ROUTE", "ROUTE_LOST", "OFFLINE", "TIMEOUT"}
HEALTH_METHODS = {"catalog.sync": CATALOG_HEALTH_METHOD, "service.status": STATUS_HEALTH_METHOD}
GROVE_SERVICE = 'service.grove_admin'


class PreparedDirectory(NamedTuple):
    pair: Pair
    sampled_at: float
    mode: str
    cursor: dict | None
    result: dict | None


def authorized_service(db: sqlite3.Connection, pair: Pair, service_id: str, permission: str):
    require_pair(db, pair)
    grant = db.execute("""
        SELECT status, logs FROM peer_export WHERE peer_id=? AND service_id=?
        """, (pair.node_id, service_id)).fetchone()
    if not grant or not grant[permission]:
        raise PeerError("NOT_FOUND", "Service is unavailable to this peer")
    service = get_service(db, service_id)
    if service is None:
        raise PeerError("NOT_FOUND", "Service is unavailable to this peer")
    return service


def parse_logs(result: dict) -> dict:
    if (not isinstance(result, dict) or result.keys() not in (
            {"text_b64", "truncated", "source", "checked_at"},
            {"text", "truncated", "source", "checked_at"})
            or type(result["truncated"]) is not bool or not isinstance(result["source"], str)
            or result["source"] not in DRIVERS or type(result["checked_at"]) not in {int, float}
            or not 0 <= result["checked_at"] <= MAX_REVISION):
        raise PeerError("PROTOCOL", "Invalid remote log metadata")
    try:
        if 'text' in result:
            text = result['text']
            if not isinstance(text, str) or len(text.encode('utf-8')) > LOG_LIMIT:
                raise ValueError('Invalid UTF-8 log text')
        else:
            text = parse_b64(result["text_b64"], LOG_LIMIT).decode("utf-8")
    except ValueError as exc:
        raise PeerError("PROTOCOL", "Invalid or oversized remote log text") from exc
    return {"text": text, "truncated": result["truncated"], "source": result["source"], "checked_at": result["checked_at"]}


def log_result(snapshot: dict, *, text_encoding: bool = False) -> dict:
    raw = snapshot['text'].encode('utf-8')
    text = raw[:LOG_LIMIT].decode('utf-8', 'ignore')
    bounded = text.encode('utf-8')
    result = {'truncated': snapshot['truncated'] or len(raw) > LOG_LIMIT,
              'source': snapshot['source'], 'checked_at': snapshot['checked_at']}
    # JSON is already UTF-8. Avoid Base64 expansion when the requester supports
    # text, but keep the bounded legacy form if JSON escaping would be larger.
    if text_encoding and len(json.dumps(text, ensure_ascii=False).encode('utf-8')) <= 4 * ((len(bounded) + 2) // 3) + 2:
        result['text'] = text
    else:
        result['text_b64'] = wire_b64(bounded)
    return result


class PeerServices:
    def __init__(self, state: State, local_id: str, controller: Controller, name: str, *, route_mode: str = 'legacy',
                 neighbor_minimum: int = 2, neighbor_target: int = 7, dial_enabled: bool = True,
                 advertise_ip: str | None = None, advertise_port: int | None = None) -> None:
        if route_mode not in {'legacy', 'adaptive'}:
            raise ValueError('Unknown Mesh route mode')
        self.state = state
        self.local_id = local_id
        self.controller = controller
        self.seed_deployments: SeedDeployments | None = None
        self.deployment_status: Callable[[], dict] | None = None
        self.grove_refresh: asyncio.Task[tuple[str, dict | None]] | None = None
        self.grove_sync_requested = asyncio.Event()
        self.mesh_enrollment_policy = None
        self.seed_wizard = None
        self.grove_updates = None
        self.service_setup = None
        self.terminals = None
        self.workspace = None
        self.service_deployments = None
        self.grove_directory_issuer: str | None = None
        self.grove_issuer_connection_id: str | None = None
        self.manager = PeerManager(state, local_id, self.handle, dial_enabled=dial_enabled)
        self.discovery = Discovery(state, local_id)
        signing_key = state.signing_key()
        self.grove_endpoints = (GroveEndpoints(local_id, signing_key, advertise_ip=advertise_ip, advertise_port=advertise_port)
                                if route_mode == 'adaptive' else None)
        self.manager.grove_endpoints = self.grove_endpoints
        self.endpoint_cursor = 0
        self.routing = Routing(self.manager, signing_key, adaptive=route_mode == 'adaptive')
        self.reputation = Reputation()
        self.account_operator_id = operator_id(signing_key.public_key())
        self.relay = Relay(self.manager, self.routing, self.handle)
        self.routing.relay_only = True
        self.manager.relay_enabled = True
        self.manager.adaptive = route_mode == 'adaptive'
        self.manager.control_handler = self.mesh_control
        self.manager.neighbor_lost = self.relay.link_lost
        self.manager.routing_status = self.routing_status
        self.operations = PeerOperations(state, local_id, name, controller)
        self.outbound = OutboundOperations(state, local_id)
        self.ready: dict[str, Session] = {}
        self.pending_counts: dict[str, int] = {}
        self.sync_modes: dict[str, str] = {}
        self.target_locks: dict[str, asyncio.Lock] = {}
        self.account_locks: dict[str, asyncio.Lock] = {}
        self.prepared: WeakKeyDictionary[Session, PreparedDirectory] = WeakKeyDictionary()
        self.adaptive = (AdaptiveRoutes(self.manager, self.routing, self.relay, self.prepare_binding,
            warm=self.warm_binding, prepared=self.directory_prepared,
            prepared_remaining=self.directory_prepared_remaining) if route_mode == 'adaptive' else None)
        self.observations = Observations(self.manager)
        if self.adaptive:
            self.manager.scheduler = Neighbors(self.manager, minimum=neighbor_minimum, target=neighbor_target,
                protected=self.protected_neighbors, coverage=self.neighbor_coverage,
                demand=lambda: {node for node in self.neighbor_demand() if self.connection_for(node) is None})

    def neighbor_demand(self) -> set[str]:
        return set(self.adaptive.used) | self.adaptive.pending_targets if self.adaptive else set()

    def neighbor_coverage(self) -> dict[str, set[str]]:
        coverage: dict[str, set[str]] = {}
        for node in self.neighbor_demand():
            routes = self.routing.routes(node)
            if self.adaptive:
                routes += [binding.route for binding in self.adaptive.bindings(node)]
            for route in routes:
                if self.manager.neighbors.get(route.first.pair.node_id) is route.first:
                    coverage.setdefault(route.first.pair.node_id, set()).add(node)
        return coverage

    def protected_neighbors(self) -> dict[str, set[str]]:
        protected: dict[str, set[str]] = {}
        for circuit in self.relay.circuits.values():
            for leg in circuit.legs:
                node = leg.link.pair.node_id
                if self.manager.neighbors.get(node) is leg.link:
                    protected.setdefault(node, set()).add('relay_circuit')
        coverage = self.neighbor_coverage()
        for target in self.neighbor_demand():
            first_hops = [node for node, targets in coverage.items() if target in targets]
            if len(first_hops) == 1:
                protected.setdefault(first_hops[0], set()).add('sole_first_hop')
            active = self.adaptive.active.get(target) if self.adaptive else None
            if active and active.circuit is None and self.adaptive.live(active):
                protected.setdefault(active.route.first.pair.node_id, set()).add('recent_business')
        return protected

    def routing_status(self) -> dict:
        result = {**self.routing.status(), 'relay': self.relay.status()}
        self.reputation.prune(self.manager.pairs.keys())
        result['peer_reputation'] = {node: self.reputation.status(node) for node in self.manager.pairs}
        if self.adaptive:
            result['neighbor_scheduler'] = self.manager.scheduler.status()
            result['targets'] = {node: {**self.adaptive.status(node),
                'observations': self.observations.status(node),
                'pending_requests': self.pending_counts.get(node, 0),
                'directory_ready': self.connection_for(node) is not None and self.ready.get(node) is self.connection_for(node)}
                for node, pair in self.manager.pairs.items() if pair.routed and not pair.legacy}
        return result

    @asynccontextmanager
    async def running(self):
        self.local_pool = ThreadPoolExecutor(max_workers=LOCAL_WORKERS, thread_name_prefix="peer-local")
        self.local_slots = asyncio.Semaphore(LOCAL_SLOTS)
        self.rpc_pool = ThreadPoolExecutor(max_workers=IN_FLIGHT, thread_name_prefix="peer-rpc")
        self.rpc_slots = asyncio.Semaphore(IN_FLIGHT)
        try:
            async with self.manager.running():
                tasks = [asyncio.create_task(self.sync()), asyncio.create_task(self.exchange_addresses()),
                         asyncio.create_task(self.relay.sweep()), asyncio.create_task(self.sync_policy()),
                         asyncio.create_task(self.sync_grove()), asyncio.create_task(self.sync_grove_metadata()),
                         asyncio.create_task(self.sync_grove_pairing())]
                if self.adaptive:
                    tasks.append(asyncio.create_task(self.adaptive.running()))
                    tasks.append(asyncio.create_task(self.exchange_observations()))
                try:
                    yield
                finally:
                    for task in tasks:
                        task.cancel()
                    if self.grove_refresh is not None:
                        self.grove_refresh.cancel()
                        tasks.append(self.grove_refresh)
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await self.routing.close()
                    self.ready.clear()
                    self.sync_modes.clear()
                    self.prepared.clear()
        finally:
            await asyncio.gather(
                asyncio.to_thread(self.local_pool.shutdown, cancel_futures=True),
                asyncio.to_thread(self.rpc_pool.shutdown, cancel_futures=True),
            )

    async def work(self, function, *args, rpc: bool = False, optional: tuple[str, str] | None = None):
        pool, slots = (self.rpc_pool, self.rpc_slots) if rpc else (self.local_pool, self.local_slots)
        if slots.locked():
            raise PeerError("BUSY", "Inbound Peer RPC slots are full" if rpc else "Local Peer state work is busy")
        await slots.acquire()
        reservation = None
        try:
            if optional is not None:
                reservation = self.reputation.reserve(*optional)
            future = asyncio.get_running_loop().run_in_executor(pool, partial(function, *args))
        except BaseException:
            if reservation is not None:
                self.reputation.release(reservation)
            slots.release()
            raise

        def finished(task):
            if reservation is not None:
                self.reputation.release(reservation)
            slots.release()
            if not task.cancelled():
                task.exception()

        future.add_done_callback(finished)
        return await asyncio.shield(future)

    async def committed_work(self, function, *args):
        return await self.wait_owned(asyncio.create_task(self.work(function, *args)))

    @staticmethod
    async def wait_owned(task):
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Keep the target lock until the executor has committed or rolled back.
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not task.cancelled():
                task.exception()
            raise

    def target_lock(self, node: str) -> asyncio.Lock:
        return self.target_locks.setdefault(node, asyncio.Lock())

    def mark_directory_ready(self, node: str, connection: Session) -> None:
        if self.ready.get(node) is not connection:
            connection.directory_generation = getattr(connection, 'directory_generation', 0) + 1
        self.ready[node] = connection
        if node == self.grove_directory_issuer and connection.connection_id != self.grove_issuer_connection_id:
            self.grove_issuer_connection_id = connection.connection_id
            self.grove_sync_requested.set()

    def directory_prepared(self, node: str, connection: Session) -> bool:
        return self.directory_prepared_remaining(node, connection) > 0

    def directory_prepared_remaining(self, node: str, connection: Session) -> float:
        stamp = self.prepared.get(connection)
        if not stamp or stamp.pair.node_id != node or connection.closed or not self.adaptive or not self.adaptive.admitted(stamp.pair):
            return 0.0
        age = self.adaptive.clock() - stamp.sampled_at
        return max(0.0, IDLE - age) if age >= 0 else 0.0

    def remember_directory(self, pair: Pair, connection: Session, mode: str, *,
                           cursor: dict | None = None, result: dict | None = None) -> PreparedDirectory:
        previous = self.prepared.get(connection)
        if mode == 'unchanged' and previous and previous.pair == pair:
            mode = previous.mode
        stamp = PreparedDirectory(pair, self.adaptive.clock(), mode, cursor, result)
        self.prepared[connection] = stamp
        return stamp

    def require_binding(self, pair: Pair, binding: Binding) -> None:
        if not self.adaptive or not self.adaptive.admitted(pair) or not self.adaptive.live(binding):
            raise PeerError('ROUTE_LOST', 'The candidate Mesh session is no longer available')

    async def sync_binding(self, pair: Pair, binding: Binding, cursor: dict) -> PreparedDirectory:
        self.require_binding(pair, binding)
        result = await self.request(binding.session, 'catalog.sync', cursor)
        self.require_binding(pair, binding)
        await self.work(self.validate_catalog, pair, result)
        self.require_binding(pair, binding)
        return self.remember_directory(pair, binding.session, result['mode'], cursor=cursor, result=result)

    async def warm_binding(self, pair: Pair, binding: Binding) -> None:
        try:
            async with self.target_lock(pair.node_id):
                self.require_binding(pair, binding)
                cursor = await self.work(self.cursor, pair, True)
                await self.sync_binding(pair, binding, cursor)
        except sqlite3.Error as error:
            raise PeerError('UNAVAILABLE', 'The standby Mesh catalog could not be updated') from error

    async def prepare_binding(self, pair: Pair, binding: Binding, commit: Callable[[], None],
                              check: Callable[[], None] | None = None) -> None:
        node = pair.node_id
        invalidated = None
        try:
            async with self.target_lock(node):
                self.require_binding(pair, binding)
                # Revalidate the persisted member even when the session already
                # synchronized its directory in the bounded standby task.
                cursor = await self.work(self.cursor, pair, True)
                self.require_binding(pair, binding)
                stamp = self.prepared.get(binding.session)
                if stamp is None or stamp.cursor != cursor or not self.directory_prepared(node, binding.session):
                    stamp = await self.sync_binding(pair, binding, cursor)
                await self.reconcile(pair, binding.session)
                self.require_binding(pair, binding)
                if not self.directory_prepared(node, binding.session):
                    cursor = await self.work(self.cursor, pair, True)
                    stamp = await self.sync_binding(pair, binding, cursor)
                if check is not None:
                    check()
                # The old connection cannot certify a cache committed by the candidate.
                previous = self.ready.pop(node, None)
                try:
                    await self.committed_work(self.apply, pair, stamp.result)
                except sqlite3.Error:
                    # The transaction failed. The previous session still owns the unchanged mirror.
                    if previous is not None and self.adaptive.admitted(pair) and self.connection_for(node) is previous:
                        self.ready[node] = previous
                    raise
                invalidated = previous
                self.require_binding(pair, binding)
                commit()
                self.mark_directory_ready(node, binding.session)
                mode = self.remember_directory(pair, binding.session, stamp.mode).mode
                if mode != 'unchanged' or node not in self.sync_modes:
                    self.sync_modes[node] = mode
        except SwitchDeferred:
            # Reconfirm the committed directory on the surviving primary, outside the target lock.
            if (invalidated is not None and self.adaptive.admitted(pair)
                    and self.connection_for(node) is invalidated):
                await self.sync_peer(pair, invalidated)
            raise
        except sqlite3.Error as error:
            raise PeerError('UNAVAILABLE', 'The local Mesh catalog could not be updated') from error

    async def handle(self, pair: Pair, method: str, params: dict) -> dict:
        node = pair.node_id
        group = OPTIONAL_RPC.get(method)
        current = pair.enabled and self.manager.pairs.get(node) == pair
        if group and not current:
            raise PeerError('OFFLINE', 'Peer pairing changed before optional work')
        optional = (node, group) if group else None
        try:
            return await self.dispatch(pair, method, params, optional)
        except PeerError as error:
            if error.code == 'INVALID_REQUEST' and current and self.manager.pairs.get(node) == pair:
                self.reputation.invalid_request(node, method)
            raise

    async def dispatch(self, pair: Pair, method: str, params: dict, optional: tuple[str, str] | None) -> dict:
        if method == OBSERVE_METHOD and self.adaptive:
            link = self.manager.neighbors.get(pair.node_id)
            if link is None or link.pair != pair:
                raise PeerError('OFFLINE', 'Observation requires the current direct neighbor')
            return self.observations.response(link, params)
        if method == grove.METHOD:
            return await self.work(self.grove_reply, pair, params, rpc=True)
        if method == grove_metadata.METHOD:
            return await self.work(grove_metadata.page, self.state, pair, params, rpc=True)
        if method == grove_pairing.METHOD:
            return await self.work(grove_pairing.attest,self.state,self.mesh_enrollment_policy,pair,params,rpc=True)
        if method in {grove_login.METHOD, grove_login.STANDBY_METHOD, grove_login.RECOVERY_METHOD}:
            return await self.work(self.grove_login_reply, pair, params, method, rpc=True)
        if method in {grove_web_join.METHOD, grove_web_join.INVITATION_METHOD}:
            config = getattr(self, 'grove_config', None)
            if config is None:
                raise PeerError('DENIED', 'Grove login verification is unavailable')
            handler = grove_web_join.invitation_reply if method == grove_web_join.INVITATION_METHOD else grove_web_join.reply
            return await self.work(handler, self.state, config, pair, params, rpc=True)
        if method in {grove_continuity.METHOD, grove_continuity.VOTE_METHOD, grove_continuity.PASSWORD_VOTE_METHOD,
                      grove_continuity.ROLE_VOTE_METHOD, grove_continuity.MEMBERS_VOTE_METHOD}:
            return await self.work(self.grove_continuity_vote, pair, params, method, rpc=True)
        if method == grove_continuity.STATUS_METHOD:
            return await self.work(self.grove_continuity_ready, pair, params, rpc=True)
        if method == grove_continuity.INSTALL_METHOD:
            return await self.work(self.grove_continuity_install, pair, params, rpc=True)
        if method == grove_continuity.DOCUMENT_METHOD:
            return await self.work(self.grove_continuity_document, pair, params, rpc=True)
        if method == grove_continuity.SNAPSHOT_METHOD:
            return await self.work(self.grove_continuity_snapshot, pair, params, rpc=True)
        if method == grove_continuity.RECOVERY_VOTE_METHOD:
            return await self.work(self.grove_recovery_vote, pair, params, rpc=True)
        if method == grove_revocation.APPLY:
            return await self.work(self.grove_operator_revocations, pair, params, rpc=True)
        if method == grove_password.APPLY:
            return await self.work(self.grove_password_change, pair, params, rpc=True)
        if method in {grove_roles.BALLOT_METHOD, grove_roles.GET_METHOD, grove_roles.APPLY_METHOD}:
            return await self.work(self.grove_role_rpc, pair, method, params, rpc=True)
        if method in {grove_admission.BALLOT, grove_admission.GET, grove_admission.APPLY, grove_admission.JOIN}:
            return await self.work(self.grove_admission_rpc, pair, method, params, rpc=True)
        if self.grove_updates is not None and method == self.grove_updates.method:
            return await self.grove_updates.dispatch(pair, params)
        if self.seed_wizard is not None:
            if method == self.seed_wizard.method:
                return await self.seed_wizard.dispatch(pair, params)
            if method == seed_admission.METHOD:
                return await self.work(self.seed_wizard.admission, pair, params, rpc=True)
        if method in (SEED_CATALOG, SEED_RECEIPT_CATALOG, SEED_SETUP_CATALOG) and self.seed_deployments is not None:
            return await self.work(self.seed_catalog_reply, pair, params, method, rpc=True)
        if method in (DEPLOYMENT_METHOD, DEPLOYMENT_HOST_METHOD, DEPLOYMENT_WEB_METHOD,
                      DEPLOYMENT_DIRECTORY_METHOD, DEPLOYMENT_PACKAGE_METHOD) and self.deployment_status is not None:
            return await self.work(self.deployment_reply, pair, params, method != DEPLOYMENT_METHOD,
                                   method in (DEPLOYMENT_WEB_METHOD, DEPLOYMENT_DIRECTORY_METHOD, DEPLOYMENT_PACKAGE_METHOD),
                                   method in (DEPLOYMENT_DIRECTORY_METHOD, DEPLOYMENT_PACKAGE_METHOD),
                                   method == DEPLOYMENT_PACKAGE_METHOD,
                                   rpc=True, optional=optional)
        if method == GROVE_ENDPOINT_METHOD and self.grove_endpoints is not None:
            realm_id = await self.work(self.endpoint_realm, pair, params, rpc=True)
            trust = self.grove_endpoints.members
            if trust is None or trust.realm_id != realm_id or pair.node_id not in trust.origins:
                raise PeerError('DENIED', 'Grove Mesh membership changed')
            return self.grove_endpoints.page(pair, self.manager.listening)
        if method == PEX_METHOD and not pair.legacy:
            return await self.work(self.discovery.page, pair, params, rpc=True)
        if method == mesh_policy.METHOD:
            return await self.work(self.policy_reply, pair, params, rpc=True)
        if method == evidence_exchange.LIST:
            return await self.work(evidence_exchange.page, self.state, pair, params, rpc=True, optional=optional)
        if method == evidence_exchange.PART:
            return await self.work(evidence_exchange.part, self.state, pair, params, rpc=True, optional=optional)
        if method in {"catalog.sync", "service.status", "service.logs", CATALOG_HEALTH_METHOD, STATUS_HEALTH_METHOD}:
            return await self.work(self.local, pair, method, params, rpc=True, optional=optional)
        if method == GROVE_SERVICE:
            return await self.work(self.grove_service_rpc, pair, params, rpc=True)
        if self.service_setup is not None and method == self.service_setup.method:
            return await self.work(self.service_setup.dispatch, pair, params, rpc=True)
        if self.terminals is not None and method == self.terminals.method:
            return await self.work(self.terminals.dispatch, pair, params, rpc=True)
        if self.workspace is not None and method == self.workspace.method:
            return await self.work(self.workspace.dispatch, pair, params, rpc=True)
        if self.service_deployments is not None and method == self.service_deployments.method:
            return await self.work(self.service_deployments.dispatch, pair, params, rpc=True)
        if method in frp_access.METHODS:
            return await self.work(frp_access.handle, self.state, self.local_id, pair, method, params, rpc=True)
        if method in OPERATIONS:
            return await self.work(self.operations.handle, pair, method, params, rpc=True)
        return await diagnostic_rpc(pair, method, params)

    def policy_reply(self, pair: Pair, params: dict) -> dict:
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_pair(db, pair)
            return mesh_policy.response(db, pair.mesh_id, params)

    def policy_cursor(self) -> dict | None:
        with self.state.connect() as db:
            db.execute("BEGIN")
            if mesh_policy.configured_trust(db) is None:
                return None
            return mesh_policy.cursor(db)

    def grove_reply(self, pair: Pair, params: dict) -> dict:
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            realm = db.execute('SELECT * FROM grove_realm').fetchone()
            member = db.execute('SELECT enabled FROM grove_member WHERE node_id=?', (pair.node_id,)).fetchone()
            if not realm or not member or not member['enabled'] or params != {'realm_id': realm['id']}:
                raise PeerError('DENIED', 'This peer is not an active Grove member')
            envelope = grove.publish(self.state, db, realm)
            grove.record_directory_request(db, realm, pair.node_id, transport='mesh')
            return envelope

    def endpoint_realm(self, pair: Pair, params: dict) -> str:
        if params:
            raise PeerError('INVALID_REQUEST', 'Grove Mesh endpoint exchange expects empty parameters')
        with self.state.connect() as db:
            db.execute('BEGIN')
            require_pair(db, pair)
            trust = trusted_members(db, self.local_id)
            if pair.legacy or trust is None or pair.node_id not in trust.origins:
                raise PeerError('DENIED', 'This peer is not an active Grove Mesh member')
            return trust.realm_id

    def grove_login_reply(self, pair: Pair, params: dict, method: str) -> dict:
        config = getattr(self, 'grove_config', None)
        if config is None or pair.legacy or pair.node_id not in config.grove_login_replicas:
            raise PeerError('DENIED', 'This member is not enrolled for Grove login verification')
        if set(params) != {'realm_id'} or not isinstance(params['realm_id'], str):
            raise PeerError('INVALID_REQUEST', 'Expected the current Grove ID')

        def authorize(db):
            require_pair(db, pair)
            if quarantine.contains(db, pair.node_id):
                raise PeerError('DENIED', 'This member is locally quarantined')

        standby = (config.grove_login_replicas if config.grove_login_standby else frozenset()) if method != grove_login.METHOD else None
        recovery = (config.grove_login_replicas if config.grove_login_recovery else frozenset()) if method == grove_login.RECOVERY_METHOD else None
        return grove_login.export_verifiers(self.state, pair.node_id, params['realm_id'], authorize, standby, recovery,
                                            standby_voters=config.grove_standby_voters)

    def grove_continuity_vote(self, pair: Pair, params: dict, method: str) -> dict:
        fields = {'nonce', 'anchor'}
        if method != grove_continuity.METHOD:
            fields.add('revocations')
        if method in {grove_continuity.PASSWORD_VOTE_METHOD, grove_continuity.ROLE_VOTE_METHOD, grove_continuity.MEMBERS_VOTE_METHOD}:
            fields.add('passwords')
        if method in {grove_continuity.ROLE_VOTE_METHOD, grove_continuity.MEMBERS_VOTE_METHOD}:
            fields.add('roles')
        if method == grove_continuity.MEMBERS_VOTE_METHOD:
            fields.add('members')
        if (params.keys() != fields or not matches(RANDOM_ID, params['nonce'])
                or any(not matches(grove_continuity.ANCHOR_DIGEST, params[field]) for field in fields - {'nonce'})):
            raise PeerError('INVALID_REQUEST', 'Invalid Grove continuity vote request')
        with self.state.connect(read_only=True) as db:
            require_pair(db, pair)
            if pair.legacy or quarantine.contains(db, pair.node_id):
                raise PeerError('DENIED', 'Grove continuity requires an active Mesh peer')
        return grove_continuity.vote(self.state, pair.node_id, params['nonce'], params['anchor'], params.get('revocations'),
                                    params.get('passwords'), params.get('roles'), params.get('members'))

    def grove_continuity_ready(self, pair: Pair, params: dict) -> dict:
        with self.state.connect(read_only=True) as db:
            require_pair(db, pair)
            realm = db.execute('SELECT id,issuer_node FROM grove_realm').fetchone()
            if (pair.legacy or quarantine.contains(db, pair.node_id) or realm is None
                    or pair.node_id != realm['issuer_node'] or params != {'realm_id': realm['id']}):
                raise PeerError('DENIED', 'Only the current Grove issuer can check member readiness')
        return grove_continuity.readiness(self.state, realm['id'])

    def grove_continuity_install(self, pair: Pair, params: dict) -> dict:
        if params.keys() != {'authorization'}:
            raise PeerError('INVALID_REQUEST', 'Expected a Grove retirement authorization')

        def authorize(db):
            require_pair(db, pair)
            realm = db.execute('SELECT issuer_node FROM grove_realm').fetchone()
            if (realm is None or pair.node_id != realm['issuer_node'] or pair.legacy
                    or quarantine.contains(db, pair.node_id)):
                raise PeerError('DENIED', 'Only the original identity node can initiate Grove retirement')

        anchor = grove_continuity.install_anchor(self.state, params['authorization'], authorize)
        return {'sequence': anchor['sequence']}

    def grove_continuity_document(self, pair: Pair, params: dict) -> dict:
        if params.keys() != {'realm_id'} or not isinstance(params['realm_id'], str):
            raise PeerError('INVALID_REQUEST', 'Expected the current Grove ID')
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            require_pair(db, pair)
            if pair.legacy or quarantine.contains(db, pair.node_id):
                raise PeerError('DENIED', 'The retirement authorization requires an active Mesh peer')
            return grove_continuity.retirement_document(db, params['realm_id'], pair.node_id)

    def grove_continuity_snapshot(self, pair: Pair, params: dict) -> dict:
        if params.keys() != {'realm_id'} or not isinstance(params['realm_id'], str):
            raise PeerError('INVALID_REQUEST', 'Expected the current Grove ID')
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            require_pair(db, pair)
            if pair.legacy:
                raise PeerError('DENIED', 'Grove recovery requires an active Mesh peer')
            return grove_continuity.snapshot(self.state, db, params['realm_id'], pair.node_id)

    def adopt_grove_snapshot(self, pair: Pair, bundle: dict, admission_certificate=None) -> None:
        config = getattr(self, 'grove_config', None)
        if config is None or pair.legacy:
            raise PeerError('DENIED', 'The local Grove panel origin is required')
        grove_continuity.import_snapshot(self.state, bundle, pair.node_id, config.origin, lambda db: require_pair(db, pair),
                                         admission_certificate)

    def grove_recovery_vote(self, pair: Pair, params: dict) -> dict:
        if params.keys() != {'anchor'} or not matches(grove_continuity.ANCHOR_DIGEST, params['anchor']):
            raise PeerError('INVALID_REQUEST', 'Expected the Grove recovery authorization digest')
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            require_pair(db, pair)
            if pair.legacy:
                raise PeerError('DENIED', 'Grove recovery requires an active Mesh peer')
            return grove_continuity.recovery_reply(db, pair.node_id, params['anchor'])

    def grove_operator_revocations(self, pair: Pair, params: dict) -> dict:
        def authorize(db):
            require_pair(db, pair)
            if pair.legacy:
                raise PeerError('DENIED', 'Grove revocation requires an active Mesh peer')

        if params.keys() != {'revocation'}:
            raise PeerError('INVALID_REQUEST', 'Expected one Grove operator revocation')
        count = grove_revocation.apply(self.state, [params['revocation']], pair.node_id, authorize)
        return {'accepted': True, 'applied': count}

    async def revoke_grove_operator(self, actor: Actor, user_id: str) -> dict:
        document, voters = await self.work(grove_revocation.issue, self.state, actor, user_id)
        replies = await asyncio.gather(*(self.call(node, grove_revocation.APPLY, {'revocation': document}, diagnostic=True)
                                       for node in voters if node != self.local_id), return_exceptions=True)
        confirmed = 1 + sum(isinstance(reply, dict) and reply.get('accepted') is True for reply in replies)
        await self.request_grove_sync()
        return {'confirmed': confirmed, 'members': len(voters)}

    def grove_password_change(self, pair: Pair, params: dict) -> dict:
        def authorize(db):
            require_pair(db, pair)
            if pair.legacy:
                raise PeerError('DENIED', 'Grove password changes require an active Mesh peer')

        if params.keys() != {'change'}:
            raise PeerError('INVALID_REQUEST', 'Expected one Grove password change')
        count = grove_password.apply(self.state, [params['change']], pair.node_id, authorize)
        return {'accepted': True, 'applied': count}

    async def change_grove_password(self, actor: Actor, current_password: str, new_password: str) -> dict:
        document, voters = await self.work(grove_password.issue, self.state, actor, current_password, new_password)
        replies = await asyncio.gather(*(self.call(node, grove_password.APPLY, {'change': document}, diagnostic=True)
                                       for node in voters if node != self.local_id), return_exceptions=True)
        confirmed = 1 + sum(isinstance(reply, dict) and reply.get('accepted') is True for reply in replies)
        await self.request_grove_sync()
        return {'confirmed': confirmed, 'members': len(voters)}

    def grove_role_rpc(self, pair: Pair, method: str, params: dict) -> dict:
        def authorize(db):
            require_pair(db, pair)
            if pair.legacy:
                raise PeerError('DENIED', 'Grove roles require an active Mesh peer')

        if method == grove_roles.APPLY_METHOD:
            if params.keys() != {'certificate'}:
                raise PeerError('INVALID_REQUEST', 'Expected a Grove role certificate')
            count = grove_roles.apply(self.state, [params['certificate']], pair.node_id, authorize)
            return {'applied': count}
        if params.keys() != {'user_id'} or not matches(grove_roles.USER_ID, params['user_id']):
            raise PeerError('INVALID_REQUEST', 'Expected a Grove user ID')
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            authorize(db)
            reader = grove_roles.read_vote if method == grove_roles.BALLOT_METHOD else grove_roles.read_certificate
            return reader(db, pair.node_id, params['user_id'])

    async def approve_grove_role(self, actor: Actor, user_id: str, role: str) -> dict:
        proposal, voters = await self.work(grove_roles.approve, self.state, actor, user_id, role)
        members = [node for node in voters if node != self.local_id]
        replies = await asyncio.gather(*(self.call(node, grove_roles.BALLOT_METHOD, {'user_id': user_id}, diagnostic=True)
                                       for node in members), return_exceptions=True)
        result, certificate = await self.work(grove_roles.collect, self.state, proposal, [r for r in replies if isinstance(r, dict)])
        if certificate:
            await asyncio.gather(*(self.call(node, grove_roles.APPLY_METHOD, {'certificate': certificate}, diagnostic=True)
                                   for node in members), return_exceptions=True)
            await self.request_grove_sync()
        return result

    def grove_admission_rpc(self, pair: Pair, method: str, params: dict) -> dict:
        def authorize(db):
            require_pair(db, pair)
            if pair.legacy:
                raise PeerError('DENIED', 'Grove admission requires a Mesh peer')

        if method == grove_admission.APPLY:
            if params.keys() != {'certificate'}:
                raise PeerError('INVALID_REQUEST', 'Expected a Grove admission certificate')
            changed = grove_admission.synchronize(self.state, params['certificate'], pair.node_id, authorize)
            return {'applied': changed}
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            authorize(db)
            if method == grove_admission.JOIN and not params:
                return grove_admission.join_bundle(self.state, db, pair.node_id)
            if method in {grove_admission.GET, grove_admission.BALLOT} and params.keys() == {'node_id'} and matches(NODE_ID, params['node_id']):
                reader = grove_admission.read_certificate if method == grove_admission.GET else grove_admission.read_ballot
                return reader(db, pair.node_id, params['node_id'])
        raise PeerError('INVALID_REQUEST', 'Invalid Grove admission request')

    async def approve_grove_member(self, actor: Actor, node: str, origin: str) -> dict:
        proposal, voters = await self.work(grove_admission.approve, self.state, actor, node, origin)
        others = [voter for voter in voters if voter != self.local_id]
        replies = await asyncio.gather(*(self.call(voter, grove_admission.BALLOT, {'node_id': node}, diagnostic=True)
                                       for voter in others), return_exceptions=True)
        result, certificate = await self.work(grove_admission.collect, self.state, proposal, [r for r in replies if isinstance(r, dict)])
        payload = {'certificate': certificate}
        if certificate and len(grove.encoded(payload)) < REQUEST - 128:
            await asyncio.gather(*(self.call(voter, grove_admission.APPLY, payload, diagnostic=True)
                                   for voter in others), return_exceptions=True)
        return result

    async def join_grove_as_member(self, actor: Actor, source: str) -> dict:
        def authorize_join():
            with self.state.connect(read_only=True) as db:
                grove_admission.require_unjoined_admin(db, actor)

        await self.work(authorize_join)
        pair = self.pair_for(source)
        if pair.legacy or not pair.enabled:
            raise PeerError('DENIED', 'Choose an authenticated Mesh member')
        bundle = await self.call(source, grove_admission.JOIN, {}, diagnostic=True)
        realm = await self.work(grove_admission.join, self.state, actor, self.grove_config.origin, bundle, source,
                                lambda db: require_pair(db, pair))
        await self.request_grove_sync()
        return realm

    async def join_grove_from_invitation(self, actor: Actor | None, code: str, *, seed_certificate=None) -> dict:
        expected, sources = grove_admission.read_invitation(code)

        def authorize_join():
            with self.state.connect(read_only=True) as db:
                if actor is not None:
                    grove_admission.require_unjoined_admin(db, actor)
                elif seed_certificate is None or db.execute('SELECT 1 FROM grove_realm').fetchone():
                    raise PeerError('DENIED', 'SSH enrollment requires an unjoined node and its admission certificate')

        await self.work(authorize_join)
        pairs = [pair for node in sources if (pair := self.manager.pairs.get(node)) is not None
                 and pair.enabled and not pair.legacy]
        if not pairs:
            raise PeerError('GROVE_PAIRING_REQUIRED', 'Pair this panel with a Grove voter before joining')

        slots = asyncio.Semaphore(4)

        async def retrieve(pair: Pair) -> tuple[Pair, dict]:
            async with slots:
                return pair, await self.call(pair.node_id, grove_admission.JOIN, {}, diagnostic=True)

        pending = [asyncio.create_task(retrieve(pair)) for pair in pairs]
        found = None
        deadline = asyncio.get_running_loop().time() + 18
        try:
            for result in asyncio.as_completed(pending):
                try:
                    async with asyncio.timeout_at(deadline):
                        pair, bundle = await result
                except TimeoutError:
                    break
                except PeerError:
                    continue
                if not isinstance(bundle, dict) or bundle.get('realm') != expected:
                    continue
                try:
                    found = await self.work(partial(grove_admission.join, seed_certificate=seed_certificate), self.state,
                                            actor, self.grove_config.origin, bundle, pair.node_id, partial(require_pair, pair=pair))
                except (PeerError, TypeError, ValueError, KeyError):
                    continue
                break
        finally:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        if found is None:
            raise PeerError('GROVE_ADMISSION_PENDING', 'No paired voter provided verified majority approval for this panel')
        await self.request_grove_sync()
        return found

    async def retire_grove_issuer(self, actor: Actor, voters: frozenset[str], *, selected: bool = False) -> dict:
        info = await self.work(grove.describe, self.state)
        if not info.get('local_issuer'):
            raise PeerError('DENIED', 'Only the original Grove identity node can retire its signing role')
        realm_id = info['realm']['id']

        async def check(node):
            return node, await self.call(node, grove_continuity.STATUS_METHOD, {'realm_id': realm_id}, diagnostic=True)

        readiness = {} if info.get('issuer_retired') or len(voters) < 2 else dict(
            await asyncio.gather(*(check(node) for node in voters)))
        authorization, anchor = await self.work(grove_continuity.issue_anchor, self.state, actor, voters, readiness, selected)
        results = await asyncio.gather(*(self.call(node, grove_continuity.INSTALL_METHOD,
            {'authorization': authorization}, diagnostic=True) for node in anchor['voters']), return_exceptions=True)
        delivered = sum(result == {'sequence': anchor['sequence']} for result in results)
        return {'authorization': authorization, 'delivered': delivered, 'required': len(anchor['voters'])}

    async def pull_grove_verifiers(self, realm: sqlite3.Row) -> None:
        issuer = realm['issuer_node']
        neighbor = self.manager.neighbors.get(issuer)
        if neighbor is not None and grove_login.METHOD not in neighbor.capabilities:
            return
        if neighbor is None and issuer not in self.manager.pairs:
            return
        try:
            params = {'realm_id': realm['id']}
            for method in (grove_login.RECOVERY_METHOD, grove_login.STANDBY_METHOD):
                if neighbor is not None and grove_login.STANDBY_METHOD not in neighbor.capabilities:
                    continue
                try:
                    bundle = await self.call(issuer, method, params, diagnostic=True)
                except PeerError as error:
                    if error.code != 'UNSUPPORTED_METHOD':
                        raise
                else:
                    expected = {'verifiers', 'standby', 'recovery'} if method == grove_login.RECOVERY_METHOD else {'verifiers', 'standby'}
                    if bundle.keys() != expected:
                        raise PeerError('PROTOCOL', 'Invalid Grove verifier bundle')
                    await self.work(grove_login.apply_verifiers, self.state, bundle['verifiers'], bundle['standby'], bundle.get('recovery'))
                    return
            envelope = await self.call(issuer, grove_login.METHOD, params, diagnostic=True)
            await self.work(grove_login.apply_verifiers, self.state, envelope)
        except (PeerError, ValueError, OSError, sqlite3.Error, StateError) as error:
            logger.debug('Grove member login verifier refresh deferred: %s', error)

    async def recover_grove_continuity(self, realm_id: str) -> None:
        recovery = await self.work(grove_continuity.recovery_status, self.state)
        if recovery is not None and await self.collect_grove_recovery(recovery):
            return

        async def retrieve(node):
            params = {'realm_id': realm_id}
            try:
                authorization = await self.call(node, grove_continuity.DOCUMENT_METHOD, params, diagnostic=True)
                await self.work(grove_continuity.install_document, self.state, authorization)
                return True
            except (PeerError, OSError, ValueError):
                pass
            if getattr(self, 'grove_config', None) is None:
                return False
            try:
                approved = await self.call(node, grove_admission.JOIN, {}, diagnostic=True)
                if approved.keys() != {'realm','certificate','snapshot'}:
                    raise PeerError('PROTOCOL', 'Invalid Grove member snapshot')
                await self.work(self.adopt_grove_snapshot, self.pair_for(node), approved['snapshot'], approved['certificate'])
                return True
            except (PeerError, OSError, ValueError, StateError):
                pass
            try:
                bundle = await self.call(node, grove_continuity.SNAPSHOT_METHOD, params, diagnostic=True)
                await self.work(self.adopt_grove_snapshot, self.pair_for(node), bundle)
                return True
            except (PeerError, OSError, ValueError, StateError) as error:
                logger.debug('Cannot recover Grove identity snapshot from %s: %s', node, error)
                return False

        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            realm = db.execute('SELECT issuer_node,frozen FROM grove_realm').fetchone()
            if realm is None:
                return
            roster = {row[0] for row in db.execute('SELECT node_id FROM grove_member WHERE enabled=1 AND node_id!=?',
                                                   (realm['issuer_node'],))}
        direct = {node for node, link in self.manager.neighbors.items()
                  if node in roster and grove_continuity.DOCUMENT_METHOD in link.capabilities}
        routed = {node for node, pair in self.manager.pairs.items()
                  if node in roster and node not in direct and pair.enabled and not pair.legacy and pair.routed
                  and (realm['frozen'] == 'restore' or self.connection_for(node) is not None)}
        for nodes in (direct, routed):
            candidates = [asyncio.create_task(retrieve(node)) for node in nodes]
            try:
                for result in asyncio.as_completed(candidates):
                    if await result:
                        return
            finally:
                for task in candidates:
                    task.cancel()
                await asyncio.gather(*candidates, return_exceptions=True)

    async def collect_grove_recovery(self, recovery: tuple[dict, dict, dict]) -> bool:
        envelope, anchor, local_ballot = recovery
        params = {'anchor': grove_continuity.anchor_digest(envelope)}

        async def collect(node):
            try:
                return node, await self.call(node, grove_continuity.RECOVERY_VOTE_METHOD, params, diagnostic=True)
            except (PeerError, ValueError, OSError):
                return node, None

        ballots = [asyncio.create_task(collect(node)) for node in anchor['voters'] if node != self.local_id]
        votes = {self.local_id: local_ballot}
        try:
            for result in asyncio.as_completed(ballots):
                node, ballot = await result
                if ballot is not None:
                    votes[node] = ballot
                if len(votes) > len(anchor['voters']) // 2:
                    await self.work(grove_continuity.install_recovery, self.state, {'authorization': envelope, 'votes': votes})
                    return True
            return False
        finally:
            for task in ballots:
                task.cancel()
            await asyncio.gather(*ballots, return_exceptions=True)

    async def renew_grove_continuity(self) -> bool | None:
        current = grove_continuity.local_anchor(self.state)
        if current is None:
            return None
        return await self.renew_grove_snapshot(current, standby=False)

    async def renew_grove_snapshot(self, current: tuple[dict, dict], *, standby: bool) -> bool:
        envelope, anchor = current
        nonce = token_hex(16)
        params = {'nonce': nonce, 'anchor': grove_continuity.anchor_digest(envelope)}
        if not standby:
            with self.state.connect(read_only=True) as db:
                db.execute('BEGIN')
                revision = grove_continuity.revocation_digest(db, params['anchor'])
                passwords = grove_continuity.password_digest(db, params['anchor'])
                roles = grove_continuity.role_versions(db)
                members = grove_continuity.admission_versions(db)
            roles_digest = grove_continuity.role_digest(roles)
            admissions_digest = grove_continuity.admission_digest(members)

        async def synchronize_roles(node_id, versions):
            if (not isinstance(versions, dict) or len(versions) > 64
                    or any(not matches(grove_roles.USER_ID, user_id) or type(version) is not int or not 0 < version < 2**63
                           for user_id, version in versions.items())):
                raise PeerError('PROTOCOL', 'Invalid Grove role versions')
            for user_id, version in versions.items():
                if version > roles.get(user_id, 0):
                    reply = await self.call(node_id, grove_roles.GET_METHOD, {'user_id': user_id}, diagnostic=True)
                    await self.work(grove_roles.apply, self.state, [reply.get('certificate')], node_id)

        async def synchronize_admissions(node_id, versions):
            if (not isinstance(versions, dict) or len(versions) > grove_admission.MAX_ADMISSIONS
                    or any(not matches(NODE_ID, member) or not isinstance(origin, str)
                           or len(origin) > grove_admission.MAX_ORIGIN_LENGTH for member, origin in versions.items())):
                raise PeerError('PROTOCOL', 'Invalid Grove admissions')
            for member, origin in versions.items():
                if members.get(member) != origin:
                    reply = await self.call(node_id, grove_admission.GET, {'node_id': member}, diagnostic=True)
                    pair = self.pair_for(node_id)
                    await self.work(grove_admission.synchronize, self.state, reply.get('certificate'), node_id,
                                    lambda db: require_pair(db, pair))

        async def request(node_id):
            try:
                if not standby:
                    versions = (
                        (grove_continuity.MEMBERS_VOTE_METHOD, {'revocations': revision, 'passwords': passwords,
                            'roles': roles_digest, 'members': admissions_digest}),
                        (grove_continuity.ROLE_VOTE_METHOD, {'revocations': revision, 'passwords': passwords,
                                                             'roles': roles_digest}),
                        (grove_continuity.PASSWORD_VOTE_METHOD, {'revocations': revision, 'passwords': passwords}),
                        (grove_continuity.VOTE_METHOD, {'revocations': revision}),
                    )
                    for method, fields in versions:
                        try:
                            reply = await self.call(node_id, method, params | fields, diagnostic=True)
                        except PeerError as error:
                            if error.code != 'UNSUPPORTED_METHOD':
                                raise
                            continue
                        if reply.keys() != {'ballot'} | fields.keys():
                            raise PeerError('PROTOCOL', 'Invalid Grove continuity vote')
                        if reply['revocations']:
                            await self.work(grove_revocation.apply, self.state, reply['revocations'], node_id)
                        if reply.get('passwords'):
                            await self.work(grove_password.apply, self.state, reply['passwords'], node_id)
                        if 'roles' in fields:
                            await synchronize_roles(node_id, reply['roles'])
                        if 'members' in fields:
                            await synchronize_admissions(node_id, reply['members'])
                        return node_id, reply['ballot']
                reply = await self.call(node_id, grove_continuity.METHOD, params, diagnostic=True)
                return node_id, reply
            except (PeerError, ValueError, OSError):
                return node_id, None

        requests = [asyncio.create_task(request(node)) for node in anchor['voters'] if node != self.local_id]
        votes = {}
        try:
            for result in asyncio.as_completed(requests):
                node, vote = await result
                if vote is not None:
                    votes[node] = vote
                if len(votes) + int(self.local_id in anchor['voters']) > len(anchor['voters']) // 2:
                    if await self.work(partial(grove_continuity.renew, standby=standby), self.state, envelope, nonce, votes):
                        return True
            return False
        finally:
            for task in requests:
                task.cancel()
            await asyncio.gather(*requests, return_exceptions=True)

    def seed_catalog_reply(self, pair: Pair, params: dict, method: str = SEED_CATALOG) -> dict:
        if params:
            raise PeerError('INVALID_REQUEST', 'Seed catalog expects empty parameters')

        def authorize(db):
            require_pair(db, pair)
            trust = trusted_members(db, self.local_id)
            if (pair.legacy or quarantine.contains(db, pair.node_id)
                    or trust is None or pair.node_id not in trust.origins):
                raise PeerError('DENIED', 'Seed catalog requires an active Grove Mesh member')

        model = {SEED_CATALOG: CatalogTarget, SEED_RECEIPT_CATALOG: CatalogReceiptTarget, SEED_SETUP_CATALOG: CatalogSetupTarget}[method]
        return self.seed_deployments.catalog(pair.node_id, authorize, model)

    def deployment_member(self, pair: Pair) -> tuple[str, str]:
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            require_pair(db, pair)
            trust = trusted_members(db, self.local_id)
            if (pair.legacy or quarantine.contains(db, pair.node_id)
                    or trust is None or pair.node_id not in trust.origins):
                raise PeerError('DENIED', 'Deployment status requires an active Grove Mesh member')
            return trust.realm_id, trust.origins[pair.node_id]

    def deployment_reply(self, pair: Pair, params: dict, include_host: bool = False, include_web_digest: bool = False,
                         include_directory: bool = False, include_package: bool = False) -> dict:
        member = self.deployment_member(pair)
        if params != {'realm_id': member[0]}:
            raise PeerError('DENIED', 'Grove membership changed')
        status = self.deployment_status()
        if not include_package and 'package_checksums_sha256' in status:
            status = {key: value for key, value in status.items() if key != 'package_checksums_sha256'}
        if include_directory:
            status = status | {'member_directory': grove.cached_member_directory_version(self.state, member[0])}
        if self.deployment_member(pair) != member:
            raise PeerError('DENIED', 'Grove membership changed')
        if not include_web_digest:
            status = status | {'web': {key: value for key, value in status['web'].items() if key != 'package_web_sha256'}}
        return status if include_host else {key: status[key] for key in ('build', 'web')}

    async def peer_deployment(self, node_id: str) -> dict:
        pair = self.pair_for(node_id)
        realm, origin = await self.work(self.deployment_member, pair)
        for method in (DEPLOYMENT_PACKAGE_METHOD, DEPLOYMENT_DIRECTORY_METHOD, DEPLOYMENT_WEB_METHOD,
                       DEPLOYMENT_HOST_METHOD, DEPLOYMENT_METHOD):
            try:
                result, connection = await self.call_with_connection(node_id, method, {'realm_id': realm}, diagnostic=True)
                break
            except PeerError as error:
                if error.code != 'UNSUPPORTED_METHOD':
                    raise
        else:
            raise PeerError('DEPLOYMENT_UNSUPPORTED', 'This node does not report deployment status')
        try:
            status = DeploymentStatus.model_validate(result)
        except ValidationError as error:
            raise PeerError('PROTOCOL', 'Invalid deployment status') from error
        if await self.work(self.deployment_member, pair) != (realm, origin):
            raise PeerError('DENIED', 'Grove membership changed')
        if self.connection_for(node_id) is not connection:
            raise PeerError('ROUTE_LOST', 'The deployment status connection changed')
        return {'node_id': node_id, 'origin': origin, 'connection_id': connection.connection_id,
                **status.model_dump(exclude_unset=True, by_alias=True)}

    def deployment_directory(self, realm_id: str, envelope: dict) -> dict:
        with self.state.connect(read_only=True) as db:
            row = db.execute('SELECT * FROM grove_realm WHERE id=?', (realm_id,)).fetchone()
        if row is None or row['frozen'] or row['issuer_paused']:
            raise PeerError('DENIED', 'Grove membership changed')
        directory = grove.directory_data(envelope, grove.realm_data(row))
        return {**grove.member_directory_version(directory), 'members': directory['members']}

    async def peer_deployment_directory(self, node_id: str) -> dict:
        pair = self.pair_for(node_id)
        realm, origin = await self.work(self.deployment_member, pair)
        envelope, connection = await self.call_with_connection(node_id, grove.METHOD, {'realm_id': realm}, diagnostic=True)
        result = await self.work(self.deployment_directory, realm, envelope)
        if await self.work(self.deployment_member, pair) != (realm, origin):
            raise PeerError('DENIED', 'Grove membership changed')
        if self.connection_for(node_id) is not connection:
            raise PeerError('ROUTE_LOST', 'The deployment directory connection changed')
        return {'node_id': node_id, 'origin': origin, 'connection_id': connection.connection_id, **result}

    def seed_catalog_access(self, node_id: str) -> str:
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            trust = trusted_members(db, self.local_id)
            if trust is None or node_id not in trust.origins or node_id == self.local_id:
                raise PeerError('NOT_FOUND', 'Unknown active Grove deployment node')
            pair = self.pair_for(node_id)
            require_pair(db, pair)
            if pair.legacy or quarantine.contains(db, node_id):
                raise PeerError('DENIED', 'Seed catalog requires an active Grove Mesh member')
            return trust.origins[node_id]

    async def seed_catalog(self, node_id: str) -> dict:
        await self.work(self.seed_catalog_access, node_id)
        for method, model in ((SEED_SETUP_CATALOG, SeedSetupCatalog), (SEED_RECEIPT_CATALOG, SeedReceiptCatalog),
                              (SEED_CATALOG, SeedCatalog)):
            try:
                result = await self.call(node_id, method, {}, diagnostic=True)
                break
            except PeerError as error:
                if error.code != 'UNSUPPORTED_METHOD':
                    raise
        else:
            raise PeerError('NOT_FOUND', 'This panel version has no SSH seed catalog')
        try:
            targets = model.model_validate(result).targets
            if len({target.id for target in targets}) != len(targets):
                raise ValueError('Duplicate target IDs')
        except (ValidationError, ValueError) as error:
            raise PeerError('PROTOCOL', 'Invalid Grove seed catalog') from error
        origin = await self.work(self.seed_catalog_access, node_id)
        return {'node_id': node_id, 'origin': origin, 'targets': [target.model_dump(exclude_unset=True) for target in targets]}

    async def pull_grove(self, realm: sqlite3.Row) -> str | None:
        async def request(session: Session) -> dict | None:
            try:
                return await session.call(grove.METHOD, {'realm_id': realm['id']})
            except (PeerError, ValueError, OSError):
                return None

        async def apply(response: dict | None) -> str | None:
            if response is not None:
                try:
                    return await self.work(grove.apply_directory, self.state, response)
                except (PeerError, ValueError, OSError):
                    pass
            return None

        issuer = self.connection_for(realm['issuer_node'])
        if issuer is not None:
            status = await apply(await request(issuer))
            if status in {'applied', 'unchanged', 'conflict'}:
                return 'issuer-mesh'

        sessions = dict.fromkeys(neighbor.session for neighbor in self.manager.neighbors.values()
                                 if grove.METHOD in neighbor.capabilities and neighbor.session is not issuer)
        neighbors = [asyncio.create_task(request(session)) for session in sessions]
        try:
            # Start both paths together. A verified issuer reply makes pending cache reads unnecessary.
            source = None
            config = getattr(self, 'grove_config', None)
            if config is not None:
                try:
                    status, via = await self.work(grove.pull_http, self.state, config)
                    if status == 'conflict':
                        return via
                    if status in {'applied', 'unchanged'}:
                        source = via
                except (PeerError, ValueError, OSError) as error:
                    logger.debug('Cannot refresh the Grove directory over HTTPS: %s', error)
            received = [task for task in neighbors if task.done()] if source == 'issuer-https' else neighbors
            # Apply each verified cache reply as it arrives. A slower peer can still advance the directory.
            for response in asyncio.as_completed(received):
                status = await apply(await response)
                if status == 'conflict':
                    return 'neighbor'
                if status == 'applied' or (status == 'unchanged' and source is None):
                    source = 'neighbor'
            return source
        finally:
            for task in neighbors:
                task.cancel()
            await asyncio.gather(*neighbors, return_exceptions=True)

    async def refresh_grove(self, *, report: bool = False) -> str | dict:
        task = self.grove_refresh
        if task is None or task.done():
            task = self.grove_refresh = asyncio.create_task(self.check_grove_directory())
            task.add_done_callback(self.finish_grove_refresh)
        status, receipt = await asyncio.shield(task)
        if report and status in {'checked', 'issuer'}:
            return receipt if receipt is not None else 'unavailable'
        return status

    def finish_grove_refresh(self, task: asyncio.Task) -> None:
        if self.grove_refresh is task:
            self.grove_refresh = None
        if not task.cancelled():
            task.exception()

    async def check_grove_directory(self) -> tuple[str, dict | None]:
        with self.state.connect(read_only=True) as db:
            realm = db.execute('SELECT * FROM grove_realm').fetchone()
        issuer = realm['issuer_node'] if realm is not None and not realm['is_issuer'] else None
        if issuer != self.grove_directory_issuer:
            self.grove_directory_issuer = issuer
            self.grove_issuer_connection_id = None
        if realm is None:
            return 'not-configured', None
        if realm['is_issuer']:
            if realm['issuer_paused']:
                return 'frozen', None
            if (config := getattr(self, 'grove_config', None)) is not None:
                await self.work(grove.sync_http, self.state, config)
            source = 'local-issuer'
        else:
            if (self.manager.pairs or self.manager.neighbors) and (recovery_realm := grove_continuity.recovery_realm(self.state)):
                await self.recover_grove_continuity(recovery_realm)
            continuity = await self.renew_grove_continuity()
            if continuity is not None:
                source = 'member-quorum' if continuity else None
            else:
                source = await self.pull_grove(realm)
                if source:
                    await self.pull_grove_verifiers(realm)
                if source not in {'issuer-mesh', 'issuer-https'} and (standby := grove_continuity.standby_anchor(self.state)):
                    if await self.renew_grove_snapshot(standby, standby=True):
                        source = 'member-standby'
        if not source:
            return 'unavailable', None
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            current = db.execute('SELECT * FROM grove_realm').fetchone()
            lease = grove.member_directory_lease(db, current['sequence']) if current is not None else None
            directory = grove.signed_member_directory_version(current, lease, db)
        if current is None or grove.realm_data(current) != grove.realm_data(realm):
            return 'changed', None
        if current['frozen'] or current['issuer_paused']:
            return 'frozen', None
        receipt = None if directory is None else {
            'realm_id': current['id'], 'source': source,
            'previous_sequence': str(realm['sequence']) if realm['manifest'] else None,
            'member_directory': directory,
        }
        return ('issuer' if realm['is_issuer'] else 'checked'), receipt

    async def request_grove_sync(self) -> None:
        self.grove_sync_requested.set()

    async def sync_grove(self) -> None:
        while True:
            self.grove_sync_requested.clear()
            try:
                await self.refresh_grove()
            except (PeerError, ValueError, OSError, sqlite3.Error) as error:
                logger.debug('Grove identity synchronization is waiting: %s', error)
            try:
                await asyncio.wait_for(self.grove_sync_requested.wait(), timeout=18 + randbelow(5))
            except TimeoutError:
                pass

    async def pull_grove_metadata(self, neighbor: Neighbor, realm: str) -> None:
        after = ''
        try:
            for _ in range(16):
                reply = await neighbor.session.call(grove_metadata.METHOD, {'realm':realm,'after':after})
                if reply.keys() != {'records','next'} or self.manager.neighbors.get(neighbor.pair.node_id) is not neighbor:
                    return
                await self.work(grove_metadata.merge, self.state, realm, reply['records'])
                cursor = reply['next']
                if not isinstance(cursor,str) or cursor <= after or not matches(NODE_ID,cursor):
                    return
                after = cursor
        except (PeerError, ValueError, OSError, sqlite3.Error) as error:
            logger.debug('Grove metadata synchronization is waiting: %s', error)

    async def sync_grove_metadata(self) -> None:
        while True:
            try:
                if realm := await self.work(grove_metadata.current_realm, self.state):
                    await asyncio.gather(*(self.pull_grove_metadata(node, realm)
                                           for node in self.manager.neighbors.values() if not node.pair.legacy))
            except (PeerError, ValueError, OSError, sqlite3.Error) as error:
                logger.debug('Grove metadata synchronization is waiting: %s', error)
            await asyncio.sleep(7)

    async def sync_grove_pairing(self) -> None:
        while True:
            try:
                context = await self.work(grove_pairing.candidates,self.state)
                if context:
                    _, anchor, voters, targets = context
                    sources = [node for node in voters if node in self.manager.pairs and self.manager.pairs[node].enabled]
                    if len(sources)>len(voters)//2:
                        for target in targets:
                            nonce = token_hex(16)
                            params = {'anchor':anchor,'target':target,'nonce':nonce}
                            votes = await asyncio.gather(*(self.call(node,grove_pairing.METHOD,params,diagnostic=True)
                                                           for node in sources),return_exceptions=True)
                            accepted = {node:vote for node,vote in zip(sources,votes) if isinstance(vote,dict)}
                            if len(accepted)>len(voters)//2:
                                await self.work(grove_pairing.install,self.state,target,nonce,accepted)
            except (PeerError,ValueError,OSError,StateError,sqlite3.Error) as error:
                logger.debug('Grove peer pairing synchronization is waiting: %s',error)
            await asyncio.sleep(12)

    async def pull_policy(self, neighbor: Neighbor, cursor: dict) -> None:
        try:
            result = await neighbor.session.call(mesh_policy.METHOD, cursor)
            if result == {"status": "unchanged"}:
                return
            if (result.keys() != {"status", "delegation", "snapshot"} or result["status"] != "snapshot"):
                raise ValueError("Unexpected Mesh policy response")
            if self.manager.neighbors.get(neighbor.pair.node_id) is neighbor:
                bundle = {key: result[key] for key in ("delegation", "snapshot")}
                await self.work(mesh_policy.apply, self.state, bundle, neighbor.pair.node_id)
        except (InvalidSignature, PeerError, StateError, ValueError, sqlite3.Error, OSError) as exc:
            logger.debug("Cannot refresh Mesh policy from %s: %s", neighbor.pair.node_id, exc)

    async def sync_policy(self) -> None:
        while True:
            try:
                cursor = await self.work(self.policy_cursor)
                if cursor is not None:
                    peers = [item for item in self.manager.neighbors.values() if mesh_policy.METHOD in item.capabilities]
                    await asyncio.gather(*(self.pull_policy(peer, cursor) for peer in peers))
            except (PeerError, sqlite3.Error) as exc:
                logger.debug("Cannot schedule Mesh policy sync: %s", exc)
            await asyncio.sleep(28 + randbelow(5))

    def mesh_control(self, neighbor: Neighbor, frame: dict) -> None:
        if frame["type"] in RELAY_FRAMES:
            self.relay.handle(neighbor, frame)
        else:
            self.routing.handle(neighbor, frame)

    def connection_for(self, node: str) -> Session | None:
        pair = self.manager.pairs.get(node)
        if self.adaptive and pair and pair.routed and not pair.legacy:
            return self.adaptive.connection_for(node)
        return self.manager.connection_for(node) or self.relay.session_for(node)

    def statuses(self) -> list[dict]:
        entries = self.manager.statuses()
        trust = self.grove_endpoints.members if self.grove_endpoints else None
        for entry in entries:
            node = entry["node_id"]
            pair = self.manager.pairs[node]
            automatic = entry.get('automatic_endpoint')
            origin = trust.origins.get(node) if trust else None
            origin_ip = literal_endpoint(urlsplit(origin).hostname or '') if origin else None
            if origin:
                entry['display_host'] = origin_ip or pair.host
            else:
                entry['display_host'] = automatic[0] if automatic else pair.source_ip or pair.host
            entry['local_reputation'] = self.reputation.status(node)
            if entry.get('local_quarantine'):
                continue
            if publication := self.directory_publication(node):
                entry['directory_generation'] = publication[1]
            if self.adaptive and pair.enabled and not pair.legacy:
                entry['observations'] = self.observations.status(node)
            if self.adaptive and pair.routed and not pair.legacy:
                session = self.adaptive.connection_for(node)
                binding = self.adaptive.active.get(node) if session else None
                if binding is None and pair.enabled:
                    # The business session can be idle while the direct Mesh link stays up.
                    binding = self.adaptive.direct(node)
                if binding:
                    entry.update(binding.route.public_data(), status='online', tls='TLSv1.3', **binding.session.link_metrics())
                    if binding.circuit:
                        entry['circuit_id'] = binding.circuit.identity
                else:
                    entry['status'] = ('disabled' if not pair.enabled else
                        'probing' if node in self.adaptive.attempts or node in self.routing.attempts else
                        'idle' if self.adaptive.reasons.get(node) == 'idle' else 'unreachable')
                entry['route_diagnostics'] = self.adaptive.status(node)
                entry['route_diagnostics']['observations'] = entry.get('observations', [])
                entry['route_diagnostics']['pending_requests'] = self.pending_counts.get(node, 0)
                entry['directory_ready'] = session is not None and self.ready.get(node) is session
                if session is not None:
                    entry['connection_id'] = session.connection_id
                continue
            session = self.manager.connection_for(node)
            if session is not None and not session.closed:
                entry.update(hops=1, direct=True, connection_id=session.connection_id)
                continue
            route = self.relay.route_for(node)
            session = self.relay.session_for(node)
            if route and session:
                entry.update(route.public_data(), status="online", tls="TLSv1.3",
                             circuit_id=self.relay.outbound[node].identity, connection_id=session.connection_id,
                             **session.link_metrics())
            elif entry["enabled"] and (node in self.relay.attempts or node in self.routing.attempts):
                entry["status"] = "probing"
        return entries

    async def connect(self, pair: Pair, *, background: bool = False) -> Session:
        if not pair.enabled:
            raise PeerError("OFFLINE", "Peer is disabled")
        if self.adaptive and pair.routed and not pair.legacy:
            return await self.adaptive.connect(pair, background=background)
        active = self.connection_for(pair.node_id)
        if active is not None:
            return active
        if pair.legacy or not pair.routed:
            raise PeerError("OFFLINE", "Peer is offline")
        return await self.relay.connect(pair)

    async def verify_route(self, node: str) -> Route:
        try:
            async with asyncio.timeout(22):
                session = await self.connect(self.pair_for(node))
                if await self.request(session, 'peer.ping', {}) != {'status': 'ok'}:
                    raise PeerError('PROTOCOL', 'Invalid Mesh probe response')
        except TimeoutError as error:
            raise PeerError('TIMEOUT', 'Mesh probe reached its total deadline') from error

        if self.connection_for(node) is session and not session.closed:
            binding = self.adaptive.active.get(node) if self.adaptive else None
            if binding is not None and binding.session is session:
                return binding.route
            if (neighbor := self.manager.neighbors.get(node)) is not None and neighbor.session is session:
                return Route((self.local_id, node), neighbor)
            if self.relay.session_for(node) is session and (route := self.relay.route_for(node)) is not None:
                return route
        raise PeerError('ROUTE_LOST', 'The verified Mesh session changed during the probe')

    def invalidate(self, node: str, session: Session | None, code: str = 'ROUTE_LOST') -> None:
        if self.adaptive:
            self.adaptive.invalidate(node, session, code)
        else:
            self.relay.invalidate(node, session)

    def local(self, pair: Pair, method: str, params: dict) -> dict:
        if method in {"catalog.sync", CATALOG_HEALTH_METHOD}:
            with self.state.connect() as db:
                db.execute("BEGIN")
                require_pair(db, pair)
                return catalog_result(db, pair.node_id, self.local_id, params,
                                      lambda key: self.describe(db, key, include_health=method == CATALOG_HEALTH_METHOD))
        logs = method == "service.logs"
        required = {"service_id", "tail"} if logs else {"service_id"}
        text_encoding = logs and params.keys() == required | {'text_encoding'} and params['text_encoding'] == 'utf8'
        if ((params.keys() != required and not text_encoding) or not matches(RANDOM_ID, params["service_id"])
                or (logs and (type(params["tail"]) is not int or not 1 <= params["tail"] <= 500))):
            raise PeerError("INVALID_REQUEST", "Invalid service request")
        service_id = params["service_id"]
        with self.state.connect() as db:
            db.execute("BEGIN")
            service = authorized_service(db, pair, service_id, "logs" if logs else "status")
            if not logs:
                return observation(self.controller.describe(service)["observation"], OBSERVATION_TTL,
                                   include_health=method == STATUS_HEALTH_METHOD)
        try:
            snapshot = self.controller.logs(service, params["tail"])
        except ControlError as exc:
            code = "BUSY" if exc.status == 429 else "UNAVAILABLE"
            raise PeerError(code, "Log data is temporarily unavailable") from exc
        with self.state.connect() as db:
            db.execute("BEGIN")
            authorized_service(db, pair, service_id, "logs")
        return log_result(snapshot, text_encoding=text_encoding)

    def describe(self, db: sqlite3.Connection, key: str, *, include_health: bool) -> dict:
        service = get_service(db, key)
        return observation(self.controller.describe(service)["observation"], OBSERVATION_TTL, include_health=include_health)

    def cursor(self, pair: Pair, require_current: bool = False) -> dict:
        with self.state.connect() as db:
            if require_current:
                require_pair(db, pair)
            row = mirror_row(db, pair.node_id)
        return {"epoch": row["epoch"], "revision": row["revision"]} if row else {"epoch": None, "revision": 0}

    def apply(self, pair: Pair, result: dict) -> None:
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            apply_result(db, pair.node_id, result)

    def validate_catalog(self, pair: Pair, result: dict) -> None:
        with self.state.connect(read_only=True) as db:
            db.execute("BEGIN")
            require_pair(db, pair)
            validate_result(mirror_row(db, pair.node_id), pair.node_id, result)

    async def exchange_addresses(self) -> None:
        while True:
            if self.manager.discovery_enabled:
                try:
                    await self.work(self.discovery.refresh)
                except (StateError, PeerError, sqlite3.Error, ValueError, OSError) as exc:
                    logger.debug("Cannot publish Mesh address: %s", exc)
                else:
                    await asyncio.gather(*(self.exchange_with(peer) for peer in self.manager.neighbors.values()
                                           if not peer.pair.legacy and PEX_METHOD in peer.capabilities))
            if self.grove_endpoints is not None and self.grove_endpoints.members is not None:
                await self.exchange_grove_endpoints()
            await asyncio.sleep(PEX_INTERVAL)

    async def exchange_grove_endpoints(self) -> None:
        trust = self.grove_endpoints.members
        contacts = []
        for node in sorted(trust.origins.keys() & self.manager.pairs.keys()):
            pair = self.manager.pairs[node]
            session = self.manager.connection_for(node) or self.connection_for(node)
            if pair.enabled and not pair.legacy and session is not None and not session.closed:
                contacts.append((pair, session))
        if not contacts:
            return
        start = self.endpoint_cursor % len(contacts)
        count = min(4, len(contacts))
        self.endpoint_cursor = start + count

        async def exchange(pair: Pair, session: Session) -> None:
            try:
                response = await session.call(GROVE_ENDPOINT_METHOD, {})
                if (self.manager.pairs.get(pair.node_id) == pair and self.grove_endpoints.members == trust
                        and session in (self.manager.connection_for(pair.node_id), self.connection_for(pair.node_id))):
                    self.grove_endpoints.accept(response, self.manager.pairs)
            except PeerError as error:
                logger.debug('Cannot exchange Grove Mesh endpoints with %s: %s', pair.node_id, error)

        await asyncio.gather(*(exchange(*contacts[(start + offset) % len(contacts)]) for offset in range(count)))

    async def exchange_with(self, neighbor: Neighbor) -> None:
        after = None
        try:
            for _ in range(4):
                page = await neighbor.session.call(PEX_METHOD, {"after": after})
                if self.manager.neighbors.get(neighbor.pair.node_id) is not neighbor:
                    return
                after = await self.work(self.discovery.accept_page, neighbor.pair, page, after)
                if after is None:
                    return
        except (PeerError, sqlite3.Error) as exc:
            logger.debug("Cannot exchange Mesh addresses with %s: %s", neighbor.pair.node_id, exc)

    async def observe_with(self, neighbor: Neighbor) -> None:
        try:
            payload = await neighbor.session.call(OBSERVE_METHOD, {})
            self.observations.accept(neighbor, payload)
        except PeerError as error:
            logger.debug('Cannot refresh direct observations from %s: %s', neighbor.pair.node_id, error)

    async def exchange_observations(self) -> None:
        try:
            while True:
                self.observations.expire()
                neighbors = [link for link in self.manager.neighbors.values() if self.observations.current(link)]
                await asyncio.gather(*(self.observe_with(link) for link in neighbors))
                await asyncio.sleep(OBSERVE_INTERVAL + randbelow(1001) / 1000)
        finally:
            self.observations.evidence.clear()

    async def sync(self) -> None:
        probes: dict[str, tuple[Pair, asyncio.Task[bool]]] = {}
        successful: dict[str, Pair] = {}
        next_probe: dict[str, float] = {}
        witnessed: set[str] = set()
        hinted: set[str] = set()
        try:
            while True:
                try:
                    await self.work(clean_expired, self.state)
                    if self.adaptive:
                        self.pending_counts = await self.work(self.outbound.pending_counts)
                        self.adaptive.pending_targets = set(self.pending_counts)
                except (PeerError, sqlite3.Error) as exc:
                    logger.debug("Cannot clean expired remote permissions: %s", exc)
                for node, (pair, task) in list(probes.items()):
                    if task.done():
                        probes.pop(node)
                        if await task:
                            successful[node] = pair
                for node, pair in list(successful.items()):
                    if self.manager.pairs.get(node) != pair:
                        successful.pop(node)
                for node in self.ready.keys() - self.manager.pairs.keys():
                    self.ready.pop(node, None)
                    self.sync_modes.pop(node, None)
                    next_probe.pop(node, None)
                for node in next_probe.keys() - self.manager.pairs.keys():
                    next_probe.pop(node)
                now = time.monotonic()
                observed = self.observations.targets() if self.adaptive else set()
                hinted = (hinted | (observed - witnessed)) & observed
                for node in observed - witnessed:
                    if self.connection_for(node) is None:
                        next_probe[node] = min(next_probe.get(node, now), now)
                witnessed = observed
                demand = self.neighbor_demand()
                active = []
                pairs = sorted(self.manager.pairs.items(), key=lambda item: (
                    item[0] not in (self.adaptive.pending_targets if self.adaptive else set()),
                    item[0] not in demand,
                    item[0] not in hinted,
                    self.adaptive.last_served.get(item[0], 0) if self.adaptive else 0,
                    next_probe.get(item[0], 0), item[0]))
                for node, pair in pairs:
                    connection = self.connection_for(node)
                    if connection is not None and node not in probes:
                        hinted.discard(node)  # The live connection already serves this observation.
                        if self.ready.get(node) is connection and not connection.closed:
                            successful[node] = pair
                        active.append(self.sync_peer(pair, connection))
                    elif connection is None:
                        self.ready.pop(node, None)
                        self.sync_modes.pop(node, None)
                        # An open console can keep primary reachability current.
                        # With no viewer, unused relays keep their idle lease.
                        physical = self.manager.connection_for(node)
                        renew = (self.adaptive is None or successful.get(node) != pair
                                 or self.adaptive.watching_statuses
                                 or node in demand or node in hinted
                                 or (physical is not None and not physical.closed))
                        if (pair.enabled and pair.routed and not pair.legacy and len(probes) < 2
                                and renew and node not in probes and next_probe.get(node, 0) <= now):
                            next_probe[node] = now + 8
                            if node in hinted:
                                self.routing.counts['observed_probes'] += 1
                                hinted.discard(node)
                            probes[node] = pair, asyncio.create_task(self.probe(pair))
                await asyncio.gather(*active)
                await asyncio.sleep(2)
        finally:
            for _, task in probes.values():
                task.cancel()
            await asyncio.gather(*(task for _, task in probes.values()), return_exceptions=True)

    async def probe(self, pair: Pair) -> bool:
        try:
            connection = await self.connect(pair, background=True)
            await self.sync_peer(pair, connection)
            return (self.ready.get(pair.node_id) is connection
                    and self.connection_for(pair.node_id) is connection and not connection.closed)
        except PeerError as exc:
            if self.adaptive and self.adaptive.reasons.get(pair.node_id) == 'idle':
                self.adaptive.reasons[pair.node_id] = 'probe_failed'
            logger.debug("Cannot establish a routed directory for %s: %s", pair.node_id, exc)
            return False

    async def sync_peer(self, pair: Pair, connection: Session) -> bool:
        node = pair.node_id
        try:
            async with self.target_lock(node):
                if connection is not self.connection_for(node):
                    return False
                cursor = await self.work(self.cursor, pair)
                result = await self.request(connection, "catalog.sync", cursor)
                if connection is not self.connection_for(node):
                    return False
                await self.committed_work(self.apply, pair, result)
                try:
                    await self.reconcile(pair, connection)
                except PeerError as exc:
                    # Keep serving the synchronized catalog on an established
                    # session. A new session still must reconcile before use.
                    if exc.code not in {"TIMEOUT", "BUSY"} or self.ready.get(node) is not connection:
                        raise
                    logger.debug("Cannot update remote operation receipts for %s: %s", node, exc)
                if connection is self.connection_for(node) and not connection.closed:
                    self.mark_directory_ready(node, connection)
                    if self.adaptive:
                        self.remember_directory(pair, connection, result['mode'])
                    if result["mode"] != "unchanged" or node not in self.sync_modes:
                        self.sync_modes[node] = result["mode"]
                    return True
        except (PeerError, sqlite3.Error) as exc:
            if self.ready.get(node) is connection:
                self.ready.pop(node, None)
            logger.debug("Cannot update remote directory for %s: %s", node, exc)
        return False

    async def directory(self, node_id: str, *, refresh: bool = False) -> dict:
        pair = self.pair_for(node_id)
        connection = self.connection_for(node_id)
        adaptive = self.adaptive if self.adaptive and self.adaptive.admitted(pair) else None
        if adaptive:
            adaptive.touch(node_id)
        needs_connection = adaptive is not None and (connection is None or self.ready.get(node_id) is not connection)
        refreshed = None
        if needs_connection or (refresh and pair.enabled and connection is not None):
            try:
                async with asyncio.timeout(15):
                    if needs_connection:
                        connection = await self.connect(pair)
                    if connection is not None and (refresh or self.ready.get(node_id) is not connection):
                        if await self.sync_peer(pair, connection):
                            refreshed = connection
            except (PeerError, TimeoutError) as exc:
                logger.debug("Directory view for %s is using its cached snapshot: %s", node_id, exc)
        publication = self.directory_publication(node_id)
        if refresh and (publication is None or publication[0] is not refreshed):
            publication = None
        snapshot = await self.work(self.cached, pair)
        return self.directory_view(node_id, snapshot, publication)

    def directory_connection(self, node_id: str) -> Session | None:
        connection = self.connection_for(node_id)
        if connection is not None and not connection.closed and self.ready.get(node_id) is connection:
            return connection
        return None

    def directory_publication(self, node_id: str) -> tuple[Session, int] | None:
        connection = self.directory_connection(node_id)
        if connection is not None:
            return connection, getattr(connection, 'directory_generation', 0)
        return None

    def directory_view(self, node_id: str, snapshot: tuple[dict, dict, dict], publication: tuple[Session, int] | None) -> dict:
        cursor, entries, observations = snapshot
        current = publication is not None and self.directory_publication(node_id) == publication
        now = time.time()
        services = []
        for key, entry in entries.items():
            observed = observations.get(key)
            if observed:
                observed = {**observed, "stale": (observed["stale"] or not current
                            or observed["valid_until"] is None or observed["valid_until"] <= now)}
                if observed["stale"]:
                    observed.pop("health", None)
            services.append({**entry, "observation": observed})
        return {
            **cursor, "node_id": node_id, "stale": not current, "sync_mode": self.sync_modes.get(node_id) if current else None,
            "connection_id": publication[0].connection_id if current else None,
            "directory_generation": publication[1] if current else None,
            "services": sorted(services, key=lambda entry: (entry["name"], entry["id"])),
        }

    def grove_service_rpc(self, pair: Pair, params: dict) -> dict:
        if params.keys() != {'identity', 'action', 'body'} or not isinstance(params['body'], dict):
            raise PeerError('INVALID_REQUEST', 'Invalid Grove service request')
        actor = GroveServiceAdmin.from_wire(self.local_id, pair, params['identity'])
        action, body = params['action'], params['body']
        if action == 'catalog' and not body:
            with self.state.connect() as db:
                db.execute('BEGIN')
                actor.require(db)
                services = [Service.from_row(row) for row in db.execute('SELECT * FROM service ORDER BY name,id')]
            return {'services': [{'id': service.id, 'name': service.name, 'driver': service.driver,
                                  'version': service.version, 'status': True, 'logs': service.logs_available,
                                  'actions': service.actions,
                                  'observation': observation(self.controller.describe(service)['observation'],
                                                             OBSERVATION_TTL, include_health=True)}
                                 for service in services]}
        service_id = body.get('service_id')
        if not matches(RANDOM_ID, service_id):
            raise PeerError('INVALID_REQUEST', 'Invalid service ID')
        service_version = body.get('service_version')
        valid_version = type(service_version) is int and 1 <= service_version <= MAX_REVISION
        if action == 'actions' and body.keys() == {'service_id', 'service_version'} and (valid_version or service_version is None):
            return self.operations.grove_actions(actor, service_id, service_version)
        if (action == 'submit' and body.keys() == {'service_id', 'service_version', 'action', 'request_id'}
                and valid_version and matches(RANDOM_ID, body['request_id'])
                and isinstance(body['action'], str) and body['action'] in ACTIONS):
            return self.operations.grove_submit(actor, service_id, body)
        if action == 'receipt' and body.keys() == {'service_id', 'request_id'} and matches(RANDOM_ID, body['request_id']):
            return {'receipt': self.operations.grove_receipt(actor, service_id, body['request_id'])}
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
            service = grove_service_for(db, service_id)
        if action == 'status' and body.keys() == {'service_id'}:
            return observation(self.controller.describe(service)['observation'], OBSERVATION_TTL, include_health=True)
        tail = body.get('tail')
        if action == 'logs' and body.keys() == {'service_id', 'tail'} and type(tail) is int and 1 <= tail <= 500:
            if not service.logs_available:
                raise PeerError('NOT_FOUND', 'Windows service logs are unavailable')
            try:
                snapshot = self.controller.logs(service, tail)
            except ControlError as error:
                raise PeerError('BUSY' if error.status == 429 else 'UNAVAILABLE', 'Log data is temporarily unavailable') from error
            with self.state.connect() as db:
                db.execute('BEGIN')
                actor.require(db)
                if grove_service_for(db, service_id) != service:
                    raise PeerError('CONFLICT', 'The service changed while reading its logs')
            return log_result(snapshot, text_encoding=True)
        raise PeerError('INVALID_REQUEST', 'Invalid Grove service request')

    async def grove_service(self, node_id: str, actor: Actor, action: str, body: dict, *,
                            connection_id: str | None = None, directory_generation: int | None = None) -> dict | None:
        pair = self.pair_for(node_id)
        try:
            identity = await self.work(source_identity, self.state, self.local_id, pair, actor)
        except PeerError as error:
            if error.code in {'DENIED', 'OFFLINE'}:
                return None
            raise
        params = {'identity': identity, 'action': action, 'body': body}
        selected = None
        if connection_id is not None or directory_generation is not None:
            selected = self.directory_publication(node_id)
            if (selected is None or selected[0].connection_id != connection_id
                    or (directory_generation is not None and selected[1] != directory_generation)):
                raise PeerError('DIRECTORY_CHANGED' if action == 'submit' else 'ROUTE_LOST', 'The service directory changed')
        try:
            if selected is not None:
                if self.adaptive and self.adaptive.admitted(pair):
                    self.adaptive.touch(node_id)
                result = await selected[0].call(GROVE_SERVICE, params)
                if action != 'submit' and selected != self.directory_publication(node_id):
                    raise PeerError('ROUTE_LOST', 'The service directory changed')
                return result
            return await self.call(node_id, GROVE_SERVICE, params, diagnostic=True)
        except PeerError as error:
            if error.code == 'UNSUPPORTED_METHOD':
                return None
            raise

    async def grove_directory(self, actor: Actor, directory: dict) -> dict:
        if directory['stale']:
            return directory
        try:
            result = await self.grove_service(directory['node_id'], actor, 'catalog', {},
                                              connection_id=directory['connection_id'],
                                              directory_generation=directory['directory_generation'])
        except PeerError:
            return directory
        if result is None:
            return directory
        services = {item['id']: item for item in directory['services']}
        for item in result['services']:
            services[item['id']] = item
        return {**directory, 'services': sorted(services.values(), key=lambda item: (item['name'], item['id']))}

    async def visible_directories(self, actor: Actor) -> list[dict]:
        directories = await self.directories()
        result = []
        for start in range(0, len(directories), LOCAL_WORKERS):
            result.extend(await asyncio.gather(*(self.grove_directory(actor, entry)
                                                for entry in directories[start:start + LOCAL_WORKERS])))
        return result

    def cached(self, pair: Pair) -> tuple[dict, dict, dict]:
        with self.state.connect() as db:
            row = mirror_row(db, pair.node_id)
        return self.read_mirror(row)

    @staticmethod
    def read_mirror(row: sqlite3.Row | None) -> tuple[dict, dict, dict]:
        if row:
            return {"epoch": row["epoch"], "revision": row["revision"]}, json.loads(row["entries"]), json.loads(row["observations"])
        return {"epoch": None, "revision": 0}, {}, {}

    def cached_directories(self) -> list[tuple[Pair, tuple[dict, dict, dict]]]:
        with self.state.connect() as db:
            db.execute("BEGIN")
            pairs = members(db)
            return [(pair, self.read_mirror(row)) for row in db.execute("SELECT * FROM peer_mirror ORDER BY peer_id")
                    if (pair := pairs.get(row["peer_id"])) is not None and pair.enabled
                    and mesh_policy.member_allowed(db, pair.mesh_id, pair.node_id)]

    async def directories(self) -> list[dict]:
        # A directory published while SQLite is being read cannot certify the
        # earlier snapshot, even when it reuses the same connection.
        publications = {node: self.directory_publication(node) for node in self.manager.pairs}
        cached = await self.work(self.cached_directories)
        return [self.directory_view(pair.node_id, snapshot, publications.get(pair.node_id)) for pair, snapshot in cached
                if self.manager.pairs.get(pair.node_id) == pair and pair.node_id not in self.manager.quarantines]

    @staticmethod
    async def request(connection: Session, method: str, params: dict, *, text_logs: bool = False) -> dict:
        if method in RECEIPT_REASON_METHODS and not getattr(connection, 'receipt_reason_unsupported', False):
            try:
                return await connection.call(RECEIPT_REASON_METHODS[method], params)
            except PeerError as exc:
                if exc.code != 'UNSUPPORTED_METHOD':
                    raise
                connection.receipt_reason_unsupported = True
        if method in HEALTH_METHODS and getattr(connection, 'service_health_supported', None) is not False:
            try:
                result = await connection.call(HEALTH_METHODS[method], params)
            except PeerError as exc:
                if exc.code != 'UNSUPPORTED_METHOD':
                    raise
                connection.service_health_supported = False
            else:
                connection.service_health_supported = True
                return result
        if text_logs and method == 'service.logs' and getattr(connection, 'log_text_supported', None) is not False:
            try:
                result = await connection.call(method, {**params, 'text_encoding': 'utf8'})
            except PeerError as exc:
                if exc.code != 'INVALID_REQUEST':
                    raise
                connection.log_text_supported = False
            else:
                connection.log_text_supported = True
                return result
        return await connection.call(method, params)

    async def call(self, node_id: str, method: str, params: dict, *, diagnostic: bool = False,
                   text_logs: bool = False) -> dict:
        result, _ = await self.call_with_connection(node_id, method, params, diagnostic=diagnostic, text_logs=text_logs)
        return result

    async def call_with_connection(self, node_id: str, method: str, params: dict, *, diagnostic: bool = False,
                                   text_logs: bool = False) -> tuple[dict, Session]:
        pair = self.pair_for(node_id)
        if not pair.enabled:
            raise PeerError("OFFLINE", "Peer is disabled")
        if pair.legacy or not pair.routed:
            connection = await self.connect(pair) if diagnostic else self.live_connection(node_id)
            return await self.request(connection, method, params, text_logs=text_logs), connection
        connection = None
        try:
            async with asyncio.timeout(15):
                for attempt in range(2):
                    connection = None
                    try:
                        connection = await self.connect(self.pair_for(node_id))
                        return await self.request(connection, method, params, text_logs=text_logs), connection
                    except PeerError as exc:
                        if exc.code not in RECOVERABLE:
                            raise
                        self.invalidate(node_id, connection, exc.code)
                        if attempt:
                            raise
        except TimeoutError as exc:
            # Connecting can consume part of this caller's total budget. Its
            # cancellation alone does not make the shared transport unhealthy;
            # Session.call releases its pending item without aborting other RPCs.
            # Actual RPC/transport failures still invalidate in the loop above.
            raise PeerError("TIMEOUT", "Mesh request reached its total deadline") from exc

    def live_connection(self, node_id: str) -> Session:
        connection = self.connection_for(node_id)
        if connection is None or self.ready.get(node_id) is not connection:
            raise PeerError("OFFLINE", "Peer directory is offline or synchronizing")
        return connection

    def pair_for(self, node_id: str) -> Pair:
        pair = self.manager.pairs.get(node_id)
        if pair is None:
            raise PeerError("NOT_FOUND", "Unknown peer")
        return pair

    async def read_service(self, node_id: str, method: str, params: dict, *,
                           connection_id: str | None, text_logs: bool = False,
                           directory_generation: int | None = None) -> dict:
        if connection_id is None and directory_generation is None:
            return await self.call(node_id, method, params, text_logs=text_logs)
        publication = self.directory_publication(node_id)
        if (publication is None or publication[0].connection_id != connection_id
                or (directory_generation is not None and publication[1] != directory_generation)):
            raise PeerError("ROUTE_LOST", "The service directory connection changed")
        connection, _ = publication
        try:
            async with asyncio.timeout(15):
                result = await self.request(connection, method, params, text_logs=text_logs)
        except (PeerError, TimeoutError) as exc:
            if self.directory_publication(node_id) != publication:
                raise PeerError("ROUTE_LOST", "The service directory connection changed") from exc
            if isinstance(exc, TimeoutError):
                raise PeerError("TIMEOUT", "Mesh request reached its total deadline") from exc
            if exc.code in RECOVERABLE:
                self.invalidate(node_id, connection, exc.code)
            raise
        if self.directory_publication(node_id) != publication:
            raise PeerError("ROUTE_LOST", "The service directory connection changed")
        return result

    async def status(self, node_id: str, service_id: str, *, connection_id: str | None = None,
                     directory_generation: int | None = None) -> dict:
        result = await self.read_service(node_id, "service.status", {"service_id": service_id},
                                         connection_id=connection_id, directory_generation=directory_generation)
        if not valid_observation(result):
            raise PeerError("PROTOCOL", "Invalid remote service status")
        return result

    async def logs(self, node_id: str, service_id: str, tail: int, *, connection_id: str | None = None,
                   directory_generation: int | None = None) -> dict:
        try:
            async with asyncio.timeout(15):
                return parse_logs(await self.read_service(node_id, "service.logs", {"service_id": service_id, "tail": tail},
                                                          connection_id=connection_id, text_logs=True,
                                                          directory_generation=directory_generation))
        except TimeoutError as exc:
            raise PeerError('TIMEOUT', 'Mesh log request reached its total deadline') from exc

    async def scoped_services(self, actor: Actor) -> list[dict]:
        publications = {node: self.directory_publication(node) for node in self.manager.pairs}
        entries = await self.work(self.outbound.scoped_services, actor)
        for entry in entries:
            node = entry["node_id"]
            pair = self.manager.pairs.get(node)
            if pair and self.adaptive and self.adaptive.admitted(pair):
                self.adaptive.touch(node)
            publication = publications.get(node)
            entry["stale"] = publication is None or self.directory_publication(node) != publication
        return entries

    async def account_actions(self, node_id: str, service_id: str, *, connection_id: str | None = None,
                              explain: bool = False, service_version: int | None = None,
                              directory_generation: int | None = None) -> dict:
        publication = None
        if connection_id is not None or directory_generation is not None:
            publication = self.directory_publication(node_id)
            if (publication is None or publication[0].connection_id != connection_id
                    or (directory_generation is not None and publication[1] != directory_generation)):
                raise PeerError("ROUTE_LOST", "The service directory connection changed")
        connection = publication[0] if publication is not None else None
        params = {"service_id": service_id}
        methods = (ACCOUNT_ACTIONS_EXPLAIN, ACCOUNT_ACTIONS) if explain else (ACCOUNT_ACTIONS,)
        if explain and service_version is not None and not getattr(connection, 'account_actions_version_unsupported', False):
            methods = (ACCOUNT_ACTIONS_VERSION, *methods)
        for method in methods:
            arguments = {**params, "service_version": service_version} if method == ACCOUNT_ACTIONS_VERSION else params
            try:
                result = (await connection.call(method, arguments) if connection is not None
                          else await self.call(node_id, method, arguments))
                break
            except PeerError as exc:
                if publication is not None and self.directory_publication(node_id) != publication:
                    raise PeerError("ROUTE_LOST", "The service directory connection changed") from exc
                if exc.code != "UNSUPPORTED_METHOD":
                    raise
                if method == ACCOUNT_ACTIONS_VERSION and connection is not None:
                    connection.account_actions_version_unsupported = True
        else:
            result = {"actions": []}
        if publication is not None and self.directory_publication(node_id) != publication:
            raise PeerError("ROUTE_LOST", "The service directory connection changed")
        actions = result.get("actions")
        reason = result.get("reason")
        if (not isinstance(actions, list) or len(actions) > len(ACTIONS)
                or any(not isinstance(action, str) or action not in ACTIONS for action in actions)
                or len(set(actions)) != len(actions)
                or (result.keys() != {"actions"} and (not explain or method not in {ACCOUNT_ACTIONS_EXPLAIN, ACCOUNT_ACTIONS_VERSION}
                    or result.keys() != {"actions", "reason"} or actions
                    or not isinstance(reason, str) or reason not in ACCOUNT_ACTION_REASONS))):
            raise PeerError("PROTOCOL", "Invalid remote account actions")
        return result

    async def frp_request(self, node_id: str, method: str, params: dict, actor: Actor) -> dict:
        pair = self.pair_for(node_id)
        await self.work(frp_access.source_check, self.state, self.local_id, pair, actor, method,
                        params.get('request_id'))
        try:
            result = await self.call(node_id, method, params)
        except PeerError as exc:
            if method == 'frp.view' and exc.code == 'UNSUPPORTED_METHOD':
                return frp_access.EMPTY
            if method in ('frp.start', 'frp.revoke') and exc.code in RECOVERABLE:
                return {'pending': True}
            raise
        return frp_access.check_result(method, params['service_id'], result)

    async def shared_evidence(self, node_id: str, before: int | None) -> dict:
        pair = self.pair_for(node_id)
        scope = await self.work(evidence_exchange.authorize_peer, self.state, pair)
        try:
            result = await self.call(node_id, evidence_exchange.LIST, {'before': before, **scope.wire()})
        except PeerError as exc:
            if exc.code == 'UNSUPPORTED_METHOD':
                raise PeerError('UNAVAILABLE', 'This node does not support shared evidence yet') from exc
            raise
        if await self.work(evidence_exchange.authorize_peer, self.state, pair) != scope:
            raise PeerError('CONFLICT', 'Grove trust changed while reading shared evidence')
        return evidence_exchange.check_page(result)

    async def receive_evidence(self, node_id: str, term: int, actor: Actor) -> dict:
        pair = self.pair_for(node_id)
        scope = await self.work(evidence_exchange.authorize_peer, self.state, pair)
        params = {'term': term, **scope.wire()}
        first = await self.call(node_id, evidence_exchange.PART, {**params, 'index': 0})
        second = await self.call(node_id, evidence_exchange.PART, {**params, 'index': 1})
        document = evidence_exchange.assemble(first, second)
        return await self.work(evidence_exchange.receive, self.state, pair, scope, term, document, actor.operation_actor)

    async def account_action(self, node_id: str, service_id: str, data: dict, key: str, actor: Actor, *,
                             connection_id: str | None = None, directory_generation: int | None = None) -> dict:
        pair = self.pair_for(node_id)
        request_id = account_request_id(actor, key)
        intent = {**data, "service_id": service_id, "request_id": request_id, "operator_key_id": self.account_operator_id}
        async with self.account_locks.setdefault(node_id, asyncio.Lock()):
            previous = await self.work(self.outbound.account_submission, pair, intent, actor)
            if previous is not None:
                return previous
            result = await self.grove_service(node_id, actor, 'submit', {**data, 'service_id': service_id,
                                                                        'request_id': request_id},
                                              connection_id=connection_id, directory_generation=directory_generation)
            if result is not None:
                return await self.work(self.outbound.remember_grove_receipt, pair, actor, service_id, request_id, result)
            publication = None
            if connection_id is not None or directory_generation is not None:
                publication = self.directory_publication(node_id)
                if (publication is None or publication[0].connection_id != connection_id
                        or (directory_generation is not None and publication[1] != directory_generation)):
                    raise PeerError("DIRECTORY_CHANGED", "The service directory changed before submission")
                if not pair.enabled:
                    raise PeerError("OFFLINE", "Peer is disabled")
                connection = publication[0]
                if self.adaptive and self.adaptive.admitted(pair):
                    self.adaptive.touch(node_id)
                try:
                    async with asyncio.timeout(15):
                        challenge = await self.request(connection, "operation.prepare", intent)
                except (PeerError, TimeoutError) as exc:
                    if self.directory_publication(node_id) != publication:
                        raise PeerError("DIRECTORY_CHANGED", "The service directory changed before submission") from exc
                    if isinstance(exc, TimeoutError):
                        raise PeerError("TIMEOUT", "Mesh request reached its total deadline") from exc
                    if pair.routed and exc.code in RECOVERABLE:
                        self.invalidate(node_id, connection, exc.code)
                    raise
            else:
                challenge = await self.call(node_id, "operation.prepare", intent)
                connection = await self.connect(pair) if pair.routed else self.live_connection(node_id)
            return await self.wait_owned(asyncio.create_task(
                self.send_account_action(pair, connection, intent, challenge, actor, publication=publication)))

    async def account_receipt(self, node_id: str, service_id: str, key: str, actor: Actor) -> dict | None:
        pair = self.pair_for(node_id)
        saved = await self.work(self.outbound.account_receipt, pair, service_id, key, actor)
        if saved is not None:
            return saved
        request_id = account_request_id(actor, key)
        result = await self.grove_service(node_id, actor, 'receipt', {'service_id': service_id, 'request_id': request_id})
        if result and result['receipt']:
            return await self.work(self.outbound.remember_grove_receipt, pair, actor, service_id, request_id, result['receipt'])
        return None

    async def send_account_action(self, pair: Pair, connection: Session, intent: dict, challenge: dict, actor: Actor, *,
                                  publication: tuple[Session, int] | None = None) -> dict:
        request_id = intent["request_id"]
        if publication is not None and self.directory_publication(pair.node_id) != publication:
            raise PeerError("DIRECTORY_CHANGED", "The service directory changed before submission")
        approval = await self.work(self.outbound.approve_account, pair, intent, challenge, actor)
        if publication is not None and self.directory_publication(pair.node_id) != publication:
            await self.work(self.outbound.discard_rejected_account_submission, pair, request_id, actor)
            raise PeerError("DIRECTORY_CHANGED", "The service directory changed before submission")
        try:
            result = await connection.call("operation.submit", approval)
        except PeerError as exc:
            if exc.code in RECOVERABLE:
                if pair.routed and (publication is None or self.directory_publication(pair.node_id) == publication):
                    self.invalidate(pair.node_id, connection, exc.code)
                return {"request_id": request_id, "pending": True}
            await self.work(self.outbound.discard_rejected_account_submission, pair, request_id)
            raise
        await self.work(self.outbound.store, pair, request_id, result)
        return result

    async def prepare(self, node_id: str, service_id: str, intent: dict, actor: Actor | None = None) -> dict:
        pair = self.pair_for(node_id)
        data = {**intent, "service_id": service_id, "request_id": token_hex(16)}
        if actor is not None:
            data = await self.work(self.outbound.scoped_intent, pair, data, actor)
            capability = await self.call(node_id, "security.capabilities", {"service_id": service_id})
            if capability not in ({"approval_versions": [2], "required_approval_version": 2},
                                  {"approval_versions": [1, 2], "required_approval_version": 1}):
                raise PeerError("APPROVAL_VERSION_REQUIRED", "Target did not declare M003 approval support")
        result = await self.call(node_id, operation_method("prepare", 2 if actor else 1), data)
        return await self.work(self.outbound.record, pair, data, result, actor)

    async def submit(self, node_id: str, service_id: str, approval: dict, actor: Actor | None = None) -> dict:
        pair = self.pair_for(node_id)
        connection = await self.connect(pair) if pair.routed else self.live_connection(node_id)
        async with self.target_lock(node_id):
            connection = self.connection_for(node_id)
            if connection is None:
                raise PeerError('OFFLINE', 'Mesh session was replaced before submission')
            request_id = await self.committed_work(self.outbound.start_submission, pair, service_id, approval, actor)
        try:
            result = await connection.call(operation_method("submit", 2 if actor else 1), approval)
        except PeerError as exc:
            if (pair.routed or actor is not None) and exc.code in RECOVERABLE:
                if pair.routed:
                    self.invalidate(node_id, connection, exc.code)
                raise PeerError("RESULT_PENDING", f"Operation result pending for request {request_id}") from exc
            raise
        await self.work(self.outbound.store, pair, request_id, result)
        return result

    async def get_operation(self, node_id: str, service_id: str, request_id: str, actor: Actor | None = None) -> dict:
        pair = self.pair_for(node_id)
        await self.work(self.outbound.known, pair, service_id, request_id, actor)
        result = await self.call(node_id, operation_method("get", 2 if actor else 1), {"request_id": request_id})
        saved = await self.work(self.outbound.store, pair, request_id, result)
        # Only return detailed data when this read returned it from the target.
        return saved if "operation" in result else result

    async def history(self, node_id: str, service_id: str, actor: Actor | None = None, *, request_id: str | None = None) -> list[dict]:
        history = partial(self.outbound.history, request_id=request_id)
        return await self.work(history, self.pair_for(node_id), service_id, actor)

    async def reconcile(self, pair: Pair, connection: Session) -> None:
        after = ''
        while True:
            page = await self.work(self.outbound.pending_page, pair, after)
            if not page:
                return

            async def query(request_id, version):
                try:
                    result = await self.request(connection, operation_method('get', version), {'request_id': request_id})
                except PeerError as error:
                    if error.code != 'NOT_FOUND':
                        raise
                    result = None
                await self.committed_work(self.outbound.store, pair, request_id, result)

            async def batch():
                results = await asyncio.gather(*(query(request_id, version) for request_id, version in page), return_exceptions=True)
                for result in results:
                    if isinstance(result, BaseException):
                        raise result

            await self.wait_owned(asyncio.create_task(batch()))
            after = page[-1][0]


def operation_method(action: str, version: int) -> str:
    return f"operation.v2.{action}" if version == 2 else f"operation.{action}"
