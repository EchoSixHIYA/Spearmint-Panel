import asyncio
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, replace
from ipaddress import ip_address, ip_network
import json
import logging
import os
from pathlib import Path
from secrets import randbelow, token_hex
import socket
import sqlite3
import tempfile
import time

from cryptography import x509

from ..state import State, StateError
from ..platforms import boot_id, process_start, replace_file
from .credentials import fingerprint, node_id, tls_context
from .discovery import METHOD as PEX_METHOD, AddressPolicy, Endpoint, network_view, public_config
from .grove_endpoints import GroveEndpoints, trusted_members
from .mesh_policy import METHOD as POLICY_METHOD, member_allowed, member_set
from .pairing import Pair, configured, members
from .quarantine import entries as quarantine_entries
from .protocol import DEADLINE, RELAY_CAPABILITY, PeerError, ProtocolError, encode, receive
from .routing import CAPABILITY as ROUTING_CAPABILITY, MULTIPATH_CAPABILITY
from .observations import METHOD as OBSERVE_METHOD
from .neighbors import LIMIT as NEIGHBORS, Neighbors
from .session import Session, close_stream


logger = logging.getLogger(__name__)
HANDSHAKES = 4
DIRECTION_HANDSHAKES = HANDSHAKES - 1
INBOUND_FAILURE_DELAY = 1.0
INBOUND_FAILURE_SOURCES = 512
MESH_CAPABILITY = "mesh.v2"
RPC_CAPABILITIES = ("peer.ping", "catalog.sync", "service.status", "service.logs", POLICY_METHOD, "grove.identity.get")
LEGACY_OPERATION_CAPABILITIES = ("operation.prepare", "operation.submit", "operation.get")
LINK_ERRORS = (OSError, ValueError, EOFError, sqlite3.Error, ExceptionGroup)
RpcHandler = Callable[[Pair, str, dict], Awaitable[dict]]


def read_runtime(state: State) -> dict | None:
    try:
        status = json.loads((state.directory / "peer-runtime.json").read_bytes())
        if status["boot_id"] == boot_id() and process_start(int(status["pid"])) == status["process_start"]:
            return status["peer"]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        pass
    return None


async def diagnostic_rpc(_pair: Pair, method: str, params: dict) -> dict:
    if method != "peer.ping":
        raise PeerError("UNSUPPORTED_METHOD", "Unsupported Peer RPC method")
    if params:
        raise PeerError("INVALID_REQUEST", "peer.ping expects empty parameters")
    return {"status": "ok"}


def error_message(error: BaseException) -> str:
    if isinstance(error, BaseExceptionGroup):
        return error_message(error.exceptions[0])
    return str(error) or type(error).__name__


@dataclass(frozen=True)
class GroveIngress:
    realm_id: str
    member_origin: str


GroveAddress = tuple[str, str, bool] | GroveIngress


@dataclass(frozen=True)
class Neighbor:
    pair: Pair
    session: Session
    generation: str
    rank: tuple[bool, str]
    initiator: str
    connected_at: float
    address: str
    capabilities: frozenset[str]
    grove_address: GroveAddress | None = None
    dialed_endpoint: Endpoint | None = None


class PeerManager:
    def __init__(self, state: State, local_id: str, handler: RpcHandler = diagnostic_rpc, *,
                 dial_enabled: bool = True) -> None:
        self.state = state
        self.local_id = local_id
        self.handler = handler
        self.dial_enabled = dial_enabled
        self.use_system_egress = False
        self.pairs: dict[str, Pair] = {}
        self.admitted: dict[str, Pair] = {}
        self.quarantines: dict[str, dict] = {}
        self.neighbors: dict[str, Neighbor] = {}
        self.states: dict[str, dict] = {}
        self.established: dict[str, int] = {}
        self.discovery_enabled = False
        self.networks: dict[str, tuple[AddressPolicy, ...]] = {}
        self.endpoints: dict[str, tuple[Endpoint, ...]] = {}
        self.grove_endpoints: GroveEndpoints | None = None
        self.automatic_members: set[str] = set()
        self.listening = False
        self.forwarding_enabled = False
        self.control_handler: Callable[[Neighbor, dict], None] | None = None
        self.routing_status: Callable[[], dict] | None = None
        self.relay_enabled = False
        self.adaptive = False
        self.scheduler: Neighbors | None = None
        self.neighbor_lost: Callable[[Neighbor], None] | None = None
        self.neighbor_ready: Callable[[Neighbor], None] | None = None
        self.listener_error: str | None = None
        self.handshakes = 0
        self.outbound_handshakes = 0
        self.peak_handshakes = 0
        self.runtime_path = self.state.directory / "peer-runtime.json"

    @property
    def pair(self) -> Pair | None:
        return next((pair for pair in self.pairs.values() if pair.legacy), None)

    @property
    def connection(self) -> Session | None:
        pair = self.pair
        return self.connection_for(pair.node_id) if pair else None

    def connection_for(self, node_id: str) -> Session | None:
        neighbor = self.neighbors.get(node_id)
        return neighbor.session if neighbor else None

    def status_for(self, pair: Pair) -> dict:
        quarantine = self.quarantines.get(pair.node_id)
        if quarantine:
            return {**pair.public_data(), 'status': 'quarantined', 'local_quarantine': quarantine}
        neighbor = self.neighbors.get(pair.node_id)
        if neighbor and not neighbor.session.closed:
            status = {"status": "online", "session_id": neighbor.generation, "tls": "TLSv1.3",
                      "connected_at": neighbor.connected_at, "initiator_node_id": neighbor.initiator,
                      "connected_ip": neighbor.address,
                      **neighbor.session.link_metrics()}
        elif self.listener_error and pair.node_id in self.admitted:
            status = {"status": "error", "detail": self.listener_error}
        else:
            status = self.states.get(pair.node_id, {"status": "unreachable" if pair.enabled else "disabled"})
        result = {**pair.public_data(), **status, 'local_quarantine': None,
                  "reconnects": max(0, self.established.get(pair.node_id, 0) - 1)}
        if pair.node_id in self.automatic_members:
            result['automatic_endpoint'] = next(iter(self.endpoints.get(pair.node_id, ())), None)
        if self.scheduler:
            result['neighbor_use'] = self.scheduler.status_for(pair.node_id)
        return result

    def close_neighbor(self, neighbor: Neighbor, reason: str) -> bool:
        node = neighbor.pair.node_id
        if self.neighbors.get(node) is not neighbor:
            return False
        self.neighbors.pop(node)
        self.states[node] = {'status': 'backoff', 'detail': reason}
        if self.neighbor_lost is not None:
            self.neighbor_lost(neighbor)
        neighbor.session.writer.transport.abort()
        return True

    def statuses(self) -> list[dict]:
        return [self.status_for(pair) for pair in self.pairs.values()]

    @property
    def status(self) -> dict:
        pair = self.pair
        if pair:
            return self.status_for(pair)
        if self.listener_error:
            return {"status": "error", "detail": self.listener_error}
        return {"status": "online" if self.neighbors else ("listening" if self.admitted else "disabled")}

    def publish(self, status: dict) -> None:
        pid = os.getpid()
        data = {"pid": pid, "process_start": process_start(pid), "boot_id": boot_id(), "peer": status}
        with tempfile.NamedTemporaryFile(dir=self.state.directory, prefix=".peer-runtime-", delete=False) as stream:
            path = Path(stream.name)
            try:
                stream.write(json.dumps(data).encode("utf-8"))
                stream.close()
                replace_file(path, self.runtime_path)
            finally:
                path.unlink(missing_ok=True)

    def read_neighbor(self, node_id: str, ip: str, grove_address: GroveAddress | None) -> Pair | None:
        with self.state.connect() as db:
            db.execute("BEGIN")
            pair = configured(db, node_id)
            if pair is None or not pair.enabled or not member_allowed(db, pair.mesh_id, pair.node_id):
                return None
            if pair.ingress_only and not db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (node_id,)).fetchone():
                return None
            if pair.source_ip == ip:
                return pair
            if not pair.legacy and db.execute("SELECT 1 FROM mesh_profile WHERE discovery=1").fetchone():
                networks = db.execute("SELECT network FROM peer_network WHERE node_id=?", (node_id,))
                if any(ip_address(ip) in ip_network(row["network"]) for row in networks):
                    return pair
            if (self.grove_endpoints is not None and not pair.legacy and pair.source_ip is None
                    and not db.execute('SELECT 1 FROM peer_network WHERE node_id=?', (node_id,)).fetchone()):
                trust = trusted_members(db, self.local_id, operational=True, transport=True)
                origin = trust.origins.get(node_id) if trust else None
                if grove_address is not None and origin is not None:
                    if isinstance(grove_address, GroveIngress):
                        return pair if grove_address == GroveIngress(trust.realm_id, origin) else None
                    binding = self.grove_endpoints.connection_address(origin, pair)
                    if binding is not None and grove_address == (trust.realm_id, *binding):
                        return pair
        return None

    def read_members(self):
        with self.state.connect() as db:
            db.execute("BEGIN")
            pairs = members(db)
            registered = {row[0] for row in db.execute('SELECT node_id FROM grove_member WHERE enabled=1')}
            pairs = {node: replace(pair, enabled=False) if pair.ingress_only and node not in registered else pair
                     for node, pair in pairs.items()}
            quarantines = quarantine_entries(db)
            for node in pairs.keys() & quarantines.keys():
                pairs[node] = replace(pairs[node], enabled=False)
            profile = public_config(db)
            if profile is not None:
                allowed = member_set(db, profile["mesh_id"])
                if allowed is not None:
                    pairs = {key: pair if key in allowed else replace(pair, enabled=False) for key, pair in pairs.items()}
            trust = trusted_members(db, self.local_id, operational=True, transport=True) if self.grove_endpoints is not None else None
            explicit_networks = {row['node_id'] for row in db.execute('SELECT DISTINCT node_id FROM peer_network')} if trust else set()
            automatic = {node for node, pair in pairs.items() if trust and node in trust.origins and pair.enabled
                         and not pair.legacy and pair.source_ip is None and node not in explicit_networks}
            return pairs, *network_view(db, pairs), bool(profile and profile["forwarding"]), trust, automatic, quarantines

    def admit(self, pairs: dict[str, Pair], validated: dict[str, tuple[Pair, float]]) -> dict[str, Pair]:
        now = time.time()
        admitted = {}
        for node_id, pair in pairs.items():
            if not pair.enabled or (pair.source_ip is None and node_id not in self.networks and node_id not in self.automatic_members):
                continue
            cached = validated.get(node_id)
            if cached is None or cached[0] != pair or now >= cached[1]:
                try:
                    deadline = pair.validate(self.local_id)
                except ValueError as exc:
                    self.states[node_id] = {"status": "error", "detail": str(exc)}
                    continue
                validated[node_id] = (pair, deadline)
            admitted[node_id] = pair
        return admitted

    async def monitor(self) -> None:
        listener = None
        dialers: dict[str, asyncio.Task] = {}
        settings = None
        contexts = None
        validated: dict[str, tuple[Pair, float]] = {}
        last_dial_endpoints: dict[str, tuple[Endpoint, ...]] = {}
        published = None
        try:
            while True:
                error = None
                try:
                    (pairs, self.discovery_enabled, self.networks, self.endpoints, self.forwarding_enabled,
                     trust, self.automatic_members, self.quarantines) = await asyncio.to_thread(self.read_members)
                except (StateError, sqlite3.Error, OSError, ValueError) as exc:
                    pairs = {}
                    self.discovery_enabled, self.networks, self.endpoints = False, {}, {}
                    self.forwarding_enabled = False
                    trust, self.automatic_members = None, set()
                    self.quarantines = {}
                    error = error_message(exc)
                retry_addresses: set[str] = set()
                if self.grove_endpoints is not None:
                    candidates = self.grove_endpoints.update(trust, pairs)
                    for node in last_dial_endpoints.keys() - self.automatic_members:
                        last_dial_endpoints.pop(node)
                    for node in self.automatic_members & candidates.keys():
                        endpoints = candidates[node]
                        self.endpoints[node] = endpoints
                        previous_endpoints = last_dial_endpoints.get(node)
                        if previous_endpoints is not None and previous_endpoints != endpoints:
                            retry_addresses.add(node)
                        last_dial_endpoints[node] = endpoints
                changed = {key for key in self.pairs.keys() | pairs.keys() if self.pairs.get(key) != pairs.get(key)}
                for key in changed:
                    self.states.pop(key, None)
                    validated.pop(key, None)
                    if key not in pairs:
                        self.established.pop(key, None)
                self.pairs = pairs
                admitted = self.admit(pairs, validated)
                sample = next(iter(admitted.values()), None)
                new_settings = (sample.bind_ip, sample.listen_port, sample.ca_pem, sample.local_pem) if sample else None
                if settings != new_settings or (listener and listener.done()):
                    self.admitted = {}
                    self.listening = False
                    await self.stop_tasks([*dialers.values(), *([listener] if listener else [])])
                    dialers.clear()
                    listener = None
                    contexts = None
                    settings = new_settings
                previous = self.admitted
                self.admitted = admitted
                replaced = {key for key in previous if previous[key] != admitted.get(key)}
                for key, link in self.neighbors.items():
                    if not self.neighbor_address_current(link):
                        replaced.add(key)
                        if key in self.automatic_members:
                            retry_addresses.add(key)
                for key in replaced:
                    neighbor = self.neighbors.get(key)
                    if neighbor:
                        self.close_neighbor(neighbor, 'Peer admission changed')
                    if key not in admitted:
                        self.states.pop(key, None)
                await self.stop_tasks([dialers.pop(key) for key in replaced | retry_addresses if key in dialers])
                if self.scheduler:
                    for node in retry_addresses & admitted.keys():
                        self.scheduler.reset_dial_backoff(node)
                    self.scheduler.step()
                self.listener_error = error
                if settings and listener is None:
                    try:
                        contexts = await asyncio.to_thread(self.contexts, sample)
                        sock = self.bind_listener(sample)
                    except (ValueError, OSError, StateError) as exc:
                        self.listener_error = error_message(exc)
                    else:
                        listener = asyncio.create_task(self.listen(sock, contexts[0]))
                        listener.add_done_callback(lambda _, bound=sock: bound.close())
                        self.listening = True
                if listener and contexts:
                    for key in [key for key, task in dialers.items() if task.done()]:
                        await self.stop_tasks([dialers.pop(key)])
                    for key, pair in admitted.items():
                        dialer = self.dial_enabled and not pair.ingress_only and (not pair.legacy or self.local_id < key)
                        self.states.setdefault(key, {"status": "connecting" if dialer else "listening"})
                        if dialer and key not in dialers:
                            dialers[key] = asyncio.create_task(self.dial(pair, contexts[1]))
                status = {**self.status, "neighbors": self.statuses()}
                if self.routing_status is not None:
                    status["routing"] = self.routing_status()
                if published != status:
                    try:
                        self.publish(status)
                    except OSError:
                        logger.exception("Cannot write Peer diagnostics")
                    else:
                        published = status
                await asyncio.sleep(1)
        finally:
            self.admitted = {}
            self.listening = False
            await self.stop_tasks([*dialers.values(), *([listener] if listener else [])])

    @staticmethod
    async def stop_tasks(tasks: list[asyncio.Task]) -> None:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def contexts(self, pair: Pair):
        key = self.state.signing_key()
        return (tls_context(key, pair.ca_pem, pair.local_pem, self.state.directory, server=True),
                tls_context(key, pair.ca_pem, pair.local_pem, self.state.directory, server=False))

    @asynccontextmanager
    async def running(self):
        task = asyncio.create_task(self.monitor())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            with suppress(OSError):
                self.runtime_path.unlink(missing_ok=True)

    async def call(self, method: str, params: dict, *, node_id: str | None = None) -> dict:
        connection = self.connection if node_id is None else self.connection_for(node_id)
        if connection is None:
            raise PeerError("OFFLINE", "Peer is offline")
        return await connection.call(method, params)

    def hello_capabilities(self, pair: Pair) -> list[str]:
        capabilities = list(RPC_CAPABILITIES)
        if pair.legacy:
            capabilities.extend(LEGACY_OPERATION_CAPABILITIES)
            return capabilities
        # Mesh peers use mesh.v2 for the baseline operation RPCs. Omit the
        # legacy announcements to leave room for optional handshake features.
        capabilities.extend((MESH_CAPABILITY, PEX_METHOD, 'grove.login.verifiers', 'grove.login.verifiers.v2',
                             'grove.login.continuity.get'))
        if self.control_handler is not None:
            capabilities.append(ROUTING_CAPABILITY)
            if self.relay_enabled:
                capabilities.append(RELAY_CAPABILITY)
                if self.adaptive:
                    capabilities.extend((MULTIPATH_CAPABILITY, OBSERVE_METHOD))
        return capabilities

    async def authenticate(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                           expected: Pair | None, dialed_endpoint: Endpoint | None
                           ) -> tuple[Pair, str, str, frozenset[str], GroveAddress | None]:
        tls = writer.get_extra_info("ssl_object")
        leaf = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
        peer_id = node_id(leaf.public_key())
        pair = self.admitted.get(peer_id)
        address = str(ip_address(writer.get_extra_info("peername")[0]))
        if (pair is None or (expected is not None and pair != expected) or tls.version() != "TLSv1.3"
                or tls.session_reused or fingerprint(leaf) != pair.fingerprint
                or not self.address_allowed(pair, address)
                or (expected is None and pair.legacy and self.local_id < peer_id)):
            raise ProtocolError("TLS peer identity or certificate fingerprint mismatch")
        inbound = expected is None
        grove_address = self.grove_address(pair, inbound=inbound)
        if peer_id in self.automatic_members and not self.automatic_address_allowed(pair, address, dialed_endpoint, grove_address):
            raise ProtocolError("Peer address is outside the current Grove advertisement")
        own_session = token_hex(16)
        capabilities = self.hello_capabilities(pair)
        async with asyncio.timeout(DEADLINE):
            writer.write(encode({
                "type": "hello", "protocol_version": 1, "mesh_id": pair.mesh_id, "node_id": self.local_id,
                "session_id": own_session, "capabilities": capabilities,
            }))
            await writer.drain()
            hello, _ = await receive(reader)
            if hello["type"] != "hello" or hello["mesh_id"] != pair.mesh_id or hello["node_id"] != pair.node_id:
                raise ProtocolError("Peer HELLO does not match the configured identity")
            if not pair.legacy and MESH_CAPABILITY not in hello["capabilities"]:
                raise ProtocolError("Peer did not negotiate Mesh capabilities")
            if (await asyncio.to_thread(self.read_neighbor, peer_id, address, grove_address) != pair
                    or self.admitted.get(peer_id) != pair
                    or not self.address_allowed(pair, address)
                    or grove_address != self.grove_address(pair, inbound=inbound)
                    or (peer_id in self.automatic_members and not self.automatic_address_allowed(pair, address, dialed_endpoint, grove_address))):
                raise ProtocolError("Peer pairing changed during authentication")
        return pair, ":".join(sorted((own_session, hello["session_id"]))), address, frozenset(hello["capabilities"]), grove_address

    async def use_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             expected: Pair | None, release: Callable[[], None],
                             *, started_at: float | None = None, dialed_endpoint: Endpoint | None = None) -> None:
        pair, generation, address, capabilities, grove_address = await self.authenticate(reader, writer, expected, dialed_endpoint)
        node = pair.node_id
        initiator = self.local_id if expected is not None else node
        rank = (initiator != min(self.local_id, node), generation)
        previous = self.neighbors.get(node)
        if previous and (pair.legacy or previous.rank <= rank):
            return
        if previous is None and self.scheduler and not self.scheduler.accept(pair):
            raise ProtocolError('Automatic neighbor trial or protected capacity is occupied')
        if previous is None and len(self.neighbors) >= NEIGHBORS:
            raise ProtocolError("Neighbor capacity reached")
        control = None
        if not pair.legacy and ROUTING_CAPABILITY in capabilities and self.control_handler is not None:
            control = lambda frame: self.control_handler(neighbor, frame)
        session = Session(reader, writer, lambda method, params: self.handle(pair, session, method, params), control=control,
                          relay=control is not None and self.relay_enabled and RELAY_CAPABILITY in capabilities,
                          handshake_started=started_at)
        neighbor = Neighbor(pair, session, generation, rank, initiator, time.time(), address, capabilities, grove_address, dialed_endpoint)
        self.neighbors[node] = neighbor
        self.established[node] = self.established.get(node, 0) + 1
        if self.scheduler:
            self.scheduler.bound(neighbor)
        release()
        if previous:
            previous.session.writer.transport.abort()
        logger.info("Peer %s online (%s)", node, generation)
        if self.neighbor_ready is not None:
            self.neighbor_ready(neighbor)
        try:
            await session.run()
        finally:
            if self.neighbors.get(node) is neighbor:
                del self.neighbors[node]
                self.states[node] = {"status": "listening" if expected is None else "reconnecting", **session.link_metrics()}
                if self.scheduler:
                    self.scheduler.lost(neighbor)
            if self.neighbor_lost is not None:
                self.neighbor_lost(neighbor)

    async def handle(self, pair: Pair, session: Session, method: str, params: dict) -> dict:
        if self.connection_for(pair.node_id) is not session:
            raise PeerError("OFFLINE", "Peer session was replaced")
        return await self.handler(pair, method, params)

    def reserve(self, on_release: Callable[[], None]) -> Callable[[], None]:
        self.handshakes += 1
        self.peak_handshakes = max(self.peak_handshakes, self.handshakes)
        held = True

        def release() -> None:
            nonlocal held
            if held:
                self.handshakes -= 1
                held = False
                on_release()

        return release

    async def accept(self, client: socket.socket, tls, release: Callable[[], None], rejected: Callable[[], None]) -> None:
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        writer = None
        established = False

        def authenticated():
            nonlocal established
            established = True
            release()

        try:
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, client, ssl=tls, ssl_handshake_timeout=DEADLINE, ssl_shutdown_timeout=1,
            )
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            await self.use_connection(reader, writer, None, authenticated, started_at=started_at)
        except LINK_ERRORS as exc:
            if not established:
                rejected()
            logger.info("Incoming Peer: %s", error_message(exc))
        finally:
            release()
            if writer:
                await close_stream(writer)

    def address_allowed(self, pair: Pair, ip: str) -> bool:
        return (pair.source_ip == ip or pair.node_id in self.automatic_members
                or any(policy.allows(ip) for policy in self.networks.get(pair.node_id, ())))

    def grove_address(self, pair: Pair, *, inbound: bool) -> GroveAddress | None:
        if self.grove_endpoints is None or pair.node_id not in self.automatic_members:
            return None
        trust = self.grove_endpoints.members
        origin = trust.origins.get(pair.node_id) if trust else None
        if origin is None:
            return None
        # A member behind NAT can initiate a session without a reverse dial target.
        if inbound:
            return GroveIngress(trust.realm_id, origin)
        binding = self.grove_endpoints.connection_address(origin, pair)
        return (trust.realm_id, *binding) if binding is not None else None

    def automatic_address_allowed(self, pair: Pair, address: str, endpoint: Endpoint | None, grove_address: GroveAddress | None) -> bool:
        if isinstance(grove_address, GroveIngress):
            return endpoint is None
        if grove_address is None or endpoint is None:
            return False
        _, enrolled, _ = grove_address
        return address == enrolled and endpoint in self.endpoints.get(pair.node_id, ())

    def neighbor_address_current(self, link: Neighbor) -> bool:
        if not self.address_allowed(link.pair, link.address):
            return False
        current = self.grove_address(link.pair, inbound=link.initiator != self.local_id)
        if link.pair.node_id not in self.automatic_members:
            return link.grove_address is None
        return current == link.grove_address and self.automatic_address_allowed(link.pair, link.address, link.dialed_endpoint, current)

    def allowed_source(self, ip: str) -> bool:
        return any(self.address_allowed(pair, ip) and (not pair.legacy or self.local_id > pair.node_id)
                   for pair in self.admitted.values())

    def established_source(self, ip: str) -> bool:
        return (any(pair.source_ip == ip for pair in self.admitted.values())
                or any(link.address == ip for link in self.neighbors.values()))

    async def listen(self, listener: socket.socket, tls) -> None:
        loop = asyncio.get_running_loop()
        sources: dict[str, bool] = {}
        failures: dict[str, float] = {}
        connections: set[asyncio.Task] = set()

        def done(task: asyncio.Task, client: socket.socket, release: Callable[[], None]) -> None:
            client.close()
            release()
            connections.discard(task)

        try:
            while True:
                client, address = await loop.sock_accept(listener)
                ip = str(ip_address(address[0]))
                established = self.established_source(ip)
                if (ip in sources or len(sources) >= DIRECTION_HANDSHAKES or self.handshakes >= HANDSHAKES
                        or (not established and False in sources.values())
                        or failures.get(ip, 0) > loop.time() or not self.allowed_source(ip)):
                    client.close()
                    continue
                permit = self.scheduler.incoming(ip) if self.scheduler else lambda: None
                if permit is None:
                    client.close()
                    continue
                sources[ip] = established

                def released(ip=ip, permit=permit):
                    sources.pop(ip, None)
                    permit()

                def rejected(ip=ip):
                    failures.pop(ip, None)
                    if len(failures) >= INBOUND_FAILURE_SOURCES:
                        failures.pop(next(iter(failures)))
                    failures[ip] = loop.time() + INBOUND_FAILURE_DELAY

                release = self.reserve(released)
                task = asyncio.create_task(self.accept(client, tls, release, rejected))
                connections.add(task)
                task.add_done_callback(lambda result, sock=client, slot=release: done(result, sock, slot))
        finally:
            listener.close()
            await self.stop_tasks(list(connections))

    async def dial(self, pair: Pair, tls) -> None:
        delay = 1
        attempt = 0
        worker = asyncio.current_task()

        while self.admitted.get(pair.node_id) == pair:
            candidates = self.endpoints.get(pair.node_id, ())
            if pair.source_ip is not None and pair.port is not None:
                candidates = ((pair.source_ip, pair.port),) + tuple(item for item in candidates if item != (pair.source_ip, pair.port))
            if (not candidates or pair.node_id in self.neighbors or self.handshakes >= HANDSHAKES
                    or self.outbound_handshakes >= DIRECTION_HANDSHAKES):
                await asyncio.sleep(0.5)
                continue
            if self.scheduler and not self.scheduler.allow_dial(pair):
                await asyncio.sleep(.5)
                continue
            address, port = candidates[attempt % len(candidates)]
            attempt += 1
            writer = None
            self.outbound_handshakes += 1

            def released():
                self.outbound_handshakes -= 1

            release = self.reserve(released)
            established = False

            def authenticated() -> None:
                nonlocal established
                established = True
                release()

            try:
                started_at = asyncio.get_running_loop().time()
                reader, writer = await asyncio.wait_for(asyncio.open_connection(
                    address, port, server_hostname=pair.host, ssl=tls, ssl_handshake_timeout=DEADLINE,
                    ssl_shutdown_timeout=1, local_addr=None if self.use_system_egress else (pair.bind_ip, 0),
                ), DEADLINE + 1)
                await self.use_connection(reader, writer, pair, authenticated, started_at=started_at,
                                          dialed_endpoint=(address, port))
            except LINK_ERRORS as exc:
                if worker.cancelling():
                    raise asyncio.CancelledError from None
                if pair.node_id not in self.neighbors:
                    self.states[pair.node_id] = {"status": "reconnecting", "detail": error_message(exc)}
                logger.info("Outgoing Peer %s: %s", pair.node_id, error_message(exc))
            finally:
                release()
                if writer:
                    await close_stream(writer)
                if self.scheduler and not established and not self.scheduler.fixed(pair):
                    self.scheduler.failed(pair.node_id)
            if self.admitted.get(pair.node_id) != pair:
                return
            if established:
                delay = 1
            await asyncio.sleep(min(30, delay * (1 + randbelow(251) / 1000)))
            delay = min(30, delay * 2)

    @staticmethod
    def bind_listener(pair: Pair) -> socket.socket:
        family = socket.AF_INET if ip_address(pair.bind_ip).version == 4 else socket.AF_INET6
        listener = socket.socket(family)
        try:
            option = socket.SO_EXCLUSIVEADDRUSE if os.name == 'nt' else socket.SO_REUSEADDR
            listener.setsockopt(socket.SOL_SOCKET, option, 1)
            listener.bind((pair.bind_ip, pair.listen_port))
            listener.listen(NEIGHBORS)
            listener.setblocking(False)
        except OSError:
            listener.close()
            raise
        return listener
