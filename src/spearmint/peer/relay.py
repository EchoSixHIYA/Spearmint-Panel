import asyncio
from collections import Counter
from collections.abc import Awaitable, Callable, Iterator
from contextlib import suppress
from hashlib import sha256
import logging
from secrets import token_hex
import time

from cryptography.exceptions import InvalidSignature

from .credentials import NODE_ID, mesh_authorities
from .manager import Neighbor, PeerManager
from .pairing import Pair
from .protocol import DEADLINE, RELAY_CAPABILITY, PeerError, ProtocolError, matches, parse_b64, wire_b64
from .routing import HOPS, TIME_SKEW, Route, Routing
from .session import Session
from .signed import SignedRecord
from .tunnel import CHUNK, TunnelTLS


logger = logging.getLogger(__name__)
WINDOW = 4
CIRCUITS = 16
PER_ORIGIN = 4
REPLAY_LIMIT = 512
REPLAY_TTL = 30
IDLE = 60
REASONS = {"CLOSED", "ROUTE_LOST", "DENIED", "BUSY", "PROTOCOL"}
OPEN_FIELDS = {"mesh_id", "origin_node_id", "target_node_id", "circuit_id", "ticket_digest", "expires_at"}


class Leg:
    def __init__(self, link: Neighbor, circuit_id: str) -> None:
        self.link, self.circuit_id = link, circuit_id
        self.queue: asyncio.Queue[tuple[int, bytes] | None] = asyncio.Queue(WINDOW)
        self.writable = asyncio.Event()
        self.sent = 0
        self.acked = -1
        self.arrived = 0
        self.consumed = -1
        self.closed = False

    def frame(self, kind: str, **fields) -> None:
        self.link.session.send({"type": kind, "circuit_id": self.circuit_id, **fields})

    def feed(self, frame: dict) -> None:
        if frame["type"] == "relay.window":
            through = frame["through"]
            if through != self.acked + 1 or through >= self.sent:
                raise ProtocolError("Invalid relay acknowledgement")
            self.acked = through
            self.writable.set()
            return
        sequence = frame["sequence"]
        if sequence != self.arrived or sequence > self.consumed + WINDOW:
            raise ProtocolError("Relay receive window or sequence was exceeded")
        data = parse_b64(frame["data"], CHUNK)
        if not data:
            raise ProtocolError("Empty relay data chunk")
        self.queue.put_nowait((sequence, data))
        self.arrived += 1

    async def send(self, data: bytes) -> None:
        if not 0 < len(data) <= CHUNK:
            raise ProtocolError("Invalid relay chunk size")
        while self.sent > self.acked + WINDOW and not self.closed:
            self.writable.clear()
            await self.writable.wait()
        if self.closed:
            raise PeerError("ROUTE_LOST", "Relay circuit closed")
        self.frame("relay.data", sequence=self.sent, data=wire_b64(data))
        self.sent += 1

    def acknowledge(self, sequence: int) -> None:
        self.frame("relay.window", through=sequence)
        self.consumed = sequence

    async def receive(self) -> bytes:
        if self.closed:
            return b""
        item = await self.queue.get()
        if item is None:
            return b""
        sequence, data = item
        self.acknowledge(sequence)
        return data

    def close(self) -> None:
        self.closed = True
        self.link.session.discard_relay(self.circuit_id)
        self.writable.set()
        while not self.queue.empty():
            self.queue.get_nowait()
        self.queue.put_nowait(None)


class Circuit:
    def __init__(self, identity: str, path: tuple[str, ...], ticket: SignedRecord,
                 previous: Neighbor | None, following: Neighbor | None, *, route: Route | None = None,
                 role: str | None = None) -> None:
        self.identity, self.path, self.ticket = identity, path, ticket
        self.previous = Leg(previous, identity) if previous else None
        self.following = Leg(following, identity) if following else None
        self.legs = tuple(leg for leg in (self.previous, self.following) if leg is not None)
        self.route = route
        self.role = role or ('active' if route else 'forward' if previous and following else 'inbound')
        self.ready = asyncio.Event()
        self.bound = asyncio.Event()
        self.session: Session | None = None
        self.member: Pair | None = None
        self.task: asyncio.Task | None = None
        self.failure: str | None = None
        self.valid_until: float | None = None
        self.created = self.last_wire = time.monotonic()


class Relay:
    def __init__(self, manager: PeerManager, routing: Routing, handler: Callable[[Pair, str, dict], Awaitable[dict]]) -> None:
        self.manager, self.routing, self.handler = manager, routing, handler
        self.local = manager.local_id
        self.circuits: dict[str, Circuit] = {}
        self.retired: dict[str, float] = {}
        self.outbound: dict[str, Circuit] = {}
        self.attempts: dict[str, asyncio.Task[Session]] = {}
        self.workers: set[asyncio.Task] = set()
        self.handshakes = asyncio.Semaphore(4)
        self.counts: Counter[str] = Counter()
        self.context_lock = asyncio.Lock()
        self.context_cache = None
        self.context_settings = None

    def is_link(self, link: Neighbor | None) -> bool:
        return bool(link and not getattr(link.session, 'closed', False) and link.session.relay
                    and RELAY_CAPABILITY in link.capabilities and self.routing.is_live(link))

    def status(self) -> dict:
        return {"active_circuits": len(self.circuits), "tasks": len(self.workers), "buffered_chunks": sum(
            leg.queue.qsize() for circuit in self.circuits.values() for leg in circuit.legs),
            'roles': dict(Counter(circuit.role for circuit in self.circuits.values())), **self.counts}

    def live(self, circuit: Circuit) -> bool:
        remote = circuit.path[0] if circuit.path[-1] == self.local else circuit.path[-1]
        member = self.manager.pairs.get(remote)
        return bool(self.circuits.get(circuit.identity) is circuit and not circuit.failure
                    and member and member.enabled and member.routed and not member.legacy and circuit.member == member
                    and circuit.session and not circuit.session.closed
                    and circuit.valid_until is not None and time.time() < circuit.valid_until
                    and all(self.is_link(leg.link) for leg in circuit.legs)
                    and all(self.manager.pairs.get(node) and self.manager.pairs[node].enabled
                            for node in circuit.path if node != self.local))

    def incoming(self, node: str) -> Iterator[tuple[Route, Circuit]]:
        for circuit in self.circuits.values():
            if circuit.path[0] == node and circuit.path[-1] == self.local and self.live(circuit):
                # The reverse path describes the established TLS session. Its
                # original ticket cannot authorize opening a new reverse circuit.
                yield Route(circuit.path[::-1], circuit.previous.link, circuit.ticket), circuit

    def session_for(self, node: str) -> Session | None:
        circuit = self.outbound.get(node)
        member = self.manager.pairs.get(node)
        if (circuit and member and member.enabled and member.routed and circuit.member == member
                and circuit.session and not circuit.session.closed
                and all(self.manager.pairs.get(peer) and self.manager.pairs[peer].enabled for peer in circuit.path[1:])):
            return circuit.session
        return None

    def route_for(self, node: str) -> Route | None:
        circuit = self.outbound.get(node)
        return circuit.route if circuit and self.session_for(node) else None

    async def connect(self, pair: Pair) -> Session:
        session = self.session_for(pair.node_id)
        if session is not None:
            return session
        task = self.attempts.get(pair.node_id)
        if task is None:
            if len(self.attempts) >= PER_ORIGIN:
                raise PeerError("BUSY", "Too many Mesh circuits are being opened")
            task = asyncio.create_task(self.open_outbound(pair))
            self.attempts[pair.node_id] = task
            task.add_done_callback(lambda result: self.finish_attempt(pair.node_id, result))
        return await asyncio.shield(task)

    def finish_attempt(self, node: str, task: asyncio.Task) -> None:
        if self.attempts.get(node) is task:
            self.attempts.pop(node)
        if not task.cancelled():
            task.exception()

    def reap_retired(self) -> None:
        now = time.monotonic()
        self.retired = {identity: expiry for identity, expiry in self.retired.items() if expiry > now}

    def register(self, circuit: Circuit) -> None:
        self.reap_retired()
        if (len(self.circuits) >= CIRCUITS or len(self.retired) + len(self.circuits) >= REPLAY_LIMIT
                or sum(item.path[0] == circuit.path[0] for item in self.circuits.values()) >= PER_ORIGIN):
            self.counts["limited"] += 1
            raise PeerError("BUSY", "Relay capacity reached")
        self.circuits[circuit.identity] = circuit
        self.counts["peak_circuits"] = max(self.counts["peak_circuits"], len(self.circuits))

    def run_circuit(self, circuit: Circuit, work: Awaitable[None]) -> None:
        task = circuit.task = asyncio.ensure_future(work)
        self.workers.add(task)
        task.add_done_callback(self.worker_done)

    def worker_done(self, task: asyncio.Task) -> None:
        self.workers.discard(task)
        if not task.cancelled():
            error = task.exception()
            if error:
                logger.error("Relay worker stopped unexpectedly", exc_info=error)

    async def open_outbound(self, pair: Pair) -> Session:
        route = await self.routing.find(pair.node_id)
        if route.ticket is None:
            return route.first.session
        circuit = await self.open_route(pair, route, role='active')
        return circuit.session

    async def open_route(self, pair: Pair, route: Route, *, role: str = 'trial') -> Circuit:
        if (route.ticket is None or route.path[0] != self.local or route.path[-1] != pair.node_id
                or route.expires <= time.monotonic()):
            raise PeerError('ROUTE_LOST', 'Mesh route ticket cannot open this path')
        if not self.is_link(route.first):
            self.routing.invalidate(route)
            raise PeerError("ROUTE_LOST", "Mesh first hop was replaced")
        self.routing.verified(route.first, route.ticket.wire(), query=False)
        circuit = Circuit(token_hex(16), route.path, route.ticket, None, route.first, route=route, role=role)
        self.register(circuit)
        if role == 'active':
            self.outbound[pair.node_id] = circuit
        phase = 'ready'
        try:
            token = SignedRecord.create("open", {"mesh_id": pair.mesh_id, "origin_node_id": self.local,
                "target_node_id": pair.node_id, "circuit_id": circuit.identity, "ticket_digest": sha256(route.ticket.raw).hexdigest(),
                "expires_at": int(time.time()) + DEADLINE}, self.routing.key)
            circuit.following.frame("relay.open", record=token.wire(), ticket=route.ticket.wire())
            async with asyncio.timeout(DEADLINE):
                await circuit.ready.wait()
            if circuit.failure:
                raise PeerError(circuit.failure, "Mesh circuit was rejected before authentication")
            phase = 'auth'
            self.run_circuit(circuit, self.endpoint(circuit, pair, server=False))
            async with asyncio.timeout(2 * DEADLINE + 1):
                await circuit.bound.wait()
            if not circuit.session or circuit.failure:
                raise PeerError(circuit.failure or "ROUTE_LOST", "Mesh circuit failed endpoint authentication")
            return circuit
        except TimeoutError as exc:
            self.counts['open_' + phase + '_timeouts'] += 1
            self.drop(circuit, "ROUTE_LOST")
            raise PeerError("ROUTE_LOST", "Timed out establishing a Mesh circuit") from exc
        except (PeerError, asyncio.CancelledError):
            self.drop(circuit, circuit.failure or "ROUTE_LOST")
            raise

    def promote(self, node: str, circuit: Circuit | None) -> None:
        if circuit is not None and (circuit.path[-1] != node or not self.live(circuit)):
            raise PeerError('ROUTE_LOST', 'The selected Mesh circuit is no longer active')
        previous = self.outbound.get(node)
        if previous is not None and previous is not circuit:
            previous.role = 'draining'
        if circuit is None:
            self.outbound.pop(node, None)
        else:
            circuit.role = 'active'
            self.outbound[node] = circuit

    def handle(self, link: Neighbor, frame: dict) -> None:
        if not self.is_link(link):
            return
        identity = frame["circuit_id"]
        if frame["type"] == "relay.open":
            if not self.routing.allowed("relay.open", link.pair.node_id, 16):
                return
            try:
                self.open_inbound(link, frame)
            except PeerError as exc:
                self.reject(link, identity, exc.code)
            except (InvalidSignature, ValueError):
                self.counts["invalid_frames"] += 1
                self.reject(link, identity, "PROTOCOL")
            return
        circuit = self.circuits.get(identity)
        if circuit is None:
            return
        leg = next((item for item in circuit.legs if item.link is link), None)
        if leg is None:
            self.counts["invalid_frames"] += 1
            return
        try:
            self.accept(circuit, leg, frame)
        except (ProtocolError, ValueError, asyncio.QueueFull, PeerError):
            self.counts["invalid_frames"] += 1
            self.drop(circuit, "PROTOCOL")

    def reject(self, link: Neighbor, identity: str, code: str) -> None:
        with suppress(PeerError):
            link.session.send({"type": "route.error", "circuit_id": identity, "code": code})

    def open_inbound(self, link: Neighbor, frame: dict) -> None:
        identity = frame["circuit_id"]
        self.reap_retired()
        if identity in self.circuits or identity in self.retired:
            return
        token = SignedRecord.parse(frame["record"])
        data = token.payload()
        ticket, reply = self.routing.verified(link, frame["ticket"], query=False)
        path = reply["path"]
        now = int(time.time())
        if (data.keys() != OPEN_FIELDS or data["mesh_id"] != link.pair.mesh_id or data["circuit_id"] != identity
                or data["origin_node_id"] != reply["origin_node_id"] or data["target_node_id"] != reply["target_node_id"]
                or data["ticket_digest"] != sha256(ticket.raw).hexdigest() or type(data["expires_at"]) is not int
                or not now < data["expires_at"] <= now + DEADLINE + TIME_SKEW
                or not isinstance(path, list) or not 3 <= len(path) <= HOPS + 1
                or not all(matches(NODE_ID, node) for node in path) or len(set(path)) != len(path)
                or path[0] != data["origin_node_id"] or path[-1] != data["target_node_id"] or self.local not in path[1:]):
            raise ProtocolError("Invalid signed relay open")
        index = path.index(self.local)
        if path[index - 1] != link.pair.node_id:
            raise ProtocolError("Relay open came from an unexpected neighbor")
        token.verify("open", self.routing.signer(path[0], link.pair.mesh_id))
        source = self.manager.pairs[path[0]]
        next_link = None
        if index == len(path) - 1:
            if not source.routed:
                raise PeerError("DENIED", "The member has no routed permission")
        else:
            if not self.manager.forwarding_enabled:
                raise PeerError("ROUTE_LOST", "Relay forwarding is disabled")
            next_link = self.manager.neighbors.get(path[index + 1])
            if not self.is_link(next_link):
                raise PeerError("ROUTE_LOST", "The next physical neighbor is offline")
        circuit = Circuit(identity, tuple(path), ticket, link, next_link)
        self.register(circuit)
        try:
            if next_link:
                next_link.session.send(frame)
                self.run_circuit(circuit, self.forward(circuit))
            else:
                circuit.previous.frame("relay.ready")
                circuit.ready.set()
                self.run_circuit(circuit, self.endpoint(circuit, source, server=True))
        except PeerError:
            self.drop(circuit, "ROUTE_LOST", skip=link)
            raise

    def accept(self, circuit: Circuit, leg: Leg, frame: dict) -> None:
        kind = frame["type"]
        circuit.last_wire = time.monotonic()
        if kind in {"route.error", "relay.close"}:
            if (kind == "route.error" and leg is not circuit.following) or frame["code"] not in REASONS:
                self.counts["invalid_frames"] += 1
                return
            self.drop(circuit, frame["code"], skip=leg.link)
        elif kind == "relay.ready":
            if leg is not circuit.following or circuit.ready.is_set():
                raise ProtocolError("Unexpected relay ready")
            circuit.ready.set()
            if circuit.previous:
                circuit.previous.frame("relay.ready")
        else:
            if not circuit.ready.is_set():
                raise ProtocolError("Relay data preceded circuit confirmation")
            leg.feed(frame)

    async def pump(self, circuit: Circuit, reader: Leg, writer: Leg) -> None:
        while True:
            item = await reader.queue.get()
            if item is None:
                return
            sequence, data = item
            await writer.send(data)
            reader.acknowledge(sequence)
            circuit.last_wire = time.monotonic()
            self.counts["forwarded_chunks"] += 1
            self.counts["forwarded_bytes"] += len(data)

    async def forward(self, circuit: Circuit) -> None:
        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(self.pump(circuit, circuit.previous, circuit.following))
                group.create_task(self.pump(circuit, circuit.following, circuit.previous))
        except (OSError, ValueError, PeerError, ExceptionGroup) as exc:
            logger.debug("Relay forward failed: %s", exc)
        finally:
            self.drop(circuit, "ROUTE_LOST")

    async def contexts(self, pair: Pair):
        settings = pair.ca_pem, pair.local_pem
        async with self.context_lock:
            if settings != self.context_settings:
                self.context_cache = await asyncio.to_thread(self.manager.contexts, pair)
                self.context_settings = settings
        return self.context_cache

    async def endpoint(self, circuit: Circuit, pair: Pair, *, server: bool) -> None:
        leg, = circuit.legs
        circuit.member = pair
        code = "ROUTE_LOST"
        phase, tls = 'context', None
        try:
            if self.handshakes.locked():
                code = "BUSY"
                return
            async with self.handshakes:
                handshake_started = asyncio.get_running_loop().time()
                circuit.valid_until = pair.validate(self.local)
                contexts = await self.contexts(pair)
                tls = TunnelTLS(leg, contexts[0 if server else 1], server=server, host=pair.host)
                phase = 'tls'
                await tls.handshake(mesh_authorities(pair.ca_pem), pair.node_id, pair.fingerprint)
                await tls.bind(mesh_id=pair.mesh_id, local_id=self.local, peer_id=pair.node_id, circuit_id=circuit.identity,
                               ticket_digest=sha256(circuit.ticket.raw).hexdigest())
            if self.manager.pairs.get(pair.node_id) != pair or not pair.enabled or not pair.routed:
                code = "DENIED"
                raise ProtocolError("Routed member admission changed")
            circuit.session = Session(tls, None, lambda method, params: self.endpoint_rpc(circuit, pair, method, params),
                                      send_wire=tls.send, handshake_started=handshake_started)
            phase = 'session'
            circuit.bound.set()
            self.counts["authenticated_circuits"] += 1
            await circuit.session.run()
        except (OSError, ValueError, EOFError, PeerError, ExceptionGroup) as exc:
            stage = tls.stage if phase == 'tls' and tls is not None else phase
            side = 'server' if server else 'client'
            outcome = 'timeouts' if isinstance(exc, TimeoutError) else 'failures'
            self.counts['endpoint_' + side + '_' + stage + '_' + outcome] += 1
            if isinstance(exc, ProtocolError) and code != "DENIED":
                code = "PROTOCOL"
            logger.debug("Tunnel %s ended: %s", circuit.identity, exc, exc_info=True)
        finally:
            self.drop(circuit, code)

    async def endpoint_rpc(self, circuit: Circuit, pair: Pair, method: str, params: dict) -> dict:
        if (circuit.failure or self.manager.pairs.get(pair.node_id) != pair or not pair.routed
                or circuit.valid_until is None or time.time() >= circuit.valid_until
                or method in {"mesh.pex", "mesh.observe"}):
            raise PeerError("DENIED", "RPC is not allowed on this Mesh circuit")
        return await self.handler(pair, method, params)

    def drop(self, circuit: Circuit, code: str, *, skip: Neighbor | None = None) -> None:
        if self.circuits.get(circuit.identity) is not circuit:
            return
        self.circuits.pop(circuit.identity)
        self.retired[circuit.identity] = time.monotonic() + REPLAY_TTL
        circuit.failure = code
        self.counts["closed_circuits"] += 1
        if circuit.route:
            node = circuit.path[-1]
            if self.outbound.get(node) is circuit:
                self.outbound.pop(node)
            if code != "CLOSED":
                self.routing.invalidate(circuit.route)
        for leg in circuit.legs:
            leg.close()
            if leg.link is not skip and self.is_link(leg.link):
                kind = "route.error" if leg is circuit.previous and code != "CLOSED" else "relay.close"
                with suppress(PeerError):
                    leg.frame(kind, code=code)
        if circuit.task and circuit.task is not asyncio.current_task():
            circuit.task.cancel()
        circuit.ready.set()
        circuit.bound.set()

    def invalidate(self, node: str, session: Session | None) -> None:
        circuit = self.outbound.get(node)
        if circuit and circuit.session is session:
            self.drop(circuit, "ROUTE_LOST")

    def link_lost(self, link: Neighbor) -> None:
        for circuit in list(self.circuits.values()):
            if any(leg.link is link for leg in circuit.legs):
                self.drop(circuit, "ROUTE_LOST", skip=link)

    async def sweep(self) -> None:
        try:
            while True:
                now = time.monotonic()
                for circuit in list(self.circuits.values()):
                    peers = (self.manager.pairs.get(node) for node in circuit.path if node != self.local)
                    if len(circuit.legs) == 2 and not self.manager.forwarding_enabled:
                        self.drop(circuit, "ROUTE_LOST")
                    elif (any(pair is None or not pair.enabled for pair in peers)
                            or (circuit.valid_until is not None and time.time() >= circuit.valid_until)
                            or (circuit.member and self.manager.pairs.get(circuit.member.node_id) != circuit.member)):
                        self.drop(circuit, "DENIED")
                    elif not circuit.ready.is_set() and now - circuit.created >= DEADLINE:
                        self.drop(circuit, "ROUTE_LOST")
                    elif now - circuit.last_wire > IDLE + 15 or (circuit.session and now - circuit.session.last_business > IDLE):
                        self.drop(circuit, "CLOSED")
                self.reap_retired()
                await asyncio.sleep(0.5)
        finally:
            tasks = [*self.attempts.values(), *self.workers]
            for circuit in list(self.circuits.values()):
                self.drop(circuit, "CLOSED")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
