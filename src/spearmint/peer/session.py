import asyncio
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import suppress
import logging
from secrets import token_hex
import time

from .directory import CATALOG_HEALTH_METHOD
from .path_selection import Latency
from .protocol import (
    CATALOG, DEADLINE, FRAME, IN_FLIGHT, RELAY_CONTROL, RELAY_FRAMES, RELAY_STREAM, ROUTE_FRAMES,
    PeerError, ProtocolError, encode, receive,
)


logger = logging.getLogger(__name__)
Handler = Callable[[str, dict], Awaitable[dict]]
ControlHandler = Callable[[dict], None]
HEARTBEAT = 5
WRITE_BYTES = 1024 * 1024
BOUNDED_REPLIES = {
    "catalog.sync": CATALOG, CATALOG_HEALTH_METHOD: CATALOG, "mesh.pex": CATALOG, "security.policy.get": CATALOG,
    "grove.identity.get": CATALOG,
    "grove.login.verifiers": CATALOG, "grove.login.verifiers.v2": CATALOG, "grove.login.verifiers.v3": CATALOG,
    "grove.login.continuity.v2": CATALOG, "grove.login.continuity.v3": CATALOG, "grove.login.continuity.v4": CATALOG,
    "grove.login.continuity.v5": 2 * CATALOG, "grove.members.admit.get": CATALOG,
    "grove.login.roles.get": CATALOG,
    "security.evidence.list": CATALOG, "security.evidence.part": CATALOG,
    "grove.update.v1": 132 * 1024,
    "grove.deploy.v1": 128 * 1024,
    "grove.seed.catalog": CATALOG, "grove.seed.catalog.v2": CATALOG, "grove.seed.catalog.v3": CATALOG,
}
RELAY_QUEUE_CIRCUITS = 128
RELAY_QUEUE_FRAMES = 8
RPC_RTT_ALLOWANCE = 2.0
TRANSFER_WINDOW_BYTES = 64 * 1024
TRANSFER_EXTENSION = 7.0
MAINTENANCE_METHODS = frozenset({'peer.ping', 'catalog.sync', CATALOG_HEALTH_METHOD,
                                 'mesh.pex', 'mesh.observe', 'mesh.grove_endpoints'})


async def close_stream(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        with suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1.5)
    finally:
        writer.transport.abort()


def session_busy(session) -> bool:
    """Include replies still being handled or written when retiring a session."""
    return bool(getattr(session, 'pending', None) or getattr(session, 'handling', None)
                or getattr(session, 'write_bytes', 0))


class Session:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, handler: Handler,
                 *, control: ControlHandler | None = None, relay: bool = False,
                 send_wire: Callable[[bytes], Awaitable[None]] | None = None,
                 handshake_started: float | None = None) -> None:
        self.reader = reader
        self.writer = writer
        self.handler = handler
        self.control = control
        self.relay = relay
        self.send_wire = send_wire
        self.pending: dict[str, tuple[str, asyncio.Future]] = {}
        self.handling: set[str] = set()
        self.writes: asyncio.PriorityQueue[tuple[bool, int, float, bytes]] = asyncio.PriorityQueue(maxsize=8)
        self.write_sequence = 0
        self.small_write_burst = 0
        self.logs_started = 0
        self.log_text_supported: bool | None = None
        self.service_health_supported: bool | None = None
        self.priority: deque[tuple[float, bytes]] = deque()
        self.relay_notices: deque[tuple[float, bytes]] = deque()
        self.relay_writes: dict[str, deque[tuple[float, bytes]]] = {}
        self.write_ready = asyncio.Event()
        self.write_bytes = 0
        self.pings: deque[tuple[str, float]] = deque()
        self.heartbeat_samples: deque[bool] = deque(maxlen=12)
        self.loop = asyncio.get_running_loop()
        # Local identifier for matching panel status and directory responses.
        self.connection_id = token_hex(16)
        self.directory_generation = 0
        self.created_at = self.loop.time()
        self.handshake_ms = (max(0, self.created_at - handshake_started) * 1000
                             if handshake_started is not None else None)
        self.last_pong = self.loop.time()
        self.last_seen = time.time()
        self.last_business = self.loop.time()
        self.last_workload = self.last_business
        self.rtt_ms: float | None = None
        self.latency = Latency()
        self.closed = False

    def link_metrics(self) -> dict:
        missed = sum(self.heartbeat_samples)
        elapsed_now = time.perf_counter()
        overdue = sum(elapsed_now - sent >= HEARTBEAT for _, sent in self.pings)
        samples = len(self.heartbeat_samples) + overdue
        now = self.loop.time()
        return {"rtt_ms": self.rtt_ms, **self.latency.public_data(now), "last_seen_at": self.last_seen,
                "handshake_ms": round(self.handshake_ms, 3) if self.handshake_ms is not None else None,
                "session_age_seconds": round(max(0, now - self.created_at), 3),
                "heartbeat_samples": samples, "heartbeat_timeout_rate": (missed + overdue) / samples if samples else None}

    def observe_rtt(self, delay: float, sampled_at: float) -> None:
        self.latency.add(delay * 1000, sampled_at)
        self.rtt_ms = round(delay * 1000, 3)

    def frame_timeout(self, size: int) -> float:
        # Authenticated tunnels must turn over their fixed 64 KiB credit window
        # several times for a full log response. Physical links and small frames
        # keep their original deadline; stale samples never extend a transfer.
        if (self.send_wire is None or size <= TRANSFER_WINDOW_BYTES
                or not self.latency.fresh(self.loop.time())):
            return DEADLINE
        windows = (size + TRANSFER_WINDOW_BYTES - 1) // TRANSFER_WINDOW_BYTES
        rtt = max(self.latency.latest_ms or 0, self.latency.ewma_ms or 0) / 1000
        return DEADLINE + min(TRANSFER_EXTENSION, windows * rtt)

    def send(self, frame: dict, limit: int = FRAME) -> None:
        if self.closed:
            raise PeerError("OFFLINE", "Peer connection closed")
        wire = encode(frame, limit, mesh=self.control is not None, relay=self.relay)
        kind = frame["type"]
        # A queued heartbeat can wait behind one atomic bulk frame. Its active
        # transfer is still timed separately below, and queue/byte caps remain.
        queue_budget = DEADLINE if self.send_wire is None else DEADLINE + self.frame_timeout(FRAME)
        if self.send_wire is not None and self.write_bytes > TRANSFER_WINDOW_BYTES:
            # The current bulk frame and this reply share one serial stream.
            # Use the existing queue ceiling rather than count one transfer twice.
            queue_budget = 2 * DEADLINE + TRANSFER_EXTENSION
        deadline = self.loop.time() + queue_budget
        if kind in {"ping", "pong"} or (self.control is not None and kind in ROUTE_FRAMES):
            slots = 6 if kind in ROUTE_FRAMES else 8
            if len(self.priority) >= slots:
                raise PeerError("BUSY", "Peer control queue is full")
            self.priority.append((deadline, wire))
        elif kind in RELAY_CONTROL:
            if len(self.relay_notices) >= 2 * RELAY_QUEUE_CIRCUITS:
                raise PeerError("BUSY", "Relay notice queue is full")
            self.relay_notices.append((deadline, wire))
        elif kind in RELAY_STREAM:
            circuit = frame["circuit_id"]
            queue = self.relay_writes.get(circuit)
            if queue is None:
                if len(self.relay_writes) >= RELAY_QUEUE_CIRCUITS:
                    raise PeerError("BUSY", "Relay link circuit queue is full")
                queue = self.relay_writes[circuit] = deque()
            if len(queue) >= RELAY_QUEUE_FRAMES:
                raise PeerError("BUSY", "Relay circuit queue is full")
            queue.append((deadline, wire))
        else:
            if self.writes.full() or self.write_bytes + len(wire) > WRITE_BYTES:
                raise PeerError("BUSY", "Peer write queue is full")
            self.write_sequence += 1
            self.writes.put_nowait((len(wire) > TRANSFER_WINDOW_BYTES, self.write_sequence, deadline, wire))
            self.write_bytes += len(wire)
        self.write_ready.set()

    def discard_relay(self, circuit: str) -> None:
        self.relay_writes.pop(circuit, None)
        if self.writes.empty() and not (self.priority or self.relay_notices or self.relay_writes):
            self.write_ready.clear()

    def next_write(self) -> tuple[float, bytes]:
        # The queue has at most eight entries. Inspect them atomically so an
        # expired bulk reply cannot hide behind newly arriving small replies.
        queued = [self.writes.get_nowait() for _ in range(self.writes.qsize())]
        if any(self.loop.time() >= item[2] for item in queued):
            raise TimeoutError("Peer write queue deadline exceeded")
        index = 0
        if self.small_write_burst >= 4:
            index = next((i for i, item in enumerate(queued) if item[0]), 0)
        bulk, _, deadline, wire = queued.pop(index)
        for item in queued:
            self.writes.put_nowait(item)
        self.small_write_burst = 0 if bulk else min(4, self.small_write_burst + 1)
        return deadline, wire

    async def write_frames(self) -> None:
        burst = 0
        relay_turn = False
        notice_turn = False
        while True:
            await self.write_ready.wait()
            if self.writes.empty() and not (self.priority or self.relay_notices or self.relay_writes):
                self.write_ready.clear()
                continue
            regular = False
            if (self.priority or self.relay_notices) and (burst < 4 or (self.writes.empty() and not self.relay_writes)):
                notice = bool(self.relay_notices and (notice_turn or not self.priority))
                deadline, wire = (self.relay_notices if notice else self.priority).popleft()
                notice_turn = not notice
                burst = min(4, burst + 1)
            else:
                regular = not self.relay_writes or (not relay_turn and not self.writes.empty())
                if regular:
                    deadline, wire = self.next_write()
                else:
                    circuit = next(iter(self.relay_writes))
                    queue = self.relay_writes.pop(circuit)
                    deadline, wire = queue.popleft()
                    if queue:
                        self.relay_writes[circuit] = queue
                relay_turn = regular
                burst = 0
            if self.writes.empty() and not (self.priority or self.relay_notices or self.relay_writes):
                self.write_ready.clear()
            transfer_deadline = min(deadline, self.loop.time() + self.frame_timeout(len(wire)))
            async with asyncio.timeout_at(transfer_deadline):
                if self.loop.time() >= deadline:
                    raise TimeoutError("Peer write queue deadline exceeded")
                if self.send_wire is None:
                    self.writer.write(wire)
                    await self.writer.drain()
                else:
                    await self.send_wire(wire)
            if regular:
                self.write_bytes -= len(wire)

    async def call(self, method: str, params: dict) -> dict:
        if self.closed:
            raise PeerError("OFFLINE", "Peer connection closed")
        if len(self.pending) >= IN_FLIGHT:
            raise PeerError("BUSY", "Too many requests to the peer")
        request_id = token_hex(16)
        self.last_business = self.loop.time()
        if method not in MAINTENANCE_METHODS:
            self.last_workload = self.last_business
        result = self.loop.create_future()
        had_logs = any(name == "service.logs" and not future.done() for name, future in self.pending.values())
        log_generation = self.logs_started
        if method == "service.logs":
            self.logs_started += 1
        self.pending[request_id] = (method, result)
        try:
            self.send({"type": "request", "id": request_id, "method": method, "params": params})
            bulk_update = method == "grove.update.v1" and params.get("action") == "chunk"
            timeout = 10 if bulk_update else 5 if method == "service.logs" else DEADLINE
            if self.latency.fresh(self.loop.time()):
                # The responder's handler keeps its own DEADLINE. Leave a
                # bounded allowance for the already measured network round trip.
                rtt = max(self.latency.latest_ms or 0, self.latency.ewma_ms or 0) / 1000
                timeout += min(RPC_RTT_ALLOWANCE, rtt)
                if method == "service.logs":
                    timeout += self.frame_timeout(FRAME) - DEADLINE
            # A reply cannot overtake an already transmitting bulk frame.
            # Keep the ordinary deadline first, then allow at most one bounded
            # bulk transfer if legitimate log requests overlapped this call.
            wait_started = self.loop.time()
            done, _ = await asyncio.wait({result}, timeout=timeout)
            if done:
                return result.result()
            if (self.send_wire is not None
                    and (had_logs or self.logs_started > log_generation + int(method == "service.logs"))):
                limit = 14 if method == "service.logs" else 15
                remaining = min(self.frame_timeout(FRAME), limit - (self.loop.time() - wait_started))
                if remaining > 0:
                    return await asyncio.wait_for(result, remaining)
            raise TimeoutError("Peer response timed out")
        except TimeoutError as exc:
            raise PeerError("TIMEOUT", "Peer response timed out") from exc
        finally:
            self.pending.pop(request_id, None)
            if result.done() and not result.cancelled():
                result.exception()
            else:
                result.cancel()

    async def heartbeat(self) -> None:
        next_ping = self.loop.time()
        while True:
            now = self.loop.time()
            deadline = self.last_pong + 3 * HEARTBEAT
            if now >= deadline:
                raise TimeoutError("Peer heartbeat expired")
            if now >= next_ping:
                key = token_hex(16)
                # On Python 3.12/Windows the loop clock can have 15.6 ms
                # resolution. Measure elapsed RTT on the precise monotonic
                # counter; keep scheduling and freshness on the loop clock.
                self.pings.append((key, time.perf_counter()))
                self.send({"type": "ping", "nonce": key})
                next_ping = now + HEARTBEAT
            await asyncio.sleep(max(0, min(next_ping, deadline) - self.loop.time()))

    def send_error(self, request_id: str, error: PeerError) -> None:
        with suppress(PeerError):
            self.send({"type": "response", "id": request_id,
                       "error": {"code": error.code, "message": str(error)[:256]}})

    async def answer(self, frame: dict) -> None:
        request_id, method = frame["id"], frame["method"]
        try:
            try:
                result = await self.handler(method, frame["params"])
            except PeerError as exc:
                self.send_error(request_id, exc)
            except Exception:
                logger.exception("Peer RPC handler failed")
                self.send_error(request_id, PeerError("INTERNAL", "Peer request failed"))
            else:
                try:
                    self.send({"type": "response", "id": request_id, "result": result},
                              BOUNDED_REPLIES.get(method, FRAME))
                except ProtocolError:
                    self.send_error(request_id, PeerError("LIMIT", "Peer response exceeds its size limit"))
                except PeerError as exc:
                    self.send_error(request_id, exc)
        finally:
            self.handling.remove(request_id)

    def accept_response(self, frame: dict, size: int) -> None:
        pending = self.pending.get(frame["id"])
        if pending is None:
            return
        method, result = pending
        if result.done():
            return
        if size > BOUNDED_REPLIES.get(method, FRAME):
            raise ProtocolError("Peer RPC response exceeds its size limit")
        if "error" in frame:
            result.set_exception(PeerError(frame["error"]["code"], frame["error"]["message"]))
        else:
            result.set_result(frame["result"])

    async def read_frames(self, group: asyncio.TaskGroup) -> None:
        while True:
            frame, size = await receive(self.reader, mesh=self.control is not None, relay=self.relay,
                                        frame_timeout=self.frame_timeout)
            self.last_seen = time.time()
            match frame["type"]:
                case "ping":
                    self.send({"type": "pong", "nonce": frame["nonce"]})
                case "pong":
                    if not self.pings or self.pings[0][0] != frame["nonce"]:
                        raise ProtocolError("Unexpected Peer heartbeat response")
                    _, sent = self.pings.popleft()
                    self.last_pong = self.loop.time()
                    delay = time.perf_counter() - sent
                    self.observe_rtt(delay, self.last_pong)
                    self.heartbeat_samples.append(delay >= HEARTBEAT)
                case "response":
                    self.accept_response(frame, size)
                case "request":
                    self.last_business = self.loop.time()
                    if frame['method'] not in MAINTENANCE_METHODS:
                        self.last_workload = self.last_business
                    key = frame["id"]
                    if key in self.handling:
                        raise ProtocolError("Duplicate in-flight request ID")
                    if len(self.handling) == IN_FLIGHT:
                        self.send_error(key, PeerError("BUSY", "Too many requests from the peer"))
                    else:
                        self.handling.add(key)
                        group.create_task(self.answer(frame))
                case kind if self.control is not None and kind in ROUTE_FRAMES | RELAY_FRAMES:
                    self.control(frame)
                case _:
                    raise ProtocolError("Unexpected HELLO on an active session")

    async def run(self) -> None:
        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(self.write_frames())
                group.create_task(self.heartbeat())
                group.create_task(self.read_frames(group))
        finally:
            self.closed = True
            for _, future in self.pending.values():
                if not future.done():
                    future.set_exception(PeerError("OFFLINE", "Peer connection closed"))
