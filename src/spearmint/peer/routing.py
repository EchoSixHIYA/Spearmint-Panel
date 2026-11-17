import asyncio
from collections import Counter, deque
from dataclasses import dataclass
from hashlib import sha256
from secrets import token_hex
import time
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .credentials import FINGERPRINT, NODE_ID, RANDOM_ID, certificate, is_current
from .protocol import RELAY_CAPABILITY, PeerError, ProtocolError, matches
from .signed import SignedRecord

if TYPE_CHECKING:
    from .manager import Neighbor, PeerManager


CAPABILITY = "mesh.route"
MULTIPATH_CAPABILITY = "mesh.route.multipath"
HOPS = 4
QUERY_TTL = 5
ROUTE_TTL = 30
DEDUPE_TTL = 15
SEEN_LIMIT = 256
INPUT_LIMIT = 32
ORIGIN_LIMIT = 12
TIME_SKEW = 5
COMMON = {"mesh_id", "origin_node_id", "target_node_id", "discovery_id", "expires_at"}
PATHS = 3
PREFIXES = 2


@dataclass(frozen=True)
class Route:
    path: tuple[str, ...]
    first: "Neighbor"
    ticket: SignedRecord | None = None
    expires: float = 0.0

    def public_data(self) -> dict:
        return {"path": list(self.path), "hops": len(self.path) - 1, "next_hop": self.first.pair.node_id,
                "session_id": self.first.generation, "direct": self.ticket is None}


@dataclass(frozen=True)
class Trail:
    prefix: tuple[str, ...]
    previous: "Neighbor"
    digest: str
    expires: float


@dataclass(frozen=True)
class Pending:
    target: str
    digest: str
    future: asyncio.Future[Route]
    expires: float


class Routing:
    def __init__(self, manager: "PeerManager", key: Ed25519PrivateKey, *, adaptive: bool = False) -> None:
        self.manager = manager
        self.key = key
        self.local = manager.local_id
        self.cache: dict[str, Route] = {}
        self.candidates: dict[str, dict[tuple[str, ...], Route]] = {}
        self.seen: dict[tuple, Trail] = {}
        self.pending: dict[str, Pending] = {}
        self.attempts: dict[str, asyncio.Task[Route]] = {}
        self.first_results: dict[str, asyncio.Future[Route]] = {}
        self.candidate_updates: dict[str, asyncio.Event] = {}
        self.rates: dict[tuple[str, str], deque[float]] = {}
        self.counts: Counter[str] = Counter()
        self.relay_only = False
        self.adaptive = adaptive

    def is_live(self, neighbor: "Neighbor") -> bool:
        return self.manager.neighbors.get(neighbor.pair.node_id) is neighbor

    def routes(self, target: str) -> list[Route]:
        member = self.manager.pairs.get(target)
        if member is None or not member.enabled:
            self.cache.pop(target, None)
            self.candidates.pop(target, None)
            return []
        result = []
        direct = self.manager.neighbors.get(target)
        if direct and not getattr(direct.session, 'closed', False):
            result.append(Route((self.local, target), direct))
        pool = self.candidates.get(target, {})
        cached = self.cache.get(target)
        if cached is not None:
            pool.setdefault(cached.path, cached)
        now = time.monotonic()
        valid = {path: route for path, route in pool.items() if member.routed and not member.legacy
                 and now < route.expires and self.is_live(route.first)
                 and not getattr(route.first.session, 'closed', False)
                 and all(self.manager.pairs.get(node) and self.manager.pairs[node].enabled for node in route.path[1:])}
        if cached is not None and cached.path in valid:
            valid = self.bounded_candidates(valid, cached.path)
            self.cache[target] = valid[cached.path]
        else:
            self.cache.pop(target, None)
        if valid:
            self.candidates[target] = valid
            result.extend(sorted(valid.values(), key=lambda route: (len(route.path), route.path)))
        else:
            self.candidates.pop(target, None)
        return result

    def lookup(self, target: str) -> Route | None:
        routes = self.routes(target)
        if not routes:
            return None
        direct = next((route for route in routes if route.ticket is None), None)
        return direct or self.cache.get(target) or routes[0]

    def remember(self, route: Route) -> None:
        target = route.path[-1]
        if route.ticket is None:
            return
        self.routes(target)
        pool = self.candidates.setdefault(target, {})
        pool[route.path] = route
        cached = self.cache.get(target, route)
        self.candidates[target] = self.bounded_candidates(pool, cached.path)
        self.cache[target] = pool[cached.path]
        if update := self.candidate_updates.get(target):
            update.set()

    def bounded_candidates(self, pool: dict[tuple[str, ...], Route], cached_path: tuple[str, ...]) -> dict[tuple[str, ...], Route]:
        limit = PATHS if self.adaptive else 1
        if len(pool) <= limit:
            return pool
        selected = [cached_path]
        if self.adaptive:
            # A short path can overlap the cached route and still be worth sampling.
            shortest = min(pool, key=lambda path: (len(path), path))
            if shortest != cached_path:
                selected.append(shortest)
        while len(selected) < limit:
            edges = {(a, b) for path in selected for a, b in zip(path, path[1:])}
            remaining = (path for path in pool if path not in selected)
            selected.append(min(remaining, key=lambda path: (
                sum((a, b) in edges for a, b in zip(path, path[1:])), len(path), path)))
        return {path: pool[path] for path in selected}

    def invalidate(self, route: Route) -> None:
        target = route.path[-1]
        cached = self.cache.get(target)
        if cached and cached.path == route.path and cached.first is route.first:
            self.cache.pop(target, None)
        pool = self.candidates.get(target, {})
        current = pool.get(route.path)
        if current and current.first is route.first:
            pool.pop(route.path)
        if not pool:
            self.candidates.pop(target, None)

    def status(self) -> dict:
        now = time.monotonic()
        self.seen = {key: trail for key, trail in self.seen.items() if trail.expires > now}
        for key, samples in list(self.rates.items()):
            while samples and now - samples[0] >= QUERY_TTL:
                samples.popleft()
            if not samples:
                self.rates.pop(key)
        paths = []
        for target in list(self.candidates.keys() | self.cache.keys()):
            for route in self.routes(target):
                if route.ticket is not None:
                    paths.append({**route.public_data(), 'ticket_remaining_seconds': round(max(0, route.expires - time.monotonic()), 3)})
        return {"mode": 'adaptive' if self.adaptive else 'legacy', "cached_paths": paths,
                "discoveries_in_flight": len(self.attempts), "reverse_records": len(self.seen), **self.counts}

    async def find(self, target: str, *, refresh: bool = False) -> Route:
        member = self.manager.pairs.get(target)
        if member is None or not member.enabled:
            raise PeerError("NOT_FOUND", "Unknown or disabled Mesh member")
        existing = self.lookup(target)
        if existing is not None and not refresh:
            if existing.ticket is not None:
                self.counts["cache_hits"] += 1
            return existing
        if member.legacy or not member.routed:
            raise PeerError("NO_ROUTE", "Member has no permitted Mesh route")
        task = self.attempts.get(target)
        if existing is None and task is not None and self.first_results[target].done():
            if self.adaptive:
                # The first ticket may fail while replies to this discovery are still in flight.
                self.counts['coalesced'] += 1
                update = self.candidate_updates.setdefault(target, asyncio.Event())
                while self.attempts.get(target) is task:
                    update.clear()
                    await update.wait()
                    if replacement := self.lookup(target):
                        return replacement
                await task
            else:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            return await self.find(target, refresh=refresh)
        result = self.refresh(target)
        if existing is not None:
            return existing
        return await asyncio.shield(result)

    def refresh(self, target: str) -> asyncio.Future[Route]:
        member = self.manager.pairs.get(target)
        if member is None or not member.enabled or member.legacy or not member.routed:
            raise PeerError("NO_ROUTE", "Member has no permitted Mesh route")
        if target in self.attempts:
            self.counts["coalesced"] += 1
            return self.first_results[target]
        if len(self.attempts) >= 4:
            raise PeerError("BUSY", "Too many Mesh route discoveries")
        result = asyncio.get_running_loop().create_future()
        result.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        self.first_results[target] = result
        task = asyncio.create_task(self.discover(target, member.mesh_id))
        self.attempts[target] = task
        task.add_done_callback(lambda done: self.finished(target, done))
        return result

    def finished(self, target: str, task: asyncio.Task) -> None:
        if self.attempts.get(target) is task:
            self.attempts.pop(target)
            self.first_results.pop(target, None)
            if update := self.candidate_updates.pop(target, None):
                update.set()
        if not task.cancelled():
            task.exception()

    async def close(self) -> None:
        tasks = list(self.attempts.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.attempts.clear()
        self.first_results.clear()
        self.pending.clear()
        self.cache.clear()
        self.candidates.clear()
        self.seen.clear()
        self.rates.clear()

    async def discover(self, target: str, mesh_id: str) -> Route:
        result = self.first_results[target]
        query_ids = []
        now = time.monotonic()
        versions = (True, False) if self.adaptive else (False,)
        self.counts["discoveries"] += 1
        try:
            sent = 0
            for multipath in versions:
                links = [link for node, link in self.manager.neighbors.items() if node != target
                         and (not self.adaptive or (MULTIPATH_CAPABILITY in link.capabilities) == multipath)]
                if not links:
                    continue
                query_id = token_hex(16)
                payload = {"mesh_id": mesh_id, "origin_node_id": self.local, "target_node_id": target,
                           "discovery_id": query_id, "hop_limit": HOPS, "expires_at": int(time.time()) + QUERY_TTL}
                signed = SignedRecord.create("query.v3" if multipath else "query", payload, self.key)
                self.pending[query_id] = Pending(target, sha256(signed.raw).hexdigest(), result, now + QUERY_TTL)
                query_ids.append(query_id)
                frame = {"type": "route.query.v3" if multipath else "route.query", "record": signed.wire(), "path": [self.local]}
                sent += sum(self.send(link, frame) for link in links)
            if sent:
                remaining = max(0, now + QUERY_TTL - time.monotonic())
                if self.adaptive:
                    await asyncio.sleep(remaining)
                else:
                    try:
                        await asyncio.wait_for(asyncio.shield(result), remaining)
                    except TimeoutError:
                        pass
            if not result.done():
                self.counts["failures"] += 1
                result.set_exception(PeerError("NO_ROUTE", "Mesh route discovery found no reachable target"))
            return result.result()
        finally:
            for query_id in query_ids:
                self.pending.pop(query_id, None)
            if not result.done():
                result.cancel()

    def send(self, link: "Neighbor", frame: dict) -> bool:
        if (CAPABILITY not in link.capabilities or not self.is_live(link)
                or frame['type'] == 'route.query.v3' and MULTIPATH_CAPABILITY not in link.capabilities
                or (self.relay_only and RELAY_CAPABILITY not in link.capabilities)):
            return False
        try:
            link.session.send(frame)
        except PeerError:
            self.counts["busy"] += 1
            return False
        return True

    def flood(self, path: tuple[str, ...], frame: dict) -> int:
        return sum(self.send(link, frame) for node, link in self.manager.neighbors.items() if node not in path)

    def allowed(self, kind: str, node: str, limit: int) -> bool:
        now = time.monotonic()
        key = (kind, node)
        if key not in self.rates:
            self.rates = {k: v for k, v in self.rates.items() if k[1] in self.manager.pairs}
        times = self.rates.setdefault(key, deque())
        while times and now - times[0] >= QUERY_TTL:
            times.popleft()
        if len(times) >= limit:
            self.counts["rate_limited"] += 1
            return False
        times.append(now)
        return True

    def handle(self, link: "Neighbor", frame: dict) -> None:
        if not self.is_live(link) or not self.allowed("link", link.pair.node_id, INPUT_LIMIT):
            return
        try:
            if frame["type"] == "route.query.v3" and (not self.adaptive or MULTIPATH_CAPABILITY not in link.capabilities):
                self.counts['not_negotiated'] += 1
                return
            if frame["type"] in {"route.query", "route.query.v3"}:
                self.query(link, frame)
            else:
                self.reply(link, frame)
        except (ValueError, InvalidSignature):
            self.counts["invalid"] += 1

    def verified(self, link: "Neighbor", wire, *, query: bool, multipath: bool = False) -> tuple[SignedRecord, dict]:
        signed = SignedRecord.parse(wire)
        data = signed.payload()
        lifetime = QUERY_TTL if query else ROUTE_TTL
        now = int(time.time())
        extras = {"hop_limit"} if query else {"path", "query_digest"}
        if (data.keys() != COMMON | extras or data["mesh_id"] != link.pair.mesh_id
                or not matches(NODE_ID, data["origin_node_id"]) or not matches(NODE_ID, data["target_node_id"])
                or data["origin_node_id"] == data["target_node_id"] or not matches(RANDOM_ID, data["discovery_id"])
                or type(data["expires_at"]) is not int or not now < data["expires_at"] <= now + lifetime + TIME_SKEW):
            raise ProtocolError("Invalid or expired Mesh route record")
        signer = data["origin_node_id"] if query else data["target_node_id"]
        signed.verify(("query.v3" if multipath else "query") if query else "reply", self.signer(signer, link.pair.mesh_id))
        return signed, data

    def signer(self, node: str, mesh: str):
        if node == self.local:
            return self.key.public_key()
        member = self.manager.pairs.get(node)
        if member is None or member.legacy or not member.enabled or member.mesh_id != mesh:
            raise ProtocolError("Route signer is not a Mesh member")
        leaf = certificate(member.remote_pem)
        if not is_current(leaf):
            raise ProtocolError("Route signer certificate expired")
        return leaf.public_key()

    def query(self, link: "Neighbor", frame: dict) -> None:
        multipath = frame['type'] == 'route.query.v3'
        signed, data = self.verified(link, frame["record"], query=True, multipath=multipath)
        origin, target, query_id = (data[key] for key in ("origin_node_id", "target_node_id", "discovery_id"))
        path = tuple(frame["path"])
        hops = data["hop_limit"]
        if (type(hops) is not int or not 1 <= len(path) <= hops <= HOPS or len(set(path)) != len(path)
                or path[0] != origin or path[-1] != link.pair.node_id or self.local in path or target in path):
            raise ProtocolError("Invalid forward route path")
        if target != self.local and not self.manager.forwarding_enabled:
            return
        if target == self.local and not self.manager.pairs[origin].routed:
            return
        if target != self.local and (target not in self.manager.pairs or not self.manager.pairs[target].enabled):
            return
        now = time.monotonic()
        self.seen = {key: value for key, value in self.seen.items() if value.expires > now}
        base = (origin, target, query_id)
        key = (*base, path) if multipath else base
        if key in self.seen:
            self.counts["duplicates"] += 1
            return
        if multipath and sum(item[:3] == base for item in self.seen) >= (PATHS if target == self.local else PREFIXES):
            self.counts['prefix_limited'] += 1
            return
        if len(self.seen) >= SEEN_LIMIT or not self.allowed("origin", origin, ORIGIN_LIMIT):
            return
        digest = sha256(signed.raw).hexdigest()
        self.seen[key] = Trail(path, link, digest, now + DEDUPE_TTL)
        path += (self.local,)
        if target == self.local:
            reply = {key: data[key] for key in COMMON}
            reply.update(path=list(path), query_digest=digest, expires_at=int(time.time()) + ROUTE_TTL)
            record = SignedRecord.create("reply", reply, self.key)
            self.send(link, {"type": "route.reply", "record": record.wire()})
        elif len(path) <= hops:
            self.counts["forwarded"] += self.flood(path, {**frame, "path": list(path)})

    def reply(self, link: "Neighbor", frame: dict) -> None:
        signed, data = self.verified(link, frame["record"], query=False)
        path = data["path"]
        origin, target, query_id = (data[key] for key in ("origin_node_id", "target_node_id", "discovery_id"))
        if (not isinstance(path, list) or not 2 <= len(path) <= HOPS + 1
                or not all(matches(NODE_ID, node) for node in path) or len(set(path)) != len(path)
                or path[0] != origin or path[-1] != target or self.local not in path[:-1]
                or not matches(FINGERPRINT, data["query_digest"])):
            raise ProtocolError("Invalid signed route path")
        index = path.index(self.local)
        if path[index + 1] != link.pair.node_id:
            raise ProtocolError("Route reply came from the wrong neighbor")
        if index:
            base = (origin, target, query_id)
            trail = self.seen.get((*base, tuple(path[:index]))) or self.seen.get(base)
            if (trail and trail.expires > time.monotonic() and trail.prefix == tuple(path[:index])
                    and trail.digest == data["query_digest"] and self.manager.forwarding_enabled):
                self.send(trail.previous, frame)
            return
        pending = self.pending.get(query_id)
        if pending and pending.target == target and pending.digest == data["query_digest"] and time.monotonic() < pending.expires:
            route = Route(tuple(path), link, signed, time.monotonic() + min(ROUTE_TTL, data["expires_at"] - time.time()))
            self.remember(route)
            self.counts['candidate_replies'] += 1
            if not pending.future.done():
                pending.future.set_result(route)
