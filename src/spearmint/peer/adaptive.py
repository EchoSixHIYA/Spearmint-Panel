"""Selection of authenticated business sessions, with bounded trials and draining."""
import asyncio
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
import logging
import time

from .directory import CATALOG_HEALTH_METHOD
from .manager import PeerManager
from .pairing import Pair
from .path_selection import Candidate, MIN_DWELL, MIN_SAMPLES, REQUIRED_COMPARISONS, Selector, required_saving_ms
from .protocol import PeerError
from .relay import CIRCUITS, PER_ORIGIN, Circuit, Relay
from .routing import Route, Routing
from .session import Session


logger = logging.getLogger(__name__)
MAX_TRIALS = 2
SAMPLE_TIMEOUT = 15
TRIAL_AGE = 35
IDLE = 60
IDLE_PATH_TTL = 30
STATUS_WATCH_TTL = 12
REFRESH = 15
STANDBY_ROTATION = 30
COOLDOWN = 5
# Existing tunnel RPCs can wait up to fourteen/fifteen seconds during a bulk
# reply. Their own timers still end each call; a path switch must not cut that
# wait short. Draining keeps occupying the same bounded circuit budget.
DRAIN_TIMEOUT = 15
STANDBY_PING_INTERVAL = 25
STANDBY_PREPARE_TIMEOUT = 10
PATH_ERRORS = {'NO_ROUTE', 'ROUTE_LOST', 'OFFLINE', 'TIMEOUT', 'BUSY'}


@dataclass(eq=False)
class Binding:
    route: Route
    session: Session
    circuit: Circuit | None = None

    @property
    def incoming(self) -> bool:
        return self.circuit is not None and self.circuit.path[-1] == self.route.path[0]

    @property
    def key(self):
        generation = self.route.first.generation
        return self.route.path, generation + (':' + self.circuit.identity if self.circuit else '')

    @property
    def created_at(self) -> float:
        return self.circuit.created if self.circuit else self.session.created_at

    def candidate(self) -> Candidate:
        return Candidate(self.route.path, self.key[1], self.session.latency, verified=True)


@dataclass(frozen=True)
class IdlePath:
    pair: Pair
    path: tuple[str, ...]
    retired_at: float


class SwitchDeferred(Exception):
    """A healthy path no longer meets the conditions for a proactive switch."""


Prepare = Callable[[Pair, Binding, Callable[[], None], Callable[[], None] | None], Awaitable[None]]
Warm = Callable[[Pair, Binding], Awaitable[None]]
Prepared = Callable[[str, Session], bool]


class AdaptiveRoutes:
    def __init__(self, manager: PeerManager, routing: Routing, relay: Relay, prepare: Prepare,
                 *, clock: Callable[[], float] = time.monotonic, warm: Warm | None = None,
                 prepared: Prepared | None = None, prepared_remaining: Callable[[str, Session], float] | None = None) -> None:
        self.manager, self.routing, self.relay, self.prepare = manager, routing, relay, prepare
        self.clock = clock
        self.warm, self.prepared = warm, prepared
        self.prepared_remaining = prepared_remaining
        self.active: dict[str, Binding] = {}
        self.trials: dict[str, Binding] = {}
        self.opening: dict[str, asyncio.Task] = {}
        self.waiting_for_trial: dict[str, float] = {}
        self.keepers: dict[str, asyncio.Task] = {}
        self.standby_attempted: dict[str, tuple[tuple, float]] = {}
        self.attempts: dict[str, asyncio.Task] = {}
        self.switching: dict[str, asyncio.Task] = {}
        self.deferred_switches: dict[str, tuple[Binding, str, float]] = {}
        self.draining: dict[str, tuple[Binding, float]] = {}
        self.selectors: dict[str, Selector] = {}
        self.used: dict[str, float] = {}
        self.last_served: dict[str, float] = {}
        self.idle_paths: dict[str, IdlePath] = {}
        self.pending_targets: set[str] = set()
        self.status_watch_until = 0.0
        self.watch_recoveries: dict[str, tuple[Pair, float]] = {}
        self.refreshed: dict[str, float] = {}
        self.trialled_paths: dict[tuple[tuple[str, ...], str], float] = {}
        self.last_trial: dict[str, float] = {}
        self.failed: dict[tuple, float] = {}
        self.reasons: dict[str, str] = {}
        self.path_errors: dict[str, str] = {}
        self.counts: Counter[str] = Counter()

    @staticmethod
    def route_key(route: Route):
        return route.path, route.first.generation

    def failure_key(self, binding: Binding):
        return binding.key if binding.incoming else self.route_key(binding.route)

    def trial_order(self, route: Route) -> tuple[float, int, tuple[str, ...]]:
        return self.trialled_paths.get(self.route_key(route), float('-inf')), len(route.path), route.path

    def admitted(self, pair: Pair) -> bool:
        return self.manager.pairs.get(pair.node_id) == pair and pair.enabled and pair.routed and not pair.legacy

    def live(self, binding: Binding) -> bool:
        route = binding.route
        pair = self.manager.pairs.get(route.path[-1])
        if (pair is None or not self.admitted(pair) or binding.session.closed
                or self.failed.get(self.failure_key(binding), 0) > self.clock()):
            return False
        if binding.circuit is not None:
            return self.relay.live(binding.circuit)
        return self.manager.neighbors.get(pair.node_id) is route.first and route.first.pair == pair

    def direct(self, node: str) -> Binding | None:
        link = self.manager.neighbors.get(node)
        binding = Binding(Route((self.manager.local_id, node), link), link.session) if link else None
        return binding if binding and self.live(binding) else None

    def bindings(self, node: str) -> list[Binding]:
        values = [Binding(route, circuit.session, circuit) for route, circuit in self.relay.incoming(node)]
        values.extend((self.direct(node), self.active.get(node), self.trials.get(node)))
        return list({binding.key: binding for binding in values if binding and self.live(binding)}.values())

    def connection_for(self, node: str) -> Session | None:
        binding = self.active.get(node)
        return binding.session if binding and self.live(binding) else None

    def touch(self, node: str) -> None:
        self.used[node] = self.clock()

    def watch_statuses(self) -> None:
        now = self.clock()
        if now >= self.status_watch_until:
            self.watch_recoveries.clear()
        self.status_watch_until = now + STATUS_WATCH_TTL

    @property
    def watching_statuses(self) -> bool:
        return self.clock() < self.status_watch_until

    def remember_watched_failure(self, node: str) -> None:
        pair = self.manager.pairs.get(node)
        if self.watching_statuses and pair is not None and self.admitted(pair):
            self.watch_recoveries[node] = pair, self.clock()

    def cancel_keeper(self, node: str) -> None:
        task = self.keepers.get(node)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    def retire(self, node: str, binding: Binding) -> None:
        if self.active.get(node) is binding:
            self.active.pop(node)
        if self.trials.get(node) is binding:
            self.trials.pop(node)
            self.cancel_keeper(node)
        if binding.circuit and not binding.incoming and self.relay.circuits.get(binding.circuit.identity) is binding.circuit:
            if binding.session.pending:
                binding.circuit.role = 'draining'
                self.draining[binding.circuit.identity] = binding, self.clock() + DRAIN_TIMEOUT
            else:
                self.relay.drop(binding.circuit, 'CLOSED')

    def invalidate(self, node: str, session: Session | None, code: str = 'ROUTE_LOST') -> None:
        if session is None:
            return
        for binding in (self.active.get(node), self.trials.get(node)):
            if binding and binding.session is session:
                self.failed[self.failure_key(binding)] = self.clock() + COOLDOWN
                if not binding.incoming:
                    self.routing.invalidate(binding.route)
                if binding.circuit and not binding.incoming:
                    self.relay.drop(binding.circuit, 'ROUTE_LOST')
                if self.active.get(node) is binding:
                    self.active.pop(node)
                    self.remember_watched_failure(node)
                    self.reasons[node] = code.lower()
                else:
                    self.path_errors[node] = 'trial_' + code.lower()
                if self.trials.get(node) is binding:
                    self.trials.pop(node)
                    self.cancel_keeper(node)
                self.counts['failures_' + code.lower()] += 1

    def relay_capacity_full(self, queued: int = 0) -> bool:
        return (len(self.relay.circuits) + queued >= CIRCUITS or
                sum(circuit.path[0] == self.manager.local_id for circuit in self.relay.circuits.values()) + queued >= PER_ORIGIN)

    def make_space(self, node: str, *, business: bool) -> None:
        if not self.relay_capacity_full():
            return
        # A primary needs a slot even when background discovery initiated it.
        candidates = [(other, binding) for other, binding in self.trials.items()
                      if other != node and (business or self.connection_for(other) is not None)]
        if business:
            candidates += [(other, binding) for other, binding in self.active.items()
                           if other != node and other not in self.pending_targets
                           and self.clock() - self.used.get(other, 0) > 20]
        candidates.sort(key=lambda item: (self.active.get(item[0]) is item[1], item[0] in self.pending_targets,
                                         self.used.get(item[0], 0), item[0]))
        for other, binding in candidates:
            keeper = self.keepers.get(other)
            probe_only = (self.trials.get(other) is binding and keeper is not None
                          and not keeper.done() and not keeper.cancelling()
                          and bool(binding.session.pending) and all(
                              isinstance(item, tuple) and item and item[0] in {'peer.ping', 'catalog.sync', CATALOG_HEALTH_METHOD}
                              for item in binding.session.pending.values()))
            if binding.circuit and not binding.incoming and (not binding.session.pending or probe_only):
                if probe_only:
                    # The owned standby read can be cancelled without dropping an operation or its receipt.
                    self.cancel_keeper(other)
                    self.trials.pop(other)
                    self.relay.drop(binding.circuit, 'CLOSED')
                else:
                    self.retire(other, binding)
                self.counts['capacity_reclaimed'] += 1
                if not self.relay_capacity_full():
                    return
        raise PeerError('BUSY', 'Mesh channel budget is occupied by active requests')

    async def promote(self, pair: Pair, binding: Binding, reason: str, *, check: Callable[[], None] | None = None) -> None:
        node = pair.node_id
        previous = self.active.get(node)
        if previous and previous.session is binding.session and self.live(previous):
            return
        # A background directory read must yield the per-target lock before
        # foreground receipt reconciliation and publication start.
        self.cancel_keeper(node)

        def commit() -> None:
            if self.active.get(node) is not previous or not self.admitted(pair) or not self.live(binding):
                raise PeerError('ROUTE_LOST', 'The prepared Mesh session was replaced')
            if check is not None:
                check()
            self.relay.promote(node, None if binding.incoming else binding.circuit)
            self.active[node] = binding
            self.watch_recoveries.pop(node, None)
            self.idle_paths.pop(node, None)
            if self.trials.get(node) is binding:
                self.trials.pop(node)
                self.cancel_keeper(node)
            if binding.circuit and not binding.incoming:
                self.routing.cache[node] = binding.route
            self.selectors.setdefault(node, Selector()).choose(binding.candidate(), self.clock(), reason)
            self.reasons[node] = reason
            self.path_errors.pop(node, None)
            self.deferred_switches.pop(node, None)
            self.last_served[node] = self.clock()
            if previous:
                self.retire(node, previous)
            self.counts['promotions'] += 1
            if binding.incoming:
                self.counts['incoming_promotions'] += 1

        await self.prepare(pair, binding, commit, check)
        if self.active.get(node) is not binding:
            raise PeerError('ROUTE_LOST', 'The prepared Mesh session was not published')

    async def switch_route(self, pair: Pair, primary: Binding, selected: Binding, reason: str) -> None:
        node = pair.node_id
        if self.active.get(node) is not primary:
            return

        self.deferred_switches.pop(node, None)
        deferred = False

        def check_cost() -> None:
            nonlocal deferred
            now = self.clock()
            primary_cost = primary.candidate().measured_cost(now)
            alternatives = [(cost, len(binding.route.path), binding.key) for binding in self.bindings(node)
                            if binding is not primary and (cost := binding.candidate().measured_cost(now)) is not None]
            best = min(alternatives, default=None)
            if self.active.get(node) is not primary or not self.live(primary):
                cause = None
            elif not self.live(selected):
                cause = 'candidate_unavailable'
            elif primary_cost is None or selected.candidate().measured_cost(now) is None or best is None:
                cause = 'samples_expired'
            elif primary_cost - best[0] < required_saving_ms(primary_cost):
                cause = 'saving_lost'
            elif best[2] != selected.key:
                cause = 'better_candidate'
            else:
                return
            if cause is not None:
                self.deferred_switches[node] = primary, cause, now
            deferred = True
            raise SwitchDeferred

        try:
            async with asyncio.timeout(15):
                await self.promote(pair, selected, reason, check=check_cost if reason == 'lower_cost' else None)
        except (SwitchDeferred, PeerError, TimeoutError) as error:
            if deferred or isinstance(error, SwitchDeferred):
                # Reconfirming the original directory can consume the rest of the switch deadline.
                self.counts['switches_deferred'] += 1
            elif self.active.get(node) is primary:
                code = error.code.lower() if isinstance(error, PeerError) else 'timeout'
                self.path_errors[node] = 'prepare_' + code
                self.failed[self.failure_key(selected)] = self.clock() + COOLDOWN
                if selected.circuit:
                    self.retire(node, selected)

    async def connect(self, pair: Pair, *, background: bool = False) -> Session:
        if not self.admitted(pair):
            raise PeerError('OFFLINE', 'Mesh member is unavailable')
        if not background:
            self.touch(pair.node_id)
        connection = self.connection_for(pair.node_id)
        if connection is not None:
            return connection
        return await asyncio.shield(self.start_attempt(pair, background=background))

    def start_attempt(self, pair: Pair, *, background: bool) -> asyncio.Task:
        task = self.attempts.get(pair.node_id)
        if task is None:
            if len(self.attempts) >= 4:
                raise PeerError('BUSY', 'Too many Mesh targets are being connected')
            switching = self.switching.get(pair.node_id)
            if switching is not None:
                switching.cancel()
            task = asyncio.create_task(self.establish(pair, background=background))
            self.attempts[pair.node_id] = task
            task.add_done_callback(lambda done: self.finished(self.attempts, pair.node_id, done))
        return task

    @staticmethod
    def finished(tasks: dict, node: str, task: asyncio.Task) -> None:
        if tasks.get(node) is task:
            tasks.pop(node)
        if not task.cancelled():
            task.exception()

    async def recovery_bindings(self, node: str) -> AsyncIterator[Binding]:
        now = self.clock()
        bindings = self.bindings(node)
        opening = self.opening.get(node)
        for binding in sorted(bindings, key=lambda item: item.candidate().recovery_rank(now)):
            yield binding
        if opening is not None:
            # A running trial already has a bounded ready/auth deadline. Wait
            # within the recovery deadline instead of dialing the same ticket.
            await asyncio.shield(opening)
            trial = self.trials.get(node)
            if trial is not None and trial not in bindings:
                yield trial

    async def establish(self, pair: Pair, *, background: bool) -> Session:
        node = pair.node_id
        reason = 'resumed' if self.reasons.get(node) == 'idle' else 'failure' if node in self.selectors else 'initial'
        visited = set()
        last_error = None
        phase = failure_phase = 'connect'
        deadline = asyncio.get_running_loop().time() + 15
        try:
            async with asyncio.timeout_at(deadline):
                async for binding in self.recovery_bindings(node):
                    if not self.live(binding):
                        continue
                    phase = 'prepare'
                    try:
                        await self.promote(pair, binding, reason)
                        return binding.session
                    except PeerError as error:
                        if error.code not in PATH_ERRORS:
                            raise
                        self.invalidate(node, binding.session, error.code)
                        self.failed[self.failure_key(binding)] = self.clock() + COOLDOWN
                        if binding.circuit and not binding.incoming:
                            self.relay.drop(binding.circuit, 'CLOSED')
                        failure_phase, last_error = phase, error
                for stage in range(3):
                    if stage:
                        phase = 'connect'
                        try:
                            await self.routing.find(node, refresh=True)
                            discovery = self.routing.attempts.get(node)
                            if stage == 2 and discovery is not None:
                                await asyncio.shield(discovery)
                        except PeerError as error:
                            if last_error is None:
                                failure_phase, last_error = phase, error
                    routes = [route for route in self.routing.routes(node)
                              if self.route_key(route) not in visited and self.failed.get(self.route_key(route), 0) <= self.clock()]
                    routes.sort(key=lambda route: (len(route.path), self.trial_order(route)))
                    for route in routes:
                        visited.add(self.route_key(route))
                        binding = None
                        phase = 'open'
                        try:
                            if route.ticket is None:
                                binding = self.direct(node)
                                if binding is None:
                                    continue
                            else:
                                self.make_space(node, business=not background)
                                # Extra candidates must not shorten a healthy path's
                                # existing ready/TLS budget. All attempts still share
                                # the same fifteen-second outer deadline.
                                budget = min(10, max(.1, deadline - asyncio.get_running_loop().time()))
                                async with asyncio.timeout(budget):
                                    circuit = await self.relay.open_route(pair, route, role='opening')
                                binding = Binding(route, circuit.session, circuit)
                            phase = 'prepare'
                            await self.promote(pair, binding, reason)
                            return binding.session
                        except TimeoutError:
                            failure_phase = phase
                            last_error = PeerError('TIMEOUT', 'Timed out establishing a candidate Mesh session')
                        except PeerError as error:
                            if error.code not in PATH_ERRORS:
                                if binding and binding.circuit:
                                    self.relay.drop(binding.circuit, 'CLOSED')
                                raise
                            failure_phase, last_error = phase, error
                        except BaseException:
                            if binding and binding.circuit:
                                self.relay.drop(binding.circuit, 'CLOSED')
                            raise
                        if binding and binding.circuit:
                            self.relay.drop(binding.circuit, 'CLOSED')
                        if route.ticket is not None:
                            self.trialled_paths[self.route_key(route)] = self.clock()
                        if last_error and last_error.code == 'BUSY':
                            self.counts['capacity_failures'] += 1
                        else:
                            self.failed[self.route_key(route)] = self.clock() + COOLDOWN
                            self.routing.invalidate(route)
                phase = failure_phase
                raise last_error or PeerError('NO_ROUTE', 'No candidate Mesh path is available')
        except TimeoutError as error:
            self.path_errors[node] = phase + '_timeout'
            raise PeerError('TIMEOUT', 'Mesh connection reached its total deadline') from error
        except PeerError as error:
            self.path_errors[node] = phase + '_' + error.code.lower()
            raise

    async def open_trial(self, pair: Pair, route: Route) -> None:
        node = pair.node_id
        if self.relay_capacity_full():
            self.path_errors[node] = 'trial_busy'
            return
        self.last_trial[node] = self.trialled_paths[self.route_key(route)] = self.clock()
        binding = None
        try:
            circuit = await self.relay.open_route(pair, route, role='trial')
            binding = Binding(route, circuit.session, circuit)
            recovering = (node in self.attempts or node in self.pending_targets
                          or self.clock() - self.used.get(node, float('-inf')) <= IDLE
                          or (self.watching_statuses and node in self.watch_recoveries))
            if (not self.admitted(pair) or not self.live(binding)
                    or not (node in self.active or recovering)):
                self.relay.drop(circuit, 'CLOSED')
                return
            self.trials[node] = binding
            if self.path_errors.get(node, '').startswith('trial_'):
                self.path_errors.pop(node, None)
            self.counts['trials_opened'] += 1
        except PeerError as error:
            self.failed[self.route_key(route)] = self.clock() + COOLDOWN
            if error.code != 'BUSY':
                self.routing.invalidate(route)
            self.path_errors[node] = 'trial_' + error.code.lower()
        except BaseException:
            if binding and binding.circuit:
                self.relay.drop(binding.circuit, 'CLOSED')
            raise

    async def keep_standby(self, node: str, binding: Binding) -> None:
        def current():
            return (self.live(binding) and self.connection_for(node) is not binding.session
                    and any(item.session is binding.session for item in self.bindings(node)))
        if not current():
            return
        try:
            async with asyncio.timeout(STANDBY_PREPARE_TIMEOUT):
                if self.warm:
                    await self.warm(self.manager.pairs[node], binding)
                elif await binding.session.call('peer.ping', {}) != {'status': 'ok'}:
                    raise PeerError('PROTOCOL', 'Unexpected standby diagnostic response')
            if current():
                self.counts['standby_keepalives'] += 1
        except (PeerError, TimeoutError) as error:
            self.counts['standby_keepalive_errors'] += 1
            code = error.code if isinstance(error, PeerError) else 'TIMEOUT'
            if (self.trials.get(node) is binding
                    and (not self.live(binding) or code not in {'TIMEOUT', 'BUSY'})):
                self.retire(node, binding)

    def trial_priority(self, node: str, demand: set[str]) -> tuple[bool, bool]:
        return node not in self.pending_targets, node not in demand

    def trial_age_order(self, node: str) -> tuple[float, str]:
        return self.last_trial.get(node, float('-inf')), node

    def can_reassign_trial(self, node: str, other: str, binding: Binding, demand: set[str], now: float,
                           *, shorter: bool = False) -> bool:
        if other in self.switching or binding.session.pending or self.connection_for(other) is None:
            return False
        priority = self.trial_priority(node, demand)
        incumbent = self.trial_priority(other, demand)
        if priority != incumbent:
            return priority < incumbent
        if (not shorter and (now - binding.session.created_at < STANDBY_ROTATION
                or self.trial_age_order(node) >= self.trial_age_order(other))):
            return False
        primary = self.active[other].candidate().measured_cost(now)
        standby = binding.candidate().measured_cost(now)
        return primary is not None and standby is not None and primary - standby < required_saving_ms(primary)

    async def step(self) -> None:
        now = self.clock()
        previously_waiting = self.waiting_for_trial
        self.waiting_for_trial = {}
        self.failed = {key: until for key, until in self.failed.items() if until > now}
        self.used = {node: used for node, used in self.used.items() if now - used <= IDLE and node in self.manager.pairs}
        self.trialled_paths = {key: when for key, when in self.trialled_paths.items()
                              if now - when <= 4 * STANDBY_ROTATION and key[0][-1] in self.manager.pairs}
        self.idle_paths = {node: sample for node, sample in self.idle_paths.items()
                           if now - sample.retired_at < IDLE_PATH_TTL and self.admitted(sample.pair)}
        demand = self.used.keys() | self.pending_targets
        watched = demand.copy()
        watching = self.watching_statuses
        if watching:
            watched.update(self.active)
            watched.update(self.trials)
            watched.update(self.switching)
            self.watch_recoveries = {node: entry for node, entry in self.watch_recoveries.items() if self.admitted(entry[0])}
            watched.update(self.watch_recoveries)
        else:
            self.watch_recoveries.clear()
        for identity, (binding, deadline) in list(self.draining.items()):
            if not binding.session.pending or now >= deadline or not self.relay.live(binding.circuit):
                self.relay.drop(binding.circuit, 'CLOSED')
                self.draining.pop(identity)
        for node, binding in list(self.active.items()):
            if not self.live(binding):
                self.remember_watched_failure(node)
                self.retire(node, binding)
            elif (not watching and node not in self.pending_targets
                  and now - self.used.get(node, binding.created_at) >= IDLE):
                if binding.circuit is not None:
                    self.idle_paths[node] = IdlePath(self.manager.pairs[node], binding.route.path, now)
                self.retire(node, binding)
                if node in self.selectors:
                    self.selectors[node].choose(None, now, 'idle')
                self.reasons[node] = 'idle'
        watched.update(self.active)
        for node, binding in list(self.trials.items()):
            age = now - binding.created_at
            # Heartbeats cannot start until tunnel TLS and HELLO have finished.
            # Only unqualified trials use the absolute setup/sample lifetime.
            # A qualified standby leases one of the existing slots while its
            # target is demanded; it must survive a primary's failure detector.
            qualified = binding.session.latency.samples >= MIN_SAMPLES
            sample_timeout = (now - binding.session.created_at >= SAMPLE_TIMEOUT
                              and binding.session.latency.samples < MIN_SAMPLES)
            if sample_timeout:
                self.failed[self.route_key(binding.route)] = now + COOLDOWN
                self.counts['trial_sample_timeouts'] += 1
            unused = node not in watched
            if not self.live(binding) or (not qualified and age >= TRIAL_AGE) or sample_timeout or unused:
                self.retire(node, binding)
                self.refreshed[node] = now
        options = {node: self.routing.routes(node) for node in watched if node in self.active}

        def shorter_option(route: Route, active: Binding) -> bool:
            key = self.route_key(route)
            return (route.ticket is not None and len(route.path) < len(active.route.path) and self.failed.get(key, 0) <= now
                    and now - self.trialled_paths.get(key, float('-inf')) >= STANDBY_ROTATION)

        shorter = {node for node, routes in options.items()
                   if any(shorter_option(route, self.active[node]) for route in routes)}

        def scheduling_order(node: str):
            priority = self.trial_priority(node, demand)
            if node not in self.active:
                return (*priority, 0, -self.used.get(node, 0), 0, node)
            return (*priority, 1, node not in shorter, previously_waiting.get(node, now), *self.trial_age_order(node))

        queued_trials = 0
        for node in sorted(watched, key=scheduling_order):
            pair = self.manager.pairs.get(node)
            active = self.active.get(node)
            if pair is None or not self.admitted(pair) or node in self.attempts:
                continue
            if active is None:
                recovery = self.watch_recoveries.get(node)
                if len(self.attempts) < 4 and (recovery is None or node in demand or now >= recovery[1]):
                    self.start_attempt(pair, background=True)
                    if recovery is not None:
                        self.watch_recoveries[node] = pair, now + COOLDOWN
                continue
            if node in self.switching:
                continue
            bindings = self.bindings(node)
            stable = False
            if len(self.switching) < MAX_TRIALS:
                selector = self.selectors.setdefault(node, Selector())
                checkpoint = selector.active, selector.selected_at, selector.switches
                decision = selector.select([binding.candidate() for binding in bindings], now)
                if decision.changed and decision.candidate:
                    selected = next(binding for binding in bindings if binding.key == decision.candidate.key)
                    # Publish the selection only when the new session is ready.
                    selector.active, selector.selected_at, selector.switches = checkpoint
                    task = asyncio.create_task(self.switch_route(pair, active, selected, decision.reason))
                    self.switching[node] = task
                    task.add_done_callback(lambda done, target=node: self.finished(self.switching, target, done))
                    continue
                stable = decision.reason == 'stable'
            # Use the same two global background slots for physical direct
            # alternatives and relay standbys; these reads never renew demand.
            alternatives = [binding for binding in bindings if binding.session is not active.session
                            and binding.session.latency.samples >= MIN_SAMPLES
                            and binding.session.latency.fresh(now)]
            alternatives.sort(key=lambda binding: (binding.candidate().cost(now), binding.key))
            if alternatives and node not in self.keepers and len(self.keepers) < MAX_TRIALS:
                standby = alternatives[0]
                last_key, attempted = self.standby_attempted.get(node, (None, -COOLDOWN))
                needs_directory = self.prepared is not None and not self.prepared(node, standby.session)
                refreshed_at = (attempted if self.warm and last_key == standby.key
                                else standby.session.last_business)
                if ((last_key != standby.key or now - attempted >= COOLDOWN)
                        and (needs_directory or now - refreshed_at >= STANDBY_PING_INTERVAL)):
                    self.standby_attempted[node] = standby.key, now
                    task = asyncio.create_task(self.keep_standby(node, standby))
                    self.keepers[node] = task
                    task.add_done_callback(lambda done, target=node: self.finished(self.keepers, target, done))
            if now - self.refreshed.get(node, -REFRESH) >= REFRESH:
                try:
                    self.routing.refresh(node)
                except PeerError as error:
                    if error.code != 'BUSY':
                        self.refreshed[node] = now
                else:
                    self.refreshed[node] = now
            if node in self.opening:
                continue
            existing = {binding.route.path for binding in bindings}
            routes = [route for route in options[node] if route.ticket is not None
                      and route.path not in existing and self.failed.get(self.route_key(route), 0) <= now]
            if not routes:
                continue
            routes.sort(key=lambda route: (not shorter_option(route, active), self.trial_order(route)))
            candidate = routes[0]
            prefer_shorter = shorter_option(candidate, active)
            trial = self.trials.get(node)
            if trial is not None:
                # Keep a verified standby during comparison or failure. Once
                # the primary is stable, give older candidates a sampling turn.
                if (not stable or trial.session.pending
                        or trial.session.latency.samples < MIN_SAMPLES or not trial.session.latency.fresh(now)
                        or now - trial.session.created_at < STANDBY_ROTATION
                        or (not prefer_shorter and self.trial_order(candidate)[0]
                            >= self.trialled_paths.get(self.route_key(trial.route), trial.created_at))):
                    continue
                self.retire(node, trial)
            # Tasks queued during this pass have not registered their circuits yet.
            if len(self.trials) + len(self.opening) >= MAX_TRIALS or self.relay_capacity_full(queued_trials):
                victims = [(other, binding) for other, binding in self.trials.items()
                           if self.can_reassign_trial(node, other, binding, demand, now, shorter=prefer_shorter)]
                if victims:
                    other, victim = min(victims, key=lambda item: (item[0] in self.pending_targets,
                                        item[0] in demand, *self.trial_age_order(item[0])))
                    self.retire(other, victim)
                    self.counts['standby_reassigned'] += 1
                if len(self.trials) + len(self.opening) >= MAX_TRIALS or self.relay_capacity_full(queued_trials):
                    self.waiting_for_trial[node] = previously_waiting.get(node, now)
                    continue
            task = asyncio.create_task(self.open_trial(pair, candidate))
            self.opening[node] = task
            queued_trials += 1
            task.add_done_callback(lambda done, target=node: self.finished(self.opening, target, done))
        for mapping in (self.selectors, self.last_served, self.last_trial, self.refreshed, self.reasons, self.path_errors):
            for node in mapping.keys() - self.manager.pairs.keys():
                mapping.pop(node)
        for node, (primary, _, recorded_at) in list(self.deferred_switches.items()):
            if node not in self.manager.pairs or self.active.get(node) is not primary or now - recorded_at >= REFRESH:
                self.deferred_switches.pop(node)
        for node in self.standby_attempted.keys() - watched:
            self.standby_attempted.pop(node)
            self.cancel_keeper(node)

    async def running(self) -> None:
        try:
            while True:
                try:
                    await self.step()
                except PeerError as error:
                    logger.debug('Adaptive Mesh maintenance: %s', error)
                await asyncio.sleep(.5)
        finally:
            tasks = [*self.attempts.values(), *self.switching.values(), *self.opening.values(), *self.keepers.values()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for binding in [*self.active.values(), *self.trials.values(), *(item[0] for item in self.draining.values())]:
                if binding.circuit:
                    self.relay.drop(binding.circuit, 'CLOSED')
            self.active.clear()
            self.trials.clear()
            self.waiting_for_trial.clear()
            self.draining.clear()
            self.switching.clear()
            self.deferred_switches.clear()
            self.keepers.clear()
            self.standby_attempted.clear()
            self.idle_paths.clear()
            self.watch_recoveries.clear()

    def status(self, node: str) -> dict:
        active = self.active.get(node)
        bindings = self.bindings(node)
        if active not in bindings:
            active = None
        selector = self.selectors.get(node)
        now = self.clock()
        deferred = None
        if (note := self.deferred_switches.get(node)) and note[0] is active and now - note[2] < REFRESH:
            deferred = {'reason': note[1], 'remaining_seconds': REFRESH - (now - note[2])}
        idle_path = self.idle_paths.get(node)
        recent = None
        if active is None and idle_path is not None and self.admitted(idle_path.pair):
            age = now - idle_path.retired_at
            if age < IDLE_PATH_TTL:
                recent = {'path': list(idle_path.path), 'age_seconds': age, 'remaining_seconds': IDLE_PATH_TTL - age}
        comparison = None
        best_alternative = None
        if active is not None and (active_cost := active.candidate().measured_cost(now)) is not None:
            alternatives = [(cost, binding) for binding in bindings if binding is not active
                            and (cost := binding.candidate().measured_cost(now)) is not None]
            if alternatives:
                cost, best = min(alternatives, key=lambda item: (item[0], len(item[1].route.path), item[1].key))
                required = required_saving_ms(active_cost)
                best_alternative = {'path': list(best.route.path), 'saving_ms': round(active_cost - cost, 3),
                                    'required_saving_ms': round(required, 3),
                                    'meets_threshold': active_cost - cost >= required,
                                    'remaining_seconds': min(active.session.latency.remaining(now), best.session.latency.remaining(now))}
                if (best_alternative['meets_threshold'] and selector is not None and selector.active == active.key
                        and selector.challenger == best.key and selector.selected_at is not None):
                    comparison = {'path': list(best.route.path), 'completed': selector.comparisons,
                                  'required': REQUIRED_COMPARISONS,
                                  'remaining_seconds': best_alternative['remaining_seconds'],
                                  'dwell_remaining_seconds': round(max(0, MIN_DWELL - (now - selector.selected_at)), 1)}
        sessions = []
        for binding in bindings:
            readiness = {}
            if self.prepared_remaining is not None:
                remaining = self.prepared_remaining(node, binding.session)
                readiness = {'directory_prepared': remaining > 0, 'directory_prepared_remaining_seconds': remaining}
            else:
                readiness['directory_prepared'] = bool(self.prepared and self.prepared(node, binding.session))
            sessions.append({**binding.route.public_data(), 'connection_generation': binding.key[1],
                             'role': 'active' if binding is active else 'inbound' if binding.incoming else 'trial' if binding.circuit else 'direct',
                             **readiness, 'circuit_age_seconds': round(max(0, now - binding.created_at), 3),
                             'cost_ms': binding.candidate().measured_cost(now), **binding.session.link_metrics()})
        return {'selected_path': list(active.route.path) if active else None,
                'last_idle_path': recent,
                'switch_reason': self.reasons.get(node), 'switches': selector.switches if selector else 0,
                'comparison': comparison, 'opening_trial': node in self.opening,
                'waiting_for_trial': active is not None and node in self.waiting_for_trial,
                'best_alternative': best_alternative, 'preparing_switch': node in self.switching and deferred is None,
                'deferred_switch': deferred,
                'last_path_error': self.path_errors.get(node),
                'backup_sessions': sum(binding.session is not (active.session if active else None) for binding in bindings),
                'standby_keepalive_tasks': len(self.keepers),
                'candidate_sessions': sessions, 'incoming_session_selected': bool(active and active.incoming)}
