"""Bounded automatic neighbor trials; fixed links retain their configured role."""
from collections import Counter
from dataclasses import dataclass
import time
from typing import TYPE_CHECKING

from .path_selection import MIN_SAMPLES, MIN_SAVING_MS, MIN_SAVING_RATIO

if TYPE_CHECKING:
    from .manager import Neighbor, PeerManager
    from .pairing import Pair


LIMIT = 8
QUALIFY_TIMEOUT = 20
RETRY = 30
TRIAL_INTERVAL = 10
REPLACEMENT_DWELL = 20


@dataclass
class Trial:
    node: str
    started: float
    link: 'Neighbor | None' = None


class Neighbors:
    def __init__(self, manager: 'PeerManager', *, minimum=2, target=7, protected=lambda: {},
                 coverage=lambda: {}, demand=lambda: set(), clock=time.monotonic):
        if (type(minimum) is not int or type(target) is not int or not 1 <= minimum <= target < LIMIT):
            raise ValueError('Neighbor settings require 1 <= minimum <= target <= 7')
        self.manager, self.minimum, self.target = manager, minimum, target
        self.protected, self.coverage, self.demand, self.clock = protected, coverage, demand, clock
        self.trial: Trial | None = None
        self.inbound: tuple[str, object] | None = None
        self.until: dict[str, float] = {}
        self.held: dict[str, float] = {}
        self.tried: dict[str, float] = {}
        self.failures: Counter[str] = Counter()
        self.counts: Counter[str] = Counter()
        self.next_trial = 0.0
        self.last_replacement = float('-inf')
        self.reason = 'initial'

    @staticmethod
    def fixed(pair: 'Pair') -> bool:
        return pair.legacy or pair.source_ip is not None

    def protections(self) -> dict[str, set[str]]:
        result = {node: set(reasons) for node, reasons in self.protected().items()}
        for node, link in self.manager.neighbors.items():
            if self.fixed(link.pair):
                result.setdefault(node, set()).add('fixed')
            if link.session.pending or link.session.handling or link.session.write_bytes:
                result.setdefault(node, set()).add('in_flight_rpc')
        return result

    def current(self, link: 'Neighbor') -> bool:
        return self.manager.neighbors.get(link.pair.node_id) is link and not link.session.closed

    def victims(self, *, exclude: str | None = None) -> list['Neighbor']:
        protected = self.protections()
        return [link for node, link in self.manager.neighbors.items()
                if node != exclude and not self.fixed(link.pair) and not protected.get(node) and self.current(link)]

    def can_trial(self) -> bool:
        size = len(self.manager.neighbors)
        if size >= LIMIT:
            self.reason = 'physical_limit'
            return False
        if size < self.target:
            return True
        if self.clock() < self.next_trial or self.clock() - self.last_replacement < REPLACEMENT_DWELL:
            self.reason = 'replacement_dwell'
            return False
        if any(self.fixed(pair) and node not in self.manager.neighbors for node, pair in self.manager.admitted.items()):
            self.reason = 'fixed_priority'
            return False
        if not self.victims():
            self.reason = 'protected_neighbors'
            return False
        return True

    def candidates(self) -> list[str]:
        wanted = self.demand()
        return sorted((node for node, pair in self.manager.admitted.items()
                       if not self.fixed(pair) and node not in self.manager.neighbors
                       and self.manager.endpoints.get(node)
                       and max(self.until.get(node, 0), self.held.get(node, 0)) <= self.clock()),
                      key=lambda node: (node not in wanted, self.tried.get(node, float('-inf')), node))

    def reserve(self, node: str) -> None:
        self.trial = Trial(node, self.clock())
        self.tried[node] = self.clock()
        self.reason = 'filling_minimum' if len(self.manager.neighbors) < self.minimum else 'trial'
        self.counts['trials'] += 1

    def allow_dial(self, pair: 'Pair') -> bool:
        if self.fixed(pair):
            return len(self.manager.neighbors) < LIMIT or bool(self.victims())
        if (self.manager.admitted.get(pair.node_id) != pair
                or max(self.until.get(pair.node_id, 0), self.held.get(pair.node_id, 0)) > self.clock()):
            return False
        if self.inbound is not None:
            return False
        if self.trial is not None:
            return self.trial.node == pair.node_id and self.trial.link is None
        if not self.can_trial():
            return False
        candidates = self.candidates()
        if not candidates or candidates[0] != pair.node_id:
            return False
        self.reserve(pair.node_id)
        return True

    def incoming(self, address: str):
        """Reserve before TLS when only dynamic admission could match the source."""
        if any(pair.source_ip == address for pair in self.manager.admitted.values() if self.fixed(pair)):
            return lambda: None
        if any(link.address == address for link in self.manager.neighbors.values()):
            return lambda: None  # A duplicate replaces the same logical neighbor slot.
        if self.inbound is not None:
            return None
        if self.trial is not None:
            endpoints = self.manager.endpoints.get(self.trial.node, ())
            if self.trial.link is not None or not any(ip == address for ip, _ in endpoints):
                return None
        elif not self.can_trial():
            return None
        token = object()
        self.inbound = address, token

        def release():
            if self.inbound == (address, token):
                self.inbound = None

        return release

    def accept(self, pair: 'Pair') -> bool:
        if self.fixed(pair):
            if len(self.manager.neighbors) < LIMIT:
                return True
            candidates = self.victims()
            if not candidates:
                self.reason = 'fixed_waiting_for_protected_slot'
                return False
            trial = self.trial.link if self.trial else None
            victim = trial if trial in candidates else max(candidates, key=self.quality)
            return self.retire(victim, 'fixed_priority')
        # Dial retry throttles our worker; peer recovery must not share that ban.
        if self.held.get(pair.node_id, 0) > self.clock():
            return False
        if self.trial is not None:
            return self.trial.node == pair.node_id and len(self.manager.neighbors) < LIMIT
        if not self.can_trial():
            return False
        self.reserve(pair.node_id)
        return True

    def bound(self, link: 'Neighbor') -> None:
        if self.trial and self.trial.node == link.pair.node_id:
            self.trial.link = link
            self.trial.started = link.session.created_at
        self.counts['peak_neighbors'] = max(self.counts['peak_neighbors'], len(self.manager.neighbors))

    def failed(self, node: str) -> None:
        if node in self.manager.neighbors:
            return
        if self.trial and self.trial.node == node:
            self.trial = None
        self.failures[node] += 1
        self.until[node] = self.clock() + min(RETRY, 2 ** min(self.failures[node] - 1, 5))
        self.reason = 'trial_failed'
        self.counts['failed_trials'] += 1

    def reset_dial_backoff(self, node: str) -> None:
        self.until.pop(node, None)
        self.failures.pop(node, None)

    def lost(self, link: 'Neighbor') -> None:
        if self.fixed(link.pair):
            return
        current = self.manager.neighbors.get(link.pair.node_id)
        if current is not None and current is not link:
            return
        if self.trial and self.trial.link is link:
            self.trial = None
        self.failed(link.pair.node_id)

    def quality(self, link: 'Neighbor') -> tuple:
        metrics = link.session.link_metrics()
        cost = link.session.latency.cost(1, self.clock())
        node = link.pair.node_id
        return (-len(self.coverage().get(node, set())),
                metrics['heartbeat_timeout_rate'] if metrics['heartbeat_timeout_rate'] is not None else 1,
                max(0, self.manager.established.get(node, 1) - 1),
                cost if cost is not None else float('inf'), node)

    def qualified(self, link: 'Neighbor') -> bool:
        heartbeats = list(link.session.heartbeat_samples)[-MIN_SAMPLES:]
        return (link.session.latency.samples >= MIN_SAMPLES and len(heartbeats) == MIN_SAMPLES
                and not any(heartbeats) and link.session.latency.fresh(self.clock()))

    def better(self, candidate: 'Neighbor', previous: 'Neighbor') -> bool:
        new, old = self.quality(candidate), self.quality(previous)
        if new[:3] != old[:3]:
            return new[:3] < old[:3]
        saving = old[3] - new[3]
        return saving >= MIN_SAVING_MS and (old[3] == float('inf') or saving >= old[3] * MIN_SAVING_RATIO)

    def retire(self, link: 'Neighbor', reason: str) -> bool:
        node = link.pair.node_id
        if not self.current(link) or self.protections().get(node):
            return False
        if not self.manager.close_neighbor(link, reason):
            return False
        self.until[node] = self.clock() + RETRY
        self.held[node] = self.clock() + RETRY
        if self.trial and self.trial.link is link:
            self.trial = None
        self.reason = reason
        self.counts['retired_' + reason] += 1
        return True

    def step(self) -> None:
        now = self.clock()
        for link in list(self.manager.neighbors.values()):
            if link.session.closed and self.manager.close_neighbor(link, 'offline'):
                self.lost(link)
        for mapping in (self.until, self.held, self.tried, self.failures):
            for node in mapping.keys() - self.manager.pairs.keys():
                mapping.pop(node)
        trial = self.trial
        if trial is not None:
            if trial.node not in self.manager.admitted:
                self.trial = None
            elif trial.link is not None:
                link = trial.link
                if not self.current(link):
                    if self.manager.neighbors.get(trial.node) is link and link.session.closed:
                        self.manager.close_neighbor(link, 'offline')
                    self.lost(link)
                else:
                    qualified = self.qualified(link)
                    if qualified and len(self.manager.neighbors) <= self.target:
                        self.trial = None
                        self.reason = 'minimum_ready' if len(self.manager.neighbors) >= self.minimum else 'filling_minimum'
                        self.counts['qualified'] += 1
                    elif qualified:
                        candidates = self.victims(exclude=trial.node)
                        victim = max(candidates, key=self.quality) if candidates else None
                        if (victim is not None and self.better(link, victim)
                                and now - self.last_replacement >= REPLACEMENT_DWELL):
                            if self.retire(victim, 'better_neighbor'):
                                self.trial = None
                                self.last_replacement = now
                                self.next_trial = now + TRIAL_INTERVAL
                                self.counts['replacements'] += 1
                        elif not self.protections().get(trial.node):
                            self.retire(link, 'no_improvement' if victim else 'protected_neighbors')
                            self.next_trial = now + TRIAL_INTERVAL
                        else:
                            self.reason = 'trial_protected_waiting'
                    elif now - trial.started >= QUALIFY_TIMEOUT:
                        if self.retire(link, 'qualification_timeout'):
                            self.counts['failed_trials'] += 1
                        else:
                            self.reason = 'trial_protected_waiting'
        if self.trial is None and len(self.manager.neighbors) > self.target:
            candidates = self.victims()
            if candidates:
                self.retire(max(candidates, key=self.quality), 'steady_target')
            else:
                self.reason = 'protected_neighbors'

    def status_for(self, node: str) -> dict:
        link = self.manager.neighbors.get(node)
        pair = self.manager.pairs[node]
        trial = self.trial is not None and self.trial.node == node
        return {'role': 'fixed' if self.fixed(pair) else 'trial' if trial else 'automatic' if link else 'candidate',
                'connected': link is not None, 'session_id': link.generation if link else None,
                'heartbeat_samples': link.session.latency.samples if link else 0,
                'protected_by': sorted(self.protections().get(node, set())),
                'retry_seconds': round(max(0, max(self.until.get(node, 0), self.held.get(node, 0)) - self.clock()), 3),
                'qualified': bool(link and self.qualified(link))}

    def status(self) -> dict:
        size = len(self.manager.neighbors)
        return {'minimum': self.minimum, 'target': self.target, 'limit': LIMIT, 'connected': size,
                'minimum_met': size >= self.minimum, 'trial_node_id': self.trial.node if self.trial else None,
                'trial_bound': bool(self.trial and self.trial.link), 'inbound_trial_pending': self.inbound is not None,
                'automatic_trials': int(self.trial is not None or self.inbound is not None),
                'handshakes': self.manager.handshakes, 'peak_handshakes': self.manager.peak_handshakes,
                'reason': self.reason,
                'eligible_candidates': len(self.candidates()), **self.counts}
