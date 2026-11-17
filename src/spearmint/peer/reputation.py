"""Local request observations and quotas for authenticated Mesh identities."""

from collections import deque
from collections.abc import Set
from dataclasses import dataclass, field
import logging
import math
import time

from .protocol import IN_FLIGHT, PeerError


logger = logging.getLogger(__name__)
WINDOW = 60
RESTRICTION = 120
INVALID_THRESHOLD = 3
MAX_INVALID_SAMPLES = 32
OPTIONAL_SLOTS = IN_FLIGHT - 2
PEER_OPTIONAL_SLOTS = 2
GROUPS = {
    'service.logs': 'logs',
    'security.evidence.list': 'evidence',
    'security.evidence.part': 'evidence',
    'grove.seed.catalog': 'seed',
    'grove.seed.catalog.v2': 'seed',
    'grove.seed.catalog.v3': 'seed',
    'grove.deployment.status': 'deployment',
    'grove.deployment.status.v2': 'deployment',
    'grove.deployment.status.v3': 'deployment',
    'grove.deployment.status.v5': 'deployment',
}
# Requests per window in normal and restricted operation.
LIMITS = {'logs': (24, 8), 'evidence': (12, 4), 'seed': (12, 4), 'deployment': (12, 4)}


@dataclass
class Observation:
    invalid: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_INVALID_SAMPLES))
    requests: dict[str, deque[float]] = field(default_factory=dict)
    restricted_until: float = 0
    last_invalid_method: str | None = None
    limited: int = 0
    in_flight: int = 0


def trim(samples: deque[float], now: float) -> None:
    while samples and now - samples[0] >= WINDOW:
        samples.popleft()


class Reputation:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.observations: dict[str, Observation] = {}
        self.optional_in_flight = 0

    def prune(self, members: Set[str]) -> None:
        for node in self.observations.keys() - members:
            if self.observations[node].in_flight == 0:
                del self.observations[node]

    def invalid_request(self, node: str, method: str) -> None:
        now = self.clock()
        entry = self.observations.setdefault(node, Observation())
        trim(entry.invalid, now)
        entry.invalid.append(now)
        entry.last_invalid_method = method
        if len(entry.invalid) >= INVALID_THRESHOLD:
            if now >= entry.restricted_until:
                logger.info('Locally reduced optional RPC quotas for %s after request validation errors', node)
            entry.restricted_until = now + RESTRICTION

    def reserve(self, node: str, group: str) -> Observation:
        now = self.clock()
        entry = self.observations.setdefault(node, Observation())
        samples = entry.requests.setdefault(group, deque())
        trim(samples, now)
        limit = LIMITS[group][int(now < entry.restricted_until)]
        if len(samples) >= limit:
            entry.limited += 1
            raise PeerError('BUSY', f'Peer {group} quota reached, retry later')
        if entry.in_flight >= PEER_OPTIONAL_SLOTS:
            entry.limited += 1
            raise PeerError('BUSY', 'This peer already has two optional requests running')
        if self.optional_in_flight >= OPTIONAL_SLOTS:
            raise PeerError('BUSY', 'Optional Mesh request slots are busy')
        samples.append(now)
        entry.in_flight += 1
        self.optional_in_flight += 1
        return entry

    def release(self, entry: Observation) -> None:
        entry.in_flight -= 1
        self.optional_in_flight -= 1

    def status(self, node: str) -> dict:
        now = self.clock()
        entry = self.observations.get(node)
        restricted = bool(entry and now < entry.restricted_until)
        if entry:
            trim(entry.invalid, now)
            for samples in entry.requests.values():
                trim(samples, now)
        quotas = {}
        for group, limits in LIMITS.items():
            used = len(entry.requests.get(group, ())) if entry else 0
            limit = limits[int(restricted)]
            quotas[group] = {'limit': limit, 'remaining': max(0, limit - used)}
        return {'state': 'suspected' if restricted else 'normal',
                'invalid_requests': len(entry.invalid) if entry else 0,
                'limited_requests': entry.limited if entry else 0,
                'in_flight': entry.in_flight if entry else 0,
                'restriction_seconds': math.ceil(entry.restricted_until - now) if restricted else 0,
                'last_invalid_method': entry.last_invalid_method if entry and entry.invalid else None,
                'quotas': quotas}
