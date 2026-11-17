"""Local, session-scoped latency measurements and bounded route decisions.

Only the transport owns availability and authentication. This module compares
the supplied paths without persisting samples or trusting advertised latency.
"""
from dataclasses import dataclass, field
from math import isfinite


SAMPLE_TTL = 15.0
MIN_SAMPLES = 3
MIN_DWELL = 20.0
MIN_SAVING_MS = 10.0
MIN_SAVING_RATIO = 0.15
REQUIRED_COMPARISONS = 3
HOP_PENALTY_MS = 5.0
PathKey = tuple[tuple[str, ...], str]


def required_saving_ms(cost: float) -> float:
    return max(MIN_SAVING_MS, cost * MIN_SAVING_RATIO)


def finite_number(value: float) -> bool:
    return type(value) in (float, int) and isfinite(value)


@dataclass
class Latency:
    latest_ms: float | None = None
    ewma_ms: float | None = None
    sampled_at: float | None = None
    samples: int = 0

    def add(self, rtt_ms: float, now: float) -> None:
        if (not finite_number(rtt_ms) or rtt_ms < 0 or not finite_number(now)
                or self.sampled_at is not None and now < self.sampled_at):
            raise ValueError('Latency requires a finite RTT and an ordered monotonic timestamp')
        self.latest_ms = float(rtt_ms)
        self.ewma_ms = float(rtt_ms) if self.ewma_ms is None else .25 * rtt_ms + .75 * self.ewma_ms
        self.sampled_at = float(now)
        self.samples += 1

    def fresh(self, now: float) -> bool:
        return self.sampled_at is not None and 0 <= now - self.sampled_at <= SAMPLE_TTL

    def remaining(self, now: float) -> float:
        return SAMPLE_TTL - (now - self.sampled_at) if self.sampled_at is not None and self.fresh(now) else 0.0

    def cost(self, hops: int, now: float) -> float | None:
        if type(hops) is not int or not 1 <= hops <= 4:
            raise ValueError('Path hop count must be between one and four')
        return self.ewma_ms + HOP_PENALTY_MS * (hops - 1) if self.fresh(now) and self.ewma_ms is not None else None

    def public_data(self, now: float) -> dict:
        return {'rtt_ewma_ms': round(self.ewma_ms, 3) if self.ewma_ms is not None else None,
                'rtt_sample_count': self.samples,
                'rtt_sample_age_seconds': round(max(0, now - self.sampled_at), 3) if self.sampled_at is not None else None,
                'rtt_fresh': self.fresh(now), 'rtt_remaining_seconds': self.remaining(now)}


@dataclass(frozen=True)
class Candidate:
    path: tuple[str, ...]
    generation: str
    latency: Latency = field(default_factory=Latency)
    available: bool = True
    verified: bool = False

    def __post_init__(self) -> None:
        if not 2 <= len(self.path) <= 5 or len(set(self.path)) != len(self.path) or not self.generation:
            raise ValueError('Path candidates require a loop-free bounded path and a connection generation')

    @property
    def key(self) -> PathKey:
        return self.path, self.generation

    @property
    def hops(self) -> int:
        return len(self.path) - 1

    def cost(self, now: float) -> float | None:
        return self.latency.cost(self.hops, now)

    def measured_cost(self, now: float) -> float | None:
        if self.verified and self.latency.samples >= MIN_SAMPLES:
            return self.cost(now)
        return None

    def recovery_rank(self, now: float) -> tuple[bool, bool, float, int, PathKey]:
        cost = self.measured_cost(now)
        return not self.verified, cost is None, cost if cost is not None else 0.0, self.hops, self.key


@dataclass(frozen=True)
class Decision:
    candidate: Candidate | None
    changed: bool
    reason: str
    comparisons: int = 0


class Selector:
    def __init__(self) -> None:
        self.active: PathKey | None = None
        self.selected_at: float | None = None
        self.challenger: PathKey | None = None
        self.last_samples: tuple[int, int] | None = None
        self.comparisons = 0
        self.switches = 0

    def reset_comparison(self) -> None:
        self.challenger = None
        self.last_samples = None
        self.comparisons = 0

    def choose(self, candidate: Candidate | None, now: float, reason: str) -> Decision:
        key = candidate.key if candidate else None
        changed = key != self.active
        if changed and self.active is not None and key is not None:
            self.switches += 1
        self.active = key
        self.selected_at = now if candidate else None
        self.reset_comparison()
        return Decision(candidate, changed, reason)

    def select(self, candidates: list[Candidate], now: float) -> Decision:
        if not finite_number(now):
            raise ValueError('Path decisions require a finite monotonic timestamp')
        available = {candidate.key: candidate for candidate in candidates if candidate.available}
        if not available:
            return self.choose(None, now, 'unreachable')

        active = available.get(self.active)
        if active is None:
            best = min(available.values(), key=lambda candidate: candidate.recovery_rank(now))
            return self.choose(best, now, 'failure' if self.active else 'initial')
        comparable = [(cost, candidate) for candidate in available.values()
                      if (cost := candidate.measured_cost(now)) is not None]
        current_cost = active.measured_cost(now)
        if current_cost is None:
            self.reset_comparison()
            return Decision(active, False, 'warming')
        cost, best = min(comparable, key=lambda item: (item[0], item[1].hops, item[1].key))
        if best.key == active.key or current_cost - cost < required_saving_ms(current_cost):
            self.reset_comparison()
            return Decision(active, False, 'stable')
        samples = active.latency.samples, best.latency.samples
        if self.challenger != best.key:
            self.reset_comparison()
            self.challenger = best.key
        if self.last_samples is None or all(new > old for new, old in zip(samples, self.last_samples)):
            self.comparisons += 1
            self.last_samples = samples
        if self.comparisons >= REQUIRED_COMPARISONS and self.selected_at is not None and now - self.selected_at >= MIN_DWELL:
            return self.choose(best, now, 'lower_cost')
        return Decision(active, False, 'dwell' if now - self.selected_at < MIN_DWELL else 'comparing', self.comparisons)
