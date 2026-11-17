"""Short-lived direct-neighbor evidence, never a source of business readiness."""
from dataclasses import dataclass
import time
from typing import TYPE_CHECKING

from .protocol import PeerError

if TYPE_CHECKING:
    from .manager import Neighbor, PeerManager


METHOD = 'mesh.observe'
LIMIT = 16
TTL = 20
INTERVAL = 10


@dataclass(frozen=True)
class Evidence:
    reporter: 'Neighbor'
    node: str
    method: str
    sampled_at: float
    expires: float


class Observations:
    def __init__(self, manager: 'PeerManager', *, clock=time.monotonic):
        self.manager, self.clock = manager, clock
        self.evidence: dict[tuple[str, str], Evidence] = {}

    def current(self, link: 'Neighbor') -> bool:
        return bool(self.manager.neighbors.get(link.pair.node_id) is link and not link.session.closed
                    and self.manager.pairs.get(link.pair.node_id) == link.pair and link.pair.enabled
                    and not link.pair.legacy and METHOD in link.capabilities)

    def response(self, link: 'Neighbor', params: dict) -> dict:
        if not self.current(link):
            raise PeerError('OFFLINE', 'Observation reporter session is unavailable')
        if params:
            raise PeerError('INVALID_REQUEST', 'mesh.observe expects empty parameters')
        now = self.clock()
        records = [{'node_id': self.manager.local_id, 'method': 'local', 'age_seconds': 0, 'ttl_seconds': TTL}]
        for node, neighbor in sorted(self.manager.neighbors.items()):
            if (self.manager.pairs.get(node) != neighbor.pair or not neighbor.pair.enabled
                    or neighbor.session.closed or neighbor.pair.legacy):
                continue
            age = now - neighbor.session.last_pong
            if 0 <= age < TTL:
                records.append({'node_id': node, 'method': 'direct', 'age_seconds': round(age, 3), 'ttl_seconds': TTL})
        return {'records': records[:LIMIT]}

    def accept(self, link: 'Neighbor', payload: dict) -> None:
        if not self.current(link):
            return
        if (not isinstance(payload, dict) or payload.keys() != {'records'}
                or not isinstance(payload['records'], list) or len(payload['records']) > LIMIT):
            raise PeerError('PROTOCOL', 'Invalid observation page')
        now = self.clock()
        records = {}
        for record in payload['records']:
            if (not isinstance(record, dict) or record.keys() != {'node_id', 'method', 'age_seconds', 'ttl_seconds'}
                    or not isinstance(record['node_id'], str) or record['node_id'] in records
                    or not isinstance(record['method'], str) or record['method'] not in {'local', 'direct'}
                    or record['method'] == 'local' and record['node_id'] != link.pair.node_id
                    or not all(type(record[key]) in {int, float} and 0 <= record[key] <= TTL
                               for key in ('age_seconds', 'ttl_seconds'))
                    or record['ttl_seconds'] == 0):
                raise PeerError('PROTOCOL', 'Invalid direct observation record')
            records[record['node_id']] = record
        accepted = {}
        for node, record in records.items():
            pair = self.manager.pairs.get(node)
            age, ttl = record['age_seconds'], record['ttl_seconds']
            if pair is not None and pair.enabled and age < ttl:
                accepted[link.pair.node_id, node] = Evidence(link, node, record['method'], now - age, now + ttl - age)
        self.evidence = {key: value for key, value in self.evidence.items() if key[0] != link.pair.node_id}
        self.evidence.update(accepted)
        self.expire()

    def expire(self) -> None:
        now = self.clock()
        self.evidence = {key: value for key, value in self.evidence.items()
            if now < value.expires and self.current(value.reporter)
            and (pair := self.manager.pairs.get(value.node)) is not None and pair.enabled}

    def status(self, node: str) -> list[dict]:
        self.expire()
        now = self.clock()
        return [{'observer_node_id': value.reporter.pair.node_id, 'method': value.method,
                 'age_seconds': round(max(0, now - value.sampled_at), 3),
                 'remaining_seconds': round(max(0, value.expires - now), 3)}
                for _, value in sorted(self.evidence.items()) if value.node == node]

    def targets(self) -> set[str]:
        self.expire()
        return {value.node for value in self.evidence.values()}
