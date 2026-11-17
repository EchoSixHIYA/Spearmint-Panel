"""Portable proof of conflicting Mesh policy statements and a node's observation."""

from dataclasses import dataclass
from hashlib import sha256
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..state import State
from .credentials import NODE_ID, node_id
from .mesh_policy import configured_trust
from .policy_records import BUNDLE_LIMIT, Bundle, Record, encoded, positive, public_key, root_id
from .protocol import PeerError, matches, wire_b64


LIMIT = 2 * BUNDLE_LIMIT + 4096
DOMAIN = 'policy-conflict-observation'
FIELDS = {'version', 'mesh_id', 'statements', 'observer_public_key', 'observation'}
OBSERVATION = {'version', 'proof_id', 'observer_node_id', 'recorded_at'}


@dataclass(frozen=True)
class Conflict:
    mesh_id: str
    root_key_id: str
    kind: str
    statements: tuple[Bundle, Bundle]

    @property
    def proof_id(self) -> str:
        digests = [[bundle.delegation_record.digest, bundle.snapshot_record.digest] for bundle in self.statements]
        material = encoded({'mesh_id': self.mesh_id, 'root_key_id': self.root_key_id, 'statements': digests})
        return 'mpe1-' + sha256(b'Spearmint policy conflict v1\0' + material).hexdigest()

    def summary(self) -> dict:
        return {'proof_id': self.proof_id, 'mesh_id': self.mesh_id, 'root_key_id': self.root_key_id, 'kind': self.kind,
                'statements': [{**bundle.cursor(), 'delegation_digest': bundle.delegation_record.digest,
                                'issued_at': bundle.snapshot['issued_at'], 'expires_at': bundle.snapshot['expires_at']}
                               for bundle in self.statements]}


def conflict_kind(left: Bundle, right: Bundle) -> str:
    a, b = left.snapshot, right.snapshot
    if a['term'] == b['term']:
        if left.delegation_record.digest != right.delegation_record.digest:
            return 'delegation_conflict'
        if a['sequence'] == b['sequence'] and left.snapshot_record.digest != right.snapshot_record.digest:
            return 'snapshot_conflict'
        prior, next_ = sorted((left, right), key=lambda bundle: bundle.snapshot['sequence'])
        if (next_.snapshot['sequence'] == prior.snapshot['sequence'] + 1
                and next_.snapshot['previous_digest'] != prior.snapshot_record.digest):
            return 'chain_conflict'
    raise ValueError('The signed statements do not establish a policy conflict')


def verify_statements(statements, root: Ed25519PublicKey, mesh_id: str) -> Conflict:
    if not isinstance(statements, list) or len(statements) != 2:
        raise ValueError('Provide exactly two signed policy statements')
    # Historical evidence retains the validity windows signed into each statement.
    # It never enters the current policy importer or bypasses its time check.
    left, right = sorted((Bundle.verify(item, root, mesh_id, None) for item in statements),
                         key=lambda bundle: (bundle.delegation_record.digest, bundle.snapshot_record.digest))
    return Conflict(mesh_id, root_id(root), conflict_kind(left, right), (left, right))


def verify_report(document: dict, root: Ed25519PublicKey, mesh_id: str, observer: str | None = None) -> dict:
    if (not isinstance(document, dict) or document.keys() != FIELDS
            or type(document['version']) is not int or document['version'] != 1
            or document['mesh_id'] != mesh_id):
        raise ValueError('Evidence format or expected Mesh does not match')
    proof = verify_statements(document['statements'], root, mesh_id)
    if not isinstance(document['observer_public_key'], str):
        raise ValueError('Invalid evidence observer key')
    key = public_key(document['observer_public_key'])
    record = Record.parse(document['observation'])
    observation = record.verify(DOMAIN, key)
    reporter = node_id(key)
    if (observation.keys() != OBSERVATION or type(observation['version']) is not int or observation['version'] != 1
            or observation['proof_id'] != proof.proof_id or observation['observer_node_id'] != reporter
            or not positive(observation['recorded_at'])):
        raise ValueError('The signed observation does not match the proof and observer')
    if observer is not None and (not matches(NODE_ID, observer) or observer != reporter):
        raise ValueError('Evidence observer does not match the independently supplied Node ID')
    return {**proof.summary(), 'observer_node_id': reporter, 'recorded_at': observation['recorded_at'],
            'observer_matches_expected_node': observer is not None}


def list_conflicts(state: State, *, before: int | None = None, limit: int = 20) -> dict:
    with state.connect() as db:
        db.execute('BEGIN')
        anchor = configured_trust(db)
        if anchor is None:
            return {'conflicts': [], 'next_before': None}
        rows = db.execute('''
            SELECT term, recorded_at FROM mesh_policy_conflict
            WHERE mesh_id=? AND (? IS NULL OR term<?) ORDER BY term DESC LIMIT ?
        ''', (anchor['mesh_id'], before, before, limit + 1)).fetchall()
    return {'conflicts': [dict(row) for row in rows[:limit]],
            'next_before': rows[limit - 1]['term'] if len(rows) > limit else None}


def export_report(state: State, term: int, root: Ed25519PublicKey | None = None) -> dict:
    with state.connect() as db:
        db.execute('BEGIN')
        anchor = configured_trust(db)
        if anchor is None:
            raise PeerError('NOT_FOUND', 'No Mesh policy root is configured')
        row = db.execute('SELECT * FROM mesh_policy_conflict WHERE mesh_id=? AND term=?',
                         (anchor['mesh_id'], term)).fetchone()
    if row is None:
        raise PeerError('NOT_FOUND', 'No conflict is recorded for this policy term')
    trusted_root = root or Ed25519PublicKey.from_public_bytes(anchor['root_key'])
    try:
        proof = verify_statements([json.loads(row['prior_bundle']), json.loads(row['incoming_bundle'])],
                                  trusted_root, row['mesh_id'])
        if proof.statements[0].snapshot['term'] != term:
            raise ValueError('Recorded term differs from signed policy')
    except (ValueError, InvalidSignature) as exc:
        raise PeerError('CONFLICT', 'The stored evidence does not verify under this root. Check the trusted root for this term.') from exc
    key = state.signing_key()
    observer = key.public_key()
    observation = {'version': 1, 'proof_id': proof.proof_id, 'observer_node_id': node_id(observer),
                   'recorded_at': row['recorded_at']}
    return {'version': 1, 'mesh_id': proof.mesh_id, 'statements': [item.wire() for item in proof.statements],
            'observer_public_key': wire_b64(observer.public_bytes_raw()),
            'observation': Record.sign(DOMAIN, observation, key).wire()}
