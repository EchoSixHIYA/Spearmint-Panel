import json
import secrets
import sqlite3
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..catalog import Service, get_service
from ..state import State, StateError, audit
from .approval_format import operator_id
from .credentials import certificate, node_id
from .mesh_policy import member_allowed
from . import operation_policy as scoped
from .pairing import Pair, configured
from .projection import publish
from .protocol import PeerError


def add_operator(state: State, public_key: Ed25519PublicKey) -> str:
    key_id = operator_id(public_key)
    with state.connect(write=True) as db:
        db.execute("INSERT OR IGNORE INTO operator_key VALUES (?, ?)", (key_id, public_key.public_bytes_raw()))
        audit(db, "admin", "local", "peer.operator.imported", key_id)
    return key_id


def grant(state: State, service_id: str, key_id: str | None, actions: list[str], expires_at: int, read_result: bool,
          *, node_id: str | None = None) -> str:
    with state.connect(write=True) as db:
        pair = configured(db, node_id)
        service = get_service(db, service_id)
        if pair is None or service is None:
            raise StateError("Configure the peer and register the service before granting access")
        grant_id = save_grant(db, pair, service, key_id, actions, expires_at, read_result)
        publish(db, service_id)
        audit(db, "admin", "local", "peer.grant.account_added" if key_id is None else "peer.grant.added", grant_id)
        return grant_id


def save_grant(db: sqlite3.Connection, pair: Pair, service: Service, key_id: str | None,
               actions: list[str], expires_at: int, read_result: bool) -> str:
    if not actions or any(action not in service.actions for action in actions):
        raise StateError("The requested actions are unavailable for this service")
    if expires_at <= int(time.time()):
        raise StateError("Operator grant expiration must be in the future")
    if key_id is None:
        if scoped.required_version(db, service.id) == 2:
            raise StateError("This service requires an independent M003 approval")
        if not db.execute("SELECT 1 FROM peer_export WHERE peer_id=? AND service_id=? AND directory=1",
                          (pair.node_id, service.id)).fetchone():
            raise StateError("Export the service to this peer before granting account actions")
        public = certificate(pair.remote_pem).public_key()
        key_id = operator_id(public)
        db.execute("INSERT OR IGNORE INTO operator_key VALUES (?,?)", (key_id, public.public_bytes_raw()))
    elif db.execute("SELECT 1 FROM operator_key WHERE id=?", (key_id,)).fetchone() is None:
        raise StateError("Unknown operator key")
    row = db.execute("""
        INSERT INTO peer_grant(id,peer_id,service_id,operator_key_id,actions,read_result,expires_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(peer_id,service_id,operator_key_id) DO UPDATE SET
            version=version+1, actions=excluded.actions, read_result=excluded.read_result,
            expires_at=excluded.expires_at, enabled=1
        RETURNING id
        """, (secrets.token_hex(16), pair.node_id, service.id, key_id, json.dumps(sorted(set(actions))),
              read_result, expires_at)).fetchone()
    return row["id"]


def disable_grant(db: sqlite3.Connection, grant_id: str) -> sqlite3.Row | None:
    return db.execute("""
        UPDATE peer_grant SET enabled=0, version=version+1 WHERE id=? AND enabled=1 RETURNING service_id
        """, (grant_id,)).fetchone()


def revoke(state: State, grant_id: str) -> None:
    with state.connect(write=True) as db:
        row = disable_grant(db, grant_id)
        if row is None:
            raise StateError("Unknown or inactive operator grant")
        publish(db, row["service_id"])
        audit(db, "admin", "local", "peer.grant.revoked", grant_id)


def require_pair(db: sqlite3.Connection, pair: Pair) -> None:
    if not pair.enabled or configured(db, pair.node_id) != pair or not member_allowed(db, pair.mesh_id, pair.node_id):
        raise PeerError("OFFLINE", "Peer pairing changed")


def credentials_current(pair: Pair) -> bool:
    try:
        pair.validate(node_id(certificate(pair.local_pem).public_key()))
        return True
    except ValueError:
        return False


def action_grant(db: sqlite3.Connection, peer_id: str, service_id: str, key_id: str, action: str,
                 service_version: int) -> tuple[sqlite3.Row, Service]:
    row = db.execute("""
        SELECT peer_grant.*, operator_key.public_key FROM peer_grant
        JOIN operator_key ON operator_key.id=peer_grant.operator_key_id
        JOIN peer_export USING(peer_id, service_id)
        WHERE peer_grant.peer_id=? AND peer_grant.service_id=? AND operator_key_id=?
          AND peer_grant.enabled=1 AND expires_at>? AND peer_export.directory=1
        """, (peer_id, service_id, key_id, int(time.time()))).fetchone()
    if row is None or action not in json.loads(row["actions"]):
        raise PeerError("DENIED", "No active operator grant for this action")
    service = get_service(db, service_id)
    if service is None or service.version != service_version or action not in service.actions:
        raise PeerError("CONFLICT", "The target service configuration changed")
    return row, service


def dispatch_authorized(db: sqlite3.Connection, operation: sqlite3.Row) -> bool:
    receipt = db.execute("SELECT * FROM peer_receipt WHERE operation_id=?", (operation["id"],)).fetchone()
    if receipt is None:
        return (not operation["actor"].startswith(("op1-", "usr1-")) and db.execute(
            "SELECT 1 FROM peer_operation_origin WHERE operation_id=?", (operation["id"],),
        ).fetchone() is None)
    peer = configured(db, receipt["peer_id"])
    if (peer is None or not peer.enabled or not credentials_current(peer)
            or peer.write_epoch != receipt["write_epoch"] or not member_allowed(db, peer.mesh_id, peer.node_id)):
        return False
    try:
        proof = scoped.v2_receipt(db, operation["id"])
        if proof is not None:
            target = db.execute("SELECT node_id FROM node WHERE singleton=1").fetchone()[0]
            scoped.authorize(db, peer.mesh_id, peer.node_id, target,
                             scoped.receipt_intent(receipt, proof, operation), int(time.time()))
            return True
        if operation["actor"].startswith("usr1-"):
            return False
        scoped.require_version(db, operation["service_id"], 1)
        row, _ = action_grant(db, peer.node_id, operation["service_id"], receipt["operator_key_id"],
                              operation["action"], receipt["service_version"])
    except PeerError:
        return False
    return row["id"] == receipt["grant_id"] and row["version"] == receipt["grant_version"]


def clean_expired(state: State) -> None:
    now = int(time.time())
    with state.connect() as db:
        due = db.execute("""
            SELECT 1 FROM peer_challenge WHERE expires_at<=?
            UNION ALL SELECT 1 FROM peer_grant WHERE enabled=1 AND expires_at<=? LIMIT 1
            """, (now, now)).fetchone()
    if not due:
        return
    with state.connect(write=True) as db:
        db.execute("DELETE FROM peer_challenge WHERE expires_at<=?", (now,))
        expired = db.execute("""
            UPDATE peer_grant SET enabled=0, version=version+1 WHERE enabled=1 AND expires_at<=?
            RETURNING id, service_id
            """, (now,)).fetchall()
        for row in expired:
            publish(db, row["service_id"])
            audit(db, "admin", "local", "peer.grant.expired", row["id"])
