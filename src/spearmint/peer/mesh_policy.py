import json
from secrets import token_hex
import sqlite3
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..state import State, StateError, audit
from .credentials import FINGERPRINT
from .policy_records import (
    Bundle, RESUME_FIELDS, RESUME_TTL, SNAPSHOT_LIMIT, USER_ID, Record, encoded, public_key, root_id, validate_header,
)
from .protocol import PeerError, matches
from .quarantine import contains as locally_quarantined


METHOD = "security.policy.get"
RECOVERY_TABLES = (
    ("mesh_policy_trust", ("singleton", "mesh_id", "root_key", "last_clock", "frozen_term", "resume_nonce", "execution_epoch")),
    ("mesh_policy_head", ("mesh_id", "term", "sequence", "digest", "delegation_digest", "expires_at", "bundle")),
    ("mesh_policy_conflict", ("mesh_id", "term", "prior_bundle", "incoming_bundle", "recorded_at")),
    ("mesh_policy_member", ("mesh_id", "node_id", "state")),
)


def trust(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM mesh_policy_trust WHERE singleton=1").fetchone()


def head(db: sqlite3.Connection, mesh_id: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM mesh_policy_head WHERE mesh_id=?", (mesh_id,)).fetchone()


def configured_trust(db: sqlite3.Connection) -> sqlite3.Row | None:
    anchor = trust(db)
    mesh = db.execute("SELECT mesh_id FROM mesh_profile WHERE singleton=1").fetchone()
    return anchor if anchor is not None and mesh is not None and mesh["mesh_id"] == anchor["mesh_id"] else None


def pin_root(state: State, key: Ed25519PublicKey, expected_id: str, previous_id: str | None = None) -> None:
    if root_id(key) != expected_id:
        raise StateError("Policy root does not match the approved fingerprint")
    with state.connect(write=True) as db:
        mesh = db.execute("SELECT mesh_id FROM mesh_profile WHERE singleton=1").fetchone()
        if mesh is None:
            raise StateError("Configure the local Mesh before installing its policy root")
        local_key = db.execute("SELECT public_key FROM node WHERE singleton=1").fetchone()[0]
        if local_key == key.public_bytes_raw():
            raise StateError("The local node key cannot be the policy root")
        anchor = trust(db)
        if anchor is not None:
            if anchor["mesh_id"] != mesh["mesh_id"]:
                raise StateError("The pinned root belongs to a different Mesh")
            if anchor["root_key"] != key.public_bytes_raw():
                if previous_id != root_id(Ed25519PublicKey.from_public_bytes(anchor["root_key"])):
                    raise StateError("Supply the currently pinned fingerprint to rotate the policy root")
                current = head(db, anchor["mesh_id"])
                db.execute("UPDATE mesh_policy_trust SET root_key=?, frozen_term=? WHERE singleton=1",
                           (key.public_bytes_raw(), current["term"] if current is not None else 0))
                audit(db, "admin", "local", "mesh.policy.root_rotated", expected_id)
            return
        if previous_id is not None:
            raise StateError("There is no pinned root to rotate")
        db.execute("INSERT INTO mesh_policy_trust (singleton,mesh_id,root_key) VALUES (1,?,?)",
                   (mesh["mesh_id"], key.public_bytes_raw()))
        audit(db, "admin", "local", "mesh.policy.root_pinned", expected_id)


def policy_status(db: sqlite3.Connection, now: int) -> dict:
    anchor = configured_trust(db)
    if anchor is None:
        return {"status": "unconfigured"}
    current = head(db, anchor["mesh_id"])
    if anchor["frozen_term"]:
        status = "conflict"
    elif anchor["resume_nonce"]:
        status = "recovery_required"
    elif now < anchor["last_clock"]:
        status = "clock_rollback"
    elif current is None:
        status = "awaiting_policy"
    elif now >= current["expires_at"]:
        status = "expired"
    elif not member_set(db, anchor["mesh_id"]):
        status = "member_inactive"
    else:
        status = "ready"
    result = {"status": status, "mesh_id": anchor["mesh_id"],
              "root_id": root_id(Ed25519PublicKey.from_public_bytes(anchor["root_key"]))}
    if current is not None:
        result.update({field: current[field] for field in ("term", "sequence", "digest", "expires_at")})
    return result


def cursor(db: sqlite3.Connection) -> dict:
    anchor = configured_trust(db)
    current = head(db, anchor["mesh_id"]) if anchor is not None else None
    if current is None:
        return {"term": 0, "sequence": 0, "digest": None}
    return {field: current[field] for field in ("term", "sequence", "digest")}


def freeze(db: sqlite3.Connection, current: sqlite3.Row, bundle: Bundle, source: str, now: int) -> str:
    mesh_id, term = current["mesh_id"], current["term"]
    db.execute("""
        INSERT OR IGNORE INTO mesh_policy_conflict (mesh_id,term,prior_bundle,incoming_bundle,recorded_at)
        VALUES (?,?,?,?,?)
    """, (mesh_id, term, current["bundle"], encoded(bundle.wire()).decode(), now))
    db.execute("UPDATE mesh_policy_trust SET frozen_term=?, last_clock=? WHERE mesh_id=?", (term, now, mesh_id))
    audit(db, "policy", source, "mesh.policy.conflict", f"{term}:{current['sequence']}")
    return "conflict"


def apply(state: State, document: dict, source: str = "local") -> str:
    now = int(time.time())
    with state.connect(write=True) as db:
        anchor = configured_trust(db)
        if anchor is None:
            raise StateError("Pin the policy root for this Mesh first")
        if now < anchor["last_clock"]:
            raise StateError("Local clock is below the recorded policy time")
        bundle = Bundle.verify(document, Ed25519PublicKey.from_public_bytes(anchor["root_key"]), anchor["mesh_id"], now)
        snapshot = bundle.snapshot
        term, sequence, digest = snapshot["term"], snapshot["sequence"], bundle.snapshot_record.digest
        current = head(db, anchor["mesh_id"])
        if current is not None:
            if term < current["term"]:
                return "older"
            if term == current["term"]:
                if anchor["frozen_term"] == term:
                    return "conflict"
                if bundle.delegation_record.digest != current["delegation_digest"]:
                    return freeze(db, current, bundle, source, now)
                if sequence < current["sequence"]:
                    return "older"
                if sequence == current["sequence"]:
                    return "unchanged" if digest == current["digest"] else freeze(db, current, bundle, source, now)
                if sequence == current["sequence"] + 1 and snapshot["previous_digest"] != current["digest"]:
                    return freeze(db, current, bundle, source, now)
        db.execute("""
            INSERT INTO mesh_policy_head (mesh_id,term,sequence,digest,delegation_digest,expires_at,bundle)
            VALUES (?,?,?,?,?,?,?) ON CONFLICT(mesh_id) DO UPDATE SET term=excluded.term, sequence=excluded.sequence,
                digest=excluded.digest, delegation_digest=excluded.delegation_digest, expires_at=excluded.expires_at,
                bundle=excluded.bundle
        """, (anchor["mesh_id"], term, sequence, digest, bundle.delegation_record.digest,
              snapshot["expires_at"], encoded(bundle.wire()).decode()))
        db.execute("UPDATE mesh_policy_trust SET last_clock=?, frozen_term=0 WHERE singleton=1", (now,))
        db.execute("DELETE FROM mesh_policy_member WHERE mesh_id=? AND state='active'", (anchor["mesh_id"],))
        db.executemany("""
            INSERT INTO mesh_policy_member (mesh_id,node_id,state) VALUES (?,?,?)
            ON CONFLICT(mesh_id,node_id) DO UPDATE SET state=excluded.state
        """, ((anchor["mesh_id"], entry["node_id"], entry["state"]) for entry in snapshot["members"]))
        event = "mesh.policy.applied"
        if current is not None and term == current["term"] and sequence > current["sequence"] + 1:
            event = "mesh.policy.applied_with_gap"
        audit(db, snapshot["change"]["actor"], source, event, f"{term}:{sequence}:{digest}")
        return "applied"


def member_set(db: sqlite3.Connection, mesh_id: str) -> set[str] | None:
    anchor = trust(db)
    if anchor is None or anchor["mesh_id"] != mesh_id:
        return None
    allowed = {row["node_id"] for row in db.execute(
        "SELECT node_id FROM mesh_policy_member WHERE mesh_id=? AND state='active'", (mesh_id,),
    )}
    local_id = db.execute("SELECT node_id FROM node WHERE singleton=1").fetchone()[0]
    return allowed if local_id in allowed else set()


def member_allowed(db: sqlite3.Connection, mesh_id: str, node_id: str) -> bool:
    if locally_quarantined(db, node_id):
        return False
    allowed = member_set(db, mesh_id)
    return allowed is None or node_id in allowed


def bind_user(state: State, username: str, user_id: str) -> None:
    if not matches(USER_ID, user_id):
        raise StateError("Invalid Mesh user ID")
    now = int(time.time())
    with state.connect(write=True) as db:
        status = policy_status(db, now)
        if status["status"] != "ready":
            raise StateError("An active Mesh policy is required to bind an account")
        mesh_id = status["mesh_id"]
        current = head(db, mesh_id)
        record = json.loads(current["bundle"])["snapshot"]
        snapshot = json.loads(Record.parse(record, limit=SNAPSHOT_LIMIT).raw)
        if not any(user["user_id"] == user_id and user["state"] == "active" for user in snapshot["users"]):
            raise StateError("User is not active in the current signed policy")
        account = db.execute("SELECT id FROM panel_account WHERE username=? AND enabled=1", (username,)).fetchone()
        if account is None:
            raise StateError("Local account is unavailable")
        db.execute("""
            INSERT INTO mesh_policy_account (account_id,mesh_id,user_id) VALUES (?,?,?)
            ON CONFLICT(account_id) DO UPDATE SET mesh_id=excluded.mesh_id,user_id=excluded.user_id
        """, (account["id"], mesh_id, user_id))
        audit(db, "admin", "local", "mesh.policy.user_bound", f"{account['id']}:{user_id}")


def recovery_checkpoint(db: sqlite3.Connection) -> tuple[str, dict] | None:
    anchor = configured_trust(db)
    if anchor is None:
        return None
    records = {table: [tuple(row) for row in db.execute(
        f"SELECT {','.join(columns)} FROM {table} WHERE mesh_id=?", (anchor["mesh_id"],),
    )] for table, columns in RECOVERY_TABLES}
    return anchor["mesh_id"], records


def pause_restored(db: sqlite3.Connection, checkpoint: tuple[str, dict] | None) -> None:
    restored_mesh = db.execute("SELECT mesh_id FROM mesh_profile WHERE singleton=1").fetchone()
    if checkpoint is not None and restored_mesh is not None and restored_mesh[0] == checkpoint[0]:
        mesh_id, records = checkpoint
        db.execute("DELETE FROM mesh_policy_account WHERE mesh_id<>?", (mesh_id,))
        for table, _ in reversed(RECOVERY_TABLES):
            db.execute(f"DELETE FROM {table}")
        for table, columns in RECOVERY_TABLES:
            db.executemany(
                f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                records[table],
            )
    db.execute("UPDATE mesh_policy_trust SET resume_nonce=?,execution_epoch=?", (token_hex(16), token_hex(16)))
    if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise StateError("Restored policy state failed its foreign key check")


def resume_request(state: State) -> dict:
    with state.connect() as db:
        anchor = configured_trust(db)
        if anchor is None or not anchor["resume_nonce"]:
            raise StateError("This node does not require policy recovery")
        node_id = db.execute("SELECT node_id FROM node WHERE singleton=1").fetchone()[0]
        return {"mesh_id": anchor["mesh_id"], "node_id": node_id, "nonce": anchor["resume_nonce"]}


def resume(state: State, proof: dict) -> None:
    now = int(time.time())
    with state.connect(write=True) as db:
        anchor = configured_trust(db)
        if anchor is None or not anchor["resume_nonce"] or anchor["frozen_term"] or now < anchor["last_clock"]:
            raise StateError("Policy recovery is not available")
        current = head(db, anchor["mesh_id"])
        if current is None:
            raise StateError("Install the signed policy referenced by the recovery confirmation")
        bundle = Bundle.verify(json.loads(current["bundle"]),
                               Ed25519PublicKey.from_public_bytes(anchor["root_key"]), anchor["mesh_id"], now)
        data = Record.parse(proof).verify("resume", public_key(bundle.authority["authority_public_key"]))
        validate_header(data, RESUME_FIELDS, anchor["mesh_id"], RESUME_TTL, now)
        node_id = db.execute("SELECT node_id FROM node WHERE singleton=1").fetchone()[0]
        if ((data["node_id"], data["nonce"], data["term"], data["sequence"], data["policy_digest"])
                != (node_id, anchor["resume_nonce"], current["term"], current["sequence"], current["digest"])
                or type(data["term"]) is not int or type(data["sequence"]) is not int
                or data["expires_at"] > current["expires_at"]):
            raise StateError("Policy recovery confirmation does not match this node and current policy")
        db.execute("UPDATE mesh_policy_trust SET resume_nonce=NULL,last_clock=? WHERE singleton=1", (now,))
        audit(db, "policy", "local", "mesh.policy.resumed", current["digest"])


def response(db: sqlite3.Connection, mesh_id: str, remote_cursor: dict) -> dict:
    if (remote_cursor.keys() != {"term", "sequence", "digest"}
            or any(type(remote_cursor[field]) is not int or not 0 <= remote_cursor[field] < 2**63
                   for field in ("term", "sequence"))
            or (remote_cursor["digest"] is not None and not matches(FINGERPRINT, remote_cursor["digest"]))):
        raise PeerError("INVALID_REQUEST", "Invalid policy cursor")
    anchor = configured_trust(db)
    current = head(db, mesh_id) if anchor is not None and anchor["mesh_id"] == mesh_id else None
    now = int(time.time())
    if (current is None or anchor["frozen_term"] or not anchor["last_clock"] <= now < current["expires_at"]
            or all(current[key] == value for key, value in remote_cursor.items())):
        return {"status": "unchanged"}
    return {"status": "snapshot", **json.loads(current["bundle"])}
