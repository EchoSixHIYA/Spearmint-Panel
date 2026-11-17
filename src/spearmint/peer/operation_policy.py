import json
import sqlite3
import time

from ..catalog import Service, get_service
from ..state import audit
from . import mesh_policy
from .policy_records import SNAPSHOT_LIMIT, Record, matching_grants, user_key
from .protocol import PeerError


AUDIT_DETAILS_PER_MINUTE = 32
AUDIT_CONFLICT_PAGE = 16
RESULT_REASONS = {
    "POLICY_CHANGED": {"failed"},
    "PANEL_RESTARTED": {"uncertain"},
    "RUNTIME_NOT_READY": {"failed"},
    "STATE_NOT_REACHED": {"failed"},
    "OUTCOME_UNCONFIRMED": {"uncertain"},
    "HOST_TIMEOUT": {"failed", "uncertain"},
    "HOST_ERROR": {"failed", "uncertain"},
}


def operation_result_reason(db: sqlite3.Connection, operation: sqlite3.Row, *, local: bool = False) -> str | None:
    # The operation and audit event are updated together. Start at the operation's
    # timestamp so old receipts can use the existing chronological audit index.
    result = db.execute("""
        SELECT reason FROM audit WHERE recorded_at=? AND target=? AND event=?
        ORDER BY id DESC LIMIT 1
        """, (operation["updated_at"], operation["id"],
              f"operation.{operation['action']}.{operation['status']}")).fetchone()
    reason = result["reason"] if result else None
    # Older Mesh peers only accept the existing wire reason codes.
    if local and reason == "RESTART_BEFORE_DISPATCH" and operation["status"] == "failed":
        return reason
    return reason if operation["status"] in RESULT_REASONS.get(reason, ()) else None


def required_version(db: sqlite3.Connection, service_id: str) -> int:
    protected = db.execute("SELECT 1 FROM service_protection WHERE service_id=?", (service_id,)).fetchone()
    return 2 if protected is not None else 1


def require_version(db: sqlite3.Connection, service_id: str, version: int) -> None:
    if version < required_version(db, service_id):
        raise PeerError("APPROVAL_VERSION_REQUIRED", "This service requires an M003 approval")


def active_policy(db: sqlite3.Connection, mesh_id: str, now: int) -> tuple[dict, str]:
    status = mesh_policy.policy_status(db, now)
    if status.get("mesh_id") != mesh_id or status["status"] != "ready":
        code = "POLICY_CONFLICT" if status["status"] == "conflict" else "POLICY_UNAVAILABLE"
        raise PeerError(code, "An active Mesh policy is required")
    current = mesh_policy.head(db, mesh_id)
    anchor = mesh_policy.configured_trust(db)
    snapshot = Record.parse(json.loads(current["bundle"])["snapshot"], limit=SNAPSHOT_LIMIT)
    return json.loads(snapshot.raw), anchor["execution_epoch"]


def exported_service(db: sqlite3.Connection, origin: str, service_id: str) -> Service:
    export = db.execute("""
        SELECT 1 FROM peer_export WHERE peer_id=? AND service_id=? AND directory=1
    """, (origin, service_id)).fetchone()
    service = get_service(db, service_id) if export else None
    if service is None:
        raise PeerError("NOT_FOUND", "Service is unavailable to this peer")
    return service


def authorize(db: sqlite3.Connection, mesh_id: str, origin: str, target: str, intent: dict,
              now: int, *, reading: bool = False):
    snapshot, epoch = active_policy(db, mesh_id, now)
    grant_matches = matching_grants(
        snapshot, user_id=intent["user_id"], origin=origin, target=target, service=intent["service_id"],
        action=intent["action"], now=now,
    )
    if "grant_id" in intent:
        grant_matches = [item for item in grant_matches if item["id"] == intent["grant_id"]]
    key = user_key(snapshot, intent["user_id"], intent["operator_key_id"])
    if (key is None or len(grant_matches) != 1 or (reading and not grant_matches[0]["read_result"])
            or not mesh_policy.member_allowed(db, mesh_id, origin)):
        raise PeerError("DENIED", "No active Mesh authorization for this operation")
    grant = grant_matches[0]
    service = exported_service(db, origin, intent["service_id"])
    if not reading and (service.version != intent["service_version"] or intent["action"] not in service.actions):
        raise PeerError("CONFLICT", "The target service configuration changed")
    if not reading and "policy_term" in intent:
        if (intent["policy_term"], intent["execution_epoch"], intent["grant_version"]) != (
            snapshot["term"], epoch, grant["revision"],
        ):
            raise PeerError("CONFLICT", "The Mesh authorization changed")
    return grant, service, key, snapshot, epoch


def record_event(db: sqlite3.Connection, source: str, target: str, stage: str, reason: str,
                 *, data: dict | None = None, operation_id: str | None = None, sequence: int | None = None) -> None:
    now = int(time.time())
    context = data or {}
    if stage in {"rejected", "replayed"}:
        request_id = context.get("request_id")
        if request_id is not None and db.execute("""
            SELECT count(*) FROM peer_operation_audit WHERE source=? AND stage=? AND reason=?
                AND recorded_at>? AND request_id IS NOT NULL AND request_id<>?
        """, (source, stage, reason, now - 60, request_id)).fetchone()[0] >= AUDIT_DETAILS_PER_MINUTE:
            context, operation_id, sequence = {}, None, None
            request_id, reason = None, f"{reason}_AUDIT_LIMIT"
        prior = db.execute("""
            SELECT id FROM peer_operation_audit WHERE source=? AND stage=? AND reason=?
                AND request_id IS ? AND recorded_at>?
            ORDER BY recorded_at DESC, id DESC LIMIT 1
        """, (source, stage, reason, request_id, now - 60)).fetchone()
        if prior:
            db.execute("UPDATE peer_operation_audit SET count=count+1 WHERE id=?", (prior["id"],))
            return
    db.execute("""
        INSERT INTO peer_operation_audit (recorded_at,source,target,service_id,request_id,operation_id,user_id,
            operator_key_id,action,policy_term,policy_sequence,grant_id,grant_version,stage,reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (now, source, target, context.get("service_id"), context.get("request_id"), operation_id,
          context.get("user_id"), context.get("operator_key_id"), context.get("action"), context.get("policy_term"),
          sequence, context.get("grant_id"), context.get("grant_version"), stage, reason))


def v2_receipt(db: sqlite3.Connection, operation_id: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM peer_receipt_v2 WHERE operation_id=?", (operation_id,)).fetchone()


def receipt_intent(record: sqlite3.Row, proof: sqlite3.Row, operation: sqlite3.Row) -> dict:
    return {
        "request_id": record["request_id"], "grant_id": record["grant_id"], "grant_version": record["grant_version"],
        "operator_key_id": record["operator_key_id"], "service_version": record["service_version"],
        "user_id": proof["user_id"], "policy_term": proof["policy_term"], "execution_epoch": proof["execution_epoch"],
        "service_id": operation["service_id"], "action": operation["action"],
    }


def audit_execution(db: sqlite3.Connection, operation: sqlite3.Row, stage: str, reason: str) -> None:
    proof = v2_receipt(db, operation["id"])
    if proof is None:
        return
    record = db.execute("SELECT * FROM peer_receipt WHERE operation_id=?", (operation["id"],)).fetchone()
    target = db.execute("SELECT node_id FROM node WHERE singleton=1").fetchone()[0]
    record_event(db, record["peer_id"], target, stage, reason, data=receipt_intent(record, proof, operation),
                 operation_id=operation["id"], sequence=proof["policy_sequence"])


def audit_export(db: sqlite3.Connection, node_id: str, after: int, limit: int,
                 *, local_after: int = 0, conflict_after: int = 0) -> dict:
    rows = db.execute("SELECT * FROM peer_operation_audit WHERE id>? ORDER BY id LIMIT ?", (after, limit)).fetchall()
    local_events = db.execute("SELECT * FROM audit WHERE id>? ORDER BY id LIMIT ?", (local_after, limit)).fetchall()
    conflicts = db.execute("""
        SELECT rowid AS id, * FROM mesh_policy_conflict WHERE rowid>? ORDER BY rowid LIMIT ?
    """, (conflict_after, min(limit, AUDIT_CONFLICT_PAGE))).fetchall()
    anchor = mesh_policy.configured_trust(db)
    current = mesh_policy.head(db, anchor["mesh_id"]) if anchor is not None else None
    return {
        "node_id": node_id,
        "next_after": rows[-1]["id"] if rows else after,
        "events": [dict(row) for row in rows],
        "next_local_after": local_events[-1]["id"] if local_events else local_after,
        "local_events": [dict(row) for row in local_events],
        "next_conflict_after": conflicts[-1]["id"] if conflicts else conflict_after,
        "conflicts": [{**dict(row), "prior_bundle": json.loads(row["prior_bundle"]),
                       "incoming_bundle": json.loads(row["incoming_bundle"])} for row in conflicts],
        "policy_cursor": mesh_policy.cursor(db),
        "policy": json.loads(current["bundle"]) if current is not None else None,
    }


def protect_service(db: sqlite3.Connection, service_id: str) -> None:
    if get_service(db, service_id) is None:
        raise PeerError("NOT_FOUND", "Unknown service")
    if db.execute("SELECT 1 FROM operation WHERE service_id=? AND status IN ('queued','running')", (service_id,)).fetchone():
        raise PeerError("CONFLICT", "Wait for pending service operations before enabling protection")
    changed = db.execute("INSERT OR IGNORE INTO service_protection (service_id) VALUES (?)", (service_id,))
    if changed.rowcount:
        audit(db, "admin", "local", "mesh.policy.service_protected", service_id)
