import json
import sqlite3
import time

from ..catalog import get_service
from ..state import State, StateError, audit
from .pairing import configured


EVENT_HISTORY = 256


def publish(db: sqlite3.Connection, service_id: str) -> None:
    affected = db.execute("""
        SELECT peer_id FROM peer_projection WHERE service_id=?
        UNION SELECT peer_id FROM peer_export WHERE service_id=?
    """, (service_id, service_id)).fetchall()
    for row in affected:
        publish_entry(db, row["peer_id"], service_id)


def publish_entry(db: sqlite3.Connection, peer_id: str, service_id: str) -> None:
    key = (peer_id, service_id)
    previous = db.execute(
        "SELECT entry FROM peer_projection WHERE peer_id=? AND service_id=?", key,
    ).fetchone()
    row = db.execute("""
        SELECT service.id, service.name, service.driver, service.version, service.managed, peer_export.status, peer_export.logs
        FROM service JOIN peer_export ON service.id=peer_export.service_id
        WHERE peer_export.peer_id=? AND service.id=? AND peer_export.directory=1
        """, key).fetchone()
    actions = set()
    if row and row["managed"]:
        grants = db.execute("""
            SELECT actions FROM peer_grant WHERE peer_id=? AND service_id=? AND enabled=1 AND expires_at>?
            """, (*key, int(time.time())))
        for grant in grants:
            actions.update(json.loads(grant["actions"]))
    entry = json.dumps({
        "id": row["id"], "name": row["name"], "driver": row["driver"], "version": row["version"],
        "status": bool(row["status"]), "logs": bool(row["logs"]), "actions": sorted(actions),
    }, ensure_ascii=False, separators=(",", ":")) if row else None
    if entry == (previous["entry"] if previous else None):
        return
    if entry is None:
        db.execute("DELETE FROM peer_projection WHERE peer_id=? AND service_id=?", key)
    else:
        db.execute("""
            INSERT INTO peer_projection VALUES (?, ?, ?)
            ON CONFLICT(peer_id, service_id) DO UPDATE SET entry=excluded.entry
            """, (*key, entry))
    revision = db.execute("""
        UPDATE peer_directory SET revision=revision+1 WHERE peer_id=? RETURNING revision
        """, (peer_id,)).fetchone()["revision"]
    db.execute("INSERT INTO peer_event VALUES (?, ?, ?, ?)", (peer_id, revision, service_id, entry))
    db.execute("DELETE FROM peer_event WHERE peer_id=? AND revision<=?", (peer_id, revision - EVENT_HISTORY))


def export_service(state: State, service_id: str, *, directory: bool, status: bool, logs: bool,
                   node_id: str | None = None) -> None:
    with state.connect(write=True) as db:
        pair = configured(db, node_id)
        if pair is None:
            raise StateError("Configure a peer before exporting services")
        service = get_service(db, service_id)
        if service is None:
            raise StateError("Unknown service ID")
        if logs and not service.logs_available:
            raise StateError("Windows service application logs are not available through SCM")
        event = set_export(db, pair.node_id, service_id, directory=directory, status=status, logs=logs)
        publish(db, service_id)
        audit(db, "admin", "local", event, service_id)


def set_export(db: sqlite3.Connection, node_id: str, service_id: str, *,
               directory: bool, status: bool, logs: bool) -> str:
    key = (node_id, service_id)
    previous = db.execute("SELECT directory FROM peer_export WHERE peer_id=? AND service_id=?", key).fetchone()
    if previous and previous["directory"] and not directory:
        db.execute("UPDATE peer_grant SET version=version+1 WHERE peer_id=? AND service_id=?", key)
    if directory or status or logs:
        db.execute("""
            INSERT INTO peer_export VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(peer_id, service_id) DO UPDATE SET
                directory=excluded.directory, status=excluded.status, logs=excluded.logs
            """, (*key, directory, status, logs))
        return "peer.service.exported"
    db.execute("DELETE FROM peer_export WHERE peer_id=? AND service_id=?", key)
    return "peer.service.unexported"
