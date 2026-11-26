import json
from math import isfinite
import sqlite3

from ..catalog import ACTIONS, MAX_SERVICES
from .credentials import RANDOM_ID
from .projection import EVENT_HISTORY
from .protocol import CATALOG, PeerError, matches


STATUSES = {"running", "stopped", "starting", "stopping", "failed", "missing", "unknown"}
DRIVERS = {"process", "docker"}
HEALTH_STATES = ("starting", "healthy", "unhealthy")
CATALOG_HEALTH_METHOD = "catalog.sync.v2"
GROVE_CATALOG_METHOD = 'grove.service_inventory.v1'
STATUS_HEALTH_METHOD = "service.status.v2"
MAX_REVISION = 2**63 - 1


def revision(value) -> bool:
    return type(value) is int and 0 <= value <= MAX_REVISION


def observation(data: dict, ttl: int, *, include_health: bool = False) -> dict:
    checked = data["checked_at"]
    result = {
        "status": data["status"], "source": data["source"], "checked_at": checked,
        "last_seen_at": data["last_seen_at"], "last_status": data["last_status"],
        "valid_until": checked + ttl if checked is not None else None, "stale": data["stale"],
    }
    if include_health and not result["stale"] and data.get("health") in HEALTH_STATES:
        result["health"] = data["health"]
    return result


def catalog_result(db: sqlite3.Connection, peer_id: str, owner_id: str, params: dict, observe) -> dict:
    if (params.keys() != {"epoch", "revision"} or not revision(params["revision"])
            or (params["epoch"] is None and params["revision"] != 0)
            or (params["epoch"] is not None and not matches(RANDOM_ID, params["epoch"]))):
        raise PeerError("INVALID_REQUEST", "Invalid directory cursor")
    cursor = db.execute("SELECT epoch, revision FROM peer_directory WHERE peer_id=?", (peer_id,)).fetchone()
    records = db.execute("""
        SELECT service_id, entry FROM peer_projection WHERE peer_id=? ORDER BY service_id
        """, (peer_id,)).fetchall()
    encoded = {row["service_id"]: row["entry"] for row in records}
    entries = {service_id: json.loads(entry) for service_id, entry in encoded.items()}
    result = {
        "owner_node_id": owner_id, "epoch": cursor["epoch"], "revision": cursor["revision"],
        "observations": {key: observe(key) for key, entry in entries.items() if entry["status"]},
    }
    base = params["revision"]
    if params["epoch"] == cursor["epoch"]:
        if base == cursor["revision"]:
            return {**result, "mode": "unchanged"}
        if 0 < cursor["revision"] - base <= EVENT_HISTORY:
            changes = db.execute("""
                SELECT revision, service_id, entry FROM peer_event WHERE peer_id=? AND revision>?
                ORDER BY revision
                """, (peer_id, base)).fetchall()
            # A historical upsert may contain metadata the peer can no longer read.
            if len(changes) == cursor["revision"] - base and all(
                row["entry"] is None or encoded.get(row["service_id"]) == row["entry"] for row in changes
            ):
                delta = {**result, "mode": "delta", "base": base, "events": [
                    {"revision": row["revision"], "id": row["service_id"], "entry": json.loads(row["entry"]) if row["entry"] else None}
                    for row in changes
                ]}
                if len(json.dumps(delta, ensure_ascii=False, separators=(",", ":")).encode()) + 128 <= CATALOG:
                    return delta
    return {**result, "mode": "snapshot", "entries": list(entries.values())}


def valid_entry(entry, key: str) -> bool:
    return (isinstance(entry, dict) and entry.keys() == {"id", "name", "driver", "version", "status", "logs", "actions"}
            and entry["id"] == key and isinstance(entry["name"], str)
            and 0 < len(entry["name"]) <= 80 and entry["name"].isprintable()
            and isinstance(entry["driver"], str) and entry["driver"] in DRIVERS
            and revision(entry["version"]) and entry["version"] > 0
            and type(entry["status"]) is bool and type(entry["logs"]) is bool
            and isinstance(entry["actions"], list) and len(entry["actions"]) <= len(ACTIONS)
            and all(action in ACTIONS for action in entry["actions"])
            and len(set(entry["actions"])) == len(entry["actions"]))


def valid_observation(data) -> bool:
    required = {
        "status", "source", "checked_at", "last_seen_at", "last_status", "valid_until", "stale",
    }
    return (isinstance(data, dict) and required <= data.keys() <= required | {"health"}
        and ("health" not in data or data["health"] in HEALTH_STATES)
        and isinstance(data["status"], str) and data["status"] in STATUSES
        and isinstance(data["source"], str) and data["source"] in DRIVERS
        and (data["last_status"] is None or isinstance(data["last_status"], str) and data["last_status"] in STATUSES)
        and type(data["stale"]) is bool
        and all(value is None or type(value) in {int, float} and 0 <= value <= MAX_REVISION and isfinite(value)
                for value in (data["checked_at"], data["last_seen_at"], data["valid_until"])))


def mirror_row(db: sqlite3.Connection, peer_id: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM peer_mirror WHERE peer_id=?", (peer_id,)).fetchone()


def validate_result(row: sqlite3.Row | None, peer_id: str, result: dict) -> tuple[dict, dict]:
    mode = result.get("mode")
    common = {"owner_node_id", "epoch", "revision", "observations", "mode"}
    if (result.get("owner_node_id") != peer_id or not matches(RANDOM_ID, result.get("epoch"))
            or not revision(result.get("revision")) or not isinstance(result.get("observations"), dict)):
        raise PeerError("PROTOCOL", "Invalid remote directory identity or cursor")
    version = result["revision"]
    same_epoch = row is not None and row["epoch"] == result["epoch"]
    if same_epoch and version < row["revision"]:
        raise PeerError("PROTOCOL", "Remote directory revision moved backwards")
    if mode == "snapshot" and result.keys() == common | {"entries"} and isinstance(result["entries"], list):
        entries = {}
        for entry in result["entries"]:
            key = entry.get("id") if isinstance(entry, dict) else None
            if not matches(RANDOM_ID, key) or key in entries or not valid_entry(entry, key):
                raise PeerError("PROTOCOL", "Invalid remote directory entry")
            entries[key] = entry
        if same_epoch and version == row["revision"] and entries != json.loads(row["entries"]):
            raise PeerError("PROTOCOL", "Remote directory changed without a revision")
    elif mode == "delta" and result.keys() == common | {"base", "events"} and same_epoch:
        events = result["events"]
        base = row["revision"]
        if (not revision(result["base"]) or result["base"] != base or not isinstance(events, list)
                or not 0 < len(events) <= EVENT_HISTORY or version != base + len(events)):
            raise PeerError("PROTOCOL", "Remote directory delta is not contiguous")
        entries = json.loads(row["entries"])
        for number, event in enumerate(events, base + 1):
            if (not isinstance(event, dict) or event.keys() != {"revision", "id", "entry"}
                    or not revision(event["revision"]) or event["revision"] != number
                    or not matches(RANDOM_ID, event["id"])):
                raise PeerError("PROTOCOL", "Invalid remote directory event")
            key, entry = event["id"], event["entry"]
            if entry is None:
                entries.pop(key, None)
            elif valid_entry(entry, key):
                entries[key] = entry
            else:
                raise PeerError("PROTOCOL", "Invalid remote directory upsert")
    elif mode == "unchanged" and result.keys() == common and same_epoch and version == row["revision"]:
        entries = json.loads(row["entries"])
    else:
        raise PeerError("PROTOCOL", "Unexpected remote directory response")
    if len(entries) > MAX_SERVICES:
        raise PeerError("PROTOCOL", "Remote directory service limit exceeded")
    observations = result["observations"].copy()
    for key, value in observations.items():
        if key not in entries or not entries[key]["status"] or not valid_observation(value) or value["source"] != entries[key]["driver"]:
            raise PeerError("PROTOCOL", "Invalid remote service observation")
    if same_epoch:
        old = json.loads(row["observations"])
        for key, value in observations.items():
            previous = old.get(key)
            if previous and previous["checked_at"] is not None and (value["checked_at"] or 0) < previous["checked_at"]:
                observations[key] = previous
    return entries, observations


def apply_result(db: sqlite3.Connection, peer_id: str, result: dict) -> None:
    entries, observations = validate_result(mirror_row(db, peer_id), peer_id, result)
    db.execute("""
        INSERT INTO peer_mirror VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(peer_id) DO UPDATE SET epoch=excluded.epoch, revision=excluded.revision,
            entries=excluded.entries, observations=excluded.observations
        """, (peer_id, result["epoch"], result["revision"], json.dumps(entries), json.dumps(observations)))
