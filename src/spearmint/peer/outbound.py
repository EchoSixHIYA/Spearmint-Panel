from hashlib import sha256
import json
import time

from cryptography.exceptions import InvalidSignature

from .. import auth
from ..state import State, audit
from .approval_format import ACTIONS, APPROVAL_TAG, operator_id, unpack
from .credentials import RANDOM_ID, certificate
from .pairing import Pair
from .mesh_policy import member_set
from .operation_policy import RESULT_REASONS, active_policy
from .policy import require_pair
from .policy_records import matching_grants, user_key
from .protocol import PeerError, matches, wire_b64
from .quarantine import entries as quarantine_entries


ACTIVE = {"queued", "running"}
STATUSES = ACTIVE | {"succeeded", "failed", "uncertain"}
RECEIPT_PROGRESS = {"queued": 1, "running": 2, "succeeded": 3, "failed": 3, "uncertain": 3}
# An acceptance without an operation body still needs a result lookup.
PENDING_RECEIPT = "COALESCE(json_extract(o.result, '$.operation.status'), 'queued') IN ('queued','running')"


def account_request_id(actor: auth.Actor, key: str) -> str:
    return sha256(f"account-operation\0{actor.account_id}\0{key}".encode()).hexdigest()[:32]


def actor_account(db, actor: auth.Actor):
    session = auth.active_session(db, actor.token_hash, int(time.time()))
    if session is None or session["id"] != actor.account_id:
        raise PeerError("SESSION_REQUIRED", "Sign in required")
    return session


def account_admin(db, actor: auth.Actor):
    account = actor_account(db, actor)
    if account["role"] != "node_admin" or account["csrf_token"] != actor.csrf_token:
        raise PeerError("DENIED", "Node administrator required")
    return account


def bound_user(db, account_id: str, mesh_id: str) -> str:
    row = db.execute("SELECT user_id FROM mesh_policy_account WHERE account_id=? AND mesh_id=?",
                     (account_id, mesh_id)).fetchone()
    if row is None:
        raise PeerError("DENIED", "Bind this account to a Mesh user first")
    return row["user_id"]


def source_authorization(db, pair: Pair, local_id: str, data: dict, actor: auth.Actor):
    account = actor_account(db, actor)
    if account["mfa_at"] is None:
        raise PeerError("REAUTHENTICATION_REQUIRED", "Sign in with a factor to prepare or submit an M003 approval")
    user_id = bound_user(db, account["id"], pair.mesh_id)
    if data["user_id"] != user_id:
        raise PeerError("DENIED", "Approval does not belong to this account's Mesh user")
    now = int(time.time())
    snapshot, _ = active_policy(db, pair.mesh_id, now)
    key = user_key(snapshot, user_id, data["operator_key_id"])
    grants = matching_grants(snapshot, user_id=user_id, origin=local_id, target=pair.node_id,
                             service=data["service_id"], action=data["action"], now=now)
    if key is None or len(grants) != 1:
        raise PeerError("DENIED", "No active Mesh grant for this operation")
    grant = grants[0]
    if "grant_id" in data and (data["grant_id"], data["grant_version"], data["policy_term"]) != (
        grant["id"], grant["revision"], snapshot["term"],
    ):
        raise PeerError("CONFLICT", "Source and target policy versions do not agree on this grant")
    return key


class OutboundOperations:
    def __init__(self, state: State, local_id: str) -> None:
        self.state = state
        self.local_id = local_id

    def verify(self, pair: Pair, envelope: dict, *, approved: bool, version: int = 1):
        try:
            challenge = unpack(envelope, approved=approved, version=version)
            challenge.verify_issuer(certificate(pair.remote_pem).public_key())
        except (ValueError, InvalidSignature) as exc:
            raise PeerError("DENIED", "Approval does not match the paired target signature") from exc
        data = challenge.data
        if (data["origin_node_id"] != self.local_id or data["issuer_node_id"] != pair.node_id
                or data["mesh_id"] != pair.mesh_id):
            raise PeerError("DENIED", "Approval belongs to another source or target")
        return challenge

    def scoped_intent(self, pair: Pair, intent: dict, actor: auth.Actor) -> dict:
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_pair(db, pair)
            data = {**intent, "user_id": bound_user(db, actor.account_id, pair.mesh_id)}
            source_authorization(db, pair, self.local_id, data, actor)
            return data

    def account_submission(self, pair: Pair, intent: dict, actor: auth.Actor) -> dict | None:
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_pair(db, pair)
            account_admin(db, actor)
            row = db.execute("SELECT * FROM peer_outbound WHERE peer_id=? AND request_id=?",
                             (pair.node_id, intent["request_id"])).fetchone()
            if row is None:
                return None
            if (row["service_id"], row["action"]) != (intent["service_id"], intent["action"]):
                raise PeerError("CONFLICT", "Idempotency key was used for a different request")
            return json.loads(row["result"]) if row["result"] else {"request_id": intent["request_id"], "pending": True}

    def account_receipt(self, pair: Pair, service_id: str, key: str, actor: auth.Actor) -> dict | None:
        request_id = account_request_id(actor, key)
        with self.state.connect() as db:
            db.execute("BEGIN")
            account_admin(db, actor)
            row = db.execute("""
                SELECT o.result FROM peer_outbound o LEFT JOIN peer_outbound_v2 v USING(peer_id,request_id)
                WHERE o.peer_id=? AND o.service_id=? AND o.request_id=? AND o.submitted=1 AND v.account_id IS NULL
                """, (pair.node_id, service_id, request_id)).fetchone()
        if row is None:
            return None
        return json.loads(row["result"]) if row["result"] else {"request_id": request_id, "pending": True}

    def remember_grove_receipt(self, pair: Pair, actor: auth.Actor, service_id: str, request_id: str, result: dict) -> dict:
        action = result.get('operation', {}).get('action')
        verify_receipt(result, {'request_id': request_id, 'service_id': service_id, 'action': action})
        if action not in ACTIONS:
            raise PeerError('PROTOCOL', 'Invalid Grove service operation action')
        now = int(time.time())
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            account = account_admin(db, actor)
            inserted = db.execute('''
                INSERT OR IGNORE INTO peer_outbound
                    (peer_id,request_id,service_id,action,expires_at,challenge_digest,updated_at,submitted)
                VALUES (?,?,?,?,?,?,?,1)
            ''', (pair.node_id, request_id, service_id, action, now, b'grove-admin', now)).rowcount
            if inserted:
                audit(db, account['operation_actor'], actor.address, f'peer.account.{action}.submitted', request_id)
        return self.store(pair, request_id, result)

    def approve_account(self, pair: Pair, intent: dict, envelope: dict, actor: auth.Actor) -> dict:
        challenge = self.verify(pair, envelope, approved=False)
        data = challenge.data
        if any(data[key] != value for key, value in intent.items()):
            raise PeerError("PROTOCOL", "Target returned a challenge for a different operation")
        signing_key = self.state.signing_key()
        if data["operator_key_id"] != operator_id(signing_key.public_key()):
            raise PeerError("DENIED", "Challenge does not belong to this panel")
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            account = account_admin(db, actor)
            now = int(time.time())
            signature = signing_key.sign(APPROVAL_TAG + challenge.digest)
            db.execute("""INSERT INTO peer_outbound
                (peer_id,request_id,service_id,action,expires_at,challenge_digest,updated_at,submitted)
                VALUES (?,?,?,?,?,?,?,1)""",
                (pair.node_id, data["request_id"], data["service_id"], data["action"], data["expires_at"], challenge.digest, now))
            audit(db, account["operation_actor"], actor.address, f"peer.account.{data['action']}.submitted", data["request_id"])
        return {**envelope, "operator_signature": wire_b64(signature)}

    def discard_rejected_account_submission(self, pair: Pair, request_id: str, actor: auth.Actor | None = None) -> None:
        with self.state.connect(write=True) as db:
            deleted = db.execute("DELETE FROM peer_outbound WHERE peer_id=? AND request_id=? AND result IS NULL",
                                 (pair.node_id, request_id))
            if deleted.rowcount and actor is not None:
                audit(db, actor.operation_actor, actor.address, "peer.account.directory_changed", request_id)

    def record(self, pair: Pair, intent: dict, envelope: dict, actor: auth.Actor | None = None) -> dict:
        challenge = self.verify(pair, envelope, approved=False, version=2 if actor else 1)
        data = challenge.data
        if any(data[key] != value for key, value in intent.items()):
            raise PeerError("PROTOCOL", "Target returned a challenge for a different operation")
        now = int(time.time())
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            if actor:
                source_authorization(db, pair, self.local_id, data, actor)
            db.execute("DELETE FROM peer_outbound WHERE submitted=0 AND expires_at<=?", (now,))
            db.execute("""
                INSERT INTO peer_outbound(peer_id, request_id, service_id, action, expires_at, challenge_digest, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (pair.node_id, data["request_id"], data["service_id"], data["action"], data["expires_at"],
                      challenge.digest, now))
            if actor:
                db.execute("""
                    INSERT INTO peer_outbound_v2 (peer_id,request_id,account_id,user_id) VALUES (?,?,?,?)
                """, (pair.node_id, data["request_id"], actor.account_id, data["user_id"]))
        return {"request_id": data["request_id"], "expires_at": data["expires_at"], "envelope": envelope}

    def start_submission(self, pair: Pair, service_id: str, envelope: dict, actor: auth.Actor | None = None) -> str:
        challenge = self.verify(pair, envelope, approved=True, version=2 if actor else 1)
        request_id = challenge.data["request_id"]
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            row = db.execute("""
                SELECT * FROM peer_outbound WHERE peer_id=? AND request_id=? AND service_id=?
                """, (pair.node_id, request_id, service_id)).fetchone()
            owner = db.execute("SELECT account_id FROM peer_outbound_v2 WHERE peer_id=? AND request_id=?",
                               (pair.node_id, request_id)).fetchone()
            if (row is None or row["challenge_digest"] != challenge.digest or (owner is not None) != (actor is not None)
                    or (actor is not None and owner["account_id"] != actor.account_id)):
                raise PeerError("CONFLICT", "Approval does not match an intent prepared on this panel")
            if actor:
                key = source_authorization(db, pair, self.local_id, challenge.data, actor)
                try:
                    challenge.verify_operator(key)
                except (ValueError, InvalidSignature) as exc:
                    raise PeerError("DENIED", "Invalid user approval signature") from exc
            db.execute("UPDATE peer_outbound SET submitted=1, updated_at=? WHERE peer_id=? AND request_id=?",
                       (int(time.time()), pair.node_id, request_id))
        return request_id

    def known(self, pair: Pair, service_id: str, request_id: str, actor: auth.Actor | None = None) -> None:
        with self.state.connect() as db:
            db.execute("BEGIN")
            row = db.execute("""
                SELECT v.account_id FROM peer_outbound o LEFT JOIN peer_outbound_v2 v USING(peer_id,request_id)
                WHERE o.peer_id=? AND o.service_id=? AND o.request_id=? AND o.submitted=1
                """, (pair.node_id, service_id, request_id)).fetchone()
            allowed = row is not None and self.visible(db, row["account_id"], actor)
        if not allowed:
            raise PeerError("NOT_FOUND", "Unknown operation request")

    @staticmethod
    def visible(db, owner: str | None, actor: auth.Actor | None) -> bool:
        if actor is None:
            return owner is None
        account = actor_account(db, actor)
        return owner is not None and (owner == account["id"] or account["role"] == "node_admin")

    def store(self, pair: Pair, request_id: str, payload: dict | None) -> dict | None:
        with self.state.connect(write=True) as db:
            require_pair(db, pair)
            row = db.execute("SELECT * FROM peer_outbound WHERE peer_id=? AND request_id=?",
                             (pair.node_id, request_id)).fetchone()
            if row is None:
                raise PeerError("NOT_FOUND", "Unknown operation request")
            previous = json.loads(row["result"]) if row["result"] else None
            if payload is None:
                return previous
            verify_receipt(payload, row)
            if previous:
                if previous["operation_id"] != payload["operation_id"]:
                    raise PeerError("PROTOCOL", "Target changed the operation ID for a known receipt")
                enrich = (receipt_progress(payload) == receipt_progress(previous)
                          and payload.get("operation", {}).get("status") == previous.get("operation", {}).get("status")
                          and "reason" in payload.get("operation", {}) and "reason" not in previous.get("operation", {}))
                if receipt_progress(payload) <= receipt_progress(previous) and not enrich:
                    return previous
            db.execute("UPDATE peer_outbound SET result=?, updated_at=? WHERE peer_id=? AND request_id=?",
                       (json.dumps(payload), int(time.time()), pair.node_id, request_id))
            return payload

    def pending(self, pair: Pair) -> list[tuple[str, int]]:
        with self.state.connect() as db:
            return [tuple(row) for row in db.execute(f"""
                SELECT o.request_id, CASE WHEN v.account_id IS NULL THEN 1 ELSE 2 END
                FROM peer_outbound o LEFT JOIN peer_outbound_v2 v USING(peer_id,request_id)
                WHERE o.peer_id=? AND o.submitted=1
                  AND {PENDING_RECEIPT}
                ORDER BY o.updated_at, o.request_id LIMIT 4
                """, (pair.node_id,)).fetchall()]

    def pending_page(self, pair: Pair, after: str = '') -> list[tuple[str, int]]:
        with self.state.connect() as db:
            return [tuple(row) for row in db.execute(f"""
                SELECT o.request_id, CASE WHEN v.account_id IS NULL THEN 1 ELSE 2 END
                FROM peer_outbound o LEFT JOIN peer_outbound_v2 v USING(peer_id,request_id)
                WHERE o.peer_id=? AND o.submitted=1 AND o.request_id>?
                  AND {PENDING_RECEIPT}
                ORDER BY o.request_id LIMIT 4
                """, (pair.node_id, after)).fetchall()]

    def pending_targets(self) -> list[str]:
        return sorted(self.pending_counts())

    def pending_counts(self) -> dict[str, int]:
        with self.state.connect() as db:
            return dict(db.execute(f"""
                SELECT peer_id, count(*) FROM peer_outbound o
                WHERE submitted=1 AND {PENDING_RECEIPT}
                GROUP BY peer_id ORDER BY peer_id
                """).fetchall())

    def history(self, pair: Pair, service_id: str, actor: auth.Actor | None = None, *, request_id: str | None = None) -> list[dict]:
        with self.state.connect() as db:
            db.execute("BEGIN")
            account = actor_account(db, actor) if actor else None
            rows = db.execute("""
                SELECT o.request_id, o.action, o.updated_at, CASE WHEN v.account_id IS NULL THEN o.result END AS result
                FROM peer_outbound o LEFT JOIN peer_outbound_v2 v USING(peer_id,request_id)
                WHERE o.peer_id=? AND o.service_id=? AND o.submitted=1 AND
                  ((? IS NULL AND v.account_id IS NULL) OR
                   (? IS NOT NULL AND v.account_id IS NOT NULL AND (v.account_id=? OR ?='node_admin')))
                ORDER BY (o.request_id IS ?) DESC, o.updated_at DESC, o.rowid DESC LIMIT 12
                """, (pair.node_id, service_id, account and account["id"], account and account["id"],
                      account and account["id"], account and account["role"], request_id)).fetchall()
        history = []
        for row in rows:
            entry = dict(row)
            result = entry.pop("result")
            if actor is None:
                entry["receipt"] = json.loads(result) if result is not None else None
            history.append(entry)
        return history

    def recent_history(self, actor: auth.Actor, operation: tuple[str, str, str] | None = None,
                       pending_only: bool = False, *, review_only: bool = False) -> list[dict]:
        with self.state.connect() as db:
            db.execute("BEGIN")
            account_admin(db, actor)
            scope = "AND o.peer_id=? AND o.service_id=? AND o.request_id=?" if operation else ""
            pending = f"AND {PENDING_RECEIPT}" if pending_only else ""
            review = "AND json_extract(o.result, '$.operation.status') = 'uncertain'" if review_only else ""
            rows = db.execute(f"""
                WITH recent AS (
                    SELECT o.rowid AS sequence, o.peer_id AS node_id, o.service_id,
                           o.request_id, o.action, o.updated_at, o.result
                    FROM peer_outbound o LEFT JOIN peer_outbound_v2 v USING(peer_id,request_id)
                    WHERE o.submitted=1 AND v.account_id IS NULL
                    {scope} {pending} {review}
                    ORDER BY o.updated_at DESC, o.rowid DESC LIMIT 50
                )
                SELECT recent.*, json_extract(m.entries, '$.' || recent.service_id || '.name') AS service_name
                FROM recent LEFT JOIN peer_mirror m ON m.peer_id=recent.node_id
                ORDER BY recent.updated_at DESC, recent.sequence DESC
                """, operation or ()).fetchall()
        return [{"node_id": row["node_id"], "service_id": row["service_id"], "service_name": row["service_name"],
                 "request_id": row["request_id"], "action": row["action"], "updated_at": row["updated_at"],
                 "receipt": json.loads(row["result"]) if row["result"] is not None else None} for row in rows]

    def scoped_services(self, actor: auth.Actor) -> list[dict]:
        now = int(time.time())
        with self.state.connect() as db:
            db.execute("BEGIN")
            account = actor_account(db, actor)
            binding = db.execute("SELECT mesh_id,user_id FROM mesh_policy_account WHERE account_id=?",
                                 (account["id"],)).fetchone()
            granted: dict[tuple[str, str], set[str]] = {}
            key_ids = []
            if binding is not None and account["mfa_at"] is not None:
                try:
                    snapshot, _ = active_policy(db, binding["mesh_id"], now)
                except PeerError:
                    pass
                else:
                    allowed = (member_set(db, binding["mesh_id"]) or set()) - quarantine_entries(db).keys()
                    key_ids = [entry["key_id"] for user in snapshot["users"]
                               if user["user_id"] == binding["user_id"] and user["state"] == "active"
                               for entry in user["keys"] if entry["state"] == "active"]
                    if key_ids:
                        for grant in snapshot["grants"]:
                            if (grant["user_id"] == binding["user_id"] and grant["origin_node_id"] == self.local_id
                                    and grant["target_node_id"] in allowed and now < grant["expires_at"]):
                                granted.setdefault((grant["target_node_id"], grant["service_id"]), set()).update(grant["actions"])
            history = db.execute("""
                SELECT DISTINCT o.peer_id, o.service_id FROM peer_outbound o JOIN peer_outbound_v2 v USING(peer_id,request_id)
                WHERE o.submitted=1 AND (v.account_id=? OR ?='node_admin')
                ORDER BY o.peer_id, o.service_id
            """, (account["id"], account["role"])).fetchall()
            historical = {(row["peer_id"], row["service_id"]) for row in history}
            results = []
            for node, service in sorted(granted.keys() | historical):
                mirror = db.execute("SELECT entries FROM peer_mirror WHERE peer_id=?", (node,)).fetchone()
                entry = json.loads(mirror["entries"]).get(service) if mirror is not None else None
                if entry is None and (node, service) not in historical:
                    continue
                actions = sorted(granted.get((node, service), set())) if entry is not None else []
                results.append({"node_id": node, "service_id": service, "name": entry["name"] if entry else service,
                                "version": entry["version"] if entry else 0, "actions": actions, "key_ids": key_ids})
            return results


def receipt_progress(payload: dict) -> tuple[int, int]:
    operation = payload.get("operation", {})
    return RECEIPT_PROGRESS.get(operation.get("status"), 0), operation.get("updated_at", 0)


def verify_receipt(payload: dict, request) -> None:
    fields = {"request_id", "operation_id", "accepted"}
    if (payload.keys() not in (fields, fields | {"operation"}) or payload["accepted"] is not True
            or payload["request_id"] != request["request_id"] or not matches(RANDOM_ID, payload["operation_id"])):
        raise PeerError("PROTOCOL", "Invalid target operation receipt")
    if "operation" not in payload:
        return
    operation = payload["operation"]
    required = {"id", "service_id", "action", "status", "created_at", "updated_at"}
    if (not isinstance(operation, dict) or not required <= operation.keys() <= required | {"reason"}
            or operation["id"] != payload["operation_id"] or operation["service_id"] != request["service_id"]
            or operation["action"] not in ACTIONS or operation["action"] != request["action"]
            or not isinstance(operation["status"], str) or operation["status"] not in STATUSES
            or not all(type(operation[key]) is int and 0 < operation[key] < 2**63 for key in ("created_at", "updated_at"))):
        raise PeerError("PROTOCOL", "Invalid target operation data")
    if "reason" in operation and (not isinstance(operation["reason"], str)
                                  or operation["status"] not in RESULT_REASONS.get(operation["reason"], ())):
        raise PeerError("PROTOCOL", "Invalid target operation reason")
