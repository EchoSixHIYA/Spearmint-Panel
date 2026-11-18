from contextlib import suppress
from hashlib import sha256
import json
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import auth
from ..catalog import Service, get_service
from ..control import Controller, ControlError, operation_data
from ..drivers import SystemUnitDriver, TRANSITIONAL
from ..state import State, StateError, audit
from ..windows_services import WindowsServiceDriver
from .approval_format import ACTIONS, CHALLENGE_TAGS, CHALLENGE_TTL, OPERATOR_ID, USER_ID, operator_id, unpack
from .credentials import RANDOM_ID, certificate
from .directory import revision
from .grove_service_admin import GROVE_REQUEST, OPERATION_KEY, GroveServiceAdmin, operation_origin
from .pairing import Pair, configured, members
from . import operation_policy as scoped
from .policy import action_grant, credentials_current, disable_grant, require_pair, save_grant
from .projection import publish, set_export
from .protocol import PeerError, decode_json, matches, wire_b64


ACCOUNT_ACTIONS = "operation.account_actions"
ACCOUNT_ACTIONS_EXPLAIN = "operation.account_actions.v2"
ACCOUNT_ACTIONS_VERSION = "operation.account_actions.v3"
ACCOUNT_ACTION_REASONS = {"observe", "no-grant", "approval-required", "host-unavailable", "registration-changed"}
RECEIPT_REASON_METHODS = {"operation.get": "operation.get_reason", "operation.v2.get": "operation.v2.get_reason"}
OPERATIONS = {"operation.prepare", "operation.submit", "operation.get",
              "operation.v2.prepare", "operation.v2.submit", "operation.v2.get", "security.capabilities",
              ACCOUNT_ACTIONS, ACCOUNT_ACTIONS_EXPLAIN, ACCOUNT_ACTIONS_VERSION, *RECEIPT_REASON_METHODS.values()}
MAX_CHALLENGES = 16
EXPORT_PERMISSIONS = ("directory", "status", "logs")


def require_active(db: sqlite3.Connection, pair: Pair) -> str:
    require_pair(db, pair)
    if not credentials_current(pair):
        raise PeerError("OFFLINE", "Peer credentials have expired")
    return pair.write_epoch


def account_grant(db: sqlite3.Connection, pair: Pair, service_id: str) -> sqlite3.Row | None:
    key_id = operator_id(certificate(pair.remote_pem).public_key())
    return db.execute("""SELECT id, version, actions, expires_at, enabled FROM peer_grant
                         WHERE peer_id=? AND service_id=? AND operator_key_id=?""",
                      (pair.node_id, service_id, key_id)).fetchone()


def effective_account_actions(service: Service, grant: sqlite3.Row | None, protected: bool, now: float) -> list[str]:
    if protected or not service.actions:
        return []
    granted = set(json.loads(grant["actions"])) if grant and grant["enabled"] and grant["expires_at"] > now else set()
    return [action for action in service.actions if action in granted]


def export_flags(export: sqlite3.Row | None) -> dict[str, bool]:
    return {key: bool(export and export[key]) for key in EXPORT_PERMISSIONS}


def access_revision(pair: Pair, service: Service, permissions: dict[str, bool], grant: sqlite3.Row | None,
                    protected: bool) -> str:
    values = (pair.node_id, pair.write_epoch, service.id, service.version, permissions,
              (grant["id"], grant["version"]) if grant else None, protected)
    return sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def service_access(state: State, service_id: str) -> dict:
    with state.connect() as db:
        db.execute("BEGIN")
        sampled_at = int(time.time())
        service = get_service(db, service_id)
        if service is None:
            raise PeerError("NOT_FOUND", "Unknown service ID")
        protected = scoped.required_version(db, service_id) == 2
        exports = {row["peer_id"]: row for row in db.execute(
            "SELECT * FROM peer_export WHERE service_id=?", (service_id,))}
        peers = []
        for node, pair in members(db).items():
            permissions = export_flags(exports.get(node))
            grant = account_grant(db, pair, service_id)
            try:
                require_active(db, pair)
            except PeerError:
                active = False
            else:
                active = True
            peers.append({
                "node_id": node, "host": pair.host, "active": active, **permissions,
                "actions": effective_account_actions(service, grant, protected, sampled_at) if permissions["directory"] and active else [],
                "configured_account_actions": json.loads(grant["actions"]) if grant and grant["enabled"] else [],
                "account_grant_expires_at": grant["expires_at"] if grant and grant["enabled"] else None,
                "revision": access_revision(pair, service, permissions, grant, protected),
            })
        return {"service_version": service.version, "sampled_at": sampled_at,
                "independent_approval": protected, "available_actions": service.actions,
                "logs_available": service.logs_available, "peers": peers}


def change_service_access(state: State, service_id: str, node_id: str, actor: auth.Actor, *, revision: str,
                          permissions: dict[str, bool], actions: list[str] | None, hours: int | None) -> None:
    with state.connect(write=True) as db:
        now = int(time.time())
        session = auth.active_session(db, actor.token_hash, now)
        if session is None or session["id"] != actor.account_id:
            raise PeerError("SESSION_REQUIRED", "Sign in required")
        if session["role"] != "node_admin":
            raise PeerError("DENIED", "Node administrator required")
        pair, service = configured(db, node_id), get_service(db, service_id)
        if pair is None or service is None:
            raise PeerError("NOT_FOUND", "Unknown service or peer")
        previous = export_flags(db.execute("SELECT * FROM peer_export WHERE peer_id=? AND service_id=?",
                                           (node_id, service_id)).fetchone())
        grant = account_grant(db, pair, service_id)
        protected = scoped.required_version(db, service_id) == 2
        if revision != access_revision(pair, service, previous, grant, protected):
            raise PeerError("CONFLICT", "Access settings changed. Reopen the editor and try again")
        if actions or any(permissions[key] and not previous[key] for key in EXPORT_PERMISSIONS):
            try:
                require_active(db, pair)
            except PeerError as error:
                raise PeerError("CONFLICT", "Enable this peer before expanding its access") from error
        if actions and protected:
            raise PeerError("APPROVAL_VERSION_REQUIRED", "This service requires an independent M003 approval")
        if permissions["logs"] and not service.logs_available:
            raise PeerError("INVALID_REQUEST", "Windows service application logs are not available through SCM")
        if bool(actions) != (hours is not None) or (actions and not permissions["directory"]):
            raise PeerError("INVALID_REQUEST", "Account actions need directory access and a grant duration")
        if permissions != previous:
            event = set_export(db, node_id, service_id, **permissions)
            audit(db, actor.operation_actor, actor.address, event, service_id, reason=node_id)
        if actions:
            assert hours is not None
            try:
                grant_id = save_grant(db, pair, service, None, actions, now + hours * 3600, True)
            except StateError as error:
                raise PeerError("INVALID_REQUEST", str(error)) from error
            audit(db, actor.operation_actor, actor.address, "peer.grant.account_added", grant_id, reason=node_id)
        elif (actions == [] or previous["directory"] != permissions["directory"]) and grant:
            if disable_grant(db, grant["id"]) is not None:
                audit(db, actor.operation_actor, actor.address, "peer.grant.revoked", grant["id"], reason=node_id)
        publish(db, service_id)


def grove_operation_receipt(db, row, request_id: str) -> dict:
    result = operation_data(row, db=db)
    result.pop('message', None)
    return {'request_id': request_id, 'operation_id': row['id'], 'accepted': True, 'operation': result}


def grove_operation_row(db, origin: str, request_id: str):
    return db.execute(f'SELECT * FROM operation WHERE source=? AND {GROVE_REQUEST}',
                      (origin, request_id)).fetchone()


def grove_service_for(db, service_id: str) -> Service:
    service = get_service(db, service_id)
    if service is None:
        raise PeerError('NOT_FOUND', 'Unknown service')
    return service


def result_access(db: sqlite3.Connection, record: sqlite3.Row) -> bool:
    row = db.execute("""
        SELECT 1 FROM peer_grant WHERE id=? AND peer_id=? AND operator_key_id=?
            AND enabled=1 AND read_result=1 AND expires_at>?
        """, (record["grant_id"], record["peer_id"], record["operator_key_id"], int(time.time()))).fetchone()
    return row is not None


def receipt(db: sqlite3.Connection, record: sqlite3.Row, pair: Pair, target: str, *, require_read: bool = True,
            include_reason: bool = False) -> dict:
    payload = {"request_id": record["request_id"], "operation_id": record["operation_id"], "accepted": True}
    row = db.execute("SELECT * FROM operation WHERE id=?", (record["operation_id"],)).fetchone()
    proof = scoped.v2_receipt(db, record["operation_id"])
    if proof is None:
        allowed = result_access(db, record)
    else:
        try:
            scoped.authorize(db, pair.mesh_id, pair.node_id, target, scoped.receipt_intent(record, proof, row),
                             int(time.time()), reading=True)
        except PeerError:
            allowed = False
        else:
            allowed = True
    if not allowed:
        if require_read:
            raise PeerError("NOT_FOUND", "Operation result is unavailable to this peer")
        return payload
    operation = operation_data(row)
    # Driver diagnostics can include private paths. The owning node retains the original message.
    operation.pop("message")
    if include_reason and row["status"] in {"failed", "uncertain"}:
        if reason := scoped.operation_result_reason(db, row):
            operation["reason"] = reason
    return {**payload, "operation": operation}


class PeerOperations:
    def __init__(self, state: State, local_id: str, name: str, controller: Controller) -> None:
        self.state = state
        self.local_id = local_id
        self.name = name[:255]
        self.controller = controller

    def handle(self, pair: Pair, method: str, params: dict) -> dict:
        version = 2 if method.startswith("operation.v2.") else 1
        context: dict = {}
        try:
            match method:
                case "operation.prepare" | "operation.v2.prepare":
                    return self.prepare(pair, params, version, audit_context=context)
                case "operation.submit" | "operation.v2.submit":
                    return self.submit(pair, params, version, audit_context=context)
                case "operation.get" | "operation.v2.get" | "operation.get_reason" | "operation.v2.get_reason":
                    return self.get(pair, params, version, audit_context=context, include_reason=method.endswith("get_reason"))
                case "security.capabilities":
                    return self.capabilities(pair, params)
                case "operation.account_actions" | "operation.account_actions.v2":
                    return self.account_actions(pair, params, explain=method == ACCOUNT_ACTIONS_EXPLAIN)
                case "operation.account_actions.v3":
                    return self.account_actions(pair, params, explain=True, check_version=True)
            raise PeerError("UNSUPPORTED_METHOD", "Unsupported Peer RPC method")
        except PeerError as exc:
            if version == 2 or exc.code == "APPROVAL_VERSION_REQUIRED":
                with suppress(sqlite3.Error), self.state.connect(write=True) as db:
                    scoped.record_event(db, pair.node_id, self.local_id, "rejected", exc.code, data=context,
                                        operation_id=context.get("operation_id"), sequence=context.get("policy_sequence"))
            raise

    def capabilities(self, pair: Pair, params: dict) -> dict:
        if params.keys() != {"service_id"} or not matches(RANDOM_ID, params["service_id"]):
            raise PeerError("INVALID_REQUEST", "Invalid service ID")
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_active(db, pair)
            scoped.exported_service(db, pair.node_id, params["service_id"])
            required = scoped.required_version(db, params["service_id"])
            return {"approval_versions": [2] if required == 2 else [1, 2], "required_approval_version": required}

    @staticmethod
    def account_availability(db: sqlite3.Connection, pair: Pair, service: Service) -> dict:
        if scoped.required_version(db, service.id) == 2:
            return {"actions": [], "reason": "approval-required"}
        if not service.actions:
            return {"actions": [], "reason": "observe"}
        actions = effective_account_actions(service, account_grant(db, pair, service.id), False, time.time())
        return {"actions": actions} if actions else {"actions": [], "reason": "no-grant"}

    def host_ready(self, service: Service) -> bool:
        if service.existing_systemd_unit:
            return SystemUnitDriver.management_status(service.target, timeout=1, host_permissions=service.host_permissions)["ready"]
        if service.existing_windows_service:
            return WindowsServiceDriver(self.state).management_status(service.target, host_permissions=service.host_permissions)["ready"]
        observation = self.controller.describe(service)["observation"]
        return not observation["stale"] and observation["status"] not in {*TRANSITIONAL, "unknown", "missing"}

    def grove_actions(self, actor: GroveServiceAdmin, service_id: str, version: int | None) -> dict:
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
            service = grove_service_for(db, service_id)
            if version is not None and version != service.version:
                return {'actions': [], 'reason': 'registration-changed'}
            if not service.actions:
                return {'actions': [], 'reason': 'observe'}
        if not self.host_ready(service):
            return {'actions': [], 'reason': 'host-unavailable'}
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
            if grove_service_for(db, service_id) != service:
                return {'actions': [], 'reason': 'registration-changed'}
        return {'actions': list(service.actions)}

    def grove_submit(self, actor: GroveServiceAdmin, service_id: str, intent: dict) -> dict:
        request_id = intent['request_id']
        action = intent['action']
        version = intent['service_version']
        with self.state.connect(write=True) as db:
            actor.require(db)
            if row := grove_operation_row(db, actor.address, request_id):
                expected = OPERATION_KEY.fullmatch(row['request_key'])
                if (expected is None or (row['actor'], row['service_id'], row['action'], int(expected[1]))
                        != (actor.operation_actor, service_id, action, version)):
                    raise PeerError('CONFLICT', 'Idempotency key was used for another operation')
                return grove_operation_receipt(db, row, request_id)
            grove_service_for(db, service_id)
            try:
                result = self.controller.enqueue(db, service_id, action, actor.operation_key(version, request_id),
                                                 actor.operation_actor, actor.address, int(time.time()), remote=True,
                                                 service_version=version)
            except ControlError as error:
                codes = {403: 'DENIED', 404: 'NOT_FOUND', 409: 'CONFLICT'}
                raise PeerError(codes.get(error.status, 'BUSY'), str(error)) from error
            row = db.execute('SELECT * FROM operation WHERE id=?', (result['id'],)).fetchone()
            return grove_operation_receipt(db, row, request_id)

    def grove_receipt(self, actor: GroveServiceAdmin, service_id: str, request_id: str) -> dict | None:
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
            row = grove_operation_row(db, actor.address, request_id)
            if (row is None or row['actor'] != actor.operation_actor or row['service_id'] != service_id
                    or not operation_origin(db, row, self.local_id)):
                return None
            return grove_operation_receipt(db, row, request_id)

    def account_actions(self, pair: Pair, params: dict, *, explain: bool = False, check_version: bool = False) -> dict:
        fields = {"service_id", "service_version"} if check_version else {"service_id"}
        version = params.get("service_version")
        if (params.keys() != fields or not matches(RANDOM_ID, params["service_id"])
                or (check_version and (not revision(version) or version == 0))):
            raise PeerError("INVALID_REQUEST", "Invalid service ID or version")
        service_id = params["service_id"]
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_active(db, pair)
            service = scoped.exported_service(db, pair.node_id, service_id)
            if check_version and service.version != version:
                return {"actions": [], "reason": "registration-changed"}
            result = self.account_availability(db, pair, service)
        if result["actions"] and (service.existing_system_service or service.driver == "docker"):
            ready = self.host_ready(service)
            # Recheck the grant and registration after the host query.
            with self.state.connect() as db:
                db.execute("BEGIN")
                require_active(db, pair)
                current = scoped.exported_service(db, pair.node_id, service_id)
                result = (self.account_availability(db, pair, current) if current == service
                          else {"actions": [], "reason": "registration-changed"})
            if result["actions"] and not ready:
                result = {"actions": [], "reason": "host-unavailable"}
        return result if explain else {"actions": result["actions"]}

    def prepare(self, pair: Pair, intent: dict, version: int = 1, *, audit_context: dict | None = None) -> dict:
        fields = {"service_id", "service_version", "action", "operator_key_id", "request_id"}
        if version == 2:
            fields.add("user_id")
        if (intent.keys() != fields
                or not matches(RANDOM_ID, intent["service_id"]) or not matches(RANDOM_ID, intent["request_id"])
                or not revision(intent["service_version"]) or intent["service_version"] == 0
                or intent["action"] not in ACTIONS or not matches(OPERATOR_ID, intent["operator_key_id"])
                or (version == 2 and not matches(USER_ID, intent["user_id"]))):
            raise PeerError("INVALID_REQUEST", "Invalid operation intent")
        if audit_context is not None:
            audit_context.update(intent)
        with self.state.connect(write=True) as db:
            epoch = require_active(db, pair)
            now = int(time.time())
            if version == 1 and scoped.required_version(db, intent["service_id"]) == 2:
                scoped.exported_service(db, pair.node_id, intent["service_id"])
            scoped.require_version(db, intent["service_id"], version)
            context = {}
            sequence = None
            expires = now + CHALLENGE_TTL
            if version == 2:
                grant, service, _, snapshot, execution_epoch = scoped.authorize(
                    db, pair.mesh_id, pair.node_id, self.local_id, intent, now,
                )
                grant_version = grant["revision"]
                context = {"policy_term": snapshot["term"], "execution_epoch": execution_epoch}
                sequence = snapshot["sequence"]
                expires = min(expires, grant["expires_at"], snapshot["expires_at"])
                if audit_context is not None:
                    audit_context.update(policy_term=snapshot["term"], policy_sequence=sequence,
                                         grant_id=grant["id"], grant_version=grant_version)
            else:
                grant, service = action_grant(db, pair.node_id, intent["service_id"], intent["operator_key_id"],
                                              intent["action"], intent["service_version"])
                grant_version = grant["version"]
            key = (pair.node_id, intent["request_id"])
            if db.execute("SELECT 1 FROM peer_receipt WHERE peer_id=? AND request_id=?", key).fetchone():
                raise PeerError("CONFLICT", "This request already has a receipt")
            db.execute("DELETE FROM peer_challenge WHERE expires_at<=?", (now,))
            previous = db.execute("SELECT * FROM peer_challenge WHERE peer_id=? AND request_id=?", key).fetchone()
            if previous:
                data = decode_json(previous["raw"])
                if (data["version"] != version or any(data.get(name) != value for name, value in (intent | context).items())
                        or data["grant_id"] != grant["id"] or data["grant_version"] != grant_version
                        or previous["write_epoch"] != epoch):
                    raise PeerError("CONFLICT", "Request ID already used for another challenge")
                raw, digest = previous["raw"], previous["digest"]
            else:
                count = db.execute("SELECT count(*) FROM peer_challenge WHERE peer_id=?", (pair.node_id,)).fetchone()[0]
                if count >= MAX_CHALLENGES:
                    raise PeerError("BUSY", "Too many outstanding operation challenges")
                data = {
                    **intent, **context, "version": version, "mesh_id": pair.mesh_id, "issuer_node_id": self.local_id,
                    "origin_node_id": pair.node_id, "grant_id": grant["id"], "grant_version": grant_version,
                    "target_name": self.name, "service_name": service.name, "params": {},
                    "challenge_id": secrets.token_hex(16), "issued_at": now, "expires_at": expires,
                }
                raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                digest = sha256(raw).digest()
                db.execute("INSERT INTO peer_challenge VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (data["challenge_id"], *key, epoch, raw, digest, data["expires_at"]))
                audit(db, intent["operator_key_id"], pair.node_id, "peer.challenge.issued", data["challenge_id"])
                if version == 2:
                    scoped.record_event(db, pair.node_id, self.local_id, "prepared", "OK", data=data, sequence=sequence)
            signature = self.state.signing_key().sign(CHALLENGE_TAGS[version] + digest)
        return {"challenge": wire_b64(raw), "issuer_signature": wire_b64(signature)}

    def submit(self, pair: Pair, envelope: dict, version: int = 1, *, audit_context: dict | None = None) -> dict:
        try:
            challenge = unpack(envelope, approved=True, version=version)
            if audit_context is not None:
                audit_context["request_id"] = challenge.data["request_id"]
            challenge.verify_issuer(self.state.signing_key().public_key())
        except (ValueError, InvalidSignature) as exc:
            raise PeerError("DENIED", "Invalid operation approval") from exc
        data = challenge.data
        if (data["mesh_id"] != pair.mesh_id or data["origin_node_id"] != pair.node_id
                or data["issuer_node_id"] != self.local_id):
            raise PeerError("DENIED", "Approval belongs to another source or target")
        if audit_context is not None:
            audit_context.update(data)
        with self.state.connect(write=True) as db:
            epoch = require_active(db, pair)
            key = (pair.node_id, data["request_id"])
            if version == 1:
                public = db.execute("SELECT public_key FROM operator_key WHERE id=?", (data["operator_key_id"],)).fetchone()
                try:
                    if public is None:
                        raise ValueError("Unknown operator key")
                    challenge.verify_operator(Ed25519PublicKey.from_public_bytes(public["public_key"]))
                except (ValueError, InvalidSignature) as exc:
                    raise PeerError("DENIED", "Invalid operator signature") from exc
            approved = challenge.approval_digest()
            previous = db.execute("SELECT * FROM peer_receipt WHERE peer_id=? AND request_id=?", key).fetchone()
            if previous:
                proof = scoped.v2_receipt(db, previous["operation_id"])
                if audit_context is not None:
                    audit_context["operation_id"] = previous["operation_id"]
                    if proof is not None:
                        audit_context["policy_sequence"] = proof["policy_sequence"]
                if previous["approval_digest"] != approved or (proof is not None) != (version == 2):
                    raise PeerError("CONFLICT", "Request ID already accepted with a different approval")
                result = receipt(db, previous, pair, self.local_id)
                if proof is not None:
                    scoped.record_event(db, pair.node_id, self.local_id, "replayed", "SAME_APPROVAL",
                                        data=data, operation_id=previous["operation_id"], sequence=proof["policy_sequence"])
                return result
            scoped.require_version(db, data["service_id"], version)
            now = int(time.time())
            if not data["issued_at"] <= now < data["expires_at"]:
                raise PeerError("EXPIRED", "The operation challenge has expired")
            issued = db.execute("SELECT * FROM peer_challenge WHERE id=? AND peer_id=? AND request_id=?",
                                (data["challenge_id"], *key)).fetchone()
            if (issued is None or issued["raw"] != challenge.raw or issued["digest"] != challenge.digest
                    or issued["write_epoch"] != epoch):
                raise PeerError("DENIED", "The operation challenge is no longer active")
            if version == 2:
                _, _, public_key, snapshot, execution_epoch = scoped.authorize(
                    db, pair.mesh_id, pair.node_id, self.local_id, data, now,
                )
                if audit_context is not None:
                    audit_context["policy_sequence"] = snapshot["sequence"]
                try:
                    challenge.verify_operator(public_key)
                except (ValueError, InvalidSignature) as exc:
                    raise PeerError("DENIED", "Invalid operator signature") from exc
            else:
                grant, _ = action_grant(db, pair.node_id, data["service_id"], data["operator_key_id"],
                                        data["action"], data["service_version"])
                if (grant["id"], grant["version"]) != (data["grant_id"], data["grant_version"]):
                    raise PeerError("CONFLICT", "The operator grant changed after the challenge was issued")
            try:
                operation = Controller.enqueue(db, data["service_id"], data["action"], ":".join(key),
                                               data.get("user_id", data["operator_key_id"]), pair.node_id, now, remote=True)
            except ControlError as exc:
                code = {403: "DENIED", 404: "NOT_FOUND", 409: "CONFLICT"}.get(exc.status, "BUSY")
                raise PeerError(code, str(exc)) from exc
            row = db.execute("""
                INSERT INTO peer_receipt VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *
                """, (*key, operation["id"], data["operator_key_id"], data["grant_id"], data["grant_version"],
                      data["service_version"], epoch, approved)).fetchone()
            if version == 2:
                db.execute("""
                    INSERT INTO peer_receipt_v2 (operation_id,user_id,policy_term,policy_sequence,execution_epoch)
                    VALUES (?,?,?,?,?)
                """, (operation["id"], data["user_id"], snapshot["term"], snapshot["sequence"], execution_epoch))
                scoped.record_event(db, pair.node_id, self.local_id, "accepted", "OK", data=data,
                                    operation_id=operation["id"], sequence=snapshot["sequence"])
            db.execute("DELETE FROM peer_challenge WHERE id=?", (data["challenge_id"],))
            audit(db, data["operator_key_id"], pair.node_id, "peer.receipt.accepted", operation["id"])
            return receipt(db, row, pair, self.local_id, require_read=False)

    def get(self, pair: Pair, params: dict, version: int = 1, *, audit_context: dict | None = None,
            include_reason: bool = False) -> dict:
        if params.keys() != {"request_id"} or not matches(RANDOM_ID, params["request_id"]):
            raise PeerError("INVALID_REQUEST", "Invalid operation request ID")
        if audit_context is not None:
            audit_context["request_id"] = params["request_id"]
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_active(db, pair)
            record = db.execute("SELECT * FROM peer_receipt WHERE peer_id=? AND request_id=?",
                                (pair.node_id, params["request_id"])).fetchone()
            if record is None and version == 1:
                row = grove_operation_row(db, pair.node_id, params['request_id'])
                if row is not None and operation_origin(db, row, self.local_id):
                    return grove_operation_receipt(db, row, params['request_id'])
            proof = scoped.v2_receipt(db, record["operation_id"]) if record is not None else None
            if record is None or (proof is not None) != (version == 2):
                raise PeerError("NOT_FOUND", "Operation result is unavailable to this peer")
            if audit_context is not None and proof is not None:
                operation = db.execute("SELECT * FROM operation WHERE id=?", (record["operation_id"],)).fetchone()
                audit_context.update(scoped.receipt_intent(record, proof, operation),
                                     operation_id=record["operation_id"], policy_sequence=proof["policy_sequence"])
            return receipt(db, record, pair, self.local_id, include_reason=include_reason)
