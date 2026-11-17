from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .approval_format import ACTIONS, OPERATOR_ID, USER_ID, operator_id
from .credentials import FINGERPRINT, NODE_ID, RANDOM_ID, node_id
from .protocol import decode_json, matches, parse_b64, wire_b64


DELEGATION_TTL = 30 * 24 * 3600
POLICY_TTL = 15 * 60
ENROLLMENT_TTL = 5 * 60
RESUME_TTL = 2 * 60
SNAPSHOT_LIMIT = 40 * 1024
BUNDLE_LIMIT = 64 * 1024
HEADER = {"version", "mesh_id", "issued_at", "expires_at"}
DELEGATION_FIELDS = HEADER | {"term", "root_key_id", "authority_public_key", "scope"}
POLICY_FIELDS = HEADER | {"term", "sequence", "previous_digest", "change", "users", "members", "grants"}
ENROLLMENT_FIELDS = HEADER | {"user_id", "public_key", "nonce"}
RESUME_FIELDS = HEADER | {"node_id", "nonce", "term", "sequence", "policy_digest"}


def encoded(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def read_document(path: Path, limit: int = BUNDLE_LIMIT) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Policy document exceeds its size limit")
    return decode_json(raw)


def root_id(key: Ed25519PublicKey) -> str:
    return "root1-" + sha256(key.public_bytes_raw()).hexdigest()


def public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(parse_b64(value, 32))


def positive(value) -> bool:
    return type(value) is int and 0 < value < 2**63


def text(value, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and value.isprintable()


@dataclass(frozen=True)
class Record:
    raw: bytes
    signature: bytes

    @classmethod
    def parse(cls, value, limit: int = 2048) -> "Record":
        if not isinstance(value, dict) or value.keys() != {"record", "signature"}:
            raise ValueError("Invalid policy record")
        signature = parse_b64(value["signature"], 64)
        if len(signature) != 64:
            raise ValueError("Invalid policy signature size")
        return cls(parse_b64(value["record"], limit), signature)

    @classmethod
    def sign(cls, domain: str, payload: dict, key: Ed25519PrivateKey, limit: int = 2048) -> "Record":
        raw = encoded(payload)
        if len(raw) > limit:
            raise ValueError("Policy record exceeds its size limit")
        return cls(raw, key.sign(signature_input(domain, raw)))

    @property
    def digest(self) -> str:
        return sha256(self.raw).hexdigest()

    def verify(self, domain: str, key: Ed25519PublicKey) -> dict:
        key.verify(self.signature, signature_input(domain, self.raw))
        return decode_json(self.raw)

    def wire(self) -> dict:
        return {"record": wire_b64(self.raw), "signature": wire_b64(self.signature)}


def signature_input(domain: str, raw: bytes) -> bytes:
    return f"Spearmint-M003 {domain} v1\0".encode("ascii") + sha256(raw).digest()


def validate_header(data: dict, fields: set[str], mesh_id: str, ttl: int, now: int | None) -> None:
    if (data.keys() != fields or type(data["version"]) is not int or data["version"] != 1
            or data["mesh_id"] != mesh_id or not matches(RANDOM_ID, mesh_id)
            or not positive(data["issued_at"]) or not positive(data["expires_at"])
            or not 0 < data["expires_at"] - data["issued_at"] <= ttl
            or (now is not None and not data["issued_at"] <= now < data["expires_at"])):
        raise ValueError("Policy record fields, Mesh or validity do not match")


def delegation(record: Record, root: Ed25519PublicKey, mesh_id: str, now: int | None) -> dict:
    data = record.verify("delegation", root)
    validate_header(data, DELEGATION_FIELDS, mesh_id, DELEGATION_TTL, now)
    authority = public_key(data["authority_public_key"])
    if (not positive(data["term"]) or data["root_key_id"] != root_id(root) or data["scope"] != "mesh_policy"
            or authority.public_bytes_raw() == root.public_bytes_raw()):
        raise ValueError("Invalid policy delegation")
    return data


def indexed(items, key: str, fields: set[str], pattern: re.Pattern, limit: int) -> dict[str, dict]:
    if not isinstance(items, list) or len(items) > limit:
        raise ValueError(f"Invalid policy list for {key}")
    result = {}
    for item in items:
        if (not isinstance(item, dict) or item.keys() != fields or not matches(pattern, item[key])
                or item[key] in result):
            raise ValueError(f"Invalid or duplicate policy {key}")
        result[item[key]] = item
    return result


def validate_snapshot(data: dict, authority: dict, now: int | None) -> None:
    validate_header(data, POLICY_FIELDS, authority["mesh_id"], POLICY_TTL, now)
    if (not positive(data["term"]) or data["term"] != authority["term"] or not positive(data["sequence"])
            or not authority["issued_at"] <= data["issued_at"] < data["expires_at"] <= authority["expires_at"]):
        raise ValueError("Policy version or delegation window does not match")
    previous = data["previous_digest"]
    if (data["sequence"] == 1 and previous is not None) or (data["sequence"] > 1 and not matches(FINGERPRINT, previous)):
        raise ValueError("Invalid previous policy digest")
    change = data["change"]
    if (not isinstance(change, dict) or change.keys() != {"actor", "reason"}
            or not text(change["actor"], 64) or not text(change["reason"], 256)):
        raise ValueError("Policy change requires an actor and reason")
    users = indexed(data["users"], "user_id", {"user_id", "display_name", "state", "role", "keys"}, USER_ID, 64)
    members = indexed(data["members"], "node_id", {"node_id", "state"}, NODE_ID, 64)
    grants = indexed(data["grants"], "id", {
        "id", "revision", "user_id", "origin_node_id", "target_node_id", "service_id",
        "actions", "read_result", "expires_at",
    }, RANDOM_ID, 256)
    keys = set()
    for user in users.values():
        if (user["state"] not in ("active", "revoked") or user["role"] not in ("operator", "administrator")
                or not text(user["display_name"], 64)):
            raise ValueError("Invalid policy user")
        entries = indexed(user["keys"], "key_id", {"key_id", "public_key", "state"}, OPERATOR_ID, 8)
        for key_id, entry in entries.items():
            if (entry["state"] not in ("active", "revoked") or key_id in keys
                    or key_id != operator_id(public_key(entry["public_key"]))):
                raise ValueError("Invalid or reused policy user key")
            keys.add(key_id)
    if any(member["state"] not in ("active", "revoked") for member in members.values()):
        raise ValueError("Invalid policy member state")
    scopes = set()
    for grant in grants.values():
        actions = grant["actions"]
        if (not positive(grant["revision"]) or not matches(USER_ID, grant["user_id"]) or grant["user_id"] not in users
                or not matches(NODE_ID, grant["origin_node_id"]) or grant["origin_node_id"] not in members
                or not matches(NODE_ID, grant["target_node_id"]) or grant["target_node_id"] not in members
                or grant["origin_node_id"] == grant["target_node_id"] or not matches(RANDOM_ID, grant["service_id"])
                or not positive(grant["expires_at"]) or type(grant["read_result"]) is not bool
                or not isinstance(actions, list) or not actions or not all(action in ACTIONS for action in actions)
                or len(set(actions)) != len(actions)):
            raise ValueError("Invalid policy grant")
        prefix = tuple(grant[field] for field in ("user_id", "origin_node_id", "target_node_id", "service_id"))
        for action in actions:
            scope = (*prefix, action)
            if scope in scopes:
                raise ValueError("Overlapping Mesh operation grants")
            scopes.add(scope)


@dataclass(frozen=True)
class Bundle:
    delegation_record: Record
    snapshot_record: Record
    authority: dict
    snapshot: dict

    @classmethod
    def verify(cls, document: dict, root: Ed25519PublicKey, mesh_id: str, now: int | None) -> "Bundle":
        if not isinstance(document, dict) or document.keys() != {"delegation", "snapshot"}:
            raise ValueError("Invalid signed policy bundle")
        delegation_record = Record.parse(document["delegation"])
        authority = delegation(delegation_record, root, mesh_id, now)
        snapshot_record = Record.parse(document["snapshot"], SNAPSHOT_LIMIT)
        snapshot = snapshot_record.verify("policy", public_key(authority["authority_public_key"]))
        validate_snapshot(snapshot, authority, now)
        members = {item["node_id"] for item in snapshot["members"]}
        authority_key = public_key(authority["authority_public_key"])
        infrastructure = {root.public_bytes_raw(), authority_key.public_bytes_raw()}
        if node_id(root) in members or node_id(authority_key) in members:
            raise ValueError("A policy key cannot also be a Mesh node key")
        for user in snapshot["users"]:
            for entry in user["keys"]:
                key = public_key(entry["public_key"])
                if key.public_bytes_raw() in infrastructure or node_id(key) in members:
                    raise ValueError("A user key cannot also be a Mesh node or policy key")
        return cls(delegation_record, snapshot_record, authority, snapshot)

    def wire(self) -> dict:
        return {"delegation": self.delegation_record.wire(), "snapshot": self.snapshot_record.wire()}

    def cursor(self) -> dict:
        return {"term": self.snapshot["term"], "sequence": self.snapshot["sequence"],
                "digest": self.snapshot_record.digest}


def verify_enrollment(value: dict, mesh_id: str, now: int) -> dict:
    record = Record.parse(value)
    unsigned = decode_json(record.raw)
    key = public_key(unsigned.get("public_key"))
    data = record.verify("enrollment", key)
    validate_header(data, ENROLLMENT_FIELDS, mesh_id, ENROLLMENT_TTL, now)
    if not matches(USER_ID, data["user_id"]) or not matches(RANDOM_ID, data["nonce"]):
        raise ValueError("Invalid policy user enrollment")
    return data


def user_key(snapshot: dict, user_id: str, operator_key_id: str) -> Ed25519PublicKey | None:
    for user in snapshot["users"]:
        if user["user_id"] == user_id and user["state"] == "active":
            for entry in user["keys"]:
                if entry["key_id"] == operator_key_id and entry["state"] == "active":
                    return public_key(entry["public_key"])
    return None


def matching_grants(snapshot: dict, *, user_id: str, origin: str, target: str,
                    service: str, action: str, now: int) -> list[dict]:
    return [grant for grant in snapshot["grants"]
            if (grant["user_id"], grant["origin_node_id"], grant["target_node_id"], grant["service_id"])
            == (user_id, origin, target, service) and action in grant["actions"] and now < grant["expires_at"]]
