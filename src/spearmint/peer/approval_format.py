from dataclasses import dataclass
from hashlib import sha256
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .credentials import NODE_ID, RANDOM_ID
from .protocol import decode_json, matches, parse_b64


OPERATOR_ID = re.compile(r"op1-[0-9a-f]{64}")
USER_ID = re.compile(r"usr1-[0-9a-f]{32}")
CHALLENGE_TAG = b"Spearmint-M001 challenge v1\x00"
APPROVAL_TAG = b"Spearmint-M001 approval v1\x00"
CHALLENGE_TAGS = {1: CHALLENGE_TAG, 2: b"Spearmint-M003 challenge v2\x00"}
APPROVAL_TAGS = {1: APPROVAL_TAG, 2: b"Spearmint-M003 approval v2\x00"}
CHALLENGE_TTL = 120
ENVELOPE_LIMIT = 16384
CHALLENGE_LIMIT = 8192
ACTIONS = ("start", "stop", "restart")
CHALLENGE_FIELDS = {
    "version", "mesh_id", "issuer_node_id", "origin_node_id", "operator_key_id", "grant_id", "grant_version",
    "service_id", "service_version", "target_name", "service_name", "action", "params", "request_id",
    "challenge_id", "issued_at", "expires_at",
}
V2_FIELDS = {"user_id", "policy_term", "execution_epoch"}


def operator_id(key: Ed25519PublicKey) -> str:
    return "op1-" + sha256(key.public_bytes_raw()).hexdigest()


@dataclass(frozen=True)
class Challenge:
    raw: bytes
    digest: bytes
    data: dict
    issuer_signature: bytes
    operator_signature: bytes | None

    def verify_issuer(self, key: Ed25519PublicKey) -> None:
        key.verify(self.issuer_signature, CHALLENGE_TAGS[self.data["version"]] + self.digest)

    def verify_operator(self, key: Ed25519PublicKey) -> None:
        if self.operator_signature is None:
            raise ValueError("Operator signature is required")
        key.verify(self.operator_signature, APPROVAL_TAGS[self.data["version"]] + self.digest)

    def approval_digest(self) -> bytes:
        if self.operator_signature is None:
            raise ValueError("Operator signature is required")
        return sha256(self.digest + self.issuer_signature + self.operator_signature).digest()


def unpack(envelope: dict, *, approved: bool, version: int = 1) -> Challenge:
    if version not in CHALLENGE_TAGS:
        raise ValueError("Unsupported approval version")
    fields = {"challenge", "issuer_signature"}
    if approved:
        fields.add("operator_signature")
    if not isinstance(envelope, dict) or envelope.keys() != fields:
        raise ValueError("Unexpected approval envelope fields")
    raw = parse_b64(envelope["challenge"], CHALLENGE_LIMIT)
    issuer = parse_b64(envelope["issuer_signature"], 64)
    operator = parse_b64(envelope["operator_signature"], 64) if approved else None
    data = decode_json(raw)
    expected = CHALLENGE_FIELDS | V2_FIELDS if version == 2 else CHALLENGE_FIELDS
    if (data.keys() != expected or len(issuer) != 64 or (operator is not None and len(operator) != 64)
            or type(data["version"]) is not int or data["version"] != version or data["params"] != {}
            or not matches(OPERATOR_ID, data["operator_key_id"])
            or not all(matches(NODE_ID, data[key]) for key in ("issuer_node_id", "origin_node_id"))
            or not all(matches(RANDOM_ID, data[key]) for key in ("mesh_id", "grant_id", "service_id", "request_id", "challenge_id"))
            or not all(type(data[key]) is int and 0 < data[key] < 2**63
                       for key in ("grant_version", "service_version", "issued_at", "expires_at"))
            or not 0 < data["expires_at"] - data["issued_at"] <= CHALLENGE_TTL
            or data["action"] not in ACTIONS
            or not all(isinstance(data[key], str) and 0 < len(data[key]) <= 255 and data[key].isprintable()
                       for key in ("target_name", "service_name"))):
        raise ValueError("Invalid signed challenge fields")
    if version == 2 and (not matches(USER_ID, data["user_id"]) or not matches(RANDOM_ID, data["execution_epoch"])
                         or type(data["policy_term"]) is not int or not 0 < data["policy_term"] < 2**63):
        raise ValueError("Invalid M003 challenge context")
    return Challenge(raw, sha256(raw).digest(), data, issuer, operator)
