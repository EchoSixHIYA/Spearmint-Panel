from dataclasses import dataclass
from hashlib import sha256
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .protocol import ProtocolError, decode_json, parse_b64, wire_b64


def signed_bytes(domain: str, raw: bytes) -> bytes:
    return f"Spearmint-M002 {domain} v1\0".encode("ascii") + sha256(raw).digest()


@dataclass(frozen=True)
class SignedRecord:
    raw: bytes
    signature: bytes

    @classmethod
    def parse(cls, token, limit: int = 2048) -> "SignedRecord":
        if not isinstance(token, dict) or token.keys() != {"raw", "signature"}:
            raise ProtocolError("Invalid Mesh signed record")
        signature = parse_b64(token["signature"], 64)
        if len(signature) != 64:
            raise ProtocolError("Invalid Mesh signature size")
        return cls(parse_b64(token["raw"], limit), signature)

    @classmethod
    def create(cls, domain: str, payload: dict, key: Ed25519PrivateKey) -> "SignedRecord":
        raw = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        return cls(raw, key.sign(signed_bytes(domain, raw)))

    def payload(self) -> dict:
        return decode_json(self.raw)

    def verify(self, domain: str, public: Ed25519PublicKey) -> None:
        public.verify(self.signature, signed_bytes(domain, self.raw))

    def wire(self) -> dict:
        return {"raw": wire_b64(self.raw), "signature": wire_b64(self.signature)}
