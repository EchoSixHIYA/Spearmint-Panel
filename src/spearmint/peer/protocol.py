import asyncio
import base64
from collections.abc import Callable
import json
from math import isfinite
import re
from struct import Struct

from .credentials import FINGERPRINT, NODE_ID, RANDOM_ID


FRAME = 512 * 1024
REQUEST = 16 * 1024
DEPLOY_REQUEST = 64 * 1024
DEPLOY_UPLOAD = 384 * 1024
CATALOG = 64 * 1024
CONTROL = 16 * 1024
RELAY_FRAME = 32 * 1024
DEADLINE = 3
IN_FLIGHT = 8
HEADER = Struct("!I")
METHOD = re.compile(r"[a-z][a-z0-9_.]{0,63}")
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,47}")
ROUTE_FRAMES = {"route.query", "route.query.v3", "route.reply"}
RELAY_STREAM = {"relay.data", "relay.window"}
RELAY_CONTROL = {"relay.open", "relay.ready", "relay.close", "route.error"}
RELAY_FRAMES = RELAY_STREAM | RELAY_CONTROL
RELAY_CAPABILITY = "mesh.relay"


class ProtocolError(ValueError):
    pass


class PeerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def wire_b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def parse_b64(value, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > (limit * 4 + 2) // 3:
        raise ValueError("Invalid base64url size")
    data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(data) > limit or wire_b64(data) != value:
        raise ValueError("Non-canonical or oversized base64url payload")
    return data


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ProtocolError("Duplicate JSON key")
    return result


def check_json(value, depth: int = 0) -> None:
    if isinstance(value, dict):
        if depth >= 16:
            raise ProtocolError("JSON nesting limit exceeded")
        for key, item in value.items():
            key.encode("utf-8")
            check_json(item, depth + 1)
    elif isinstance(value, list):
        if depth >= 16:
            raise ProtocolError("JSON nesting limit exceeded")
        for item in value:
            check_json(item, depth + 1)
    elif isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, float) and not isfinite(value):
        raise ProtocolError("JSON numbers must be finite")


def decode_json(data: bytes) -> dict:
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
        check_json(result)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError("Invalid UTF-8 JSON") from exc
    if not isinstance(result, dict):
        raise ProtocolError("Expected a JSON object")
    return result


def matches(pattern: re.Pattern, value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_frame(frame: dict, size: int, *, mesh: bool = False, relay: bool = False, tunnel: bool = False) -> None:
    match frame.get("type"):
        case "hello":
            valid = (frame.keys() == {"type", "protocol_version", "mesh_id", "node_id", "session_id", "capabilities"}
                     and type(frame["protocol_version"]) is int and frame["protocol_version"] == 1
                     and matches(RANDOM_ID, frame["mesh_id"]) and matches(NODE_ID, frame["node_id"])
                     and matches(RANDOM_ID, frame["session_id"]) and isinstance(frame["capabilities"], list)
                     and len(frame["capabilities"]) <= 16 and all(matches(METHOD, item) for item in frame["capabilities"]))
        case "ping" | "pong":
            valid = frame.keys() == {"type", "nonce"} and matches(RANDOM_ID, frame["nonce"])
        case "request":
            limit = DEPLOY_UPLOAD if frame.get('method') == 'grove.deploy.upload' else DEPLOY_REQUEST if frame.get('method') == 'grove.deploy.v2' else REQUEST
            valid = (frame.keys() == {"type", "id", "method", "params"} and size <= limit
                     and matches(RANDOM_ID, frame["id"]) and matches(METHOD, frame["method"])
                     and isinstance(frame["params"], dict))
        case "response":
            valid = matches(RANDOM_ID, frame.get("id")) and (
                (frame.keys() == {"type", "id", "result"} and isinstance(frame["result"], dict)) or
                (frame.keys() == {"type", "id", "error"} and isinstance(frame["error"], dict)
                 and frame["error"].keys() == {"code", "message"}
                 and matches(ERROR_CODE, frame["error"]["code"])
                 and isinstance(frame["error"]["message"], str) and len(frame["error"]["message"]) <= 256)
            )
        case "route.query" | "route.query.v3":
            valid = (mesh and size <= CONTROL and frame.keys() == {"type", "record", "path"}
                     and isinstance(frame["record"], dict) and isinstance(frame["path"], list)
                     and 1 <= len(frame["path"]) <= 4 and all(matches(NODE_ID, node) for node in frame["path"]))
        case "route.reply":
            valid = mesh and size <= CONTROL and frame.keys() == {"type", "record"} and isinstance(frame["record"], dict)
        case "relay.open":
            valid = (relay and size <= CONTROL and frame.keys() == {"type", "circuit_id", "record", "ticket"}
                     and isinstance(frame["record"], dict) and isinstance(frame["ticket"], dict))
        case "relay.ready":
            valid = relay and size <= CONTROL and frame.keys() == {"type", "circuit_id"}
        case "relay.close" | "route.error":
            valid = (relay and size <= CONTROL and frame.keys() == {"type", "circuit_id", "code"}
                     and matches(ERROR_CODE, frame["code"]))
        case "relay.data":
            valid = (relay and size <= RELAY_FRAME and frame.keys() == {"type", "circuit_id", "sequence", "data"}
                     and type(frame["sequence"]) is int and 0 <= frame["sequence"] < 2**63 and isinstance(frame["data"], str))
        case "relay.window":
            valid = (relay and size <= CONTROL and frame.keys() == {"type", "circuit_id", "through"}
                     and type(frame["through"]) is int and 0 <= frame["through"] < 2**63)
        case "tunnel.hello":
            valid = (tunnel and size <= CONTROL and frame.keys() == {"type", "mesh_id", "node_id", "circuit_id", "ticket_digest"}
                     and matches(RANDOM_ID, frame["mesh_id"]) and matches(NODE_ID, frame["node_id"])
                     and matches(RANDOM_ID, frame["circuit_id"]) and matches(FINGERPRINT, frame["ticket_digest"]))
        case _:
            valid = False
    if not valid or (frame["type"] in RELAY_FRAMES and not matches(RANDOM_ID, frame["circuit_id"])):
        raise ProtocolError("Invalid Peer frame")


def encode(frame: dict, limit: int = FRAME, *, mesh: bool = False, relay: bool = False, tunnel: bool = False) -> bytes:
    body = json.dumps(frame, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if not 0 < len(body) <= limit:
        raise ProtocolError("Peer frame exceeds the size limit")
    validate_frame(frame, len(body), mesh=mesh, relay=relay, tunnel=tunnel)
    return HEADER.pack(len(body)) + body


async def receive(reader: asyncio.StreamReader, *, mesh: bool = False, relay: bool = False,
                  tunnel: bool = False, frame_timeout: Callable[[int], float] | None = None) -> tuple[dict, int]:
    first = await reader.readexactly(1)
    async with asyncio.timeout(DEADLINE) as timer:
        length, = HEADER.unpack(first + await reader.readexactly(HEADER.size - 1))
        if not 0 < length <= FRAME:
            raise ProtocolError("Invalid Peer frame length")
        if frame_timeout is not None:
            timer.reschedule(timer.when() + frame_timeout(length) - DEADLINE)
        body = await reader.readexactly(length)
    frame = decode_json(body)
    validate_frame(frame, length, mesh=mesh, relay=relay, tunnel=tunnel)
    return frame, length
