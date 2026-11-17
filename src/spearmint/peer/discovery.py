from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import json
import sqlite3
import time

from cryptography.exceptions import InvalidSignature

from ..state import State, StateError, audit
from .credentials import FINGERPRINT, NODE_ID, RANDOM_ID, certificate, fingerprint, is_current
from .pairing import PRIVATE_NETWORKS, Pair, check_port, configured, mesh_ip
from .policy import require_pair
from .protocol import CATALOG, PeerError, ProtocolError, matches
from .signed import SignedRecord


METHOD = "mesh.pex"
INTERVAL = 5
REFRESH = 30
TTL = 120
SKEW = 30
PAGE = 32
NETWORKS_PER_MEMBER = 4
MAX_SEQUENCE = 2**63 - 1
ADDRESS_FIELDS = {"mesh_id", "node_id", "fingerprint", "generation", "sequence", "issued_at", "expires_at", "endpoints"}
Endpoint = tuple[str, int]


@dataclass(frozen=True)
class AddressPolicy:
    network: IPv4Network | IPv6Network
    port: int

    def allows(self, ip: str) -> bool:
        return ip_address(ip) in self.network


def set_options(state: State, *, discover: bool | None, forward: bool | None) -> None:
    if discover is None and forward is None:
        raise StateError("Select at least one Mesh setting to change")
    with state.connect(write=True) as db:
        row = db.execute("""
            UPDATE mesh_profile SET discovery=coalesce(?,discovery), forwarding=coalesce(?,forwarding)
            RETURNING mesh_id,bind_ip
        """, (discover, forward)).fetchone()
        if row is None:
            raise StateError("Configure the local Mesh first")
        if discover and ip_address(row["bind_ip"]).is_global:
            raise StateError("Address discovery requires a private Mesh bind address")
        if discover is False:
            db.execute("DELETE FROM peer_address_cache")
            db.execute("UPDATE mesh_profile SET address_issued_at=0,address_record=NULL")
        audit(db, "admin", "local", "mesh.options.changed", row["mesh_id"])


def allow_network(state: State, node: str, network: str, port: int) -> None:
    parsed = ip_network(network)
    if not any(parsed.version == private.version and parsed.subnet_of(private) for private in PRIVATE_NETWORKS):
        raise ValueError("Neighbor networks must be private IPv4 or IPv6 ULA CIDRs")
    check_port(port)
    with state.connect(write=True) as db:
        pair = configured(db, node)
        if pair is None or pair.legacy:
            raise StateError("Configure a Mesh member before allowing a neighbor network")
        if parsed.version != ip_address(pair.bind_ip).version:
            raise ValueError("Neighbor network and local address must use the same IP family")
        db.execute("INSERT OR IGNORE INTO peer_network VALUES (?,?,?)", (node, str(parsed), port))
        if db.execute("SELECT count(*) FROM peer_network WHERE node_id=?", (node,)).fetchone()[0] > NETWORKS_PER_MEMBER:
            raise StateError("Neighbor network limit reached")
        audit(db, "admin", "local", "mesh.neighbor.network_allowed", node)


def approve_generation(state: State, node: str, generation: str) -> None:
    if not matches(RANDOM_ID, generation):
        raise ValueError("Invalid address generation")
    with state.connect(write=True) as db:
        pair = configured(db, node)
        if pair is None or pair.legacy:
            raise StateError("Configure a Mesh member before approving its address generation")
        changed = db.execute("""
            INSERT INTO peer_address_state(node_id,generation) VALUES (?,?)
            ON CONFLICT(node_id) DO UPDATE SET generation=excluded.generation,highest_sequence=0
                WHERE generation<>excluded.generation
            RETURNING node_id
        """, (node, generation)).fetchone()
        if changed:
            db.execute("DELETE FROM peer_address_cache WHERE node_id=?", (node,))
            audit(db, "admin", "local", "mesh.member.address_generation", node)


def public_config(db: sqlite3.Connection) -> dict | None:
    row = db.execute("SELECT mesh_id,discovery,forwarding,address_generation FROM mesh_profile").fetchone()
    return dict(row) if row is not None else None


def approved_endpoints(payload: dict, now: int) -> tuple[Endpoint, ...]:
    if (payload.keys() != ADDRESS_FIELDS or not matches(RANDOM_ID, payload["mesh_id"])
            or not matches(NODE_ID, payload["node_id"]) or not matches(FINGERPRINT, payload["fingerprint"])
            or not matches(RANDOM_ID, payload["generation"])
            or type(payload["sequence"]) is not int or not 1 <= payload["sequence"] <= MAX_SEQUENCE
            or type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int
            or not 0 < payload["issued_at"] <= now + SKEW
            or not max(now, payload["issued_at"]) < payload["expires_at"] <= payload["issued_at"] + TTL
            or not isinstance(payload["endpoints"], list) or not 1 <= len(payload["endpoints"]) <= 4):
        raise ProtocolError("Invalid or expired Mesh address record")
    endpoints = []
    for entry in payload["endpoints"]:
        if (not isinstance(entry, dict) or entry.keys() != {"ip", "port"} or not isinstance(entry["ip"], str)
                or type(entry["port"]) is not int):
            raise ProtocolError("Invalid Mesh address endpoint")
        check_port(entry["port"])
        endpoints.append((mesh_ip(entry["ip"]), entry["port"]))
    if len(set(endpoints)) != len(endpoints):
        raise ProtocolError("Duplicate Mesh address endpoint")
    return tuple(endpoints)


def network_view(db: sqlite3.Connection, pairs: dict[str, Pair]) -> tuple[bool, dict[str, tuple[AddressPolicy, ...]], dict[str, tuple[Endpoint, ...]]]:
    profile = public_config(db)
    if not profile or not profile["discovery"]:
        return False, {}, {}
    policies: dict[str, list[AddressPolicy]] = {}
    for row in db.execute("SELECT * FROM peer_network ORDER BY network,port"):
        pair = pairs[row["node_id"]]
        if pair.enabled and not pair.legacy:
            policies.setdefault(pair.node_id, []).append(AddressPolicy(ip_network(row["network"]), row["port"]))
    now = int(time.time())
    destinations = {}
    for row in db.execute("SELECT * FROM peer_address_cache WHERE expires_at>? AND issued_at<=?", (now, now + SKEW)):
        node = row["node_id"]
        allowed = policies.get(node)
        if allowed:
            payload = SignedRecord.parse(json.loads(row["record"])).payload()
            destinations[node] = tuple((ip, port) for ip, port in approved_endpoints(payload, now)
                                       if ip != pairs[node].bind_ip and any(policy.port == port and policy.allows(ip) for policy in allowed))
    return True, {node: tuple(networks) for node, networks in policies.items()}, destinations


class Discovery:
    def __init__(self, state: State, local_id: str) -> None:
        self.state = state
        self.local_id = local_id

    def refresh(self) -> None:
        now = int(time.time())
        with self.state.connect() as db:
            profile = db.execute("SELECT discovery,address_issued_at FROM mesh_profile").fetchone()
        if not profile or not profile["discovery"] or now - REFRESH < profile["address_issued_at"] <= now + SKEW:
            return
        with self.state.connect(write=True) as db:
            profile = db.execute("SELECT * FROM mesh_profile WHERE discovery=1").fetchone()
            if not profile or now - REFRESH < profile["address_issued_at"] <= now + SKEW:
                return
            sequence = profile["address_sequence"] + 1
            if sequence > MAX_SEQUENCE:
                raise StateError("Mesh address sequence is exhausted")
            payload = {"mesh_id": profile["mesh_id"], "node_id": self.local_id, "generation": profile["address_generation"],
                       "fingerprint": fingerprint(certificate(profile["local_pem"])), "sequence": sequence,
                       "issued_at": now, "expires_at": now + TTL,
                       "endpoints": [{"ip": profile["bind_ip"], "port": profile["listen_port"]}]}
            approved_endpoints(payload, now)
            token = SignedRecord.create("address", payload, self.state.signing_key()).wire()
            db.execute("UPDATE mesh_profile SET address_sequence=?,address_issued_at=?,address_record=?",
                       (sequence, now, json.dumps(token, separators=(",", ":"))))

    def page(self, source: Pair, params: dict) -> dict:
        if params.keys() != {"after"} or (params["after"] is not None and not matches(NODE_ID, params["after"])):
            raise PeerError("INVALID_REQUEST", "Invalid Peer Exchange cursor")
        now = int(time.time())
        with self.state.connect() as db:
            db.execute("BEGIN")
            require_pair(db, source)
            profile = db.execute("SELECT * FROM mesh_profile WHERE discovery=1").fetchone()
            if source.legacy or not profile:
                raise PeerError("UNSUPPORTED_METHOD", "Peer Exchange is disabled")
            rows = {row["node_id"]: row["record"] for row in db.execute("""
                SELECT c.node_id, c.record FROM peer_address_cache c JOIN peer p USING (node_id)
                WHERE p.enabled=1 AND c.expires_at>? AND c.issued_at<=?
                  AND NOT EXISTS (SELECT 1 FROM mesh_quarantine q WHERE q.node_id=c.node_id)
            """, (now, now + SKEW))}
            if profile["address_record"] and now - TTL < profile["address_issued_at"] <= now + SKEW:
                rows[self.local_id] = profile["address_record"]
        keys = sorted(node for node in rows if params["after"] is None or node > params["after"])
        selected = []
        size = 256
        for node in keys[:PAGE]:
            size += len(rows[node]) + 1
            if size > CATALOG:
                break
            selected.append(json.loads(rows[node]))
        return {"records": selected, "next": keys[len(selected) - 1] if len(selected) < len(keys) else None}

    def accept_page(self, source: Pair, reply: dict, after: str | None) -> str | None:
        if (reply.keys() != {"records", "next"} or not isinstance(reply["records"], list)
                or len(reply["records"]) > PAGE or (reply["next"] is not None and
                (not reply["records"] or not matches(NODE_ID, reply["next"]) or (after is not None and reply["next"] <= after)))):
            raise PeerError("PROTOCOL", "Invalid Peer Exchange page")
        if not reply["records"]:
            return reply["next"]
        now = int(time.time())
        with self.state.connect(write=True) as db:
            require_pair(db, source)
            if source.legacy or not db.execute("SELECT 1 FROM mesh_profile WHERE discovery=1").fetchone():
                return None
            for wire in reply["records"]:
                try:
                    signed = SignedRecord.parse(wire)
                    payload = signed.payload()
                    approved_endpoints(payload, now)
                    self.accept(db, payload, signed)
                except (ValueError, InvalidSignature):
                    continue
        return reply["next"]

    @staticmethod
    def accept(db: sqlite3.Connection, payload: dict, signed: SignedRecord) -> None:
        node = payload["node_id"]
        pair = configured(db, node)
        if (pair is None or pair.legacy or not pair.enabled or payload["mesh_id"] != pair.mesh_id
                or payload["fingerprint"] != pair.fingerprint):
            return
        approval = db.execute("SELECT generation,highest_sequence FROM peer_address_state WHERE node_id=?", (node,)).fetchone()
        if approval is None or approval["generation"] != payload["generation"] or approval["highest_sequence"] >= payload["sequence"]:
            return
        leaf = certificate(pair.remote_pem)
        if not is_current(leaf):
            return
        signed.verify("address", leaf.public_key())
        db.execute("UPDATE peer_address_state SET highest_sequence=? WHERE node_id=?", (payload["sequence"], node))
        db.execute("""
            INSERT INTO peer_address_cache VALUES (?,?,?,?)
            ON CONFLICT(node_id) DO UPDATE SET issued_at=excluded.issued_at,expires_at=excluded.expires_at,record=excluded.record
        """, (node, payload["issued_at"], payload["expires_at"], json.dumps(signed.wire(), separators=(",", ":"))))
