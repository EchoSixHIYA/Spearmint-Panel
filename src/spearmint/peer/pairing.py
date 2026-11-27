from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
import sqlite3

from cryptography.hazmat.primitives import serialization

from ..state import State, StateError, audit
from .credentials import FINGERPRINT, NODE_ID, RANDOM_ID, certificate, endpoint_name, fingerprint, mesh_authorities, validate_mesh_leaf


MAX_MEMBERS = 32
PRIVATE_NETWORKS = tuple(map(ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
MEMBER_QUERY = """
    SELECT peer.*, mesh_profile.bind_ip, mesh_profile.listen_port, mesh_profile.ca_pem,
           mesh_profile.local_pem, peer_neighbor.source_ip, peer_neighbor.port,
           CASE WHEN peer.ingress_only=1 AND peer_neighbor.source_ip IS NOT NULL THEN COALESCE((
               SELECT event='mesh.enrollment_registered' AND source=peer_neighbor.source_ip
               FROM audit WHERE target=peer.node_id AND event IN (
                   'mesh.enrollment_registered', 'mesh.neighbor.configured', 'mesh.neighbor.public_configured'
               )
               ORDER BY id DESC LIMIT 1
           ), 0) ELSE 0 END AS source_observed
    FROM peer JOIN mesh_profile USING (mesh_id) LEFT JOIN peer_neighbor USING (node_id)
"""


def private_ip(value: str) -> str:
    address = ip_address(value)
    if not address.is_private or address.is_unspecified or address.is_multicast or "%" in value:
        raise ValueError("Peer binding and source require specific private IP addresses")
    return str(address)


def mesh_ip(value: str) -> str:
    address = ip_address(value)
    if "%" in value or not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("Mesh addresses must be in private IPv4 or IPv6 ULA networks")
    return str(address)


def fixed_mesh_ip(value: str) -> str:
    address = ip_address(value)
    if ("%" not in value and address.is_global and not address.is_multicast and not address.is_reserved
            and getattr(address, "ipv4_mapped", None) is None):
        return str(address)
    return mesh_ip(value)


@dataclass(frozen=True)
class Pair:
    node_id: str
    mesh_id: str
    bind_ip: str
    listen_port: int
    source_ip: str | None
    host: str
    port: int | None
    fingerprint: str
    ca_pem: bytes
    local_pem: bytes
    remote_pem: bytes
    enabled: bool = False
    write_epoch: str = ""
    legacy: bool = True
    routed: bool = False
    ingress_only: bool = False
    source_observed: bool = False

    @property
    def fixed_source_ip(self) -> str | None:
        return None if self.source_observed else self.source_ip

    def public_data(self) -> dict:
        return {
            "node_id": self.node_id, "mesh_id": self.mesh_id, "enabled": bool(self.enabled),
            "bind_ip": self.bind_ip, "listen_port": self.listen_port, "source_ip": self.fixed_source_ip,
            "host": self.host, "port": self.port if self.fixed_source_ip else None, "fingerprint": self.fingerprint,
            "legacy": self.legacy, "routed": self.routed,
        }

    def validate(self, local_id: str) -> float:
        if not NODE_ID.fullmatch(self.node_id) or self.node_id == local_id:
            raise ValueError("Enter the peer's distinct full Node ID")
        if not RANDOM_ID.fullmatch(self.mesh_id) or not FINGERPRINT.fullmatch(self.fingerprint):
            raise ValueError("Invalid Mesh ID or leaf certificate fingerprint")
        check_ip = private_ip if self.legacy else fixed_mesh_ip
        check_ip(self.bind_ip)
        if self.source_ip is not None:
            check_ip(self.source_ip)
        check_port(self.listen_port)
        if self.port is not None:
            check_port(self.port)
        roots = mesh_authorities(self.ca_pem)
        local, remote = map(certificate, (self.local_pem, self.remote_pem))
        local_ca = validate_mesh_leaf(local, roots, local_id)
        remote_ca = validate_mesh_leaf(remote, roots, self.node_id, self.host)
        if fingerprint(remote) != self.fingerprint:
            raise ValueError("Peer certificate fingerprint does not match the approved value")
        return min(cert.not_valid_after_utc.timestamp() for cert in (local_ca, remote_ca, local, remote))


def check_port(port: int) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Peer ports must be between 1024 and 65535")


def read_member(row: sqlite3.Row) -> Pair:
    fields = {name: row[name] for name in Pair.__dataclass_fields__}
    for name in ("enabled", "legacy", "routed", "ingress_only", "source_observed"):
        fields[name] = bool(fields[name])
    return Pair(**fields)


def configured(db: sqlite3.Connection, node_id: str | None = None) -> Pair | None:
    row = (db.execute(MEMBER_QUERY + " WHERE peer.legacy=1").fetchone() if node_id is None else
           db.execute(MEMBER_QUERY + " WHERE peer.node_id=?", (node_id,)).fetchone())
    return read_member(row) if row is not None else None


def members(db: sqlite3.Connection) -> dict[str, Pair]:
    return {row["node_id"]: read_member(row) for row in db.execute(MEMBER_QUERY + " ORDER BY peer.node_id")}


def configure_mesh(state: State, mesh_id: str, bind_ip: str, port: int, ca_pem: bytes, local_pem: bytes,
                   *, allow_public_bind: bool = False) -> None:
    local_id = state.verify()
    bind_ip = fixed_mesh_ip(bind_ip) if allow_public_bind else mesh_ip(bind_ip)
    check_port(port)
    if not RANDOM_ID.fullmatch(mesh_id):
        raise ValueError("Invalid Mesh ID")
    local = certificate(local_pem)
    validate_mesh_leaf(local, mesh_authorities(ca_pem), local_id)
    settings = (mesh_id, bind_ip, port, ca_pem, local.public_bytes(serialization.Encoding.PEM))
    with state.connect(write=True) as db:
        profile = db.execute("SELECT mesh_id,bind_ip,listen_port,ca_pem,local_pem FROM mesh_profile").fetchone()
        if profile is not None and tuple(profile) != settings:
            if db.execute("SELECT 1 FROM peer LIMIT 1").fetchone():
                raise StateError("Remove members before changing the Mesh profile")
            db.execute("DELETE FROM mesh_profile")
        db.execute("""
            INSERT INTO mesh_profile (singleton,mesh_id,bind_ip,listen_port,ca_pem,local_pem,address_generation)
            VALUES (1,?,?,?,?,?,lower(hex(randomblob(16))))
            ON CONFLICT(singleton) DO NOTHING
        """, settings)
        event = "mesh.public_listener_configured" if ip_address(bind_ip).is_global else "mesh.configured"
        audit(db, "admin", "local", event, mesh_id)


def add_member(state: State, node_id: str, host: str, pin: str, remote_pem: bytes, *, routed: bool = False) -> None:
    local_id = state.verify()
    remote = certificate(remote_pem)
    host = str(endpoint_name(host).value)
    with state.connect(write=True) as db:
        profile = db.execute("SELECT * FROM mesh_profile").fetchone()
        if profile is None:
            raise StateError("Configure the local Mesh before admitting a member")
        current = configured(db, node_id)
        if current and current.legacy:
            raise StateError("Remove the M001 pairing before importing it as a Mesh member")
        if current is None and db.execute("SELECT count(*) FROM peer").fetchone()[0] >= MAX_MEMBERS:
            raise StateError("Mesh member limit reached")
        member = Pair(node_id, profile["mesh_id"], profile["bind_ip"], profile["listen_port"], None, host, None,
                      pin, profile["ca_pem"], profile["local_pem"], remote.public_bytes(serialization.Encoding.PEM),
                      legacy=False, routed=routed)
        member.validate(local_id)
        db.execute("""
            INSERT INTO peer (node_id,mesh_id,host,fingerprint,remote_pem,write_epoch,routed)
            VALUES (?,?,?,?,?,lower(hex(randomblob(16))),?)
            ON CONFLICT(node_id) DO UPDATE SET host=excluded.host,fingerprint=excluded.fingerprint,
                remote_pem=excluded.remote_pem,enabled=0,write_epoch=excluded.write_epoch,routed=excluded.routed
        """, (node_id, member.mesh_id, host, pin, member.remote_pem, routed))
        db.execute("DELETE FROM peer_challenge WHERE peer_id=?", (node_id,))
        db.execute("DELETE FROM peer_address_cache WHERE node_id=?", (node_id,))
        db.execute("INSERT OR IGNORE INTO peer_directory(peer_id) VALUES (?)", (node_id,))
        audit(db, "admin", "local", "mesh.member.imported", node_id)


def set_neighbor(state: State, node_id: str, source_ip: str | None, port: int = 8766, *,
                 allow_public: bool = False) -> None:
    state.verify()
    with state.connect(write=True) as db:
        member = configured(db, node_id)
        if member is None or member.legacy:
            raise StateError("Configure a Mesh member before setting its neighbor address")
        event = "mesh.neighbor.configured"
        if source_ip is None:
            db.execute("DELETE FROM peer_neighbor WHERE node_id=?", (node_id,))
            db.execute("DELETE FROM peer_network WHERE node_id=?", (node_id,))
        else:
            address = fixed_mesh_ip(source_ip) if allow_public else mesh_ip(source_ip)
            check_port(port)
            if ip_address(address).version != ip_address(member.bind_ip).version or address == member.bind_ip:
                raise ValueError("Neighbor and local addresses must be distinct and use the same IP family")
            db.execute("""
                INSERT INTO peer_neighbor (node_id,source_ip,port) VALUES (?,?,?)
                ON CONFLICT(node_id) DO UPDATE SET source_ip=excluded.source_ip,port=excluded.port
            """, (node_id, address, port))
            if ip_address(address).is_global:
                event = "mesh.neighbor.public_configured"
        audit(db, "admin", "local", event, node_id)


def add(state: State, pair: Pair) -> None:
    pair.validate(state.verify())
    if pair.source_ip is None or pair.port is None or not pair.legacy:
        raise ValueError("M001 pairing requires a fixed peer address and port")
    data = asdict(pair)
    data["enabled"] = False
    data["bind_ip"], data["source_ip"] = map(private_ip, (pair.bind_ip, pair.source_ip))
    endpoint = endpoint_name(pair.host).value
    data["host"] = str(endpoint)
    for name in ("ca_pem", "local_pem", "remote_pem"):
        data[name] = certificate(data[name]).public_bytes(serialization.Encoding.PEM)
    with state.connect(write=True) as db:
        current = configured(db)
        if current and current.node_id != pair.node_id:
            raise StateError("Remove the previous pairing before adding a different node")
        if current and current.mesh_id != pair.mesh_id:
            raise StateError("Remove the previous pairing before changing Mesh ID")
        if current is None and configured(db, pair.node_id) is not None:
            raise StateError("Remove the Mesh member before configuring a legacy pairing")
        if current is None and db.execute("SELECT count(*) FROM peer").fetchone()[0] >= MAX_MEMBERS:
            raise StateError("Mesh member limit reached")
        profile = db.execute("SELECT * FROM mesh_profile WHERE singleton=1").fetchone()
        shared = ("mesh_id", "bind_ip", "listen_port", "ca_pem", "local_pem")
        if profile is not None and (profile["discovery"] or profile["forwarding"]
                                    or db.execute("SELECT 1 FROM peer WHERE legacy IS NULL LIMIT 1").fetchone()):
            if any(profile[key] != data[key] for key in shared):
                raise StateError("Pairing must use the configured Mesh identity and listener")
        db.execute("""
            INSERT INTO mesh_profile (singleton,mesh_id,bind_ip,listen_port,ca_pem,local_pem,address_generation)
            VALUES (1,:mesh_id,:bind_ip,:listen_port,:ca_pem,:local_pem,lower(hex(randomblob(16))))
            ON CONFLICT(singleton) DO UPDATE SET mesh_id=excluded.mesh_id,bind_ip=excluded.bind_ip,
                listen_port=excluded.listen_port,ca_pem=excluded.ca_pem,local_pem=excluded.local_pem
        """, data)
        db.execute("""
            INSERT INTO peer (node_id,mesh_id,host,fingerprint,remote_pem,enabled,write_epoch,legacy)
            VALUES (:node_id,:mesh_id,:host,:fingerprint,:remote_pem,0,lower(hex(randomblob(16))),1)
            ON CONFLICT(legacy) DO UPDATE SET host=excluded.host,fingerprint=excluded.fingerprint,
                remote_pem=excluded.remote_pem,enabled=0,write_epoch=excluded.write_epoch
        """, data)
        db.execute("""
            INSERT INTO peer_neighbor (node_id,source_ip,port) VALUES (:node_id,:source_ip,:port)
            ON CONFLICT(node_id) DO UPDATE SET source_ip=excluded.source_ip,port=excluded.port
            """, data)
        db.execute("DELETE FROM peer_challenge WHERE peer_id=?", (pair.node_id,))
        db.execute("INSERT OR IGNORE INTO peer_directory(peer_id) VALUES (?)", (pair.node_id,))
        audit(db, "admin", "local", "peer.paired", pair.node_id)


def set_enabled(state: State, enabled: bool, node_id: str | None = None) -> None:
    local_id = state.verify()
    with state.connect(write=True) as db:
        pair = configured(db, node_id)
        if pair is None:
            raise StateError("No peer is configured")
        if enabled:
            pair.validate(local_id)
        else:
            db.execute("UPDATE peer SET write_epoch=lower(hex(randomblob(16))) WHERE node_id=?", (pair.node_id,))
            db.execute("DELETE FROM peer_challenge WHERE peer_id=?", (pair.node_id,))
            db.execute("DELETE FROM peer_address_cache WHERE node_id=?", (pair.node_id,))
        db.execute("UPDATE peer SET enabled=? WHERE node_id=?", (enabled, pair.node_id))
        audit(db, "admin", "local", "peer.enabled" if enabled else "peer.disabled", pair.node_id)


def remove(state: State, node_id: str | None = None) -> None:
    state.verify()
    with state.connect(write=True) as db:
        pair = configured(db, node_id)
        if pair:
            db.execute("DELETE FROM peer WHERE node_id=?", (pair.node_id,))
            if pair.legacy:
                db.execute("DELETE FROM mesh_profile WHERE discovery=0 AND forwarding=0 AND NOT EXISTS (SELECT 1 FROM peer)")
            audit(db, "admin", "local", "peer.removed", pair.node_id)
