"""Exchange the Mesh listening endpoints of enrolled Grove members."""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import json
import time
from urllib.parse import urlsplit

import psutil

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import grove
from .credentials import certificate, fingerprint, is_current
from .discovery import REFRESH, TTL, SKEW, Endpoint
from .pairing import MAX_MEMBERS, Pair, check_port, fixed_mesh_ip, mesh_ip
from .protocol import PeerError
from .signed import SignedRecord


METHOD = 'mesh.grove_endpoints'
DOMAIN = 'grove endpoint'
FIELDS = {'realm_id', 'mesh_id', 'node_id', 'fingerprint', 'ip', 'port', 'issued_at', 'expires_at'}


@dataclass(frozen=True)
class GroveMembers:
    realm_id: str
    origins: dict[str, str]


def trusted_members(db, local_id: str) -> GroveMembers | None:
    realm = db.execute('SELECT * FROM grove_realm').fetchone()
    if not realm or realm['frozen'] or realm['issuer_paused']:
        return None
    if realm['is_issuer']:
        members = db.execute('SELECT node_id,origin,enabled FROM grove_member')
    elif realm['manifest']:
        try:
            envelope = json.loads(realm['manifest'])
            continuity = db.execute('SELECT sequence,lease_until FROM grove_login_continuity').fetchone()
            if continuity is not None:
                if continuity['sequence'] != realm['sequence'] or continuity['lease_until'] <= int(time.time()):
                    return None
                members = grove.members_after_handoff(db, grove.verified('directory', envelope, realm['public_key'])['members'])
            else:
                members = grove.directory_data(envelope, grove.realm_data(realm))['members']
        except (ValueError, KeyError, TypeError, PeerError):
            return None
    else:
        return None
    origins = {member['node_id']: member['origin'] for member in members if member['enabled']}
    return GroveMembers(realm['id'], origins) if local_id in origins else None


def literal_endpoint(value: str) -> str | None:
    try:
        return fixed_mesh_ip(value)
    except ValueError:
        return None


def enrolled_ip(origin: str, certificate_host: str) -> str | None:
    # A verified Grove address can supersede the address in a still-pinned
    # certificate. The certificate and TLS hostname checks are independent.
    return literal_endpoint(urlsplit(origin).hostname or '') or literal_endpoint(certificate_host)


def matches_advertised_ip(origin: str, pair: Pair, address: str) -> bool:
    enrolled = enrolled_ip(origin, pair.host)
    if enrolled is not None:
        return address == enrolled
    hostname = urlsplit(origin).hostname
    try:
        loopback = hostname == 'localhost' or ip_address(hostname or '').is_loopback
        return loopback and mesh_ip(address) == address
    except ValueError:
        return False


def on_same_lan(bind_ip: str, address: str) -> bool:
    try:
        local, remote = ip_address(mesh_ip(bind_ip)), ip_address(mesh_ip(address))
        if local.version != remote.version or local == remote:
            return False
        for entries in psutil.net_if_addrs().values():
            for interface in entries:
                if interface.address.split('%')[0] == bind_ip and interface.netmask:
                    mask = ip_address(interface.netmask.split('%')[0])
                    network = ip_network((local, int(mask).bit_count()), strict=False)
                    if network.num_addresses <= 2:
                        return remote in network
                    return remote in network and remote != network.network_address and (
                        remote.version == 6 or remote != network.broadcast_address)
    except (OSError, ValueError):
        pass
    return False


@dataclass(frozen=True)
class Advertisement:
    pair: Pair
    record: SignedRecord
    endpoint: Endpoint
    issued_at: int
    expires_at: int


class GroveEndpoints:
    def __init__(self, local_id: str, key: Ed25519PrivateKey, *, advertise_ip: str | None = None,
                 advertise_port: int | None = None) -> None:
        self.local_id = local_id
        self.key = key
        self.advertise_ip = fixed_mesh_ip(advertise_ip) if advertise_ip is not None else None
        self.advertise_port = advertise_port
        self.members: GroveMembers | None = None
        self.records: dict[str, Advertisement] = {}
        self.own: tuple[dict, int, SignedRecord] | None = None

    def update(self, trust: GroveMembers | None, pairs: dict[str, Pair]) -> dict[str, tuple[Endpoint, ...]]:
        now = time.time()
        if trust is None or self.members is None or trust.realm_id != self.members.realm_id:
            self.records.clear()
        self.members = trust
        for node, record in list(self.records.items()):
            origin = trust.origins.get(node) if trust else None
            if (origin is None or pairs.get(node) != record.pair or not record.pair.enabled
                    or record.expires_at <= now or not matches_advertised_ip(origin, record.pair, record.endpoint[0])):
                self.records.pop(node)
        if trust is None:
            return {}
        return {node: (record.endpoint,) for node, record in self.records.items()
                if self.connection_address(trust.origins[node], record.pair) is not None}

    def connection_address(self, origin: str, pair: Pair) -> tuple[str, bool] | None:
        enrolled = enrolled_ip(origin, pair.host)
        if enrolled is not None:
            return enrolled, False
        record = self.records.get(pair.node_id)
        if (record and record.pair == pair and record.expires_at > time.time()
                and matches_advertised_ip(origin, pair, record.endpoint[0])
                and on_same_lan(pair.bind_ip, record.endpoint[0])):
            return record.endpoint[0], True
        return None

    def accept(self, response: dict, pairs: dict[str, Pair]) -> None:
        if response.keys() != {'records'} or not isinstance(response['records'], list) or len(response['records']) > MAX_MEMBERS:
            raise PeerError('PROTOCOL', 'Invalid Grove Mesh endpoint list')
        if self.members is None:
            return
        now = int(time.time())
        for wire in response['records']:
            try:
                record = SignedRecord.parse(wire, limit=1024)
                data = record.payload()
                if data.keys() != FIELDS or data['realm_id'] != self.members.realm_id or not isinstance(data['node_id'], str):
                    continue
                node = data['node_id']
                pair = pairs.get(node)
                origin = self.members.origins.get(node)
                if (pair is None or origin is None or not pair.enabled or pair.legacy or data['mesh_id'] != pair.mesh_id
                        or data['fingerprint'] != pair.fingerprint or not isinstance(data['ip'], str)
                        or not matches_advertised_ip(origin, pair, data['ip']) or ip_address(data['ip']) == ip_address(pair.bind_ip)
                        or ip_address(data['ip']).version != ip_address(pair.bind_ip).version):
                    continue
                issued, expires = data['issued_at'], data['expires_at']
                if (type(data['port']) is not int or type(issued) is not int or type(expires) is not int
                        or not 0 < issued <= now + SKEW or not max(now, issued) < expires <= issued + TTL
                        or (node in self.records and self.records[node].issued_at >= issued)):
                    continue
                check_port(data['port'])
                leaf = certificate(pair.remote_pem)
                if not is_current(leaf):
                    continue
                record.verify(DOMAIN, leaf.public_key())
            except (ValueError, InvalidSignature):
                continue
            self.records[node] = Advertisement(pair, record, (data['ip'], data['port']), issued, expires)

    def page(self, local_pair: Pair, listening: bool) -> dict:
        trust = self.members
        if trust is None:
            return {'records': []}
        now = int(time.time())
        records = [entry.record.wire() for entry in self.records.values() if entry.expires_at > now]
        if listening:
            address = self.advertise_ip or local_pair.bind_ip
            if ip_address(address).version == ip_address(local_pair.bind_ip).version:
                leaf = certificate(local_pair.local_pem)
                data = {'realm_id': trust.realm_id, 'mesh_id': local_pair.mesh_id, 'node_id': self.local_id,
                        'fingerprint': fingerprint(leaf), 'ip': address, 'port': self.advertise_port or local_pair.listen_port}
                if (self.own is None or self.own[0] != data
                        or not now - REFRESH < self.own[1] <= now + SKEW):
                    record = SignedRecord.create(DOMAIN, {**data, 'issued_at': now, 'expires_at': now + TTL}, self.key)
                    self.own = data, now, record
                records.insert(0, self.own[2].wire())
        return {'records': records[:MAX_MEMBERS]}
