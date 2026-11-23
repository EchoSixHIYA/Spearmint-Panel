"""Browser and authenticated Grove access to a service owner's FRP leases."""

from hashlib import sha256
import json
import re
import sys

from ..auth import Actor
from ..catalog import get_service
from ..frp import PROVIDER_ID, PROTOCOLS, Settings, authority
from .. import frp_runtime as runtime
from ..platforms import WINDOWS
from ..state import State, StateError, audit
from .credentials import RANDOM_ID
from .grove_endpoints import trusted_members
from .operation_policy import required_version
from .outbound import account_admin
from .pairing import Pair, configured
from .policy import require_pair
from .protocol import PeerError, matches


METHODS = {'frp.view', 'frp.start', 'frp.revoke', 'frp.receipt'}
EMPTY = {'options': [], 'mappings': [], 'can_start': False}
HTTP_KEY = re.compile(r'[A-Za-z0-9._-]{1,128}')
START = {'provider', 'protocol', 'ttl', 'domain', 'public_port'}


def request_id(actor: Actor, key: str) -> str:
    if not matches(HTTP_KEY, key):
        raise PeerError('INVALID_REQUEST', 'Invalid FRP request identifier')
    return sha256(f'frp\0{actor.account_id}\0{key}'.encode()).hexdigest()[:32]


def require_grove(db, local_id: str, pair: Pair) -> None:
    require_pair(db, pair)
    trust = trusted_members(db, local_id, operational=True)
    if pair.legacy or trust is None or pair.node_id not in trust.origins:
        raise PeerError('DENIED', 'This peer is not an active Grove member')


def remote_service(db, local_id: str, pair: Pair, service: str) -> bool:
    require_grove(db, local_id, pair)
    if not db.execute('SELECT 1 FROM peer_export WHERE peer_id=? AND service_id=? AND directory=1',
                      (pair.node_id, service)).fetchone():
        raise PeerError('NOT_FOUND', 'Service is unavailable to this peer')
    return required_version(db, service) != 2


def check_remote_start(db, state: State, local_id: str, row) -> None:
    origin, service = row['origin_node'], row['service_id']
    pair = configured(db, origin)
    settings = Settings.load(state.directory / 'frp.toml')
    binding = settings.bindings.get((service, row['protocol']))
    if pair is None or binding is None or not binding.permits(origin, row['provider']) or not remote_service(db, local_id, pair, service):
        raise PeerError('DENIED', 'FRP authorization changed before startup')


def source_check(state: State, local_id: str, pair: Pair, actor: Actor, method: str, key: str | None) -> None:
    with state.connect(write=method in ('frp.start', 'frp.revoke')) as db:
        if not db.in_transaction:
            db.execute('BEGIN')
        require_grove(db, local_id, pair)
        account_admin(db, actor)
        if method in ('frp.start', 'frp.revoke'):
            audit(db, actor.operation_actor, actor.address, f'frp.remote.{method.split(".")[1]}', key, aggregate=True)


def validate(method: str, params: dict) -> None:
    expected = {'service_id'}
    if method != 'frp.view':
        expected.add('request_id')
    if method == 'frp.start':
        expected.update(START)
    if method == 'frp.revoke':
        expected.add('exposure_id')
    if params.keys() != expected or not matches(RANDOM_ID, params.get('service_id')):
        raise PeerError('INVALID_REQUEST', 'Invalid FRP service request')
    if method != 'frp.view' and not matches(RANDOM_ID, params['request_id']):
        raise PeerError('INVALID_REQUEST', 'Invalid FRP request identifier')
    if method == 'frp.revoke' and not matches(RANDOM_ID, params['exposure_id']):
        raise PeerError('INVALID_REQUEST', 'Invalid FRP mapping identifier')
    if method != 'frp.start':
        return
    protocol, ttl = params['protocol'], params['ttl']
    domain, port = params['domain'], params['public_port']
    if (protocol not in PROTOCOLS or not matches(PROVIDER_ID, params['provider'])
            or type(ttl) is not int or not 1 <= ttl <= runtime.MAX_TTL):
        raise PeerError('INVALID_REQUEST', 'Invalid FRP mapping parameters')
    if protocol == 'tcp':
        if domain is not None or type(port) is not int or not 1 <= port <= 65535:
            raise PeerError('INVALID_REQUEST', 'TCP mappings require a public port')
    elif port is not None or not isinstance(domain, str) or not 1 <= len(domain) <= 253:
        raise PeerError('INVALID_REQUEST', 'Web mappings require a public domain')


class Access:
    def __init__(self, state: State, local_id: str, service_id: str, principal: Actor | Pair):
        self.state = state
        self.local_id = local_id
        self.service_id = service_id
        self.peer = principal if isinstance(principal, Pair) else None
        self.actor = principal if self.peer is None else None
        path = state.directory / 'frp.toml'
        try:
            self.settings = Settings.load(path) if path.exists() else Settings({}, {})
        except (OSError, StateError) as exc:
            raise PeerError('UNAVAILABLE', 'The service owner must check the FRP configuration') from exc

    def require_service(self, db) -> bool:
        if self.peer:
            return remote_service(db, self.local_id, self.peer, self.service_id)
        else:
            account_admin(db, self.actor)
        if get_service(db, self.service_id) is None:
            raise PeerError('NOT_FOUND', 'Unknown service')
        return True

    def permits(self, protocol: str, provider: str) -> bool:
        if self.peer is None:
            return True
        binding = self.settings.bindings.get((self.service_id, protocol))
        return binding is not None and binding.permits(self.peer.node_id, provider)

    def authorize(self, db, protocol: str, provider: str) -> None:
        if not self.require_service(db) or not self.permits(protocol, provider):
            raise PeerError('DENIED', 'This node has no FRP permission for the requested service, protocol and provider')

    @property
    def origin(self) -> str:
        return self.peer.node_id if self.peer else self.local_id

    def request(self, method: str, params: dict) -> runtime.Request:
        digest = sha256(json.dumps([method, params], sort_keys=True, separators=(',', ':')).encode()).digest()
        actor = self.peer.node_id if self.peer else self.actor.operation_actor
        return runtime.Request(self.origin, params['request_id'], digest, self.service_id, actor, self.authorize)

    def view(self) -> dict:
        with self.state.connect() as db:
            db.execute('BEGIN')
            if not self.require_service(db):
                return EMPTY
        runtime.reconcile(self.state)
        with self.state.connect() as db:
            db.execute('BEGIN')
            if not self.require_service(db):
                return EMPTY
            mappings = [
                runtime.public_data(row) for row in db.execute('''
                    SELECT * FROM frp_exposure WHERE service_id=?
                    ORDER BY status NOT IN ('starting','running','revoking'), created_at DESC LIMIT 40
                ''', (self.service_id,)) if self.permits(row['protocol'], row['provider'])
            ]
        options = []
        for (service, protocol), binding in self.settings.bindings.items():
            if service != self.service_id:
                continue
            for provider in self.settings.providers.values():
                if self.peer and not binding.permits(self.peer.node_id, provider.id):
                    continue
                if protocol == 'tcp' and provider.tcp_ports:
                    values = [{'port': number, 'address': f'tcp://{authority(provider.public_host, number)}'}
                              for number in sorted(provider.tcp_ports)]
                elif protocol in provider.web_ports:
                    number = provider.web_ports[protocol]
                    default = 443 if protocol == 'https' else 80
                    values = [{'domain': domain, 'address': f'{protocol}://{domain}' +
                               (f':{number}' if number != default else '')} for domain in sorted(provider.domains)]
                else:
                    continue
                options.append({'provider': provider.id, 'protocol': protocol, 'targets': values})
        if len(json.dumps(options)) > 65536:
            raise PeerError('UNAVAILABLE', 'The service owner must reduce the number of configured FRP options')
        binary = self.settings.browser_client
        return {'options': options, 'mappings': mappings,
                'can_start': bool(options and binary and binary.is_file() and (WINDOWS or sys.platform == 'linux'))}

    def receipt(self, key: str) -> dict:
        with self.state.connect() as db:
            db.execute('BEGIN')
            self.require_service(db)
        runtime.reconcile(self.state)
        with self.state.connect() as db:
            db.execute('BEGIN')
            row = db.execute('''
                SELECT e.* FROM frp_request r JOIN frp_exposure e ON e.id=r.exposure_id
                WHERE r.origin=? AND r.request_id=? AND e.service_id=?
            ''', (self.origin, key, self.service_id)).fetchone()
            if row is None:
                raise PeerError('NOT_FOUND', 'FRP request receipt not found')
            self.authorize(db, row['protocol'], row['provider'])
            return runtime.public_data(row)


def handle(state: State, local_id: str, principal: Actor | Pair, method: str, params: dict) -> dict:
    validate(method, params)
    access = Access(state, local_id, params['service_id'], principal)
    if method == 'frp.view':
        return access.view()
    if method == 'frp.receipt':
        return {'mapping': access.receipt(params['request_id'])}
    request = access.request(method, params)
    try:
        if method == 'frp.start':
            mapping = runtime.start(state, params['provider'], access.service_id, params['protocol'],
                                    access.settings.browser_client, params['ttl'], domain=params['domain'],
                                    public_port=params['public_port'], request=request, settings=access.settings)
        else:
            mapping = runtime.revoke(state, params['exposure_id'], request=request)
    except StateError as exc:
        raise PeerError('CONFLICT', 'The service owner could not apply this FRP request. Check the mapping configuration and current leases.') from exc
    return {'mapping': mapping}


def check_result(method: str, service_id: str, result: dict) -> dict:
    def valid_mapping(mapping):
        return (
            isinstance(mapping, dict) and mapping.keys() == set(runtime.PUBLIC_FIELDS)
            and mapping['service_id'] == service_id and matches(RANDOM_ID, mapping['id'])
            and matches(PROVIDER_ID, mapping['provider']) and mapping['protocol'] in PROTOCOLS
            and mapping['status'] in (*runtime.ACTIVE, 'expired', 'revoked', 'failed')
            and all(isinstance(mapping[key], str) for key in ('public_address', 'local_address'))
            and all(type(mapping[key]) in (int, float) and 0 <= mapping[key] <= 253402300799
                    for key in ('created_at', 'expires_at'))
            and all(mapping[key] is None or isinstance(mapping[key], str) for key in ('health', 'detail'))
        )

    if method == 'frp.view':
        valid = (
            result.keys() == EMPTY.keys() and type(result['can_start']) is bool
            and isinstance(result['mappings'], list) and len(result['mappings']) <= 40
            and all(valid_mapping(item) for item in result['mappings'])
            and isinstance(result['options'], list)
            and all(
                isinstance(option, dict) and option.keys() == {'provider', 'protocol', 'targets'}
                and matches(PROVIDER_ID, option['provider']) and option['protocol'] in PROTOCOLS
                and isinstance(option['targets'], list)
                and all(isinstance(target, dict) and isinstance(target.get('address'), str)
                        and (target.keys() == {'domain', 'address'} and isinstance(target['domain'], str)
                             or target.keys() == {'port', 'address'} and type(target['port']) is int)
                        for target in option['targets'])
                for option in result['options']
            )
        )
    else:
        valid = result.keys() == {'mapping'} and valid_mapping(result['mapping'])
    if not valid:
        raise PeerError('PROTOCOL', 'Invalid remote FRP response')
    return result
