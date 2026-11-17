"""Owner-configured FRP providers and mappings for registered local services."""

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import tomllib

from .catalog import Service, get_service
from .host import capture
from .state import State, StateError, private_path


PROTOCOLS = ('http', 'https', 'tcp')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
SERVICE_ID = re.compile(r'[0-9a-f]{32}')
PROVIDER_ID = re.compile(r'[a-z0-9][a-z0-9-]{0,31}')
NODE_ID = re.compile(r'spm1-[0-9a-f]{64}')


def fields(value, required: set[str], optional: set[str], name: str) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise StateError(f'Invalid fields in {name}')
    return value


def port(value) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise StateError('FRP ports must be integers from 1 to 65535')
    return value


def hostname(value, *, domain: bool = False) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise StateError('Invalid FRP host')
    try:
        address = ip_address(value)
    except ValueError:
        labels = value.split('.')
        if all(LABEL.fullmatch(label) for label in labels) and (not domain or len(labels) > 1 and not labels[-1].isdigit()):
            return value
    else:
        if not domain and '%' not in value and not address.is_unspecified and not address.is_multicast:
            return str(address)
    raise StateError('Use a lowercase DNS name or a literal IP address for FRP hosts, and an exact DNS name for web domains')


def file_path(directory: Path, value) -> Path:
    if not isinstance(value, str) or not value or not value.isprintable():
        raise StateError('Invalid FRP configuration file path')
    return (directory / value).absolute()


def authority(host: str, number: int) -> str:
    return f'[{host}]:{number}' if ':' in host else f'{host}:{number}'


def verify_config(binary: Path, directory: Path, content: str) -> None:
    if not binary.is_absolute() or not binary.is_file():
        raise StateError('Provide the absolute path to the installed frpc binary')
    with TemporaryDirectory(prefix='.frp-verify-', dir=directory) as temporary:
        config = Path(temporary) / 'frpc.json'
        config.write_text(content, encoding='utf-8')
        result = capture([str(binary), 'verify', '-c', str(config)], timeout=10)
        if result.code or result.truncated:
            raise StateError('frpc rejected the configuration. Check the provider files and frpc version')


@dataclass(frozen=True)
class Provider:
    id: str
    kind: str
    server_host: str
    server_port: int
    token_file: Path
    ca_file: Path
    tls_name: str
    web_ports: dict[str, int]
    domains: frozenset[str]
    public_host: str
    tcp_ports: frozenset[int]

    @classmethod
    def parse(cls, name: str, data: dict, directory: Path) -> 'Provider':
        if not PROVIDER_ID.fullmatch(name):
            raise StateError('Invalid FRP provider ID')
        data = fields(data, {'kind', 'server_host', 'server_port', 'token_file', 'ca_file'},
                      {'tls_name', 'http_port', 'https_port', 'domains', 'public_host', 'tcp_ports'}, 'FRP provider')
        if data['kind'] not in ('self-hosted', 'third-party'):
            raise StateError('FRP provider kind must be self-hosted or third-party')
        server = hostname(data['server_host'])
        web_ports = {protocol: port(data[protocol + '_port']) for protocol in ('http', 'https')
                     if protocol + '_port' in data}
        domains = data.get('domains', [])
        tcp_ports = data.get('tcp_ports', [])
        if not isinstance(domains, list) or not isinstance(tcp_ports, list):
            raise StateError('FRP domains and TCP ports must be lists')
        if bool(web_ports) != bool(domains) or not (web_ports or tcp_ports):
            raise StateError('An FRP provider needs web ports with approved domains, approved TCP ports, or both')
        return cls(name, data['kind'], server, port(data['server_port']), file_path(directory, data['token_file']),
                   file_path(directory, data['ca_file']), hostname(data.get('tls_name', server)), web_ports,
                   frozenset(hostname(domain, domain=True) for domain in domains),
                   hostname(data.get('public_host', server)), frozenset(port(number) for number in tcp_ports))

    def summary(self) -> dict:
        return {'id': self.id, 'kind': self.kind, 'server': authority(self.server_host, self.server_port),
                'public_host': self.public_host, 'web_ports': self.web_ports,
                'domains': sorted(self.domains), 'tcp_ports': sorted(self.tcp_ports)}


@dataclass(frozen=True)
class Binding:
    host: str
    port: int
    remote: tuple[tuple[str, frozenset[str]], ...] = ()

    @classmethod
    def parse(cls, data: dict) -> 'Binding':
        data = fields(data, {'port'}, {'host', 'remote'}, 'FRP service binding')
        host = data.get('host', '127.0.0.1')
        if host not in ('127.0.0.1', '::1'):
            raise StateError('FRP service bindings require a loopback address on the owning node')
        remote = data.get('remote', {})
        if not isinstance(remote, dict):
            raise StateError('FRP remote grants must map node IDs to provider lists')
        grants = []
        for node, providers in remote.items():
            if (not NODE_ID.fullmatch(node) or not isinstance(providers, list) or not providers
                    or any(not isinstance(name, str) or not PROVIDER_ID.fullmatch(name) for name in providers)):
                raise StateError('Invalid FRP remote grant')
            grants.append((node, frozenset(providers)))
        return cls(host, port(data['port']), tuple(grants))

    def permits(self, node: str, provider: str) -> bool:
        return provider in dict(self.remote).get(node, ())


@dataclass(frozen=True)
class Plan:
    provider: Provider
    service: Service
    binding: Binding
    protocol: str
    public_port: int
    domain: str | None = None

    @property
    def address(self) -> str:
        if self.protocol == 'tcp':
            return 'tcp://' + authority(self.provider.public_host, self.public_port)
        default = 443 if self.protocol == 'https' else 80
        public = self.domain if self.public_port == default else f'{self.domain}:{self.public_port}'
        return f'{self.protocol}://{public}'

    def summary(self) -> dict:
        return {'provider': self.provider.id, 'service_id': self.service.id, 'service_name': self.service.name,
                'node_id': self.service.node_id, 'protocol': self.protocol,
                'local_address': authority(self.binding.host, self.binding.port), 'public_address': self.address}

    def client_config(self) -> dict:
        provider = self.provider
        # FRP reads the token itself. No credential contents enter a command line or preview.
        private_path(provider.token_file, 0o600)
        if not provider.ca_file.is_file():
            raise StateError('FRP provider CA file is unavailable')
        identity = f'{self.service.node_id}/{self.service.id}/{provider.id}/{self.address}'
        proxy = {'name': 'spm-' + sha256(identity.encode()).hexdigest()[:32], 'type': self.protocol,
                 'localIP': self.binding.host, 'localPort': self.binding.port,
                 'healthCheck': {'type': 'tcp', 'timeoutSeconds': 1, 'maxFailed': 2, 'intervalSeconds': 2}}
        if self.protocol == 'tcp':
            proxy['remotePort'] = self.public_port
        else:
            proxy['customDomains'] = [self.domain]
        return {
            'serverAddr': provider.server_host, 'serverPort': provider.server_port,
            'transport': {'tls': {'enable': True, 'trustedCaFile': str(provider.ca_file), 'serverName': provider.tls_name}},
            'auth': {'method': 'token', 'tokenSource': {'type': 'file', 'file': {'path': str(provider.token_file)}}},
            'log': {'to': 'console', 'level': 'info', 'disablePrintColor': True},
            'proxies': [proxy],
        }

    @staticmethod
    def config_json(config: dict) -> str:
        # FRP expands Go templates before parsing JSON, so escape braces inside file paths.
        return json.dumps(config, indent=2).replace('{{', r'\u007b\u007b')

    def verify(self, binary: Path, directory: Path) -> None:
        verify_config(binary, directory, self.config_json(self.client_config()))


@dataclass(frozen=True)
class Settings:
    providers: dict[str, Provider]
    bindings: dict[tuple[str, str], Binding]
    browser_client: Path | None = None

    @classmethod
    def load(cls, path: Path) -> 'Settings':
        try:
            private_path(path, 0o600)
            with path.open('rb') as stream:
                data = stream.read(65537)
        except FileNotFoundError as error:
            raise StateError(f'FRP provider configuration is missing: {path}') from error
        if len(data) > 65536:
            raise StateError('FRP configuration exceeds 64 KiB')
        try:
            parsed = tomllib.loads(data.decode('utf-8'))
        except (UnicodeError, tomllib.TOMLDecodeError) as error:
            raise StateError('Invalid FRP TOML configuration') from error
        fields(parsed, {'providers'}, {'services', 'runtime'}, 'FRP configuration')
        providers = parsed['providers']
        services = parsed.get('services', {})
        if not isinstance(providers, dict) or not isinstance(services, dict):
            raise StateError('FRP providers and services must be tables')
        bindings = {}
        for service_id, protocols in services.items():
            if not SERVICE_ID.fullmatch(service_id):
                raise StateError('FRP service bindings must use registered service IDs')
            for protocol, binding in fields(protocols, set(), set(PROTOCOLS), 'FRP service protocols').items():
                bindings[(service_id, protocol)] = Binding.parse(binding)
        runtime = fields(parsed.get('runtime', {}), set(), {'frpc'}, 'FRP runtime')
        client = file_path(path.parent, runtime['frpc']) if 'frpc' in runtime else None
        return cls({name: Provider.parse(name, data, path.parent) for name, data in providers.items()}, bindings, client)

    def plan(self, state: State, provider_id: str, service_id: str, protocol: str, *,
             domain: str | None = None, public_port: int | None = None) -> Plan:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise StateError('Unknown FRP provider')
        with state.connect() as db:
            service = get_service(db, service_id)
        if service is None:
            raise StateError('Unknown local service ID')
        binding = self.bindings.get((service_id, protocol))
        if binding is None:
            raise StateError('This service has no local binding for the requested FRP protocol')
        if protocol == 'tcp':
            if domain is not None or public_port is None or port(public_port) not in provider.tcp_ports:
                raise StateError('TCP requires an approved public port without a domain')
        elif public_port is not None or domain not in provider.domains or protocol not in provider.web_ports:
            raise StateError('HTTP and HTTPS require an approved domain and the provider web port')
        else:
            public_port = provider.web_ports[protocol]
        return Plan(provider, service, binding, protocol, public_port, domain)
