import os
import platform
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Config:
    state_dir: Path
    origin: str
    web_dir: Path
    docker_socket: Path
    grove_ca: Path | None = None
    route_mode: str | None = 'legacy'
    neighbor_target: int = 7
    neighbor_minimum: int = 2
    mesh_dial_enabled: bool = True
    mesh_advertise_ip: str | None = None
    mesh_advertise_port: int | None = None
    seed_targets: Path | None = None
    grove_login_replicas: frozenset[str] = frozenset()
    grove_login_standby: bool = False
    grove_login_recovery: bool = False
    grove_standby_voters: frozenset[str] = frozenset()
    grove_continuity_voters: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.route_mode not in {None, 'legacy', 'adaptive'}:
            raise ValueError('SPEARMINT_ROUTE_MODE must be legacy or adaptive')
        if (type(self.neighbor_target) is not int or type(self.neighbor_minimum) is not int
                or not 1 <= self.neighbor_minimum <= self.neighbor_target <= 7):
            raise ValueError('Neighbor settings require 1 <= minimum <= target <= 7, with a hard limit of 8')
        if self.mesh_advertise_ip is not None:
            address = ip_address(self.mesh_advertise_ip)
            if str(address) != self.mesh_advertise_ip or address.is_unspecified or address.is_multicast or '%' in str(address):
                raise ValueError('SPEARMINT_MESH_ADVERTISE_IP requires one canonical IP address')
        if self.mesh_advertise_port is not None and (type(self.mesh_advertise_port) is not int
                                                     or not 1024 <= self.mesh_advertise_port <= 65535):
            raise ValueError('SPEARMINT_MESH_ADVERTISE_PORT must be between 1024 and 65535')
        if len(self.grove_login_replicas) > 64 or any(
            re.fullmatch(r'spm1-[a-f0-9]{64}', node) is None for node in self.grove_login_replicas
        ):
            raise ValueError('SPEARMINT_GROVE_LOGIN_REPLICAS requires a comma-separated list of full Node IDs')
        if self.grove_standby_voters and (not self.grove_login_standby or len(self.grove_standby_voters) < 2
                                         or not self.grove_standby_voters <= self.grove_login_replicas):
            raise ValueError('SPEARMINT_GROVE_STANDBY_VOTERS requires standby and at least two enrolled login replicas')
        if self.grove_continuity_voters and (len(self.grove_continuity_voters) < 2
                                            or not self.grove_continuity_voters <= self.grove_login_replicas):
            raise ValueError('SPEARMINT_GROVE_CONTINUITY_VOTERS requires at least two enrolled login replicas')

    @property
    def authority(self) -> str:
        return urlsplit(self.origin).netloc

    @classmethod
    def from_env(cls, *, state_dir: Path | None = None, origin: str | None = None,
                 web_dir: Path | None = None, grove_ca: Path | None = None) -> "Config":
        if origin is None:
            origin = os.environ.get("SPEARMINT_ORIGIN", "https://localhost:8443")
        parsed = urlsplit(origin)
        hostname = parsed.hostname or ""
        port = parsed.port
        authority = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None and port != 443:
            authority += f":{port}"
        if not hostname or not origin.isascii() or origin != f"https://{authority}" or any(
            character.isspace() for character in authority
        ) or port == 0:
            raise ValueError("The panel origin must be a canonical HTTPS origin without a path")
        mesh_dial = os.environ.get("SPEARMINT_MESH_DIAL", "on")
        if mesh_dial not in {"on", "off"}:
            raise ValueError("SPEARMINT_MESH_DIAL must be on or off")
        advertise_port = os.environ.get('SPEARMINT_MESH_ADVERTISE_PORT')
        replica_nodes = os.environ.get('SPEARMINT_GROVE_LOGIN_REPLICAS', '').split(',')
        standby_nodes = os.environ.get('SPEARMINT_GROVE_STANDBY_VOTERS', '').split(',')
        continuity_nodes = os.environ.get('SPEARMINT_GROVE_CONTINUITY_VOTERS', '').split(',')
        standby = os.environ.get('SPEARMINT_GROVE_LOGIN_STANDBY', 'off')
        if standby not in {'on', 'off'}:
            raise ValueError('SPEARMINT_GROVE_LOGIN_STANDBY must be on or off')
        recovery = os.environ.get('SPEARMINT_GROVE_LOGIN_RECOVERY', 'off')
        if recovery not in {'on', 'off'}:
            raise ValueError('SPEARMINT_GROVE_LOGIN_RECOVERY must be on or off')
        default_state = Path.home() / ".local/state"
        default_docker = f"/run/user/{os.getuid()}/docker.sock" if hasattr(os, "getuid") else "//./pipe/docker_engine"
        if os.name == "nt":
            default_state = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
        elif platform.system() == "Darwin":
            default_state = Path.home() / "Library/Application Support"
            default_docker = str(Path.home() / ".docker/run/docker.sock")
        state_home = Path(os.environ.get("XDG_STATE_HOME") or default_state)
        directory = state_dir if state_dir is not None else Path(os.environ.get("SPEARMINT_STATE_DIR") or state_home / "spearmint")
        if grove_ca is None and os.environ.get('SPEARMINT_GROVE_CA'):
            grove_ca = Path(os.environ['SPEARMINT_GROVE_CA'])
        return cls(
            directory.expanduser().absolute(),
            origin,
            (web_dir if web_dir is not None else Path(os.environ.get("SPEARMINT_WEB_DIR", "web/dist"))).expanduser().absolute(),
            Path(os.environ.get("SPEARMINT_DOCKER_SOCKET") or default_docker),
            grove_ca.expanduser().absolute() if grove_ca is not None else None,
            os.environ.get('SPEARMINT_ROUTE_MODE'),
            int(os.environ.get('SPEARMINT_NEIGHBOR_TARGET', '7')),
            int(os.environ.get('SPEARMINT_NEIGHBOR_MINIMUM', '2')),
            mesh_dial_enabled=mesh_dial == "on",
            mesh_advertise_ip=os.environ.get('SPEARMINT_MESH_ADVERTISE_IP'),
            mesh_advertise_port=int(advertise_port) if advertise_port is not None else None,
            seed_targets=Path(os.environ['SPEARMINT_SEED_TARGETS']).expanduser().absolute()
            if os.environ.get('SPEARMINT_SEED_TARGETS') else None,
            grove_login_replicas=frozenset(node.strip() for node in replica_nodes if node.strip()),
            grove_login_standby=standby == 'on',
            grove_login_recovery=recovery == 'on',
            grove_standby_voters=frozenset(node.strip() for node in standby_nodes if node.strip()),
            grove_continuity_voters=frozenset(node.strip() for node in continuity_nodes if node.strip()),
        )
