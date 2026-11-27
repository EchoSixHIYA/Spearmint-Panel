"""Read Windows Firewall rule coverage for the configured Mesh listener."""
from ipaddress import ip_address, ip_network
from pathlib import Path
import os
import sqlite3


def includes(value, item, parse, contains) -> bool:
    for token in (value or '*').split(','):
        token = token.strip()
        if token == '*':
            return True
        try:
            lower, separator, upper = token.partition('-')
            if separator and parse(lower) <= item <= parse(upper):
                return True
            if not separator and contains(token, item):
                return True
        except (TypeError, ValueError):
            continue
    return False


def matching_allow_rule(policy, address: str, port: int, executable: Path) -> bool:
    local = ip_address(address)
    active_profiles = policy.CurrentProfileTypes
    binary = os.path.normcase(str(executable))
    for rule in policy.Rules:
        if (not rule.Enabled or rule.Direction != 1 or rule.Action != 1
                or rule.Protocol not in (6, 256) or not (rule.Profiles & active_profiles)):
            continue
        application = rule.ApplicationName
        if application and application != '*' and os.path.normcase(os.path.expandvars(application)) != binary:
            continue
        if rule.ServiceName not in (None, '', '*'):
            continue
        if not includes(rule.LocalAddresses, local, ip_address,
                        lambda token, item: item in ip_network(token, strict=False)):
            continue
        if includes(rule.LocalPorts, port, int, lambda token, item: int(token) == item):
            return True
    return False


def check(state, executable: Path) -> dict:
    try:
        with state.connect(read_only=True) as db:
            listener = db.execute('SELECT bind_ip,listen_port FROM mesh_profile').fetchone()
    except (OSError, sqlite3.Error):
        return {'status': 'check_unavailable'}
    if listener is None:
        return {'status': 'not_configured'}
    address, port = listener
    try:
        from pywintypes import com_error
        from win32com.client import Dispatch

        rule = matching_allow_rule(Dispatch('HNetCfg.FwPolicy2'), address, port, executable)
        status = 'rule_found' if rule else 'rule_unconfirmed'
    except (ImportError, OSError, ValueError):
        status = 'check_unavailable'
    except com_error:
        status = 'check_unavailable'
    return {'status': status, 'address': address, 'port': port}
