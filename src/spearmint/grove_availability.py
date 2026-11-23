"""Bound ordinary Grove operations to the last confirmed identity snapshot."""
from pathlib import Path
from threading import RLock
import time

from .peer.protocol import PeerError


OFFLINE_SECONDS = 12 * 60 * 60
_lock = RLock()
_syncing: dict[str, set[str]] = {}


def database_key(db):
    return str(Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve())


def synchronize(state, token: str, active: bool):
    key = str(state.database.resolve())
    with _lock:
        if active:
            _syncing.setdefault(key, set()).add(token)
        elif key in _syncing:
            _syncing[key].discard(token)
            if not _syncing[key]:
                _syncing.pop(key)


def status(db, now: int | None = None, *, check_sync: bool = True) -> dict:
    from . import grove
    now = int(time.time()) if now is None else now
    result = {'mode': 'unavailable', 'offline_seconds': OFFLINE_SECONDS,
              'confirmed_at': None, 'offline_until': None, 'identity_changes': False}
    row = db.execute('''SELECT r.*, v.sequence AS replica_sequence,
        coalesce(c.lease_until,max(v.expires_at,v.standby_lease_until)) AS confirmed_until
        FROM grove_realm r LEFT JOIN grove_login_replica v ON v.singleton=1
        LEFT JOIN grove_login_continuity c ON c.singleton=1
        WHERE r.frozen='' AND r.issuer_paused=0 AND
          (c.singleton IS NULL OR c.sequence=r.sequence)''').fetchone()
    if row is None:
        return result
    if row['is_issuer']:
        return result | {'mode': 'online', 'identity_changes': True}
    until = row['confirmed_until']
    if (row['replica_sequence'] != row['sequence'] or not until or
            not db.execute('''SELECT 1 FROM grove_member m JOIN node n ON n.node_id=m.node_id
                              WHERE m.enabled=1''').fetchone()):
        return result
    confirmed = until - grove.DIRECTORY_TTL
    offline_until = confirmed + OFFLINE_SECONDS
    result |= {'confirmed_at': confirmed, 'offline_until': offline_until}
    with _lock:
        synchronizing = bool(_syncing.get(database_key(db)))
    if synchronizing and check_sync:
        return result | {'mode': 'synchronizing'}
    if confirmed > now + grove.CLOCK_SKEW or offline_until <= now:
        return result
    if until > now:
        return result | {'mode': 'online', 'identity_changes': True}
    return result | {'mode': 'offline'}


def ordinary(db, now: int | None = None, *, check_sync: bool = True) -> bool:
    return status(db, now, check_sync=check_sync)['mode'] in {'online', 'offline'}


def require_current(db):
    if not status(db)['identity_changes']:
        raise PeerError('GROVE_QUORUM_REQUIRED', '身份变更需要 Grove 多数成员完成当前权限同步，请连接恢复后重试。')
