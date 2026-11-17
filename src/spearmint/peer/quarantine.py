"""Administrative Mesh isolation recorded on the local node."""

import sqlite3
import time

from ..state import State, audit
from .credentials import NODE_ID
from .protocol import PeerError, matches


def entries(db: sqlite3.Connection) -> dict[str, dict]:
    return {row['node_id']: {'recorded_at': row['recorded_at'], 'reason': row['reason']}
            for row in db.execute('SELECT * FROM mesh_quarantine')}


def contains(db: sqlite3.Connection, node_id: str) -> bool:
    return db.execute('SELECT 1 FROM mesh_quarantine WHERE node_id=?', (node_id,)).fetchone() is not None


def set_state(state: State, node_id: str, reason: str | None, *, actor: str = 'admin', source: str = 'local') -> dict | None:
    if not matches(NODE_ID, node_id):
        raise PeerError('INVALID_REQUEST', 'Enter the complete Node ID')
    if reason is not None:
        reason = reason.strip()
        if not 1 <= len(reason) <= 160 or not reason.isprintable():
            raise PeerError('INVALID_REQUEST', 'Enter a single printable isolation reason of up to 160 characters')
    with state.connect(write=True) as db:
        if db.execute('SELECT 1 FROM peer WHERE node_id=?', (node_id,)).fetchone() is None:
            raise PeerError('NOT_FOUND', 'Unknown Mesh member')
        if reason is None:
            removed = db.execute('DELETE FROM mesh_quarantine WHERE node_id=? RETURNING reason', (node_id,)).fetchone()
            if removed is not None:
                audit(db, actor, source, 'mesh.quarantine.released', node_id, reason=removed['reason'])
            return None
        inserted = db.execute('''
            INSERT INTO mesh_quarantine VALUES (?,?,?) ON CONFLICT(node_id) DO NOTHING
            RETURNING recorded_at, reason
        ''', (node_id, int(time.time()), reason)).fetchone()
        if inserted is not None:
            # Work submitted against the old pairing epoch cannot resume after release.
            db.execute('UPDATE peer SET write_epoch=lower(hex(randomblob(16))) WHERE node_id=?', (node_id,))
            db.execute('DELETE FROM peer_challenge WHERE peer_id=?', (node_id,))
            audit(db, actor, source, 'mesh.quarantine.applied', node_id, reason=reason)
            return dict(inserted)
        return dict(db.execute('SELECT recorded_at,reason FROM mesh_quarantine WHERE node_id=?', (node_id,)).fetchone())
