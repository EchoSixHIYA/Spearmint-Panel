"""Bounded local evidence of rejected Grove business requests, without credentials."""
import json
from pathlib import Path
from threading import Lock
import time

from .platforms import secure_private
from .update_worker import write_record


class PeerFailures:
    limit = 64

    def __init__(self, state, local_id):
        self.path = state.directory / 'diagnostics' / 'peer-failures.json'
        self.local_id = local_id
        self.lock = Lock()
        self.rows = []
        self.written_at = 0.0
        try:
            value = json.loads(self.path.read_bytes())
            if value.get('version') == 1 and isinstance(value.get('events'), list):
                self.rows = value['events'][-self.limit:]
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def record(self, target, method, stage, error, context=None):
        if error.code not in {'DENIED', 'CONFLICT', 'GROVE_SYNCHRONIZING'}:
            return
        try:
            with self.lock:
                now = time.time()
                detail = ''.join(char for char in str(error) if char >= ' ')[:512]
                key = (target, method, stage, error.code, detail)
                previous = next((row for row in reversed(self.rows) if
                    (row.get('target'), row.get('method'), row.get('stage'), row.get('code'), row.get('detail')) == key), None)
                if previous is None:
                    previous = {'target': target, 'method': method, 'stage': stage, 'code': error.code,
                                'detail': detail, 'first_seen': now, 'count': 0}
                    self.rows.append(previous)
                previous.update(last_seen=now, count=previous['count'] + 1, context=context or {})
                self.rows = self.rows[-self.limit:]
                if now - self.written_at >= 2 or previous['count'] == 1:
                    self.path.parent.mkdir(mode=0o700, exist_ok=True)
                    secure_private(self.path.parent, 0o700)
                    write_record(self.path, {'version': 1, 'local_node': self.local_id, 'updated_at': now, 'events': self.rows})
                    self.written_at = now
        except Exception:
            # Diagnostic I/O must never replace the original business result.
            pass
