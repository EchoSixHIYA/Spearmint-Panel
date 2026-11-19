"""Interactive sessions carried by the authenticated Grove Mesh."""
from contextlib import suppress
from dataclasses import dataclass, field
import os
from pathlib import Path
from threading import Condition, Lock, Thread
from time import monotonic

from .peer.grove_service_admin import GroveServiceAdmin
from .peer.protocol import PeerError, parse_b64, wire_b64
from .peer.service_setup import LocalAdmin
from .state import audit
from .terminal_files import Upload, directory, path_for, read_file
from .terminal_host import open_terminal


METHOD = 'grove.terminal.v1'
BUFFER_SIZE = 1024 * 1024
OUTPUT_SIZE = 32768
IDLE_SECONDS = 60


def integer(value, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


@dataclass
class TerminalSession:
    owner: tuple
    backend: object
    expires: float = field(default_factory=lambda: monotonic() + IDLE_SECONDS)
    buffer: bytearray = field(default_factory=bytearray)
    base: int = 0
    sequence: int = 0
    last_input: bytes = b''
    ended: bool = False
    closed: bool = False
    condition: Condition = field(default_factory=Condition)
    serial: Lock = field(default_factory=Lock)
    files_lock: Lock = field(default_factory=Lock)
    uploads: dict = field(default_factory=dict)

    def start(self):
        self.reader = Thread(target=self.read_output, name='terminal-output', daemon=True)
        self.reader.start()

    def read_output(self):
        try:
            while True:
                with self.condition:
                    self.condition.wait_for(lambda: self.closed or len(self.buffer) < BUFFER_SIZE)
                    if self.closed:
                        return
                data = self.backend.read()
                if not data:
                    break
                with self.condition:
                    self.buffer.extend(data)
                    self.condition.notify_all()
        except (OSError, EOFError):
            pass
        finally:
            with self.condition:
                self.ended = True
                self.condition.notify_all()

    def exchange(self, body: dict) -> dict:
        if body.keys() != {'offset', 'sequence', 'data', 'columns', 'rows'}:
            raise PeerError('INVALID_REQUEST', 'Invalid terminal exchange')
        offset, sequence, columns, rows = (body[key] for key in ('offset', 'sequence', 'columns', 'rows'))
        if not (integer(offset, 0, 2**53 - 1) and integer(sequence, 0, 2**53 - 1)
                and integer(columns, 2, 500) and integer(rows, 2, 250)):
            raise PeerError('INVALID_REQUEST', 'Invalid terminal position or size')
        data = parse_b64(body['data'], 4096)
        with self.serial:
            with self.condition:
                if self.closed or not self.base <= offset <= self.base + len(self.buffer):
                    raise PeerError('TERMINAL_CLOSED', 'The terminal session has ended')
                del self.buffer[:offset - self.base]
                self.base = offset
                self.condition.notify_all()
            if sequence == self.sequence + 1 and data:
                self.backend.write(data)
                self.sequence = sequence
                self.last_input = data
            elif sequence != self.sequence or (data and data != self.last_input):
                raise PeerError('CONFLICT', 'Terminal input sequence changed')
            if not self.ended:
                self.backend.resize(columns, rows)
            with self.condition:
                if not self.buffer and not self.ended:
                    self.condition.wait(timeout=.12)
                output = bytes(self.buffer[:OUTPUT_SIZE])
                return {'data': wire_b64(output), 'offset': self.base + len(output), 'sequence': self.sequence,
                        'ended': self.ended and len(output) == len(self.buffer)}

    def close(self):
        with self.condition:
            if self.closed:
                return
            self.closed = True
            self.condition.notify_all()
        with suppress(OSError, EOFError):
            self.backend.close()
        self.reader.join(timeout=2)
        with self.files_lock:
            for upload in self.uploads.values():
                upload.close()

    def files(self, body: dict) -> dict:
        action = body.get('operation')
        offset = body.get('offset', 0)
        if not integer(offset, 0, 2**53 - 1):
            raise PeerError('INVALID_REQUEST', 'Invalid file offset')
        with self.files_lock:
            if action == 'list' and body.keys() <= {'operation', 'path', 'offset'}:
                return directory(path_for(body.get('path', '')), offset)
            if action == 'read' and body.keys() <= {'operation', 'path', 'offset', 'version'}:
                return read_file(path_for(body.get('path')), offset, body.get('version'))
            transfer = body.get('transfer')
            if not isinstance(transfer, str) or len(transfer) != 32 or any(char not in '0123456789abcdef' for char in transfer):
                raise PeerError('INVALID_REQUEST', 'Invalid transfer ID')
            if action == 'begin' and body.keys() == {'operation', 'transfer', 'path', 'size', 'version'}:
                if not integer(body['size'], 0, 2**53 - 1):
                    raise PeerError('INVALID_REQUEST', 'Invalid upload size')
                path = path_for(body['path'])
                upload = self.uploads.get(transfer)
                if upload is not None:
                    if (upload.path, upload.size, upload.expected) != (path, body['size'], body['version']):
                        raise PeerError('CONFLICT', 'Upload ID was reused')
                    return {'offset': upload.offset}
                if len(self.uploads) >= 32:
                    for identifier, completed in list(self.uploads.items()):
                        if not completed.temporary.exists():
                            del self.uploads[identifier]
                if len(self.uploads) >= 16:
                    raise PeerError('BUSY', 'Finish the active file transfers first')
                self.uploads[transfer] = Upload.create(path, body['version'], body['size'])
                return {'offset': 0}
            upload = self.uploads.get(transfer)
            if upload is None:
                raise PeerError('NOT_FOUND', 'Unknown upload')
            if action == 'write' and body.keys() == {'operation', 'transfer', 'offset', 'data'}:
                return upload.write(offset, body['data'])
            if action == 'finish' and body.keys() == {'operation', 'transfer'}:
                return upload.finish()
        raise PeerError('INVALID_REQUEST', 'Unknown file operation')


class TerminalService:
    method = METHOD

    def __init__(self, state, local_id: str):
        self.state, self.local_id = state, local_id
        self.sessions: dict[str, TerminalSession] = {}
        self.lock = Lock()

    def dispatch(self, pair, params):
        if params.keys() != {'identity', 'owner', 'session', 'action', 'body'}:
            raise PeerError('INVALID_REQUEST', 'Invalid terminal request')
        actor = GroveServiceAdmin.from_wire(self.local_id, pair, params['identity'])
        return self.request(actor, pair.node_id, params['owner'], params['session'], params['action'], params['body'])

    def request(self, actor, source, owner, identifier, action, body):
        if (not isinstance(owner, str) or len(owner) != 32 or not isinstance(identifier, str) or len(identifier) != 32
                or any(char not in '0123456789abcdef' for char in owner + identifier) or not isinstance(body, dict)):
            raise PeerError('INVALID_REQUEST', 'Invalid terminal session ID')
        with self.state.connect(read_only=True) as db:
            actor.require(db)
        account = actor.actor.account_id if isinstance(actor, LocalAdmin) else tuple(actor.identity)
        key = (source, owner, account)
        try:
            with self.lock:
                session = self.sessions.get(identifier)
                if session is not None and session.owner != key:
                    raise PeerError('DENIED', 'The terminal belongs to another login session')
                if action == 'open':
                    if body.keys() != {'columns', 'rows'} or not integer(body['columns'], 2, 500) or not integer(body['rows'], 2, 250):
                        raise PeerError('INVALID_REQUEST', 'Invalid terminal dimensions')
                    if session is None:
                        if len(self.sessions) >= 8:
                            raise PeerError('BUSY', 'Close an existing terminal before opening another')
                        backend = open_terminal(body['columns'], body['rows'])
                        session = TerminalSession(key, backend)
                        session.start()
                        try:
                            with self.state.connect(write=True) as db:
                                actor.require(db)
                                audit(db, actor.actor.operation_actor if isinstance(actor, LocalAdmin) else actor.operation_actor,
                                      source, 'terminal.opened', identifier)
                        except BaseException:
                            session.close()
                            raise
                        self.sessions[identifier] = session
                    return {'session': identifier, 'home': str(Path.home()), 'shell': 'cmd' if os.name == 'nt' else 'shell'}
                if action == 'close':
                    if body:
                        raise PeerError('INVALID_REQUEST', 'Invalid terminal close request')
                    session = self.sessions.pop(identifier, None)
                elif session is None:
                    raise PeerError('TERMINAL_CLOSED', 'The terminal session has ended')
                else:
                    session.expires = monotonic() + IDLE_SECONDS
            if action == 'close':
                if session is not None:
                    session.close()
                return {'closed': True}
            if action == 'exchange':
                return session.exchange(body)
            if action == 'files':
                return session.files(body)
        except PermissionError as error:
            raise PeerError('HOST_PERMISSION', 'The terminal account cannot access this file') from error
        except (OSError, EOFError) as error:
            raise PeerError('TERMINAL_IO', 'The host terminal or file is unavailable') from error
        except ValueError as error:
            raise PeerError('INVALID_REQUEST', 'Invalid terminal data') from error
        raise PeerError('INVALID_REQUEST', 'Unknown terminal action')

    def reap(self):
        with self.lock:
            expired = [identifier for identifier, session in self.sessions.items() if session.expires < monotonic()]
            sessions = [self.sessions.pop(identifier) for identifier in expired]
        for session in sessions:
            session.close()

    def shutdown(self):
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.close()
