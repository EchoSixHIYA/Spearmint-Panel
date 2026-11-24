from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
import hashlib
import os
import sqlite3
import stat
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .platforms import check_private, lock_file, secure_private, sync_directory


class StateError(RuntimeError):
    pass


ACCOUNT_SCHEMA = 9


MIGRATIONS = (
    """
    CREATE TABLE node (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        node_id TEXT NOT NULL UNIQUE,
        public_key BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE administrator (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE session (
        token_hash BLOB PRIMARY KEY,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    );
    CREATE TABLE login_attempt (
        address TEXT NOT NULL,
        attempted_at INTEGER NOT NULL
    );
    CREATE INDEX login_attempt_time ON login_attempt(attempted_at);
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY,
        recorded_at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        source TEXT NOT NULL,
        event TEXT NOT NULL,
        target TEXT
    );
    """,
    """
    CREATE TABLE service (
        id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL REFERENCES node(node_id),
        name TEXT NOT NULL UNIQUE,
        driver TEXT NOT NULL CHECK (driver IN ('process', 'docker')),
        target TEXT NOT NULL,
        spec TEXT NOT NULL,
        managed INTEGER NOT NULL CHECK (managed IN (0, 1)),
        version INTEGER NOT NULL DEFAULT 1,
        UNIQUE(driver, target)
    );
    CREATE TABLE operation (
        id TEXT PRIMARY KEY,
        service_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        source TEXT NOT NULL,
        request_key TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('start', 'stop', 'restart')),
        status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'uncertain')),
        message TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(actor, request_key)
    );
    CREATE UNIQUE INDEX operation_service_active ON operation(service_id) WHERE status IN ('queued', 'running');
    CREATE INDEX operation_history ON operation(service_id, created_at DESC);
    """,
    "CREATE INDEX audit_recent ON audit(recorded_at DESC, id DESC);",
    """
    CREATE TABLE peer (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        node_id TEXT NOT NULL UNIQUE,
        mesh_id TEXT NOT NULL,
        bind_ip TEXT NOT NULL,
        listen_port INTEGER NOT NULL,
        source_ip TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        fingerprint TEXT NOT NULL,
        ca_pem BLOB NOT NULL,
        local_pem BLOB NOT NULL,
        remote_pem BLOB NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1))
    );
    """,
    """
    CREATE TABLE peer_export (
        peer_id TEXT NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        service_id TEXT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
        directory INTEGER NOT NULL CHECK (directory IN (0, 1)),
        status INTEGER NOT NULL CHECK (status IN (0, 1)),
        logs INTEGER NOT NULL CHECK (logs IN (0, 1)),
        PRIMARY KEY (peer_id, service_id)
    );
    CREATE TABLE peer_directory (
        peer_id TEXT PRIMARY KEY REFERENCES peer(node_id) ON DELETE CASCADE,
        epoch TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
        revision INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO peer_directory(peer_id) SELECT node_id FROM peer;
    CREATE TABLE peer_projection (
        peer_id TEXT NOT NULL REFERENCES peer_directory(peer_id) ON DELETE CASCADE,
        service_id TEXT NOT NULL,
        entry TEXT NOT NULL,
        PRIMARY KEY (peer_id, service_id)
    );
    CREATE TABLE peer_event (
        peer_id TEXT NOT NULL REFERENCES peer_directory(peer_id) ON DELETE CASCADE,
        revision INTEGER NOT NULL,
        service_id TEXT NOT NULL,
        entry TEXT,
        PRIMARY KEY (peer_id, revision)
    );
    CREATE TABLE peer_mirror (
        peer_id TEXT PRIMARY KEY REFERENCES peer(node_id) ON DELETE CASCADE,
        epoch TEXT NOT NULL,
        revision INTEGER NOT NULL,
        entries TEXT NOT NULL,
        observations TEXT NOT NULL
    );
    """,
    """
    ALTER TABLE peer ADD COLUMN write_epoch TEXT NOT NULL DEFAULT '';
    UPDATE peer SET write_epoch=lower(hex(randomblob(16)));
    CREATE TABLE operator_key (
        id TEXT PRIMARY KEY,
        public_key BLOB NOT NULL
    );
    CREATE TABLE peer_grant (
        id TEXT PRIMARY KEY,
        peer_id TEXT NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        service_id TEXT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
        operator_key_id TEXT NOT NULL REFERENCES operator_key(id),
        version INTEGER NOT NULL DEFAULT 1,
        actions TEXT NOT NULL,
        read_result INTEGER NOT NULL CHECK (read_result IN (0, 1)),
        expires_at INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        UNIQUE (peer_id, service_id, operator_key_id)
    );
    CREATE TABLE peer_challenge (
        id TEXT PRIMARY KEY,
        peer_id TEXT NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        request_id TEXT NOT NULL,
        write_epoch TEXT NOT NULL,
        raw BLOB NOT NULL,
        digest BLOB NOT NULL,
        expires_at INTEGER NOT NULL,
        UNIQUE (peer_id, request_id)
    );
    CREATE TABLE peer_receipt (
        peer_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        operation_id TEXT NOT NULL UNIQUE REFERENCES operation(id),
        operator_key_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        grant_version INTEGER NOT NULL,
        service_version INTEGER NOT NULL,
        write_epoch TEXT NOT NULL,
        approval_digest BLOB NOT NULL,
        PRIMARY KEY (peer_id, request_id)
    );
    CREATE TABLE peer_outbound (
        peer_id TEXT NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        request_id TEXT NOT NULL,
        service_id TEXT NOT NULL,
        action TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        challenge_digest BLOB NOT NULL,
        submitted INTEGER NOT NULL DEFAULT 0 CHECK (submitted IN (0, 1)),
        updated_at INTEGER NOT NULL,
        result TEXT,
        PRIMARY KEY (peer_id, request_id)
    );
    """,
    """
    CREATE TABLE mesh_profile (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        mesh_id TEXT NOT NULL UNIQUE,
        bind_ip TEXT NOT NULL,
        listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1024 AND 65535),
        ca_pem BLOB NOT NULL,
        local_pem BLOB NOT NULL,
        discovery INTEGER NOT NULL DEFAULT 0 CHECK (discovery IN (0, 1)),
        forwarding INTEGER NOT NULL DEFAULT 0 CHECK (forwarding IN (0, 1))
    );
    INSERT INTO mesh_profile (singleton, mesh_id, bind_ip, listen_port, ca_pem, local_pem)
        SELECT 1, mesh_id, bind_ip, listen_port, ca_pem, local_pem FROM peer;

    CREATE TABLE peer_next (
        node_id TEXT PRIMARY KEY NOT NULL,
        mesh_id TEXT NOT NULL REFERENCES mesh_profile(mesh_id),
        host TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        remote_pem BLOB NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
        write_epoch TEXT NOT NULL,
        legacy INTEGER UNIQUE CHECK (legacy = 1),
        routed INTEGER NOT NULL DEFAULT 0 CHECK (routed IN (0, 1))
    );
    INSERT INTO peer_next (node_id, mesh_id, host, fingerprint, remote_pem, enabled, write_epoch, legacy)
        SELECT node_id, mesh_id, host, fingerprint, remote_pem, enabled, write_epoch, 1 FROM peer;

    CREATE TABLE peer_neighbor (
        node_id TEXT PRIMARY KEY NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        source_ip TEXT,
        port INTEGER NOT NULL CHECK (port BETWEEN 1024 AND 65535)
    );
    INSERT INTO peer_neighbor (node_id, source_ip, port) SELECT node_id, source_ip, port FROM peer;
    DROP TABLE peer;
    ALTER TABLE peer_next RENAME TO peer;
    """,
    """
    ALTER TABLE mesh_profile ADD COLUMN address_generation TEXT NOT NULL DEFAULT '';
    ALTER TABLE mesh_profile ADD COLUMN address_sequence INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE mesh_profile ADD COLUMN address_issued_at INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE mesh_profile ADD COLUMN address_record TEXT;
    UPDATE mesh_profile SET address_generation=lower(hex(randomblob(16)));

    CREATE TABLE peer_address_state (
        node_id TEXT PRIMARY KEY NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        generation TEXT NOT NULL,
        highest_sequence INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE peer_address_cache (
        node_id TEXT PRIMARY KEY NOT NULL REFERENCES peer_address_state(node_id) ON DELETE CASCADE,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        record TEXT NOT NULL
    );
    CREATE TABLE peer_network (
        node_id TEXT NOT NULL REFERENCES peer(node_id) ON DELETE CASCADE,
        network TEXT NOT NULL,
        port INTEGER NOT NULL CHECK (port BETWEEN 1024 AND 65535),
        PRIMARY KEY (node_id, network, port)
    );
    """,
    """
    CREATE TABLE panel_account (
        id TEXT PRIMARY KEY NOT NULL DEFAULT ('acct1-' || lower(hex(randomblob(16)))),
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('node_admin', 'remote_operator')),
        operation_actor TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK (auth_epoch > 0)
    );
    INSERT INTO panel_account (username, password_hash, role, operation_actor)
        SELECT username, password_hash, 'node_admin', 'admin' FROM administrator WHERE singleton=1;
    DROP TABLE administrator;

    DROP TABLE session;
    CREATE TABLE session (
        token_hash BLOB PRIMARY KEY NOT NULL,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        account_id TEXT NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        auth_epoch INTEGER NOT NULL
    );
    CREATE INDEX session_account ON session(account_id);
    DELETE FROM login_attempt;
    DELETE FROM peer_challenge;
    """,
    """
    ALTER TABLE panel_account ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0 CHECK (require_mfa IN (0, 1));
    ALTER TABLE session ADD COLUMN mfa_at INTEGER;

    CREATE TABLE panel_totp (
        account_id TEXT PRIMARY KEY NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        secret BLOB NOT NULL,
        last_step INTEGER NOT NULL
    );
    CREATE TABLE panel_recovery_code (
        account_id TEXT NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        code_hash BLOB NOT NULL,
        PRIMARY KEY (account_id, code_hash)
    );
    CREATE TABLE panel_totp_enrollment (
        account_id TEXT PRIMARY KEY NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        token_hash BLOB NOT NULL,
        auth_epoch INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE panel_auth_flow (
        token_hash BLOB PRIMARY KEY NOT NULL,
        account_id TEXT NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        auth_epoch INTEGER NOT NULL,
        address TEXT NOT NULL,
        purpose TEXT NOT NULL CHECK (purpose IN ('login', 'totp_rebind')),
        expires_at INTEGER NOT NULL,
        failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
        pending_secret BLOB
    );
    CREATE INDEX panel_auth_flow_account ON panel_auth_flow(account_id);
    CREATE INDEX panel_auth_flow_expiry ON panel_auth_flow(expires_at);
    """,
    """
    ALTER TABLE panel_totp_enrollment RENAME TO panel_factor_enrollment;
    ALTER TABLE panel_factor_enrollment ADD COLUMN method TEXT NOT NULL DEFAULT 'totp'
        CHECK (method IN ('totp', 'passkey'));
    DELETE FROM panel_factor_enrollment;
    DROP TABLE panel_auth_flow;
    CREATE TABLE panel_auth_flow (
        token_hash BLOB PRIMARY KEY NOT NULL,
        account_id TEXT NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        auth_epoch INTEGER NOT NULL,
        address TEXT NOT NULL,
        purpose TEXT NOT NULL CHECK (purpose IN ('login', 'totp_rebind', 'passkey_login', 'passkey_enroll')),
        expires_at INTEGER NOT NULL,
        failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
        pending_secret BLOB,
        webauthn_state TEXT,
        origin TEXT
    );
    CREATE INDEX panel_auth_flow_account ON panel_auth_flow(account_id);
    CREATE INDEX panel_auth_flow_expiry ON panel_auth_flow(expires_at);
    CREATE TABLE panel_passkey (
        id TEXT PRIMARY KEY NOT NULL DEFAULT (lower(hex(randomblob(16)))),
        account_id TEXT NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        credential_id BLOB NOT NULL UNIQUE,
        credential BLOB NOT NULL,
        origin TEXT NOT NULL,
        sign_count INTEGER NOT NULL,
        backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
    );
    CREATE INDEX panel_passkey_account ON panel_passkey(account_id);
    """,
    """
    CREATE TABLE session_next (
        token_hash BLOB PRIMARY KEY NOT NULL,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        account_id TEXT NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        auth_epoch INTEGER NOT NULL,
        mfa_at INTEGER,
        session_id TEXT NOT NULL UNIQUE
    );
    INSERT INTO session_next SELECT *, lower(hex(randomblob(16))) FROM session;
    DROP TABLE session;
    ALTER TABLE session_next RENAME TO session;
    CREATE INDEX session_account ON session(account_id);
    """,
    """
    CREATE TABLE mesh_policy_trust (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        mesh_id TEXT NOT NULL UNIQUE,
        root_key BLOB NOT NULL,
        last_clock INTEGER NOT NULL DEFAULT 0,
        frozen_term INTEGER NOT NULL DEFAULT 0,
        resume_nonce TEXT,
        execution_epoch TEXT NOT NULL DEFAULT (lower(hex(randomblob(16))))
    );
    CREATE TABLE mesh_policy_head (
        mesh_id TEXT PRIMARY KEY NOT NULL REFERENCES mesh_policy_trust(mesh_id),
        term INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        digest TEXT NOT NULL,
        delegation_digest TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        bundle TEXT NOT NULL
    );
    CREATE TABLE mesh_policy_conflict (
        mesh_id TEXT NOT NULL REFERENCES mesh_policy_trust(mesh_id),
        term INTEGER NOT NULL,
        prior_bundle TEXT NOT NULL,
        incoming_bundle TEXT NOT NULL,
        recorded_at INTEGER NOT NULL,
        PRIMARY KEY (mesh_id, term)
    );
    CREATE TABLE mesh_policy_member (
        mesh_id TEXT NOT NULL REFERENCES mesh_policy_trust(mesh_id),
        node_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('active','revoked')),
        PRIMARY KEY (mesh_id, node_id)
    );
    CREATE TABLE mesh_policy_account (
        account_id TEXT PRIMARY KEY NOT NULL REFERENCES panel_account(id) ON DELETE CASCADE,
        mesh_id TEXT NOT NULL REFERENCES mesh_policy_trust(mesh_id),
        user_id TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE service_protection (
        service_id TEXT PRIMARY KEY NOT NULL REFERENCES service(id) ON DELETE CASCADE
    );
    CREATE TABLE peer_operation_origin (
        operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operation(id) ON DELETE CASCADE
    );
    INSERT INTO peer_operation_origin SELECT id FROM operation
        WHERE actor LIKE 'op1-%' OR EXISTS (SELECT 1 FROM peer_receipt WHERE operation_id=operation.id);
    CREATE TABLE peer_receipt_v2 (
        operation_id TEXT PRIMARY KEY NOT NULL REFERENCES peer_receipt(operation_id) ON DELETE CASCADE,
        user_id TEXT NOT NULL,
        policy_term INTEGER NOT NULL,
        policy_sequence INTEGER NOT NULL,
        execution_epoch TEXT NOT NULL
    );
    CREATE TABLE peer_outbound_v2 (
        peer_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        account_id TEXT NOT NULL REFERENCES panel_account(id),
        user_id TEXT NOT NULL,
        PRIMARY KEY (peer_id, request_id),
        FOREIGN KEY (peer_id,request_id) REFERENCES peer_outbound(peer_id,request_id) ON DELETE CASCADE
    );
    CREATE TABLE peer_operation_audit (
        id INTEGER PRIMARY KEY,
        recorded_at INTEGER NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        service_id TEXT,
        request_id TEXT,
        operation_id TEXT,
        user_id TEXT,
        operator_key_id TEXT,
        action TEXT,
        policy_term INTEGER,
        policy_sequence INTEGER,
        grant_id TEXT,
        grant_version INTEGER,
        stage TEXT NOT NULL,
        reason TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX peer_operation_audit_limit ON peer_operation_audit(source,stage,reason,recorded_at);
    """,
    """
    ALTER TABLE login_attempt ADD COLUMN account_key BLOB;
    CREATE INDEX login_attempt_address_time ON login_attempt(address,attempted_at);
    CREATE INDEX login_attempt_account_time ON login_attempt(account_key,attempted_at);
    ALTER TABLE audit ADD COLUMN reason TEXT;
    ALTER TABLE audit ADD COLUMN count INTEGER NOT NULL DEFAULT 1 CHECK (count > 0);
    """,
    """
    CREATE TABLE grove_realm (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        public_key BLOB NOT NULL,
        issuer_node TEXT NOT NULL,
        issuer_origin TEXT NOT NULL,
        is_issuer INTEGER NOT NULL CHECK (is_issuer IN (0,1)),
        sequence INTEGER NOT NULL DEFAULT 0,
        manifest TEXT,
        frozen TEXT NOT NULL DEFAULT '',
        issuer_paused INTEGER NOT NULL DEFAULT 0 CHECK (issuer_paused IN (0,1))
    );
    CREATE TABLE grove_member (
        node_id TEXT PRIMARY KEY,
        origin TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1))
    );
    CREATE TABLE grove_account (
        account_id TEXT PRIMARY KEY REFERENCES panel_account(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        identity_epoch INTEGER NOT NULL,
        valid_until INTEGER NOT NULL
    );
    CREATE TABLE grove_login_flow (
        nonce TEXT PRIMARY KEY,
        browser_hash BLOB NOT NULL,
        expires_at INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('login','join')),
        realm TEXT NOT NULL,
        setup_hash BLOB
    );
    CREATE TABLE grove_operation (
        operation_id TEXT PRIMARY KEY REFERENCES operation(id) ON DELETE CASCADE,
        token_hash BLOB NOT NULL,
        account_id TEXT NOT NULL REFERENCES panel_account(id)
    );
    """,
    """
    CREATE TABLE frp_exposure (
        id TEXT PRIMARY KEY,
        service_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        protocol TEXT NOT NULL CHECK (protocol IN ('http','https','tcp')),
        domain TEXT,
        public_port INTEGER NOT NULL,
        public_address TEXT NOT NULL,
        local_address TEXT NOT NULL,
        config_sha256 TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('starting','running','revoking','revoked','expired','failed')),
        health TEXT,
        detail TEXT,
        guardian_pid INTEGER,
        guardian_start TEXT
    );
    CREATE UNIQUE INDEX frp_active_address ON frp_exposure(public_address)
        WHERE status IN ('starting','running','revoking');
    CREATE INDEX frp_exposure_history ON frp_exposure(created_at DESC);
    CREATE TRIGGER frp_prevent_service_removal BEFORE DELETE ON service
    WHEN EXISTS (SELECT 1 FROM frp_exposure WHERE service_id=OLD.id AND status IN ('starting','running','revoking'))
    BEGIN
        SELECT RAISE(ABORT, 'Revoke the active FRP mappings before unregistering this service');
    END;
    """,
    """
    ALTER TABLE frp_exposure ADD COLUMN origin_node TEXT;
    CREATE TABLE frp_request (
        origin TEXT NOT NULL,
        request_id TEXT NOT NULL,
        digest BLOB NOT NULL,
        exposure_id TEXT NOT NULL REFERENCES frp_exposure(id),
        PRIMARY KEY (origin, request_id)
    );
    """,
    """
    CREATE TABLE mesh_quarantine (
        node_id TEXT PRIMARY KEY REFERENCES peer(node_id) ON DELETE CASCADE,
        recorded_at INTEGER NOT NULL,
        reason TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE mesh_evidence_share (
        mesh_id TEXT NOT NULL,
        term INTEGER NOT NULL,
        realm_id TEXT NOT NULL,
        root_key_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (mesh_id, term),
        FOREIGN KEY (mesh_id, term) REFERENCES mesh_policy_conflict (mesh_id, term) ON DELETE CASCADE
    );
    CREATE TABLE mesh_evidence_inbox (
        observer TEXT NOT NULL,
        proof_id TEXT NOT NULL,
        realm_id TEXT NOT NULL,
        mesh_id TEXT NOT NULL,
        root_key_id TEXT NOT NULL,
        term INTEGER NOT NULL,
        kind TEXT NOT NULL,
        recorded_at INTEGER NOT NULL,
        received_at INTEGER NOT NULL,
        document TEXT NOT NULL,
        PRIMARY KEY (observer, proof_id)
    );
    CREATE INDEX mesh_evidence_received ON mesh_evidence_inbox (received_at DESC);
    """,
    """
    ALTER TABLE session ADD COLUMN grove_replica INTEGER NOT NULL DEFAULT 0 CHECK (grove_replica IN (0,1));
    CREATE TABLE grove_login_replica (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        sequence INTEGER NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        payload_digest TEXT NOT NULL
    );
    CREATE TABLE grove_login_verifier (
        user_id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK (role IN ('node_admin','remote_operator')),
        epoch INTEGER NOT NULL,
        verifier BLOB NOT NULL,
        last_step INTEGER NOT NULL DEFAULT -1
    );
    """,
    """
    ALTER TABLE grove_login_replica ADD COLUMN content_digest TEXT;
    CREATE TABLE grove_login_continuity (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        sequence INTEGER NOT NULL,
        anchor TEXT NOT NULL,
        lease_until INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    ALTER TABLE grove_login_replica ADD COLUMN standby TEXT;
    ALTER TABLE grove_login_replica ADD COLUMN standby_lease_until INTEGER NOT NULL DEFAULT 0;
    """,
    """
    ALTER TABLE grove_login_replica ADD COLUMN recovery TEXT;
    ALTER TABLE grove_login_continuity ADD COLUMN recovery_proof TEXT;
    CREATE TABLE grove_login_recovery_vote (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        anchor_digest TEXT NOT NULL,
        ballot TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE grove_login_revocation (
        user_id TEXT PRIMARY KEY,
        anchor_digest TEXT NOT NULL,
        document TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE grove_login_password (
        user_id TEXT PRIMARY KEY,
        anchor_digest TEXT NOT NULL,
        generation INTEGER NOT NULL,
        change_digest TEXT NOT NULL,
        document BLOB NOT NULL
    );
    """,
    """
    CREATE TABLE grove_login_role (
        user_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('node_admin','remote_operator')),
        certificate TEXT NOT NULL
    );
    CREATE TABLE grove_login_role_vote (
        user_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL,
        ballot TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE grove_member_admission (
        node_id TEXT PRIMARY KEY,
        origin TEXT NOT NULL UNIQUE,
        certificate TEXT NOT NULL
    );
    CREATE TABLE grove_member_admission_vote (
        node_id TEXT PRIMARY KEY,
        origin TEXT NOT NULL UNIQUE,
        ballot TEXT NOT NULL
    );
    """,
    """
    ALTER TABLE peer ADD COLUMN ingress_only INTEGER NOT NULL DEFAULT 0 CHECK (ingress_only IN (0, 1));
    CREATE TABLE mesh_enrollment_local (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        policy TEXT NOT NULL,
        certificate BLOB NOT NULL,
        complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1))
    );
    """,
    """
    CREATE TABLE grove_node_note (
        node_id TEXT PRIMARY KEY,
        revision INTEGER NOT NULL,
        author TEXT NOT NULL,
        note TEXT NOT NULL,
        envelope TEXT NOT NULL
    );
    CREATE TABLE grove_member_departure (
        node_id TEXT PRIMARY KEY,
        envelope TEXT NOT NULL
    );
    """,
)


def private_path(path: Path, mode: int, *, directory: bool = False) -> None:
    try:
        check_private(path, mode, directory)
    except ValueError as error:
        raise StateError(str(error)) from error


def audit(db: sqlite3.Connection, actor: str, source: str, event: str, target: str | None = None,
          *, reason: str | None = None, aggregate: bool = False, recorded_at: int | None = None) -> None:
    now = int(time.time()) if recorded_at is None else recorded_at
    if aggregate:
        prior = db.execute("""
            SELECT id FROM audit WHERE recorded_at>? AND actor=? AND source=? AND event=? AND target IS ? AND reason IS ?
            ORDER BY recorded_at DESC, id DESC LIMIT 1
        """, (now - 60, actor, source, event, target, reason)).fetchone()
        if prior is not None:
            db.execute("UPDATE audit SET count=count+1 WHERE id=?", (prior[0],))
            return
    if reason is None:
        db.execute("INSERT INTO audit(recorded_at, actor, source, event, target) VALUES (?, ?, ?, ?, ?)",
                   (now, actor, source, event, target))
    else:
        db.execute("INSERT INTO audit(recorded_at, actor, source, event, target, reason) VALUES (?, ?, ?, ?, ?, ?)",
                   (now, actor, source, event, target, reason))


def has_bootstrap_account(db: sqlite3.Connection, version: int) -> bool:
    if version < ACCOUNT_SCHEMA:
        return db.execute("SELECT 1 FROM administrator WHERE singleton=1").fetchone() is not None
    return db.execute("SELECT 1 FROM panel_account WHERE operation_actor='admin'").fetchone() is not None


class State:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.database = directory / "state.sqlite3"
        self.key_path = directory / "node.key"

    def prepare_directory(self) -> None:
        created = not self.directory.exists()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if created:
            secure_private(self.directory, 0o700)
        private_path(self.directory, 0o700, directory=True)

    @contextmanager
    def lock(self, name: str, *, exclusive_now: bool = False) -> Iterator[None]:
        private_path(self.directory, 0o700, directory=True)
        lock_path = self.directory / name
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            private_path(lock_path, 0o600)
            try:
                lock_file(fd, exclusive_now)
            except BlockingIOError as exc:
                raise StateError("The Spearmint state is in use") from exc
            yield
        finally:
            os.close(fd)

    @contextmanager
    def connect(self, *, write: bool = False, read_only: bool = False) -> Iterator[sqlite3.Connection]:
        mode = "ro" if read_only else "rw"
        db = sqlite3.connect(self.database.as_uri() + f"?mode={mode}", uri=True, timeout=2, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys = ON")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        finally:
            db.close()

    def signing_key(self) -> Ed25519PrivateKey:
        private_path(self.key_path, 0o600)
        try:
            return Ed25519PrivateKey.from_private_bytes(self.key_path.read_bytes())
        except ValueError as exc:
            raise StateError("Node key is damaged. Restore the state from a verified backup") from exc

    def identity(self) -> tuple[str, bytes]:
        public_key = self.signing_key().public_key().public_bytes_raw()
        return "spm1-" + hashlib.sha256(public_key).hexdigest(), public_key

    def write_key(self, key_bytes: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".node-key-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as key:
                key.write(key_bytes)
                key.flush()
                os.fsync(key.fileno())
            os.replace(temporary, self.key_path)
            sync_directory(self.directory)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def migrate(self) -> None:
        with self.connect() as db:
            current = db.execute("PRAGMA user_version").fetchone()[0]
            if current > len(MIGRATIONS):
                raise StateError("State schema is newer than this version. Restore a compatible backup")
            for version in range(current + 1, len(MIGRATIONS) + 1):
                if version == 7:
                    # Rebuild the referenced peer table without cascading the old table's drop.
                    db.execute("PRAGMA foreign_keys = OFF")
                db.executescript(f"BEGIN IMMEDIATE;\n{MIGRATIONS[version - 1]}\nPRAGMA user_version = {version};")
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise StateError(f"State migration to schema {version} failed its foreign key check")
                db.commit()
                db.execute("PRAGMA foreign_keys = ON")

    def initialize(self, password_hash: Callable[[], str]) -> str:
        self.prepare_directory()
        with self.lock("maintenance.lock"):
            database_exists = os.path.lexists(self.database)
            if not os.path.lexists(self.key_path):
                if database_exists:
                    raise StateError("Database exists without a node key. Restore the original key")
                self.write_key(Ed25519PrivateKey.generate().private_bytes_raw())
            node_id, public_key = self.identity()
            if not database_exists:
                os.close(os.open(self.database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            private_path(self.database, 0o600)
            with self.connect() as db:
                version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > len(MIGRATIONS):
                raise StateError("State schema is newer than this version. Restore a compatible backup")
            if version == 0:
                self.migrate()
                version = len(MIGRATIONS)
            with self.connect() as db:
                existing = db.execute("SELECT node_id, public_key FROM node WHERE singleton=1").fetchone()
                has_account = has_bootstrap_account(db, version)
            if existing is not None or has_account:
                self.verify()
                return node_id
            if version < len(MIGRATIONS):
                self.migrate()
                version = len(MIGRATIONS)
            credential = password_hash()
            with self.connect(write=True) as db:
                db.execute("INSERT INTO node VALUES (1, ?, ?, ?)", (node_id, public_key, int(time.time())))
                if version < ACCOUNT_SCHEMA:
                    db.execute("INSERT INTO administrator VALUES (1, 'admin', ?)", (credential,))
                else:
                    db.execute(
                        """INSERT INTO panel_account (username, password_hash, role, operation_actor)
                           VALUES ('admin', ?, 'node_admin', 'admin')""", (credential,),
                    )
                audit(db, "admin", "local", "node.initialized", node_id)
            return node_id

    def verify(self, *, allow_older: bool = False) -> str:
        return self.verify_schema(allow_older=allow_older)[0]

    def verify_schema(self, *, allow_older: bool = False) -> tuple[str, int]:
        try:
            private_path(self.directory, 0o700, directory=True)
            private_path(self.database, 0o600)
            node_id, public_key = self.identity()
        except FileNotFoundError as exc:
            raise StateError("State is incomplete. Initialize a fresh state or restore the existing identity") from exc
        with self.connect(read_only=True) as db:
            db.execute("BEGIN")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version != len(MIGRATIONS) and not (allow_older and 1 <= version < len(MIGRATIONS)):
                raise StateError(f"Incompatible state schema {version}; this version expects {len(MIGRATIONS)}. "
                                 "Run the documented migration or restore procedure")
            node = db.execute("SELECT node_id, public_key FROM node WHERE singleton=1").fetchone()
            has_account = has_bootstrap_account(db, version)
        if node is None or tuple(node) != (node_id, public_key) or not has_account:
            raise StateError("Node identity or administrator is inconsistent. Restore the verified state")
        return node_id, version
