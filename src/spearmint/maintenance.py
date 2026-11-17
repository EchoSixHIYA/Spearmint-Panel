from collections.abc import Callable
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .state import MIGRATIONS, State, StateError, audit, private_path
from .platforms import replace_file, secure_private, sync_directory, WINDOWS
from .frp_runtime import clear_restored, require_stopped
from .peer.mesh_policy import pause_restored, recovery_checkpoint
from .peer.quarantine import entries as quarantine_entries


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sync(path: Path) -> None:
    if path.is_dir():
        sync_directory(path)
        return
    # Windows' CRT can strip a trailing Ctrl-Z when opening a text file for
    # reading and writing, even though this handle is only used for fsync.
    flags = os.O_RDWR | os.O_BINARY if WINDOWS else os.O_RDONLY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_integrity(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)] or db.execute("PRAGMA foreign_key_check").fetchone():
        raise StateError("SQLite integrity check failed")


def backup(state: State, destination: Path) -> str:
    node_id = state.verify(allow_older=True)
    from .onboarding import pending
    if pending(state):
        raise StateError("Complete first-run setup before creating a backup")
    if destination.resolve().is_relative_to(state.directory.resolve()):
        raise StateError("Choose a backup directory outside the active state directory")
    if os.path.lexists(destination):
        raise StateError("Choose a new backup directory; the destination already exists")
    with tempfile.TemporaryDirectory(prefix=".backup-", dir=destination.parent) as temporary:
        stage = Path(temporary)
        secure_private(stage, 0o700)
        bundle = State(stage / "snapshot")
        bundle.prepare_directory()
        _write_backup(state, bundle, node_id)
        if os.path.lexists(destination):
            raise StateError("Choose a new backup directory; the destination already exists")
        # Both directories are on the same volume. A concurrent completed
        # backup has a nonempty destination and cannot be replaced by rename.
        bundle.directory.rename(destination)
        sync(destination.parent)
    return node_id


def _write_backup(state: State, bundle: State, node_id: str) -> None:
    bundle.key_path.write_bytes(state.key_path.read_bytes())
    bundle.key_path.chmod(0o600)
    os.close(os.open(bundle.database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    with state.connect() as source, closing(sqlite3.connect(bundle.database)) as target:
        source.backup(target)
        version = target.execute("PRAGMA user_version").fetchone()[0]
    manifest = {
        "node_id": node_id, "schema": version,
        "database_sha256": file_digest(bundle.database), "key_sha256": file_digest(bundle.key_path),
    }
    extra_paths = []
    from .grove import KEY_FILE
    if (state.directory / KEY_FILE).exists():
        private_path(state.directory / KEY_FILE, 0o600)
        extra = bundle.directory / KEY_FILE
        extra.write_bytes((state.directory / KEY_FILE).read_bytes())
        secure_private(extra)
        manifest['extra_files'] = {KEY_FILE: file_digest(extra)}
        extra_paths.append(extra)
    manifest_path = bundle.directory / "manifest.json"
    fd = os.open(manifest_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    if verify_backup(bundle.directory)["node_id"] != node_id:
        raise StateError("Backup identity verification failed")
    for path in (*extra_paths, bundle.database, bundle.key_path, manifest_path, bundle.directory):
        sync(path)


def migration_plan(state: State) -> dict:
    node_id, schema = state.verify_schema(allow_older=True)
    target = len(MIGRATIONS)
    return {"node_id": node_id, "state_directory": str(state.directory), "current_schema": schema,
            "target_schema": target, "migration_required": schema != target}


def require_no_sidecars(state: State) -> None:
    if any(os.path.lexists(f"{state.database}{suffix}") for suffix in ("-journal", "-wal", "-shm")):
        raise StateError("Unexpected SQLite sidecar exists. Stop all writers before replacing the database")


def migrate_offline(state: State, destination: Path) -> str:
    """Migrate a verified snapshot before replacing the active database."""
    plan = migration_plan(state)
    if not plan["migration_required"]:
        return backup(state, destination)
    with state.connect(read_only=True) as db:
        has_frp = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='frp_exposure'").fetchone()
    if has_frp:
        require_stopped(state, operation="migrating")
    require_no_sidecars(state)
    with tempfile.TemporaryDirectory(prefix=".migrate-", dir=state.directory) as temporary:
        candidate = State(Path(temporary))
        secure_private(candidate.directory, 0o700)
        with state.connect(read_only=True) as db:
            data_version = db.execute("PRAGMA data_version").fetchone()[0]
            node_id = backup(state, destination)
            snapshot = State(destination)
            candidate.write_key(snapshot.key_path.read_bytes())
            shutil.copyfile(snapshot.database, candidate.database)
            secure_private(candidate.database)
            candidate.migrate()
            if candidate.verify() != node_id:
                raise StateError("Migrated node identity differs from the backup")
            with closing(sqlite3.connect(candidate.database)) as migrated:
                check_integrity(migrated)
            sync(candidate.database)
            if db.execute("PRAGMA data_version").fetchone()[0] != data_version:
                raise StateError("The active database changed during migration. Stop all writers and retry")
        require_no_sidecars(state)
        replace_file(candidate.database, state.database)
        sync(state.directory)
    return node_id


def read_backup(source: Path, *, allow_older: bool = False) -> tuple[State, dict, bytes]:
    bundle = State(source)
    manifest_path = source / "manifest.json"
    private_path(manifest_path, 0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base_fields = {"node_id", "schema", "database_sha256", "key_sha256"}
    if not isinstance(manifest, dict) or set(manifest) not in (base_fields, base_fields | {'extra_files'}):
        raise StateError("Invalid backup manifest")
    schema = manifest["schema"]
    if type(schema) is not int or (not allow_older and schema != len(MIGRATIONS)):
        raise StateError(f"Restore requires a backup with schema {len(MIGRATIONS)}")
    if not 1 <= schema <= len(MIGRATIONS):
        raise StateError("Backup schema is invalid or newer than this package")
    node_id, database_schema = bundle.verify_schema(allow_older=allow_older)
    if database_schema != schema:
        raise StateError("Backup schema does not match the manifest")
    from .grove import KEY_FILE
    extras = manifest.get('extra_files', {})
    if not isinstance(extras, dict) or set(extras) - {KEY_FILE}:
        raise StateError('Unknown backup identity file')
    for name, digest in extras.items():
        private_path(bundle.directory / name, 0o600)
        if file_digest(bundle.directory / name) != digest:
            raise StateError('Grove identity file does not match the backup manifest')
    key_bytes = bundle.key_path.read_bytes()
    if node_id != manifest["node_id"] or hashlib.sha256(key_bytes).hexdigest() != manifest["key_sha256"]:
        raise StateError("Backup key does not match the manifest")
    return bundle, manifest, key_bytes


def verify_backup(source: Path) -> dict:
    require_no_sidecars(State(source))
    bundle, manifest, _ = read_backup(source, allow_older=True)
    if file_digest(bundle.database) != manifest["database_sha256"]:
        raise StateError("Backup database checksum does not match the manifest")
    from .grove import KEY_FILE

    with closing(sqlite3.connect(bundle.database.as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        check_integrity(db)
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        issuer = db.execute("SELECT public_key FROM grove_realm WHERE is_issuer=1").fetchone() if "grove_realm" in tables else None
        service_count = db.execute("SELECT count(*) FROM service").fetchone()[0] if "service" in tables else 0
    if issuer is not None:
        if KEY_FILE not in manifest.get("extra_files", {}):
            raise StateError("Grove issuer key is missing from the backup manifest")
        try:
            key = Ed25519PrivateKey.from_private_bytes((bundle.directory / KEY_FILE).read_bytes())
        except ValueError as error:
            raise StateError("Backup Grove issuer key is damaged") from error
        if key.public_key().public_bytes_raw() != issuer[0]:
            raise StateError("Backup Grove issuer key does not match the database")
    # The manifest binds the verified files without depending on its formatting or the backup path.
    backup_sha256 = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    return {"node_id": manifest["node_id"], "schema": manifest["schema"], "package_schema": len(MIGRATIONS),
            "restore_compatible": manifest["schema"] == len(MIGRATIONS), "services": service_count,
            "grove_issuer": issuer is not None, "backup_sha256": backup_sha256}


def rebuild_identity(source: Path, destination: Path, password_hash: Callable[[], str]) -> dict:
    """Build a replacement identity and a read-only catalog in a new directory."""
    if os.path.lexists(destination):
        raise StateError("Choose a new destination directory for the replacement identity")
    if destination.resolve().is_relative_to(source.resolve()):
        raise StateError("Choose a replacement directory outside the backup")
    bundle, manifest, _ = read_backup(source)
    old_id = manifest["node_id"]
    with tempfile.TemporaryDirectory(prefix=".identity-rebuild-", dir=destination.parent) as temporary:
        staging = Path(temporary)
        secure_private(staging, 0o700)
        snapshot = staging / "snapshot.sqlite3"
        shutil.copyfile(bundle.database, snapshot)
        secure_private(snapshot)
        if file_digest(snapshot) != manifest["database_sha256"]:
            raise StateError("Backup database checksum does not match the manifest")
        with closing(sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True)) as db:
            check_integrity(db)
            if db.execute("PRAGMA user_version").fetchone()[0] != manifest["schema"]:
                raise StateError("Backup schema does not match the manifest")
            services = db.execute("""
                SELECT id,name,driver,target,spec FROM service WHERE node_id=? ORDER BY name
            """, (old_id,)).fetchall()
            protected = db.execute("SELECT service_id FROM service_protection").fetchall()
            require_mfa = db.execute("SELECT require_mfa FROM panel_account WHERE operation_actor='admin'").fetchone()[0]
        snapshot.unlink()
        replacement = State(staging / "state")
        node_id = replacement.initialize(password_hash)
        if node_id == old_id:
            raise StateError("The replacement must have a new Node ID")
        with replacement.connect(write=True) as db:
            db.executemany("""
                INSERT INTO service (id,node_id,name,driver,target,spec,managed)
                VALUES (?,?,?,?,?,?,0)
            """, ((key, node_id, name, driver, target, spec) for key, name, driver, target, spec in services))
            db.executemany("INSERT INTO service_protection VALUES (?)", protected)
            db.execute("UPDATE panel_account SET require_mfa=? WHERE operation_actor='admin'", (require_mfa,))
            audit(db, "admin", "local", "node.identity_rebuilt", old_id)
        replacement.verify()
        for path in (replacement.key_path, replacement.database, replacement.directory):
            sync(path)
        if os.path.lexists(destination):
            raise StateError("The replacement destination already exists")
        os.rename(replacement.directory, destination)
        sync(destination.parent)
    return {"previous_node_id": old_id, "node_id": node_id, "services": len(services),
            "require_mfa": bool(require_mfa)}


def restore(state: State, source: Path, save_current: Path | None) -> str:
    private_path(state.directory, 0o700, directory=True)
    bundle, manifest, key_bytes = read_backup(source)
    from .grove import KEY_FILE
    extras = manifest.get('extra_files', {})
    node_id = manifest["node_id"]
    if bundle.directory.resolve() == state.directory.resolve():
        raise StateError("The backup must be separate from the active state")
    key_exists = os.path.lexists(state.key_path)
    require_mfa: list[tuple[str]] = []
    protected_services: list[tuple[str]] = []
    policy_checkpoint = None
    grove_checkpoint = None
    quarantines = {}
    if key_exists and state.identity()[0] != node_id:
        raise StateError("Backup belongs to a different node")
    if os.path.lexists(state.database):
        if save_current is None:
            raise StateError("Provide --save-current to preserve the existing state before restoring")
        if state.verify() != node_id:
            raise StateError("Active database belongs to a different node")
        require_stopped(state)
        with state.connect() as db:
            require_mfa = [(row[0],) for row in db.execute(
                "SELECT operation_actor FROM panel_account WHERE require_mfa=1",
            )]
            policy_checkpoint = recovery_checkpoint(db)
            grove_row = db.execute('SELECT id,public_key,sequence FROM grove_realm').fetchone()
            grove_checkpoint = dict(grove_row) if grove_row else None
            if grove_checkpoint is not None:
                vote = db.execute('SELECT * FROM grove_login_recovery_vote').fetchone()
                grove_checkpoint['recovery_vote'] = dict(vote) if vote is not None else None
                continuity = db.execute('SELECT sequence,anchor,recovery_proof FROM grove_login_continuity').fetchone()
                grove_checkpoint['continuity'] = dict(continuity) if continuity is not None else None
                grove_checkpoint['revocations'] = [tuple(row) for row in db.execute('SELECT * FROM grove_login_revocation')]
                grove_checkpoint['passwords'] = [tuple(row) for row in db.execute('SELECT * FROM grove_login_password')]
                grove_checkpoint['roles'] = [tuple(row) for row in db.execute('SELECT * FROM grove_login_role')]
                grove_checkpoint['role_votes'] = [tuple(row) for row in db.execute('SELECT * FROM grove_login_role_vote')]
                grove_checkpoint['admissions'] = [tuple(row) for row in db.execute('SELECT * FROM grove_member_admission')]
                grove_checkpoint['admission_votes'] = [tuple(row) for row in db.execute('SELECT * FROM grove_member_admission_vote')]
            protected_services = [(row["service_id"],) for row in db.execute("SELECT service_id FROM service_protection")]
            quarantines = quarantine_entries(db)
        backup(state, save_current)
    elif save_current is not None:
        raise StateError("There is no active database to save")
    require_no_sidecars(state)

    fd, name = tempfile.mkstemp(prefix=".restore-", dir=state.directory)
    os.close(fd)
    candidate = Path(name)
    try:
        shutil.copyfile(bundle.database, candidate)
        if file_digest(candidate) != manifest["database_sha256"]:
            raise StateError("Backup database checksum does not match the manifest")
        with closing(sqlite3.connect(candidate)) as db, db:
            check_integrity(db)
            schema = db.execute("PRAGMA user_version").fetchone()[0]
            if schema != manifest["schema"]:
                raise StateError("Backup schema does not match the manifest")
            db.execute("DELETE FROM session")
            db.execute('DELETE FROM grove_login_flow')
            db.execute('DELETE FROM grove_login_verifier')
            db.execute('DELETE FROM grove_login_replica')
            db.execute('UPDATE grove_login_continuity SET lease_until=0')
            db.execute('DELETE FROM mesh_evidence_share')
            db.execute("UPDATE grove_realm SET frozen='restore',issuer_paused=is_issuer")
            db.execute('UPDATE grove_account SET valid_until=0')
            if grove_checkpoint:
                db.execute('''UPDATE grove_realm SET sequence=max(sequence,?) WHERE id=? AND public_key=?''',
                           (grove_checkpoint['sequence'], grove_checkpoint['id'], grove_checkpoint['public_key']))
                if (vote := grove_checkpoint['recovery_vote']) is not None:
                    db.execute('''INSERT INTO grove_login_recovery_vote SELECT 1,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)
                                  ON CONFLICT(singleton) DO UPDATE SET anchor_digest=excluded.anchor_digest,ballot=excluded.ballot''',
                               (vote['anchor_digest'], vote['ballot'], grove_checkpoint['id'], grove_checkpoint['public_key']))
                if (continuity := grove_checkpoint['continuity']) is not None:
                    db.execute('''INSERT INTO grove_login_continuity(singleton,sequence,anchor,recovery_proof)
                                  SELECT 1,?,?,? WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)
                                  ON CONFLICT(singleton) DO UPDATE SET sequence=excluded.sequence,anchor=excluded.anchor,
                                  recovery_proof=excluded.recovery_proof,lease_until=0''',
                               (continuity['sequence'], continuity['anchor'], continuity['recovery_proof'],
                                grove_checkpoint['id'], grove_checkpoint['public_key']))
                db.executemany('''INSERT OR IGNORE INTO grove_login_revocation SELECT ?,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)''',
                               (values + (grove_checkpoint['id'], grove_checkpoint['public_key'])
                                for values in grove_checkpoint['revocations']))
                db.executemany('''INSERT INTO grove_login_password SELECT ?,?,?,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)
                                  ON CONFLICT(user_id) DO UPDATE SET anchor_digest=excluded.anchor_digest,
                                  generation=excluded.generation,change_digest=excluded.change_digest,document=excluded.document
                                  WHERE (excluded.generation,excluded.change_digest) > (generation,change_digest)''',
                               (values + (grove_checkpoint['id'], grove_checkpoint['public_key'])
                                for values in grove_checkpoint['passwords']))
                db.executemany('''INSERT INTO grove_login_role SELECT ?,?,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)
                                  ON CONFLICT(user_id) DO UPDATE SET generation=excluded.generation,role=excluded.role,
                                  certificate=excluded.certificate WHERE excluded.generation>generation''',
                               (values + (grove_checkpoint['id'], grove_checkpoint['public_key']) for values in grove_checkpoint['roles']))
                db.executemany('''INSERT INTO grove_login_role_vote SELECT ?,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)
                                  ON CONFLICT(user_id) DO UPDATE SET generation=excluded.generation,ballot=excluded.ballot
                                  WHERE excluded.generation>generation''',
                               (values + (grove_checkpoint['id'], grove_checkpoint['public_key']) for values in grove_checkpoint['role_votes']))
                db.executemany('''INSERT OR REPLACE INTO grove_member_admission SELECT ?,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)''',
                               (values + (grove_checkpoint['id'], grove_checkpoint['public_key'])
                                for values in grove_checkpoint['admissions']))
                db.executemany('''INSERT OR REPLACE INTO grove_member_admission_vote SELECT ?,?,?
                                  WHERE EXISTS (SELECT 1 FROM grove_realm WHERE id=? AND public_key=?)''',
                               (values + (grove_checkpoint['id'], grove_checkpoint['public_key'])
                                for values in grove_checkpoint['admission_votes']))
            db.execute("DELETE FROM login_attempt")
            db.execute("DELETE FROM panel_auth_flow")
            db.execute("DELETE FROM panel_factor_enrollment")
            db.execute("DELETE FROM panel_passkey")
            db.execute("DELETE FROM panel_totp")
            db.execute("DELETE FROM panel_recovery_code")
            db.execute("UPDATE panel_account SET auth_epoch=auth_epoch+1")
            db.executemany("UPDATE panel_account SET require_mfa=1 WHERE operation_actor=?", require_mfa)
            db.execute("UPDATE peer SET enabled=0")
            db.executemany("""
                INSERT INTO mesh_quarantine (node_id,recorded_at,reason)
                SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM peer WHERE node_id=?)
                ON CONFLICT(node_id) DO UPDATE SET recorded_at=excluded.recorded_at,reason=excluded.reason
            """, ((node, hold['recorded_at'], hold['reason'], node) for node, hold in quarantines.items()))
            db.execute("UPDATE mesh_profile SET discovery=0, forwarding=0")
            db.execute("DELETE FROM peer_address_cache")
            db.execute("""
                UPDATE mesh_profile SET address_generation=lower(hex(randomblob(16))), address_sequence=0,
                    address_issued_at=0, address_record=NULL
            """)
            pause_restored(db, policy_checkpoint)
            db.executemany("""
                INSERT OR IGNORE INTO service_protection (service_id) SELECT id FROM service WHERE id=?
            """, protected_services)
            db.execute("DELETE FROM peer_mirror")
            db.execute("DELETE FROM peer_event")
            db.execute("UPDATE peer_directory SET epoch=lower(hex(randomblob(16))), revision=0")
            db.execute("DELETE FROM peer_challenge")
            db.execute("UPDATE peer SET write_epoch=lower(hex(randomblob(16)))")
            db.execute("UPDATE peer_grant SET enabled=0, version=version+1 WHERE enabled=1")
            db.execute("DELETE FROM peer_outbound WHERE submitted=0")
            db.execute("UPDATE peer_outbound SET result=NULL")
            from .peer.projection import publish

            db.row_factory = sqlite3.Row
            clear_restored(db)
            for service in db.execute("SELECT DISTINCT service_id FROM peer_projection").fetchall():
                publish(db, service["service_id"])
            audit(db, "admin", "local", "state.restored", node_id)
        sync(candidate)
        if not key_exists:
            state.write_key(key_bytes)
        for name in extras:
            from .onboarding import write_private
            write_private(state.directory / name, (bundle.directory / name).read_bytes())
        os.replace(candidate, state.database)
        sync(state.directory)
        return state.verify()
    finally:
        candidate.unlink(missing_ok=True)
