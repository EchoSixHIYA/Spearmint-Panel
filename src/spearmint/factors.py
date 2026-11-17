from datetime import UTC, datetime
from hashlib import sha256
import os
import secrets
import sqlite3
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyotp import TOTP, random_base32

from .state import State, StateError, private_path
from .platforms import sync_directory


TOTP_INTERVAL = 30


def vault(state: State) -> AESGCM:
    path = state.directory / "factor.key"
    try:
        private_path(path, 0o600)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError("Unexpected factor key size")
        return AESGCM(key)
    except (OSError, ValueError, StateError) as exc:
        raise StateError("The local factor key is unavailable or damaged") from exc


def initialize_vault(state: State) -> None:
    """Called under the local maintenance lock before initial enrollment."""
    path = state.directory / "factor.key"
    if not os.path.lexists(path):
        fd, temporary = tempfile.mkstemp(prefix=".factor-key-", dir=state.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(AESGCM.generate_key(bit_length=256))
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, path)
            sync_directory(state.directory)
        finally:
            os.unlink(temporary)
    vault(state)


def seal(state: State, account_id: str, secret: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + vault(state).encrypt(nonce, secret.encode("ascii"), account_id.encode("ascii"))


def unseal(state: State, account_id: str, encrypted: bytes) -> str:
    try:
        return vault(state).decrypt(encrypted[:12], encrypted[12:], account_id.encode("ascii")).decode("ascii")
    except (InvalidTag, ValueError) as exc:
        raise StateError("The stored TOTP factor cannot be read. Re-enroll from the local console") from exc


def new_totp(username: str, authority: str) -> tuple[str, str]:
    secret = random_base32()
    return secret, provisioning_uri(secret, username, authority)


def provisioning_uri(secret: str, username: str, authority: str) -> str:
    issuer = f"Spearmint {authority.replace(':', ' ')}"
    return TOTP(secret, interval=TOTP_INTERVAL).provisioning_uri(name=username, issuer_name=issuer)


def matching_step(secret: str, code: str, now: int, last_step: int) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdecimal():
        return None
    factor = TOTP(secret, interval=TOTP_INTERVAL)
    step = now // TOTP_INTERVAL
    for candidate in (step + 1, step, step - 1):
        if candidate > last_step:
            instant = datetime.fromtimestamp(candidate * TOTP_INTERVAL, UTC)
            if secrets.compare_digest(factor.at(instant), code):
                return candidate
    return None


def replace_totp(db: sqlite3.Connection, account_id: str, secret: bytes, step: int) -> list[str]:
    db.execute("""
        INSERT INTO panel_totp (account_id, secret, last_step) VALUES (?, ?, ?)
        ON CONFLICT(account_id) DO UPDATE SET secret=excluded.secret, last_step=excluded.last_step
    """, (account_id, secret, step))
    return activate_factor(db, account_id)


def revoke_account_sessions(db: sqlite3.Connection, account_id: str) -> None:
    db.execute("UPDATE panel_account SET auth_epoch=auth_epoch+1 WHERE id=?", (account_id,))
    db.execute("DELETE FROM session WHERE account_id=?", (account_id,))
    db.execute("DELETE FROM panel_auth_flow WHERE account_id=?", (account_id,))
    db.execute("DELETE FROM panel_factor_enrollment WHERE account_id=?", (account_id,))


def activate_factor(db: sqlite3.Connection, account_id: str) -> list[str]:
    db.execute("UPDATE panel_account SET require_mfa=1 WHERE id=?", (account_id,))
    revoke_account_sessions(db, account_id)
    db.execute("DELETE FROM panel_recovery_code WHERE account_id=?", (account_id,))
    codes = [secrets.token_urlsafe(16) for _ in range(8)]
    db.executemany(
        "INSERT INTO panel_recovery_code (account_id, code_hash) VALUES (?, ?)",
        ((account_id, sha256(code.encode("ascii")).digest()) for code in codes),
    )
    return codes
