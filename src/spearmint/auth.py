from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import secrets
import sqlite3
from threading import BoundedSemaphore
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from . import factors
from .state import State, StateError, audit


COOKIE = "__Host-spearmint"
IDLE_SECONDS = 30 * 60
SESSION_SECONDS = 8 * 60 * 60
FLOW_SECONDS = 120
ENROLLMENT_SECONDS = 300
RECENT_FACTOR_SECONDS = 300
MAX_FLOW_FAILURES = 5
ATTEMPT_WINDOW = 60
SOURCE_ATTEMPTS = 8
ACCOUNT_ATTEMPTS = 16
PASSWORD_SLOTS = BoundedSemaphore(8)
PASSWORD = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)


class LoginLimited(Exception):
    def __init__(self, retry_after: int = ATTEMPT_WINDOW) -> None:
        super().__init__("Too many authentication attempts")
        self.retry_after = retry_after


class FactorReenrollmentRequired(Exception):
    pass


class SessionReauthenticationRequired(Exception):
    pass


class FirstFactorUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Actor:
    username: str
    address: str
    token_hash: bytes
    csrf_token: str
    account_id: str
    operation_actor: str
    role: str
    grove: bool = False
    display_name: str | None = None


@dataclass(frozen=True)
class LoginFlow:
    flow_id: str
    method: str
    expires_at: int


def digest(token: str) -> bytes:
    return sha256(token.encode("utf-8")).digest()


def bootstrap_account(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute("""
        SELECT id, username, password_hash, auth_epoch, require_mfa, operation_actor, role
        FROM panel_account WHERE operation_actor='admin' AND role='node_admin' AND enabled=1
    """).fetchone()


def local_login_available(state: State) -> bool:
    """Report independent accounts without exposing names or login material."""
    from . import onboarding

    record = onboarding.read_record(state)
    initial = record['initial_hash'] if record else ''
    with state.connect(read_only=True) as db:
        return db.execute('''SELECT 1 FROM panel_account a WHERE a.enabled=1
            AND a.password_hash LIKE '$argon2%' AND a.password_hash!=?
            AND NOT EXISTS (SELECT 1 FROM grove_account g WHERE g.account_id=a.id)
            LIMIT 1''', (initial,)).fetchone() is not None


def account_for(db: sqlite3.Connection, username: str | None) -> sqlite3.Row | None:
    if username is None:
        return bootstrap_account(db)
    return db.execute("""
        SELECT id, username, password_hash, auth_epoch, require_mfa, operation_actor, role
        FROM panel_account WHERE username=? AND enabled=1
    """, (username,)).fetchone()


def active_session(db: sqlite3.Connection, token_hash: bytes, now: int) -> sqlite3.Row | None:
    row = db.execute("""
        SELECT a.id, a.username, a.operation_actor, a.role, s.csrf_token, s.last_seen, s.mfa_at,
               ga.user_id AS grove_user, ga.display_name, ga.valid_until, r.frozen, s.grove_replica,
               EXISTS(SELECT 1 FROM grove_login_revocation rv WHERE rv.user_id=ga.user_id) AS grove_revoked,
               EXISTS(SELECT 1 FROM grove_login_replica lr JOIN grove_login_verifier lv ON lv.user_id=ga.user_id
                      LEFT JOIN grove_login_continuity c ON c.singleton=1
                      LEFT JOIN grove_login_role gr ON gr.user_id=lv.user_id
                      WHERE lr.sequence=r.sequence AND r.issuer_paused=0
                        AND (c.singleton IS NULL OR c.sequence=lr.sequence)
                        AND coalesce(c.lease_until,max(lr.expires_at,lr.standby_lease_until))>?
                        AND lv.epoch=ga.identity_epoch AND coalesce(gr.role,lv.role)=a.role) AS replica_current,
               EXISTS(SELECT 1 FROM grove_member gm JOIN node n ON gm.node_id=n.node_id WHERE gm.enabled=1) AS member_active
        FROM session s JOIN panel_account a ON a.id=s.account_id AND a.auth_epoch=s.auth_epoch
        LEFT JOIN grove_account ga ON ga.account_id=a.id
        LEFT JOIN grove_realm r ON ga.account_id IS NOT NULL AND r.singleton=1
        WHERE s.token_hash=? AND s.last_seen>? AND s.created_at>?
          AND a.enabled=1
          AND (a.require_mfa=0 OR s.mfa_at IS NOT NULL)
    """, (now, token_hash, now - IDLE_SECONDS, now - SESSION_SECONDS)).fetchone()
    if row is not None and row['grove_user'] is not None and (
        (not row['replica_current'] if row['grove_replica'] else row['valid_until'] <= now)
        or row['frozen'] != '' or not row['member_active'] or row['grove_revoked']
    ):
        return None
    return row


def record_attempt(db: sqlite3.Connection, address: str, now: int, account_key: bytes | None) -> str | None:
    db.execute("DELETE FROM login_attempt WHERE attempted_at<=?", (now - ATTEMPT_WINDOW,))
    if db.execute("SELECT count(*) FROM login_attempt WHERE address=?", (address,)).fetchone()[0] >= SOURCE_ATTEMPTS:
        return "SOURCE_LIMIT"
    if db.execute("SELECT count(*) FROM login_attempt WHERE account_key=?", (account_key,)).fetchone()[0] >= ACCOUNT_ATTEMPTS:
        return "ACCOUNT_LIMIT"
    db.execute("INSERT INTO login_attempt (address,attempted_at,account_key) VALUES (?,?,?)", (address, now, account_key))
    return None


def auth_rejection(db: sqlite3.Connection, account: sqlite3.Row | None, address: str, event: str, reason: str) -> None:
    actor = account["operation_actor"] if account is not None else "anonymous"
    audit(db, actor, address, event, reason=reason, aggregate=True)


@contextmanager
def authentication_attempt(state: State, address: str, now: int, *, username: str | None = None,
                           flow: tuple[str, str] | None = None) -> Iterator[tuple[sqlite3.Connection, sqlite3.Row | None]]:
    with state.connect(write=True) as db:
        account = account_for(db, username) if flow is None else active_flow(db, flow[0], address, now, flow[1])
        subject = account["username"] if account is not None else username
        limited = record_attempt(db, address, now, digest(subject) if subject is not None else None)
        if limited is None:
            yield db, account
            return
        auth_rejection(db, account, address, "session.login_limited", limited)
    raise LoginLimited


def issue_session(db: sqlite3.Connection, account: sqlite3.Row, address: str, now: int,
                  *, mfa_at: int | None = None, method: str = "password", grove_replica: bool = False) -> tuple[str, str]:
    token, csrf_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.execute("DELETE FROM login_attempt WHERE address=? AND account_key=?", (address, digest(account["username"])))
    db.execute("DELETE FROM session WHERE created_at<=? OR last_seen<=?", (now - SESSION_SECONDS, now - IDLE_SECONDS))
    db.execute("""
        INSERT INTO session (token_hash, csrf_token, created_at, last_seen, account_id, auth_epoch, mfa_at, session_id, grove_replica)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (digest(token), csrf_token, now, now, account["id"], account["auth_epoch"], mfa_at, secrets.token_hex(16), int(grove_replica)))
    audit(db, account["operation_actor"], address, "session.login", reason=method)
    return token, csrf_token


def issue_flow(db: sqlite3.Connection, account: sqlite3.Row, address: str, now: int, purpose: str,
               method: str, *, valid_until: int | None = None) -> LoginFlow:
    token = secrets.token_urlsafe(32)
    expiry = min(now + FLOW_SECONDS, valid_until) if valid_until is not None else now + FLOW_SECONDS
    db.execute("DELETE FROM panel_auth_flow WHERE expires_at<=?", (now,))
    db.execute("""
        INSERT INTO panel_auth_flow (token_hash, account_id, auth_epoch, address, purpose, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (digest(token), account["id"], account["auth_epoch"], address, purpose, expiry))
    return LoginFlow(token, method, expiry)


def active_flow(db: sqlite3.Connection, token: str, address: str, now: int,
                purpose: str) -> sqlite3.Row | None:
    if len(token) != 43 or not token.isascii():
        return None
    return db.execute("""
        SELECT a.id, a.username, a.auth_epoch, a.operation_actor, f.token_hash, f.pending_secret, f.webauthn_state, f.origin
        FROM panel_auth_flow f JOIN panel_account a ON a.id=f.account_id AND a.auth_epoch=f.auth_epoch
        WHERE f.token_hash=? AND f.address=? AND f.purpose=? AND f.expires_at>? AND f.failures<?
          AND a.enabled=1
          AND (f.purpose IN ('totp_rebind', 'passkey_enroll') OR a.require_mfa=1)
    """, (digest(token), address, purpose, now, MAX_FLOW_FAILURES)).fetchone()


def reject_flow(db: sqlite3.Connection, flow: sqlite3.Row, address: str) -> None:
    db.execute("UPDATE panel_auth_flow SET failures=failures+1 WHERE token_hash=?", (flow["token_hash"],))
    audit(db, flow["operation_actor"], address, "session.factor_rejected", flow["id"],
          reason="FACTOR_INVALID", aggregate=True)


def login(state: State, username: str, password: str, address: str, *,
          enrollment_token: str | None = None,
          enrollment_actor: Actor | None = None) -> tuple[str, str] | LoginFlow | None:
    with authentication_attempt(state, address, int(time.time()), username=username) as (db, account):
        if account is not None and db.execute('SELECT 1 FROM grove_account WHERE account_id=?', (account['id'],)).fetchone():
            account = None
        comparison = account or bootstrap_account(db)
    if not PASSWORD_SLOTS.acquire(blocking=False):
        with state.connect(write=True) as db:
            auth_rejection(db, account, address, "session.login_limited", "PASSWORD_CAPACITY")
        raise LoginLimited(1)
    try:
        valid = comparison is not None and PASSWORD.verify(comparison["password_hash"], password)
    except VerifyMismatchError:
        valid = False
    finally:
        PASSWORD_SLOTS.release()
    if not valid or account is None:
        with state.connect(write=True) as db:
            auth_rejection(db, account, address, "session.login_rejected", "PASSWORD_INVALID")
        return None

    with state.connect(write=True) as db:
        if account_for(db, username) != account:
            return None
        now = int(time.time())
        if enrollment_token is not None:
            enrollment = db.execute("""
                SELECT method FROM panel_factor_enrollment WHERE account_id=? AND token_hash=?
                    AND auth_epoch=? AND expires_at>?
            """, (account["id"], digest(enrollment_token), account["auth_epoch"], now)).fetchone()
            if enrollment is None:
                auth_rejection(db, account, address, "session.login_rejected", "ENROLLMENT_INVALID")
                return None
            has_factor = db.execute("""
                SELECT 1 FROM panel_totp WHERE account_id=?
                UNION ALL SELECT 1 FROM panel_passkey WHERE account_id=? AND enabled=1 LIMIT 1
            """, (account["id"], account["id"])).fetchone() is not None
            current = active_session(db, enrollment_actor.token_hash, now) if enrollment_actor else None
            recent = (current is not None and current["id"] == account["id"]
                      and current["mfa_at"] is not None and now - RECENT_FACTOR_SECONDS < current["mfa_at"] <= now)
            if has_factor and not recent:
                auth_rejection(db, account, address, "session.login_rejected", "FACTOR_REAUTHENTICATION_REQUIRED")
            else:
                db.execute("DELETE FROM panel_factor_enrollment WHERE account_id=?", (account["id"],))
                method = enrollment["method"]
                purpose = "passkey_enroll" if method == "passkey" else "totp_rebind"
                audit(db, account["operation_actor"], address, f"administrator.{method}_enrollment_started", account["id"])
                return issue_flow(db, account, address, now, purpose, purpose,
                                  valid_until=current["mfa_at"] + RECENT_FACTOR_SECONDS if has_factor else None)
        elif account["require_mfa"]:
            totp = db.execute("SELECT 1 FROM panel_totp WHERE account_id=?", (account["id"],)).fetchone()
            if totp is None and db.execute(
                "SELECT 1 FROM panel_recovery_code WHERE account_id=? LIMIT 1", (account["id"],),
            ).fetchone() is None:
                raise FactorReenrollmentRequired
            return issue_flow(db, account, address, now, "login", "totp" if totp else "recovery")
        else:
            return issue_session(db, account, address, now)
    raise SessionReauthenticationRequired


def issue_enrollment(state: State, method: str, username: str | None = None, *, recover: bool = False) -> str:
    if method not in {"totp", "passkey"}:
        raise StateError("Unknown enrollment method")
    token = secrets.token_urlsafe(32)
    with state.connect(write=True) as db:
        account = account_for(db, username)
        if account is None:
            raise StateError("Account is unavailable")
        if recover:
            db.execute("DELETE FROM panel_totp WHERE account_id=?", (account["id"],))
            db.execute("DELETE FROM panel_passkey WHERE account_id=?", (account["id"],))
            db.execute("DELETE FROM panel_recovery_code WHERE account_id=?", (account["id"],))
            db.execute("UPDATE panel_account SET require_mfa=1 WHERE id=?", (account["id"],))
            factors.revoke_account_sessions(db, account["id"])
            audit(db, "admin", "local", "administrator.factor_recovery", account["id"], reason="LOCAL_CONSOLE")
            account = account_for(db, username)
        db.execute("""
            DELETE FROM panel_auth_flow WHERE account_id=? AND purpose IN ('totp_rebind', 'passkey_enroll')
        """, (account["id"],))
        db.execute("""
            INSERT INTO panel_factor_enrollment (account_id, token_hash, auth_epoch, expires_at, method)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET token_hash=excluded.token_hash,
                auth_epoch=excluded.auth_epoch, expires_at=excluded.expires_at, method=excluded.method
        """, (account["id"], digest(token), account["auth_epoch"], int(time.time()) + ENROLLMENT_SECONDS, method))
        audit(db, "admin", "local", f"administrator.{method}_enrollment_issued", account["id"])
    return token


def first_factor_status(state: State, actor: Actor) -> dict:
    with state.connect() as db:
        db.execute("BEGIN")
        _, methods, timestamp = web_enrollment(db, actor, int(time.time()))
    return {"eligible": bool(methods), "recent": timestamp is not None,
            "grove_totp": methods == {"totp"}}


def web_enrollment(db: sqlite3.Connection, actor: Actor, now: int) -> tuple[sqlite3.Row | None, set[str], int | None]:
    account = account_for(db, actor.username)
    current = active_session(db, actor.token_hash, now)
    if account is None or current is None or account["id"] != actor.account_id or current["id"] != actor.account_id or actor.grove:
        return None, set(), None
    if db.execute("SELECT 1 FROM panel_totp WHERE account_id=?", (actor.account_id,)).fetchone():
        return account, set(), None
    passkey = db.execute("SELECT 1 FROM panel_passkey WHERE account_id=? AND enabled=1", (actor.account_id,)).fetchone()
    methods: set[str] = set()
    timestamp = None
    if not passkey and account["operation_actor"] == "admin" and not account["require_mfa"]:
        methods = {"totp", "passkey"}
        timestamp = db.execute("SELECT created_at FROM session WHERE token_hash=?", (actor.token_hash,)).fetchone()[0]
    elif passkey and account["require_mfa"] and db.execute(
        "SELECT 1 FROM grove_realm WHERE is_issuer=1 AND issuer_paused=0 AND frozen=''"
    ).fetchone():
        methods = {"totp"}
        timestamp = current["mfa_at"]
    recent = timestamp is not None and now - RECENT_FACTOR_SECONDS < timestamp <= now
    return account, methods, timestamp if recent else None


def begin_first_factor(state: State, actor: Actor, method: str) -> LoginFlow:
    if method not in {"totp", "passkey"}:
        raise ValueError("Unknown enrollment method")
    with state.lock("maintenance.lock"), state.connect(write=True) as db:
        now = int(time.time())
        account, methods, timestamp = web_enrollment(db, actor, now)
        if account is None or method not in methods:
            raise FirstFactorUnavailable
        if timestamp is None:
            raise SessionReauthenticationRequired
        factors.initialize_vault(state)
        db.execute("DELETE FROM panel_auth_flow WHERE account_id=?", (actor.account_id,))
        db.execute("DELETE FROM panel_factor_enrollment WHERE account_id=?", (actor.account_id,))
        audit(db, actor.operation_actor, actor.address, f"administrator.{method}_enrollment_started",
              actor.account_id, reason="GROVE_TOTP_WEB" if methods == {"totp"} else "FIRST_FACTOR_WEB")
        purpose = "totp_rebind" if method == "totp" else "passkey_enroll"
        return issue_flow(db, account, actor.address, now, purpose, purpose, valid_until=timestamp + RECENT_FACTOR_SECONDS)


def finish_totp(state: State, token: str, code: str, address: str) -> tuple[str, tuple[str, str]] | None:
    now = int(time.time())
    with authentication_attempt(state, address, now, flow=(token, "login")) as (db, flow):
        if flow is None:
            return None
        factor = db.execute("SELECT secret, last_step FROM panel_totp WHERE account_id=?", (flow["id"],)).fetchone()
        if factor is None:
            return None
        secret = factors.unseal(state, flow["id"], factor["secret"])
        step = factors.matching_step(secret, code, now, factor["last_step"])
        if step is None:
            reject_flow(db, flow, address)
            return None
        db.execute("UPDATE panel_totp SET last_step=? WHERE account_id=?", (step, flow["id"]))
        db.execute("DELETE FROM panel_auth_flow WHERE token_hash=?", (flow["token_hash"],))
        return flow["username"], issue_session(db, flow, address, now, mfa_at=now, method="totp")


def finish_recovery(state: State, token: str, code: str, address: str) -> LoginFlow | None:
    now = int(time.time())
    with authentication_attempt(state, address, now, flow=(token, "login")) as (db, flow):
        if flow is None:
            return None
        removed = db.execute(
            "DELETE FROM panel_recovery_code WHERE account_id=? AND code_hash=?", (flow["id"], digest(code)),
        )
        if removed.rowcount != 1:
            reject_flow(db, flow, address)
            return None
        db.execute("DELETE FROM panel_totp WHERE account_id=?", (flow["id"],))
        db.execute("DELETE FROM panel_passkey WHERE account_id=?", (flow["id"],))
        factors.revoke_account_sessions(db, flow["id"])
        account = account_for(db, flow["username"])
        if account is None:
            raise StateError("Account is unavailable")
        audit(db, flow["operation_actor"], address, "session.recovery_started", flow["id"])
        return issue_flow(db, account, address, now, "totp_rebind", "totp_rebind")


def totp_rebind_options(state: State, token: str, address: str, authority: str) -> str | None:
    with state.connect(write=True) as db:
        flow = active_flow(db, token, address, int(time.time()), "totp_rebind")
        if flow is None:
            return None
        if flow["pending_secret"] is not None:
            secret = factors.unseal(state, flow["id"], flow["pending_secret"])
            return factors.provisioning_uri(secret, flow["username"], authority)
        secret, uri = factors.new_totp(flow["username"], authority)
        db.execute("UPDATE panel_auth_flow SET pending_secret=? WHERE token_hash=?",
                   (factors.seal(state, flow["id"], secret), flow["token_hash"]))
        return uri


def finish_totp_rebind(state: State, token: str, code: str, address: str) -> list[str] | None:
    now = int(time.time())
    with authentication_attempt(state, address, now, flow=(token, "totp_rebind")) as (db, flow):
        if flow is None or flow["pending_secret"] is None:
            return None
        secret = factors.unseal(state, flow["id"], flow["pending_secret"])
        step = factors.matching_step(secret, code, now, -1)
        if step is None:
            reject_flow(db, flow, address)
            return None
        codes = factors.replace_totp(db, flow["id"], flow["pending_secret"], step)
        audit(db, flow["operation_actor"], address, "administrator.totp_enrolled", flow["id"])
        return codes


def actor_for(state: State, token: str, address: str) -> Actor | None:
    if len(token) != 43 or not token.isascii():
        return None
    now = int(time.time())
    token_hash = digest(token)
    with state.connect() as db:
        row = active_session(db, token_hash, now)
    if row is None:
        return None
    if now - row["last_seen"] >= 30:
        with state.connect(write=True) as db:
            db.execute("UPDATE session SET last_seen=MAX(last_seen, ?) WHERE token_hash=?", (now, token_hash))
    return Actor(row["username"], address, token_hash, row["csrf_token"], row["id"], row["operation_actor"], row["role"],
                 row['grove_user'] is not None, row['display_name'])


def logout(state: State, actor: Actor) -> None:
    with state.connect(write=True) as db:
        db.execute("DELETE FROM session WHERE token_hash=?", (actor.token_hash,))
        audit(db, actor.operation_actor, actor.address, "session.logout")


def list_sessions(state: State, actor: Actor) -> list[dict] | None:
    now = int(time.time())
    with state.connect() as db:
        db.execute("BEGIN")
        if active_session(db, actor.token_hash, now) is None:
            return None
        rows = db.execute("""
            SELECT session_id AS id, created_at, last_seen, token_hash=? AS current
            FROM session WHERE account_id=? AND last_seen>? AND created_at>?
            ORDER BY last_seen DESC, session_id
        """, (actor.token_hash, actor.account_id, now - IDLE_SECONDS, now - SESSION_SECONDS)).fetchall()
    return [{**dict(row), "current": bool(row["current"])} for row in rows]


def revoke_session(state: State, actor: Actor, session_id: str) -> bool | None:
    now = int(time.time())
    with state.connect(write=True) as db:
        current = active_session(db, actor.token_hash, now)
        if current is None or current["mfa_at"] is None or current["mfa_at"] < now - RECENT_FACTOR_SECONDS:
            raise SessionReauthenticationRequired
        removed = db.execute("""
            DELETE FROM session WHERE session_id=? AND account_id=? RETURNING token_hash
        """, (session_id, actor.account_id)).fetchone()
        if removed is None:
            return None
        audit(db, actor.operation_actor, actor.address, "session.revoked", session_id)
        return removed["token_hash"] == actor.token_hash


def reset_password(state: State, new_password_hash: str) -> None:
    with state.connect(write=True) as db:
        account = db.execute("""
            UPDATE panel_account SET password_hash=?
            WHERE operation_actor='admin' RETURNING id
        """, (new_password_hash,)).fetchone()
        if account is None:
            raise StateError("Bootstrap administrator is unavailable")
        db.execute('DELETE FROM grove_account WHERE account_id=?', (account['id'],))
        db.execute('UPDATE panel_account SET enabled=1 WHERE id=?', (account['id'],))
        factors.revoke_account_sessions(db, account["id"])
        db.execute("DELETE FROM login_attempt")
        audit(db, "admin", "local", "administrator.password_reset")
