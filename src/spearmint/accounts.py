import re
import secrets

from . import factors
from .state import State, StateError, audit


ROLES = ("node_admin", "remote_operator")
USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


def add(state: State, username: str, password_hash: str, role: str) -> str:
    if USERNAME.fullmatch(username) is None or role not in ROLES or username == "admin":
        raise StateError("Use a lowercase account name and a supported role")
    account_id = "acct1-" + secrets.token_hex(16)
    with state.connect(write=True) as db:
        row = db.execute("""
            INSERT INTO panel_account (id, username, password_hash, role, operation_actor, require_mfa)
            VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(username) DO NOTHING RETURNING id
        """, (account_id, username, password_hash, role, account_id)).fetchone()
        if row is None:
            raise StateError("Account name already exists")
        audit(db, "admin", "local", "account.created", account_id)
    return account_id


def set_enabled(state: State, username: str, enabled: bool) -> None:
    with state.connect(write=True) as db:
        row = db.execute("""
            UPDATE panel_account SET enabled=? WHERE username=? AND operation_actor!='admin' RETURNING id
        """, (enabled, username)).fetchone()
        if row is None:
            raise StateError("Only named accounts can be enabled or disabled")
        factors.revoke_account_sessions(db, row["id"])
        audit(db, "admin", "local", "account.enabled" if enabled else "account.disabled", row["id"])


def set_role(state: State, username: str, role: str) -> None:
    if role not in ROLES:
        raise StateError("Unknown account role")
    with state.connect(write=True) as db:
        row = db.execute("""
            UPDATE panel_account SET role=? WHERE username=? AND operation_actor!='admin' RETURNING id
        """, (role, username)).fetchone()
        if row is None:
            raise StateError("Only named accounts can change roles")
        factors.revoke_account_sessions(db, row["id"])
        audit(db, "admin", "local", "account.role_changed", row["id"])


def reset_password(state: State, username: str, password_hash: str) -> None:
    with state.connect(write=True) as db:
        row = db.execute("""
            UPDATE panel_account SET password_hash=? WHERE username=? AND operation_actor!='admin' RETURNING id
        """, (password_hash, username)).fetchone()
        if row is None:
            raise StateError("Use the administrator password command for the bootstrap account")
        factors.revoke_account_sessions(db, row["id"])
        audit(db, "admin", "local", "account.password_reset", row["id"])
