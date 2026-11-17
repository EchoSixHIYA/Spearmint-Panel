"""Owner-held first-run links, independent of terminal visibility.

The initial account has an unknown random password until claimed. A private
intent file is written before initialization so interrupted startup can resume.
The database credential is the final authority: changing it consumes the link
atomically, even if removing the handoff files is interrupted.
"""
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
import webbrowser
from urllib.parse import urlencode

from . import auth
from .accounts import USERNAME
from .config import Config
from .platforms import replace_file, secure_private, sync_directory
from .state import State, StateError, audit, private_path


LINK_SECONDS = 24 * 60 * 60
RECORD = "first-run.json"
HANDOFF = "start-setup.html"
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
INVITATION_LIMIT = 8192


class SetupUnavailable(Exception):
    pass


def loopback_host(host: str | None) -> bool:
    from ipaddress import ip_address

    try:
        return host == "localhost" or (host is not None and ip_address(host).is_loopback)
    except ValueError:
        return False


def write_private(path: Path, data: bytes) -> None:
    if os.path.lexists(path):
        private_path(path, 0o600)
    fd, temporary = tempfile.mkstemp(prefix=".setup-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        secure_private(Path(temporary))
        replace_file(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_record(state: State) -> dict | None:
    path = state.directory / RECORD
    if not os.path.lexists(path):
        return None
    private_path(path, 0o600)
    if path.stat().st_size > INVITATION_LIMIT + 4096:
        raise StateError("First-run record is damaged")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(record, dict) or record.get("version") != 1
                or not isinstance(record.get("token"), str) or TOKEN.fullmatch(record["token"]) is None
                or not isinstance(record.get("initial_hash"), str) or not record["initial_hash"].startswith("$argon2id$")
                or type(record.get("expires_at")) is not int):
            raise ValueError
        return record
    except (ValueError, KeyError, TypeError) as error:
        raise StateError("First-run record is damaged; inspect it from the node account") from error


def pending_account(db, record: dict):
    account = auth.bootstrap_account(db)
    if account is None or account["require_mfa"] or account["password_hash"] != record["initial_hash"]:
        return None
    # A first-run link must never override a factor installed through another path.
    if db.execute("""SELECT 1 FROM panel_totp WHERE account_id=? UNION ALL
                     SELECT 1 FROM panel_passkey WHERE account_id=? AND enabled=1 LIMIT 1""",
                  (account["id"], account["id"])).fetchone():
        return None
    return account


def pending(state: State) -> bool:
    record = read_record(state)
    if record is None:
        return False
    with state.connect() as db:
        return pending_account(db, record) is not None


def clear_handoff(state: State) -> None:
    for name in (RECORD, HANDOFF):
        path = state.directory / name
        if os.path.lexists(path):
            private_path(path, 0o600)
            path.unlink()
    sync_directory(state.directory)


def render_handoff(link: str, record: dict) -> bytes:
    invitation = record.get('grove_invitation')
    entry = link
    if invitation:
        entry += '?' + urlencode({'grove': json.dumps(invitation, ensure_ascii=False, separators=(',', ':'))})
    expiry = datetime.fromtimestamp(record["expires_at"], timezone.utc).isoformat()
    description = ('下一步前往已有 Grove 登录并确认加入。无需为这台节点创建新账号。' if invitation else
                   '下一步在网页创建管理员，再选择登录验证方式。无需查看控制台或复制密钥。')
    page = f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>开始配置 Spearmint</title>
<style>body{{font:16px system-ui;background:#f4f7f0;color:#193c2e;max-width:560px;margin:12vh auto;padding:24px}}article{{background:white;padding:36px;border-radius:24px}}a{{display:inline-block;background:#267554;color:white;padding:14px 22px;border-radius:12px;text-decoration:none}}p{{line-height:1.8}}small{{color:#687a6c}}</style>
<article><p>SPEARMINT · FIRST RUN</p><h1>让你的 Grove 在这里开始。</h1>
<p>{description}</p>
<p><a href="{escape(entry, quote=True)}" rel="noreferrer">打开首次配置向导 →</a></p>
<small>此入口只交给设备所有者，有效至 {escape(expiry)}。完成配置后自动失效。</small></article></html>'''
    return page.encode()


def save_handoff(state: State, origin: str, record: dict) -> Path:
    link = f"{origin}/#/setup/{record['token']}"
    record["url"] = link
    write_private(state.directory / RECORD, (json.dumps(record, indent=2) + "\n").encode())
    path = state.directory / HANDOFF
    write_private(path, render_handoff(link, record))
    return path


def read_invitation(path: Path) -> dict:
    from .grove import invitation

    with path.open('rb') as source:
        raw = source.read(INVITATION_LIMIT + 1)
    if len(raw) > INVITATION_LIMIT:
        raise ValueError('Grove invitation is too large')
    return invitation(json.loads(raw.decode('utf-8-sig')))


class ExistingNodeNeedsGrove(StateError):
    """A configured node needs its own administrator to authorize joining."""


def _verify_existing_grove(state: State, invitation: dict) -> None:
    from .grove import realm_data

    with state.connect(read_only=True) as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
    if realm is None:
        raise ExistingNodeNeedsGrove('This node is already configured. Sign in to its panel to join a Grove.')
    if realm_data(realm) != invitation:
        raise StateError('This node is already configured for a different Grove or issuer. Check the state directory and invitation.')


def prepare(state: State, config: Config, *, renew: bool = False, renew_if_expired: bool = False,
            join_grove: Path | None = None, expected_node: str | None = None) -> Path | None:
    invitation = read_invitation(join_grove) if join_grove is not None else None
    if expected_node is None:
        state.prepare_directory()
    else:
        private_path(state.directory, 0o700, directory=True)
    with state.lock("onboarding.lock"):
        if expected_node is not None and state.verify() != expected_node:
            raise StateError("The state directory does not belong to the expected Node ID")
        record = read_record(state)
        if record is None:
            if os.path.lexists(state.database) or os.path.lexists(state.key_path):
                state.verify()
                if invitation is not None:
                    _verify_existing_grove(state, invitation)
                return None
            record = {"version": 1, "token": secrets.token_urlsafe(32),
                      "initial_hash": auth.PASSWORD.hash(secrets.token_urlsafe(48)),
                      "expires_at": int(time.time()) + LINK_SECONDS}
            if invitation is not None:
                record['grove_invitation'] = invitation
            # Durable intent precedes creation of any account or node identity.
            write_private(state.directory / RECORD, (json.dumps(record) + "\n").encode())
        if expected_node is None:
            state.initialize(lambda: record["initial_hash"])
        if not pending(state):
            if invitation is not None:
                _verify_existing_grove(state, invitation)
            clear_handoff(state)
            return None
        if expected_node is not None and record.get('url') != f"{config.origin}/#/setup/{record['token']}":
            raise StateError("The first-run link does not belong to the requested HTTPS origin")
        if invitation is not None and record.get('grove_invitation') not in (None, invitation):
            raise StateError('This first-run link is prepared for a different Grove or issuer. Check the state directory and invitation.')
        now = int(time.time())
        if renew or (renew_if_expired and record['expires_at'] <= now):
            record.update(token=secrets.token_urlsafe(32), expires_at=now + LINK_SECONDS)
        if invitation is not None:
            record['grove_invitation'] = invitation
        return save_handoff(state, config.origin, record)


def recover_handoff(state: State, *, expected_origin: str | None = None) -> None:
    """Restore an installed node's private entry at its saved HTTPS origin."""
    state.verify()
    with state.lock("onboarding.lock"):
        record = read_record(state)
        with state.connect(read_only=True) as db:
            if record is None or pending_account(db, record) is None:
                return
        suffix = f"/#/setup/{record['token']}"
        saved_url = record.get("url")
        if saved_url is None and expected_origin is not None:
            saved_origin = expected_origin
        elif not isinstance(saved_url, str) or not saved_url.endswith(suffix):
            raise StateError("The first-run HTTPS origin is unavailable. Start the panel with its configured origin first.")
        else:
            saved_origin = Config.from_env(state_dir=state.directory, origin=saved_url.removesuffix(suffix)).origin
        if expected_origin is not None and saved_origin != expected_origin:
            raise StateError("The first-run link does not belong to the requested HTTPS origin")
        now = int(time.time())
        if record["expires_at"] <= now:
            record.update(token=secrets.token_urlsafe(32), expires_at=now + LINK_SECONDS)
        elif saved_url is not None:
            path = state.directory / HANDOFF
            expected_page = render_handoff(saved_url, record)
            try:
                private_path(path, 0o600)
                with path.open('rb') as stream:
                    if stream.read(len(expected_page) + 1) == expected_page:
                        return
            except FileNotFoundError:
                pass
        save_handoff(state, saved_origin, record)


def status(state: State) -> dict:
    record = read_record(state)
    with state.connect(read_only=True) as db:
        required = record is not None and pending_account(db, record) is not None
    return {"required": required, "link_expired": bool(required and record["expires_at"] <= int(time.time()))}


def owner_code(state: State) -> str:
    with state.lock("onboarding.lock"):
        record = read_record(state)
        with state.connect(read_only=True) as db:
            if record is None or pending_account(db, record) is None or record["expires_at"] <= int(time.time()):
                raise StateError("No current setup code. Renew the pending code from the node account.")
        return record["token"]


def handoff_status(state: State, *, open_browser: bool = False) -> str:
    state.verify()
    current = status(state)
    if not current["required"]:
        return "Initial setup is already complete"
    if current["link_expired"]:
        return "The first-run link has expired. Run spearmint setup-link --recover-and-open with the panel's state directory."
    path = state.directory / HANDOFF
    try:
        private_path(path, 0o600)
    except FileNotFoundError:
        if not status(state)["required"]:
            return "Initial setup is already complete"
        return "The first-run file is missing. Run spearmint setup-link --recover-and-open with the panel's state directory."
    if open_browser:
        try:
            if webbrowser.open(path.absolute().as_uri(), new=2):
                return f"Opened the private first-run file: {path}"
        except (OSError, webbrowser.Error):
            pass
    return f"Open this private file to configure the node: {path}"


def owner_record(state: State, db, token: str | None, now: int, *, local_browser: bool = False) -> dict | None:
    record = read_record(state)
    if record is None or pending_account(db, record) is None:
        return None
    if token is None:
        return record if local_browser else None
    if record["expires_at"] > now and TOKEN.fullmatch(token) and secrets.compare_digest(record["token"], token):
        return record
    return None


def complete(state: State, token: str | None, username: str, password: str, address: str,
             *, local_browser: bool = False) -> tuple[str, str]:
    if USERNAME.fullmatch(username) is None or not 12 <= len(password) <= 256:
        raise ValueError("Use a lowercase account name and a password of 12 to 256 characters")
    with state.lock("onboarding.lock"):
        now = int(time.time())
        with auth.authentication_attempt(state, address, now, username="admin") as (db, _):
            record = owner_record(state, db, token, now, local_browser=local_browser)
            if record is None:
                audit(db, "anonymous", address, "setup.rejected", reason="INVALID_OR_CONSUMED_LINK", aggregate=True)
        if record is None:
            raise SetupUnavailable
        if not auth.PASSWORD_SLOTS.acquire(blocking=False):
            raise auth.LoginLimited(1)
        try:
            credential = auth.PASSWORD.hash(password)
        finally:
            auth.PASSWORD_SLOTS.release()
        with state.connect(write=True) as db:
            current = pending_account(db, record)
            if current is None or (token is not None and record["expires_at"] <= int(time.time())):
                raise SetupUnavailable
            db.execute("UPDATE panel_account SET username=?,password_hash=?,auth_epoch=auth_epoch+1 WHERE id=?",
                       (username, credential, current["id"]))
            db.execute("DELETE FROM session WHERE account_id=?", (current["id"],))
            db.execute("DELETE FROM panel_auth_flow WHERE account_id=?", (current["id"],))
            db.execute("DELETE FROM panel_factor_enrollment WHERE account_id=?", (current["id"],))
            account = auth.account_for(db, username)
            audit(db, "admin", address, "administrator.setup_completed", account["id"],
                  reason="LOCAL_BROWSER" if token is None else "OWNER_LINK")
            session = auth.issue_session(db, account, address, int(time.time()))
        # A failed cleanup cannot make the consumed link valid again.
        try:
            clear_handoff(state)
        except (OSError, StateError):
            pass
        return session
