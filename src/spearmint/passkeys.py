import json
import re
import secrets
import sqlite3
from struct import error as StructError
import time
from urllib.parse import urlsplit

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import auth, factors
from .peer.protocol import decode_json
from .state import State, StateError, audit


MAX_PASSKEYS = 8
ALGORITHMS = {-7, -8, -257}  # ES256, EdDSA, RS256
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
INVALID_RESPONSE = (ValueError, TypeError, KeyError, IndexError, StructError, OverflowError, AssertionError)


def relying_party(origin: str) -> Fido2Server:
    url = urlsplit(origin)
    hostname = url.hostname or ""
    labels = hostname.split(".")
    if (url.scheme != "https" or len(hostname) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(DNS_LABEL.fullmatch(label) is None for label in labels)):
        raise StateError("Passkey requires the configured HTTPS DNS name")
    server = Fido2Server(
        PublicKeyCredentialRpEntity(name="Spearmint", id=hostname),
        attestation=AttestationConveyancePreference.NONE,
        verify_origin=lambda value: value == origin,
    )
    server.allowed_algorithms = [item for item in server.allowed_algorithms if item.alg in ALGORITHMS]
    server.timeout = auth.FLOW_SECONDS * 1000
    return server


def save_challenge(db: sqlite3.Connection, token_hash: bytes, state: dict, origin: str) -> None:
    db.execute("UPDATE panel_auth_flow SET webauthn_state=?, origin=? WHERE token_hash=?",
               (json.dumps(state), origin, token_hash))


def user_handle(account: sqlite3.Row) -> bytes:
    return account["id"].encode("ascii")


def verify_client_data(data: CollectedClientData, origin: str) -> None:
    parsed = decode_json(data)
    if parsed.get("crossOrigin", False) is not False or parsed.get("topOrigin", origin) != origin:
        raise ValueError("Embedded or cross-origin Passkey ceremony")


def verify_backup_flags(data: AuthenticatorData) -> None:
    if data.is_backed_up() and not data.is_backup_eligible():
        raise ValueError("Unexpected Passkey backup flags")


def login_options(state: State, username: str, address: str, origin: str) -> dict:
    server = relying_party(origin)
    options, webauthn_state = server.authenticate_begin(user_verification=UserVerificationRequirement.REQUIRED)
    now = int(time.time())
    with auth.authentication_attempt(state, address, now, username=username) as (db, account):
        if account is None:
            return {"flow_id": secrets.token_urlsafe(32), "public_key": dict(options)["publicKey"]}
        flow = auth.issue_flow(db, account, address, now, "passkey_login", "passkey")
        save_challenge(db, auth.digest(flow.flow_id), webauthn_state, origin)
    return {"flow_id": flow.flow_id, "public_key": dict(options)["publicKey"]}


def finish_login(state: State, token: str, response: dict, address: str,
                 origin: str) -> tuple[str, tuple[str, str]] | None:
    server = relying_party(origin)
    now = int(time.time())
    with auth.authentication_attempt(state, address, now, flow=(token, "passkey_login")) as (db, flow):
        if flow is None or flow["origin"] != origin or flow["webauthn_state"] is None:
            return None
        try:
            assertion = AuthenticationResponse.from_dict(response)
            credential = db.execute("""
                SELECT id, credential, sign_count, backup_eligible FROM panel_passkey
                WHERE account_id=? AND origin=? AND credential_id=? AND enabled=1
            """, (flow["id"], origin, assertion.raw_id)).fetchone()
            if credential is None or assertion.response.user_handle != user_handle(flow):
                raise ValueError("Passkey does not match this account")
            data = assertion.response.authenticator_data
            verify_client_data(assertion.response.client_data, origin)
            verify_backup_flags(data)
            if data.is_backup_eligible() != credential["backup_eligible"]:
                raise ValueError("Passkey backup eligibility changed")
            server.authenticate_complete(
                json.loads(flow["webauthn_state"]), [AttestedCredentialData(credential["credential"])], assertion,
            )
        except INVALID_RESPONSE:
            auth.reject_flow(db, flow, address)
            return None
        if (data.counter or credential["sign_count"]) and data.counter <= credential["sign_count"]:
            db.execute("UPDATE panel_passkey SET enabled=0 WHERE id=?", (credential["id"],))
            factors.revoke_account_sessions(db, flow["id"])
            audit(db, flow["operation_actor"], address, "session.passkey_counter_paused", credential["id"])
            return None
        db.execute("UPDATE panel_passkey SET sign_count=?, last_used_at=? WHERE id=?",
                   (data.counter, now, credential["id"]))
        db.execute("DELETE FROM panel_auth_flow WHERE token_hash=?", (flow["token_hash"],))
        return flow["username"], auth.issue_session(db, flow, address, now, mfa_at=now, method="passkey")


def register_options(state: State, token: str, address: str, origin: str) -> dict | None:
    server = relying_party(origin)
    with state.connect(write=True) as db:
        flow = auth.active_flow(db, token, address, int(time.time()), "passkey_enroll")
        if flow is None or flow["origin"] not in (None, origin):
            return None
        credentials = db.execute(
            "SELECT credential, origin FROM panel_passkey WHERE account_id=? AND enabled=1", (flow["id"],),
        ).fetchall()
        if len(credentials) >= MAX_PASSKEYS:
            raise StateError("Passkey limit reached. Revoke an unused credential first")
        options, webauthn_state = server.register_begin(
            PublicKeyCredentialUserEntity(id=user_handle(flow), name=flow["username"], display_name=flow["username"]),
            [AttestedCredentialData(row["credential"]) for row in credentials if row["origin"] == origin],
            resident_key_requirement=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        save_challenge(db, flow["token_hash"], webauthn_state, origin)
    return dict(options)["publicKey"]


def finish_registration(state: State, token: str, response: dict, address: str, origin: str) -> list[str] | None:
    server = relying_party(origin)
    now = int(time.time())
    with auth.authentication_attempt(state, address, now, flow=(token, "passkey_enroll")) as (db, flow):
        if flow is None or flow["origin"] != origin or flow["webauthn_state"] is None:
            return None
        try:
            registration = RegistrationResponse.from_dict(response)
            verify_client_data(registration.response.client_data, origin)
            data = server.register_complete(json.loads(flow["webauthn_state"]), registration)
            verify_backup_flags(data)
            credential = data.credential_data
            if (credential is None or not 1 <= len(credential.credential_id) <= 1023
                    or credential.credential_id != registration.raw_id or credential.public_key.get(3) not in ALGORITHMS):
                raise ValueError("Unexpected Passkey credential")
        except INVALID_RESPONSE:
            auth.reject_flow(db, flow, address)
            return None
        count = db.execute("SELECT count(*) FROM panel_passkey WHERE account_id=? AND enabled=1",
                           (flow["id"],)).fetchone()[0]
        if count >= MAX_PASSKEYS:
            raise StateError("Passkey limit reached. Revoke an unused credential first")
        entry = db.execute("""
            INSERT INTO panel_passkey (account_id, credential_id, credential, origin, sign_count, backup_eligible, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(credential_id) DO NOTHING RETURNING id
        """, (flow["id"], credential.credential_id, bytes(credential), origin,
              data.counter, data.is_backup_eligible(), now)).fetchone()
        if entry is None:
            auth.reject_flow(db, flow, address)
            return None
        codes = factors.activate_factor(db, flow["id"])
        audit(db, flow["operation_actor"], address, "administrator.passkey_enrolled", entry["id"])
        return codes


def revoke(state: State, credential_id: str) -> None:
    with state.connect(write=True) as db:
        credential = db.execute("UPDATE panel_passkey SET enabled=0 WHERE id=? AND enabled=1 RETURNING account_id",
                                (credential_id,)).fetchone()
        if credential is None:
            raise StateError("No active Passkey with that ID")
        factors.revoke_account_sessions(db, credential["account_id"])
        audit(db, "admin", "local", "administrator.passkey_revoked", credential_id)
