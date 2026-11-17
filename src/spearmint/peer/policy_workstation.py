from argparse import ArgumentParser
from contextlib import closing, contextmanager
import json
from pathlib import Path
from secrets import token_hex
import sqlite3
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .approval_format import operator_id
from .credentials import NODE_ID, RANDOM_ID, read_pem
from . import evidence
from .policy_records import (
    Bundle, DELEGATION_TTL, ENROLLMENT_TTL, POLICY_TTL, RESUME_TTL, SNAPSHOT_LIMIT, USER_ID, Record, delegation,
    encoded, positive, public_key, read_document, root_id, validate_snapshot, verify_enrollment,
)
from .protocol import matches, wire_b64
from ..platforms import secure_private


def read_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(read_pem(path))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Policy keys must use Ed25519")
    return key


def read_private(path: Path) -> Ed25519PrivateKey:
    from .workstation import passphrase

    key = serialization.load_pem_private_key(read_pem(path), passphrase())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Policy keys must use Ed25519")
    return key


def export(path: Path, document: dict) -> None:
    from .workstation import write_new

    write_new(path, encoded(document) + b"\n")


def key_init(role: str, directory: Path) -> None:
    from .workstation import passphrase, write_new

    password = passphrase(confirm=True)
    key = Ed25519PrivateKey.generate()
    directory.mkdir(mode=0o700)
    secure_private(directory, 0o700)
    write_new(directory / f"{role}.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password),
    ))
    write_new(directory / f"{role}.pub", key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(root_id(key.public_key()) if role == "root" else operator_id(key.public_key()))


@contextmanager
def ledger(path: Path):
    with closing(sqlite3.connect(path, isolation_level=None)) as db:
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS version (
                mesh_id TEXT NOT NULL, term INTEGER NOT NULL, sequence INTEGER NOT NULL,
                bundle TEXT NOT NULL, PRIMARY KEY(mesh_id,term,sequence)
            );
            CREATE TABLE IF NOT EXISTS enrollment (
                nonce TEXT PRIMARY KEY, mesh_id TEXT NOT NULL, user_id TEXT NOT NULL,
                public_key TEXT NOT NULL, expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS object_history (
                mesh_id TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
                owner TEXT NOT NULL, payload TEXT NOT NULL, retired INTEGER NOT NULL,
                PRIMARY KEY(mesh_id,kind,id)
            );
        """)
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()


def current(db: sqlite3.Connection, mesh_id: str) -> sqlite3.Row | None:
    return db.execute("""
        SELECT term, sequence, bundle FROM version WHERE mesh_id=? ORDER BY term DESC,sequence DESC LIMIT 1
    """, (mesh_id,)).fetchone()


def issue_delegation(args) -> None:
    if not matches(RANDOM_ID, args.mesh_id) or not positive(args.term) or not 0 < args.ttl <= DELEGATION_TTL:
        raise ValueError("Invalid delegation Mesh, term or lifetime")
    root, authority = read_private(args.root_key), read_public(args.authority_public)
    now = int(time.time())
    payload = {"version": 1, "mesh_id": args.mesh_id, "term": args.term, "root_key_id": root_id(root.public_key()),
               "authority_public_key": wire_b64(authority.public_bytes_raw()), "scope": "mesh_policy",
               "issued_at": now, "expires_at": now + args.ttl}
    record = Record.sign("delegation", payload, root)
    delegation(record, root.public_key(), args.mesh_id, now)
    export(args.output, record.wire())


def issue_enrollment(args) -> None:
    if not matches(RANDOM_ID, args.mesh_id) or not matches(USER_ID, args.user_id):
        raise ValueError("Invalid policy Mesh or user ID")
    nonce = token_hex(16)
    public = wire_b64(read_public(args.operator_public).public_bytes_raw())
    now = int(time.time())
    with ledger(args.ledger) as db:
        db.execute("DELETE FROM enrollment WHERE expires_at<=?", (now,))
        db.execute("INSERT INTO enrollment VALUES (?,?,?,?,?)",
                   (nonce, args.mesh_id, args.user_id, public, now + ENROLLMENT_TTL))
    export(args.output, {"nonce": nonce, "mesh_id": args.mesh_id, "user_id": args.user_id,
                         "public_key": public, "expires_at": now + ENROLLMENT_TTL})


def sign_enrollment(args) -> None:
    request = read_document(args.request, 2048)
    key = read_private(args.operator_key)
    now = int(time.time())
    if (request.keys() != {"nonce", "mesh_id", "user_id", "public_key", "expires_at"}
            or not positive(request["expires_at"]) or not 0 < request["expires_at"] - now <= ENROLLMENT_TTL
            or request["public_key"] != wire_b64(key.public_key().public_bytes_raw())):
        raise ValueError("Enrollment request does not match the user's key or current time")
    proof = Record.sign("enrollment", {"version": 1, "issued_at": now, **request}, key).wire()
    verify_enrollment(proof, request["mesh_id"], now)
    export(args.output, proof)


def objects(snapshot: dict):
    for user in snapshot["users"]:
        yield "user", user["user_id"], "", {key: value for key, value in user.items() if key != "keys"}, user["state"] == "revoked"
        for key in user["keys"]:
            yield "key", key["key_id"], user["user_id"], key, key["state"] == "revoked" or user["state"] == "revoked"
    for member in snapshot["members"]:
        yield "member", member["node_id"], "", member, member["state"] == "revoked"
    for grant in snapshot["grants"]:
        owner = ":".join(grant[field] for field in ("user_id", "origin_node_id", "target_node_id", "service_id"))
        yield "grant", grant["id"], owner, grant, False


def consume_proof(db: sqlite3.Connection, mesh_id: str, owner: str, payload: dict, proof: dict | None, now: int) -> None:
    if proof is None or (proof["user_id"], proof["public_key"]) != (owner, payload["public_key"]):
        raise ValueError("A new active key requires a proof from its registered user")
    removed = db.execute("""
        DELETE FROM enrollment WHERE nonce=? AND mesh_id=? AND user_id=? AND public_key=? AND expires_at=? AND expires_at>?
    """, (proof["nonce"], mesh_id, owner, payload["public_key"], proof["expires_at"], now))
    if removed.rowcount != 1:
        raise ValueError("Enrollment proof does not match an outstanding workstation request")


def record_history(db: sqlite3.Connection, snapshot: dict, proofs: dict, now: int) -> None:
    mesh_id = snapshot["mesh_id"]
    previous = {(row["kind"], row["id"]): row for row in db.execute(
        "SELECT * FROM object_history WHERE mesh_id=?", (mesh_id,),
    )}
    for kind, identity, owner, payload, retired in objects(snapshot):
        old = previous.pop((kind, identity), None)
        if old is not None:
            if old["owner"] != owner or (old["retired"] and not retired):
                raise ValueError(f"Cannot reassign or reactivate a retired policy {kind}")
            old_payload = json.loads(old["payload"])
            if kind == "grant" and payload != old_payload and payload["revision"] <= old_payload["revision"]:
                raise ValueError("A changed grant must advance its revision")
        elif kind == "key" and not retired:
            consume_proof(db, mesh_id, owner, payload, proofs.pop(identity, None), now)
        db.execute("""
            INSERT INTO object_history VALUES (?,?,?,?,?,?)
            ON CONFLICT(mesh_id,kind,id) DO UPDATE SET payload=excluded.payload,retired=excluded.retired
        """, (mesh_id, kind, identity, owner, encoded(payload).decode(), retired))
    if proofs:
        raise ValueError("Enrollment proofs may only be supplied for new active keys")
    for (kind, identity), old in previous.items():
        if not old["retired"] and kind != "grant":
            raise ValueError(f"Mark removed {kind} records revoked before omitting them from a policy")
        db.execute("UPDATE object_history SET retired=1 WHERE mesh_id=? AND kind=? AND id=?",
                   (mesh_id, kind, identity))


def publish(args) -> None:
    intent = read_document(args.intent, SNAPSHOT_LIMIT)
    if intent.keys() != {"change", "users", "members", "grants"} or not 0 < args.ttl <= POLICY_TTL:
        raise ValueError("Policy intent must contain change, users, members and grants")
    root, key = read_public(args.root_public), read_private(args.authority_key)
    record = Record.parse(read_document(args.delegation, 4096))
    now = int(time.time())
    mesh_id = args.mesh_id
    authority = delegation(record, root, mesh_id, now)
    if authority["authority_public_key"] != wire_b64(key.public_key().public_bytes_raw()):
        raise ValueError("Delegation does not match this authority key")
    proofs = {}
    for path in args.proof:
        proof = verify_enrollment(read_document(path, 4096), mesh_id, now)
        identity = operator_id(public_key(proof["public_key"]))
        if identity in proofs:
            raise ValueError("Duplicate key enrollment proof")
        proofs[identity] = proof
    with ledger(args.ledger) as db:
        last = current(db, mesh_id)
        sequence, previous_digest = 1, None
        if last is not None:
            if authority["term"] < last["term"]:
                raise ValueError("Delegation is older than the workstation's current term")
            if authority["term"] == last["term"]:
                previous = Bundle.verify(json.loads(last["bundle"]), root, mesh_id, None)
                if previous.delegation_record.digest != record.digest or now < previous.snapshot["issued_at"]:
                    raise ValueError("Delegation or clock conflicts with the current term")
                sequence, previous_digest = last["sequence"] + 1, previous.snapshot_record.digest
        snapshot = {"version": 1, "mesh_id": mesh_id, "term": authority["term"], "sequence": sequence,
                    "previous_digest": previous_digest, "issued_at": now,
                    "expires_at": min(now + args.ttl, authority["expires_at"]), **intent}
        validate_snapshot(snapshot, authority, now)
        record_history(db, snapshot, proofs, now)
        signed = Record.sign("policy", snapshot, key, SNAPSHOT_LIMIT)
        document = {"delegation": record.wire(), "snapshot": signed.wire()}
        Bundle.verify(document, root, mesh_id, now)
        db.execute("INSERT INTO version VALUES (?,?,?,?)", (mesh_id, authority["term"], sequence, encoded(document).decode()))
    # The signed version remains exportable if the output path was unavailable.
    export(args.output, document)
    print(f"Policy {authority['term']}:{sequence} {signed.digest}")


def export_latest(args) -> None:
    with ledger(args.ledger) as db:
        latest = current(db, args.mesh_id)
    if latest is None:
        raise ValueError("No signed policy in this workstation ledger")
    export(args.output, json.loads(latest["bundle"]))


def export_version(args) -> None:
    with ledger(args.ledger) as db:
        row = db.execute("SELECT bundle FROM version WHERE mesh_id=? AND term=? AND sequence=?",
                         (args.mesh_id, args.term, args.sequence)).fetchone()
    if row is None:
        raise ValueError("No matching policy version in this workstation ledger")
    export(args.output, json.loads(row["bundle"]))


def sign_resume(args) -> None:
    request = read_document(args.request, 2048)
    if (request.keys() != {"mesh_id", "node_id", "nonce"} or not matches(RANDOM_ID, request["mesh_id"])
            or not matches(NODE_ID, request["node_id"]) or not matches(RANDOM_ID, request["nonce"])):
        raise ValueError("Invalid policy recovery request")
    root, key = read_public(args.root_public), read_private(args.authority_key)
    now = int(time.time())
    with ledger(args.ledger) as db:
        latest = current(db, request["mesh_id"])
        if latest is None:
            raise ValueError("No signed policy in this workstation ledger")
        bundle = Bundle.verify(json.loads(latest["bundle"]), root, request["mesh_id"], now)
        if bundle.authority["authority_public_key"] != wire_b64(key.public_key().public_bytes_raw()):
            raise ValueError("Recovery must be signed by the current authority")
        if not any(member["node_id"] == request["node_id"] and member["state"] == "active"
                   for member in bundle.snapshot["members"]):
            raise ValueError("Recovery target is not an active member")
        cursor = bundle.cursor()
        proof = Record.sign("resume", {"version": 1, **request, "term": cursor["term"], "sequence": cursor["sequence"],
            "policy_digest": cursor["digest"], "issued_at": now, "expires_at": min(now + RESUME_TTL, bundle.snapshot["expires_at"])}, key)
    export(args.output, proof.wire())


def verify_evidence(args) -> None:
    root = read_public(args.root_public)
    if root_id(root) != args.root_id:
        raise ValueError('Policy root does not match the independently supplied fingerprint')
    document = read_document(args.file, evidence.LIMIT)
    result = evidence.verify_report(document, root, args.mesh_id, args.observer_node_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def configure(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="security_command", required=True)
    init = commands.add_parser("key-init", help="Create an independent root or authority key")
    init.add_argument("role", choices=("root", "authority"))
    init.add_argument("directory", type=Path)
    init.set_defaults(run=lambda args: key_init(args.role, args.directory))
    delegate = commands.add_parser("delegate", help="Delegate one Mesh policy term")
    delegate.add_argument("--mesh-id", required=True)
    delegate.add_argument("--term", type=int, required=True)
    delegate.add_argument("--ttl", type=int, default=DELEGATION_TTL)
    delegate.add_argument("--root-key", type=Path, required=True)
    delegate.add_argument("--authority-public", type=Path, required=True)
    delegate.set_defaults(run=issue_delegation)
    request = commands.add_parser("enrollment-request", help="Issue an enrollment request for a user key")
    request.add_argument("--mesh-id", required=True)
    request.add_argument("--user-id", required=True)
    request.add_argument("--operator-public", type=Path, required=True)
    request.add_argument("--ledger", type=Path, required=True)
    request.set_defaults(run=issue_enrollment)
    proof = commands.add_parser("enrollment-sign", help="Prove possession of a user key")
    proof.add_argument("--operator-key", type=Path, required=True)
    proof.add_argument("request", type=Path)
    proof.set_defaults(run=sign_enrollment)
    issue = commands.add_parser("publish", help="Sign and persist the next policy snapshot")
    issue.add_argument("--mesh-id", required=True)
    issue.add_argument("--ttl", type=int, default=POLICY_TTL)
    issue.add_argument("--ledger", type=Path, required=True)
    issue.add_argument("--root-public", type=Path, required=True)
    issue.add_argument("--authority-key", type=Path, required=True)
    issue.add_argument("--delegation", type=Path, required=True)
    issue.add_argument("--proof", action="append", type=Path, default=[])
    issue.add_argument("intent", type=Path)
    issue.set_defaults(run=publish)
    latest = commands.add_parser("latest", help="Export the latest committed snapshot again")
    latest.add_argument("--mesh-id", required=True)
    latest.add_argument("--ledger", type=Path, required=True)
    latest.set_defaults(run=export_latest)
    history = commands.add_parser("history-export", help="Export an exact historical signed version")
    history.add_argument("--mesh-id", required=True)
    history.add_argument("--ledger", type=Path, required=True)
    history.add_argument("--term", type=int, required=True)
    history.add_argument("--sequence", type=int, required=True)
    history.set_defaults(run=export_version)
    recovery = commands.add_parser("resume-sign", help="Sign recovery against the current snapshot")
    recovery.add_argument("--root-public", type=Path, required=True)
    recovery.add_argument("--authority-key", type=Path, required=True)
    recovery.add_argument("--ledger", type=Path, required=True)
    recovery.add_argument("request", type=Path)
    recovery.set_defaults(run=sign_resume)
    verify = commands.add_parser('evidence-verify', help='Verify a recorded Mesh policy conflict offline')
    verify.add_argument('--root-public', type=Path, required=True)
    verify.add_argument('--root-id', required=True)
    verify.add_argument('--mesh-id', required=True)
    verify.add_argument('--observer-node-id')
    verify.add_argument('file', type=Path)
    verify.set_defaults(run=verify_evidence)
    for command in (delegate, request, proof, issue, latest, history, recovery):
        command.add_argument("output", type=Path)
