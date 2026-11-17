from argparse import ArgumentParser
from getpass import getpass
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .approval_format import APPROVAL_TAGS, ENVELOPE_LIMIT, operator_id, unpack
from .credentials import ca_certificate, certificate, fingerprint, node_id, read_pem, sign_csr
from .protocol import decode_json, wire_b64
from ..platforms import secure_private


def passphrase(*, confirm: bool = False) -> bytes:
    if not sys.stdin.isatty():
        raise ValueError("Use a terminal to enter the private key passphrase")
    password = getpass("Private key passphrase: ")
    if not password:
        raise ValueError("The private key requires a passphrase")
    if confirm and (len(password) < 12 or password != getpass("Confirm private key passphrase: ")):
        raise ValueError("Use a matching passphrase of at least 12 characters")
    return password.encode("utf-8")


def write_new(path: Path, contents: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        secure_private(path)
        stream.write(contents)


def init_ca(directory: Path) -> None:
    password = passphrase(confirm=True)
    key = Ed25519PrivateKey.generate()
    ca = ca_certificate(key)
    directory.mkdir(mode=0o700)
    secure_private(directory, 0o700)
    write_new(directory / "ca.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password),
    ))
    write_new(directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    mesh_id = secrets.token_hex(16)
    write_new(directory / "mesh-id.txt", (mesh_id + "\n").encode("ascii"))
    print("Mesh ID", mesh_id)
    print("Mesh CA SHA-256", fingerprint(ca))


def init_operator(directory: Path) -> None:
    password = passphrase(confirm=True)
    key = Ed25519PrivateKey.generate()
    directory.mkdir(mode=0o700)
    secure_private(directory, 0o700)
    write_new(directory / "operator.key", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password),
    ))
    write_new(directory / "operator.pub", key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print("Operator key ID", operator_id(key.public_key()))


def configure_approve(parser: ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="approve_command", required=True)
    sign = commands.add_parser("sign", help="Verify and sign a target challenge on the independent workstation")
    sign.add_argument("--operator-key", type=Path, required=True)
    sign.add_argument("--target-certificate", type=Path, required=True)
    sign.add_argument("--target-id", required=True)
    sign.add_argument("--origin-id", required=True)
    sign.add_argument("--mesh-id", required=True)
    sign.add_argument("--version", type=int, choices=(1, 2), default=1)
    sign.add_argument("--target-fingerprint", help="Independently approved target certificate fingerprint for v2")
    sign.add_argument("--policy-root", type=Path, help="Pinned offline policy root for v2")
    sign.add_argument("--policy-root-id", help="Independently approved policy root fingerprint for v2")
    sign.add_argument("--policy", type=Path, help="Current signed policy bundle for v2")
    sign.add_argument("challenge_file", type=Path)
    sign.add_argument("output", type=Path)


def check_signing_policy(args, data: dict) -> int:
    from .policy_records import Bundle, matching_grants, read_document, root_id, user_key
    from .policy_workstation import read_public

    if not all((args.target_fingerprint, args.policy_root, args.policy_root_id, args.policy)):
        raise ValueError("v2 requires a target fingerprint, policy root and root ID, and a current policy bundle")
    root = read_public(args.policy_root)
    if root_id(root) != args.policy_root_id:
        raise ValueError("Policy root does not match the approved fingerprint")
    now = int(time.time())
    snapshot = Bundle.verify(read_document(args.policy), root, args.mesh_id, now).snapshot
    members = {item["node_id"] for item in snapshot["members"] if item["state"] == "active"}
    grants = matching_grants(
        snapshot, user_id=data["user_id"], origin=data["origin_node_id"], target=data["issuer_node_id"],
        service=data["service_id"], action=data["action"], now=now,
    )
    if (snapshot["term"] != data["policy_term"] or not {args.origin_id, args.target_id} <= members
            or user_key(snapshot, data["user_id"], data["operator_key_id"]) is None or len(grants) != 1
            or (grants[0]["id"], grants[0]["revision"]) != (data["grant_id"], data["grant_version"])):
        raise ValueError("The operation is outside the signed Mesh policy")
    return min(snapshot["expires_at"], grants[0]["expires_at"])


def sign_approval(args) -> None:
    with args.challenge_file.open("rb") as stream:
        body = stream.read(ENVELOPE_LIMIT + 1)
    if len(body) > ENVELOPE_LIMIT:
        raise ValueError("Challenge file exceeds 16 KiB")
    envelope = decode_json(body)
    challenge = unpack(envelope, approved=False, version=args.version)
    target = certificate(read_pem(args.target_certificate))
    public = target.public_key()
    if not isinstance(public, Ed25519PublicKey) or node_id(public) != args.target_id:
        raise ValueError("Target certificate does not match the trusted Node ID")
    if args.version == 2 and fingerprint(target) != args.target_fingerprint:
        raise ValueError("Target certificate does not match the independently approved fingerprint")
    challenge.verify_issuer(public)
    data = challenge.data
    if (data["issuer_node_id"] != args.target_id or data["origin_node_id"] != args.origin_id
            or data["mesh_id"] != args.mesh_id or not data["issued_at"] <= int(time.time()) < data["expires_at"]):
        raise ValueError("Challenge source, target, Mesh ID or validity does not match")
    expires = data["expires_at"]
    if args.version == 2:
        expires = min(expires, check_signing_policy(args, data))
        for name in ("user_id", "operator_key_id", "policy_term", "grant_id", "grant_version", "params"):
            print(name, json.dumps(data[name], ensure_ascii=False), flush=True)
    key = serialization.load_pem_private_key(read_pem(args.operator_key), passphrase())
    if not isinstance(key, Ed25519PrivateKey) or operator_id(key.public_key()) != data["operator_key_id"]:
        raise ValueError("The operator key does not match this challenge")
    for label, value in (
        ("Source Node ID", data["origin_node_id"]), ("Target Node ID", data["issuer_node_id"]),
        ("Target certificate SHA-256", fingerprint(target)), ("Target name", data["target_name"]),
        ("Service name", data["service_name"]), ("Service ID", data["service_id"]), ("Action", data["action"]),
        ("Request ID", data["request_id"]), ("Expires at Unix time", data["expires_at"]),
    ):
        print(label, json.dumps(value, ensure_ascii=False), flush=True)
    if input("Type APPROVE to sign this request: ").strip() != "APPROVE":
        raise ValueError("Approval declined")
    if int(time.time()) >= expires:
        raise ValueError("Challenge or policy expired during review")
    envelope["operator_signature"] = wire_b64(key.sign(APPROVAL_TAGS[args.version] + challenge.digest))
    write_new(args.output, json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
    print("Approved challenge SHA-256", challenge.digest.hex())


def main() -> int:
    from . import policy_workstation

    parser = ArgumentParser(prog="spearmint-mesh")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ca-init", help="Create an offline Mesh CA").add_argument("directory", type=Path)
    policy_workstation.configure(commands.add_parser("security", help="Sign and export M003 Mesh policy"))
    operator = commands.add_parser("operator", help="Manage an independent operator key")
    operator.add_subparsers(dest="operator_command", required=True).add_parser("init").add_argument("directory", type=Path)
    configure_approve(commands.add_parser("approve", help="Sign an operation challenge"))
    sign = commands.add_parser("sign-csr", help="Issue a node certificate for an approved Node ID and SAN")
    sign.add_argument("--ca", type=Path, required=True)
    sign.add_argument("--node-id", required=True)
    sign.add_argument("--address", required=True)
    sign.add_argument("csr", type=Path)
    sign.add_argument("output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "ca-init":
            init_ca(args.directory)
        elif args.command == "operator":
            init_operator(args.directory)
        elif args.command == "approve":
            sign_approval(args)
        elif args.command == "security":
            args.run(args)
        else:
            key = serialization.load_pem_private_key(read_pem(args.ca / "ca.key"), passphrase())
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("Expected an Ed25519 Mesh CA key")
            cert = sign_csr(read_pem(args.csr), key, certificate(read_pem(args.ca / "ca.pem")), args.node_id, args.address)
            write_new(args.output, cert.public_bytes(serialization.Encoding.PEM))
            print("Leaf certificate SHA-256", fingerprint(cert))
    except (OSError, ValueError, InvalidSignature, EOFError, sqlite3.Error) as exc:
        print(f"Spearmint Mesh: {exc}", file=sys.stderr)
        return 1
    return 0
