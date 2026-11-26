from datetime import UTC, datetime, timedelta
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
import re
from secrets import token_urlsafe
import ssl
import tempfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PEM_LIMIT = 8192
NODE_ID = re.compile(r"spm1-[0-9a-f]{64}")
RANDOM_ID = re.compile(r"[0-9a-f]{32}")
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
PEER_USAGES = [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]


def node_id(public_key) -> str:
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Peer identity requires an Ed25519 key")
    return "spm1-" + sha256(public_key.public_bytes_raw()).hexdigest()


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def endpoint_name(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ip_address(value))
    except ValueError:
        if len(value) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ValueError("Use an IP address or ASCII DNS name") from None
        return x509.DNSName(value.lower())


def common_name(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def read_pem(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(PEM_LIMIT + 1)
    if len(data) > PEM_LIMIT:
        raise ValueError(f"PEM file is larger than {PEM_LIMIT} bytes")
    return data


def certificate(pem: bytes) -> x509.Certificate:
    certs = x509.load_pem_x509_certificates(pem)
    if len(certs) != 1:
        raise ValueError("Expected a single certificate")
    return certs[0]


def mesh_authorities(pem: bytes) -> tuple[x509.Certificate, ...]:
    if len(pem) > PEM_LIMIT:
        raise ValueError("Mesh authority bundle is too large")
    roots = tuple(x509.load_pem_x509_certificates(pem))
    if not 1 <= len(roots) <= 8 or len({fingerprint(root) for root in roots}) != len(roots):
        raise ValueError("Invalid Mesh authority bundle")
    active = tuple(root for root in roots if is_current(root))
    if not active:
        raise ValueError("The Mesh has no current signing authority")
    for root in active:
        validate_ca(root)
    return active


def make_csr(key: Ed25519PrivateKey, address: str) -> bytes:
    subject = common_name(node_id(key.public_key()).removeprefix("spm1-"))
    return (x509.CertificateSigningRequestBuilder().subject_name(subject)
            .add_extension(x509.SubjectAlternativeName([endpoint_name(address)]), critical=False)
            .sign(key, None).public_bytes(serialization.Encoding.PEM))


def ca_certificate(key: Ed25519PrivateKey, *, name: str = "Spearmint Mesh CA") -> x509.Certificate:
    subject = common_name(name)
    now = datetime.now(UTC)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, None))


def is_current(cert: x509.Certificate) -> bool:
    return cert.not_valid_before_utc <= datetime.now(UTC) < cert.not_valid_after_utc


def validate_ca(ca: x509.Certificate) -> None:
    try:
        ca.verify_directly_issued_by(ca)
        if (not is_current(ca) or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign):
            raise ValueError("Mesh CA is expired or cannot sign certificates")
    except (InvalidSignature, x509.ExtensionNotFound) as exc:
        raise ValueError("Invalid Mesh CA certificate") from exc


def validate_leaf(cert: x509.Certificate, ca: x509.Certificate, expected_id: str, address: str | None = None) -> None:
    try:
        cert.verify_directly_issued_by(ca)
        ext = cert.extensions
        san = ext.get_extension_for_class(x509.SubjectAlternativeName).value
        if (ext.get_extension_for_class(x509.BasicConstraints).value.ca
                or not ext.get_extension_for_class(x509.KeyUsage).value.digital_signature
                or set(ext.get_extension_for_class(x509.ExtendedKeyUsage).value) != set(PEER_USAGES)):
            raise ValueError("Peer certificate requires the dual-use leaf profile")
    except (InvalidSignature, x509.ExtensionNotFound) as exc:
        raise ValueError("Invalid Mesh leaf certificate") from exc
    if not is_current(cert) or node_id(cert.public_key()) != expected_id:
        raise ValueError("Peer certificate has expired or has an unexpected node ID")
    if address is not None and endpoint_name(address) not in san:
        raise ValueError("Peer certificate SAN does not match its endpoint")


def validate_mesh_leaf(cert: x509.Certificate, roots: tuple[x509.Certificate, ...], expected_id: str,
                       address: str | None = None) -> x509.Certificate:
    for root in roots:
        if cert.issuer == root.subject:
            try:
                validate_leaf(cert, root, expected_id, address)
                return root
            except ValueError:
                if len(roots) == 1:
                    raise
    raise ValueError("Peer certificate does not match a trusted Mesh authority and endpoint")


def sign_csr(pem: bytes, key: Ed25519PrivateKey, ca: x509.Certificate, expected_id: str, address: str) -> x509.Certificate:
    validate_ca(ca)
    if ca.public_key().public_bytes_raw() != key.public_key().public_bytes_raw():
        raise ValueError("Mesh CA key and certificate do not match")
    request = x509.load_pem_x509_csr(pem)
    public = request.public_key()
    san = x509.SubjectAlternativeName([endpoint_name(address)])
    try:
        requested_san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("CSR must include its approved SAN") from exc
    if (not request.is_signature_valid or node_id(public) != expected_id
            or request.subject != common_name(expected_id.removeprefix("spm1-"))
            or requested_san != san):
        raise ValueError("CSR does not match the approved identity and SAN")
    now = datetime.now(UTC)
    return (x509.CertificateBuilder().subject_name(request.subject).issuer_name(ca.subject)
            .public_key(public).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(min(now + timedelta(days=90), ca.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage(PEER_USAGES), critical=False).add_extension(san, critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, None))


def tls_context(key: Ed25519PrivateKey, ca: bytes, leaf: bytes, directory: Path, *, server: bool) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_TICKET
    context.load_verify_locations(cadata=ca.decode("ascii"))
    if server:
        context.num_tickets = 0
    else:
        context.hostname_checks_common_name = False
    password = token_urlsafe(32).encode('ascii')
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".peer-cert-", delete_on_close=False) as chain:
        chain.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.BestAvailableEncryption(password)))
        chain.write(leaf)
        chain.flush()
        context.load_cert_chain(chain.name, password=password)
    return context
