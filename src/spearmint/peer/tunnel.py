import asyncio
from typing import Protocol
import ssl

from cryptography import x509

from .credentials import fingerprint, validate_mesh_leaf
from .protocol import DEADLINE, FRAME, HEADER, ProtocolError, encode, receive


CHUNK = 16 * 1024


class ByteChannel(Protocol):
    async def send(self, data: bytes) -> None: ...

    async def receive(self) -> bytes: ...


class TunnelTLS:
    """Drive one endpoint TLS session over a bounded relay byte channel.

    The caller owns the channel and closes it after a timeout or protocol failure.
    After authentication, one reader and one writer can operate concurrently.
    """

    def __init__(self, channel: ByteChannel, context: ssl.SSLContext, *, server: bool, host: str) -> None:
        self.channel = channel
        self.host = host
        self.server = server
        self.stage = 'new'
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=server,
                                    server_hostname=None if server else host)
        self.authenticated = False

    async def _flush(self, *, full_chunks: bool = False) -> None:
        minimum = CHUNK if full_chunks else 1
        while self.outgoing.pending >= minimum:
            await self.channel.send(self.outgoing.read(CHUNK))

    async def _receive(self) -> None:
        ciphertext = await self.channel.receive()
        if len(ciphertext) > CHUNK:
            raise ProtocolError("Relay TLS chunk exceeds the size limit")
        if ciphertext:
            self.incoming.write(ciphertext)
        else:
            self.incoming.write_eof()

    async def handshake(self, roots: x509.Certificate | tuple[x509.Certificate, ...], peer_id: str, peer_fingerprint: str) -> None:
        if self.authenticated:
            raise ProtocolError("Tunnel TLS is already authenticated")
        if self.server:
            # relay.ready has to reach the source before it can send TLS. Give
            # that first flight its own bounded wait, as for an accepted socket;
            # it must not consume the subsequent TLS exchange's full budget.
            self.stage = 'client_hello'
            async with asyncio.timeout(DEADLINE):
                await self._receive()
        self.stage = 'tls'
        async with asyncio.timeout(DEADLINE):
            while True:
                try:
                    self.tls.do_handshake()
                except ssl.SSLWantReadError:
                    await self._flush()
                    await self._receive()
                else:
                    break
            cert = x509.load_der_x509_certificate(self.tls.getpeercert(binary_form=True))
            if self.tls.version() != "TLSv1.3" or self.tls.session_reused or fingerprint(cert) != peer_fingerprint:
                raise ProtocolError("Tunnel TLS peer identity or certificate fingerprint mismatch")
            validate_mesh_leaf(cert, (roots,) if isinstance(roots, x509.Certificate) else roots, peer_id, self.host)
            await self._flush()
        self.authenticated = True
        self.stage = 'authenticated'

    async def bind(self, *, mesh_id: str, local_id: str, peer_id: str, circuit_id: str, ticket_digest: str) -> None:
        self.stage = 'bind'
        context = {"type": "tunnel.hello", "mesh_id": mesh_id, "node_id": local_id,
                   "circuit_id": circuit_id, "ticket_digest": ticket_digest}
        async with asyncio.timeout(DEADLINE):
            await self.send(encode(context, tunnel=True))
            frame, _ = await receive(self, tunnel=True)
            if frame != {**context, "node_id": peer_id}:
                raise ProtocolError("Tunnel HELLO does not match the authenticated circuit")
        self.stage = 'bound'

    async def send(self, plaintext: bytes) -> None:
        if not self.authenticated:
            raise ProtocolError("Tunnel TLS requires authentication")
        if len(plaintext) > FRAME + HEADER.size:
            raise ProtocolError("Tunnel TLS plaintext exceeds the frame limit")
        remaining = memoryview(plaintext)
        while remaining:
            count = self.tls.write(remaining[:CHUNK])
            remaining = remaining[count:]
            # A full plaintext record produces CHUNK plus TLS overhead bytes.
            # Keep that short remainder for the next record so it does not
            # consume another of the relay's four credits on every TLS write.
            # The final flush also sends small frames immediately.
            await self._flush(full_chunks=bool(remaining))

    async def readexactly(self, size: int) -> bytes:
        if not self.authenticated:
            raise ProtocolError("Tunnel TLS requires authentication")
        if not 0 <= size <= FRAME:
            raise ProtocolError("Tunnel TLS read exceeds the frame limit")
        data = bytearray()
        while len(data) < size:
            try:
                chunk = self.tls.read(min(CHUNK, size - len(data)))
            except ssl.SSLWantReadError:
                await self._receive()
                continue
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(data), size)
            data.extend(chunk)
        return bytes(data)
