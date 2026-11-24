"""Exercise a direct Mesh session from a member without a reverse dial address."""
import asyncio
from pathlib import Path
from secrets import token_hex
import socket
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from grove_fixture import GroveFixture
from spearmint.peer import pairing
from spearmint.peer.credentials import ca_certificate, fingerprint, make_csr, sign_csr, tls_context
from spearmint.peer.grove_endpoints import GroveEndpoints
from spearmint.peer.manager import PeerManager
from spearmint.peer.protocol import encode, receive
from spearmint.peer.session import close_stream


class GroveIngressTest(unittest.TestCase):
    def test_enrolled_member_without_reverse_candidate_can_open_and_keep_a_direct_session(self):
        root = Path('work/tmp/grove-ingress/tests')
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = GroveFixture(Path(directory), member_origins={0: 'https://localhost:18443'})
            client, server = fixture.states[:2]
            ca_key = Ed25519PrivateKey.generate()
            ca = ca_certificate(ca_key)
            ca_pem = ca.public_bytes(Encoding.PEM)

            def issue(state, hostname):
                csr = make_csr(state.signing_key(), hostname)
                return sign_csr(csr, ca_key, ca, state.identity()[0], hostname)

            client_id, server_id = client.identity()[0], server.identity()[0]
            client_host, server_host = 'client.mesh.invalid', 'server.mesh.invalid'
            client_cert = issue(client, client_host)
            server_cert = issue(server, server_host)
            mesh_id = token_hex(16)
            pairing.configure_mesh(server, mesh_id, '192.168.20.10', 8766, ca_pem, server_cert.public_bytes(Encoding.PEM))
            pairing.add_member(server, client_id, client_host, fingerprint(client_cert), client_cert.public_bytes(Encoding.PEM))
            pairing.set_enabled(server, True, client_id)
            manager = PeerManager(server, server_id, dial_enabled=False)
            manager.grove_endpoints = GroveEndpoints(server_id, server.signing_key())
            (manager.pairs, manager.discovery_enabled, manager.networks, manager.endpoints, manager.forwarding_enabled,
             trust, manager.automatic_members, manager.quarantines) = manager.read_members()
            manager.endpoints.update(manager.grove_endpoints.update(trust, manager.pairs))
            manager.admitted = manager.admit(manager.pairs, {})
            self.assertIn(client_id, manager.automatic_members)
            self.assertFalse(manager.endpoints.get(client_id))
            server_tls, _ = manager.contexts(manager.admitted[client_id])
            client_tls = tls_context(client.signing_key(), ca_pem, client_cert.public_bytes(Encoding.PEM),
                                     client.directory, server=False)
            asyncio.run(self.exchange(manager, client_id, mesh_id, server_tls, client_tls, server_host))

    async def exchange(self, manager, client_id, mesh_id, server_tls, client_tls, server_host):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.setblocking(False)
            port = listener.getsockname()[1]
            server_task = asyncio.create_task(manager.listen(listener, server_tls))
            try:
                async with asyncio.timeout(10):
                    reader, writer = await asyncio.open_connection('127.0.0.1', port, ssl=client_tls,
                                                                   server_hostname=server_host)
                    try:
                        writer.write(encode({'type': 'hello', 'protocol_version': 1, 'mesh_id': mesh_id,
                                             'node_id': client_id, 'session_id': token_hex(16),
                                             'capabilities': ['mesh.v2', 'peer.ping']}))
                        await writer.drain()
                        hello, _ = await receive(reader)
                        self.assertEqual((hello['type'], hello['node_id'], hello['mesh_id']),
                                         ('hello', manager.local_id, mesh_id))
                        request_id = token_hex(16)
                        writer.write(encode({'type': 'request', 'id': request_id, 'method': 'peer.ping', 'params': {}}))
                        await writer.drain()
                        frame, _ = await receive(reader)
                        while frame['type'] == 'ping':
                            writer.write(encode({'type': 'pong', 'nonce': frame['nonce']}))
                            await writer.drain()
                            frame, _ = await receive(reader)
                        self.assertEqual(frame, {'type': 'response', 'id': request_id, 'result': {'status': 'ok'}})
                        link = manager.neighbors[client_id]
                        self.assertEqual(link.initiator, client_id)
                        self.assertTrue(manager.neighbor_address_current(link))
                        self.assertFalse(manager.endpoints.get(client_id))
                    finally:
                        await close_stream(writer)
            finally:
                await manager.stop_tasks([server_task])


if __name__ == '__main__':
    unittest.main()
