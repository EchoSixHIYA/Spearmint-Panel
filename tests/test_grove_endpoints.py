from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spearmint.peer.grove_endpoints import GroveEndpoints, GroveMembers


class GroveEndpointsTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.local = 'spm1-' + '1' * 64
        self.remote = 'spm1-' + '2' * 64
        self.endpoints = GroveEndpoints(self.local, self.key)
        self.pair = SimpleNamespace(node_id=self.remote, mesh_id='owned-mesh', enabled=True, legacy=False,
            host='node.mesh.invalid', port=None, bind_ip='172.16.1.2', listen_port=8766, local_pem=b'owned')

    def test_public_member_bootstraps_without_waiting_for_an_endpoint_gossip_round(self):
        trust = GroveMembers('owned', {self.local: 'https://localhost:18443', self.remote: 'https://59.110.115.144:8765'})
        result = self.endpoints.update(trust, {self.remote: self.pair})
        self.assertEqual(result[self.remote], (('59.110.115.144', 8766),))

    def test_loopback_member_has_no_fabricated_lan_destination(self):
        trust = GroveMembers('owned', {self.local: 'https://localhost:18443', self.remote: 'https://localhost:18778'})
        self.assertEqual(self.endpoints.update(trust, {self.remote: self.pair}), {})

    def test_public_member_advertises_its_registered_address_behind_nat(self):
        self.endpoints.update(GroveMembers('owned', {self.local: 'https://59.110.115.144:8765'}), {})
        with patch('spearmint.peer.grove_endpoints.certificate', return_value=SimpleNamespace()), patch('spearmint.peer.grove_endpoints.fingerprint', return_value='a' * 64):
            reply = self.endpoints.page(self.pair, True)
        from spearmint.peer.signed import SignedRecord
        data = SignedRecord.parse(reply['records'][0], limit=1024).payload()
        self.assertEqual((data['ip'], data['port']), ('59.110.115.144', 8766))


if __name__ == '__main__':
    unittest.main()
