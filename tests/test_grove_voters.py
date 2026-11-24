"""Owned, in-memory link fixtures for voter lifecycle and interrupted changes."""
import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from grove_fixture import GroveFixture
from spearmint import grove, grove_admission, grove_continuity, grove_identity_changes, grove_login, grove_password, grove_voters, mesh_enrollment
from spearmint.state import State
from spearmint.config import Config
from spearmint.grove_voter_service import VoterService
from spearmint.peer.credentials import ca_certificate, make_csr, sign_csr, fingerprint
from spearmint.peer.grove_service_admin import admin_revision
from spearmint.peer.pairing import add_member, configure_mesh, configured, set_neighbor, set_enabled
from spearmint.peer.protocol import PeerError
from spearmint.state import State


class VoterFixture(GroveFixture):
    def __init__(self, root):
        super().__init__(root)
        self.new = State(root / 'new-member')
        self.new.initialize(lambda: self.password_hash)
        node = self.new.identity()[0]
        origin = 'https://new-member.example:18443'
        ballots = []
        for state in self.states[:2]:
            with state.connect(write=True) as db:
                ballots.append(grove_admission.record_ballot(db, state, node, origin,
                    self.envelope, self.anchor, self.users[0]['id'], 'owned'))
        self.admission = ballots
        for state in self.states:
            with state.connect(write=True) as db:
                grove_admission.admit(db, ballots, self.anchor, self.envelope, 'owned')
        source = self.states[0]
        with source.connect(read_only=True) as db:
            snapshot = grove_continuity.snapshot(source, db, self.realm['id'], node)
        grove_admission.join(self.new, None, origin, {'realm': self.realm, 'snapshot': snapshot, 'certificate': ballots},
                             source.identity()[0], lambda db: None, seed_certificate=ballots)
        with self.new.connect(write=True) as db:
            db.execute('UPDATE grove_login_continuity SET lease_until=?', (self.now + 300,))
        self.all_states = self.states + [self.new]
        ca_key = Ed25519PrivateKey.generate()
        ca = ca_certificate(ca_key)
        leaves = {}
        entries = []
        for index, state in enumerate(self.all_states):
            local = state.identity()[0]
            host = mesh_enrollment.subject_name(local)
            leaf = sign_csr(make_csr(state.signing_key(), host), ca_key, ca, local, host)
            leaves[local] = leaf
            configure_mesh(state, 'b' * 32, f'192.168.56.{index + 10}', 8766,
                ca.public_bytes(Encoding.PEM), leaf.public_bytes(Encoding.PEM))
            if state is not self.new:
                authority = mesh_enrollment.initialize_signer(state).read_text()
                entries.append({'node_id': local, 'origin': self.directory['members'][0]['origin'], 'host': host,
                    'address': f'192.168.56.{index + 10}', 'port': 8766, 'leaf': leaf.public_bytes(Encoding.PEM).decode(), 'ca': authority})
                with state.connect(read_only=True) as db:
                    entries[-1]['origin'] = db.execute('SELECT origin FROM grove_member WHERE node_id=?', (local,)).fetchone()[0]
        self.core = {'realm_id': self.realm['id'], 'mesh_id': 'b' * 32, 'legacy_ca': ca.public_bytes(Encoding.PEM).decode(),
                     'voters': sorted(entries, key=lambda item: item['node_id'])}
        for index, state in enumerate(self.all_states):
            (state.directory / mesh_enrollment.POLICY_FILE).write_text(json.dumps({'policy': self.core,
                'bind_ip': f'192.168.56.{index + 10}', 'trusted_proxy': False}))
            for other in self.all_states:
                if other is state:
                    continue
                leaf = leaves[other.identity()[0]]
                add_member(state, other.identity()[0], mesh_enrollment.subject_name(other.identity()[0]), fingerprint(leaf), leaf.public_bytes(Encoding.PEM))
                set_neighbor(state, other.identity()[0], '192.168.56.99')
                set_enabled(state, True, node_id=other.identity()[0])
        self.services = {}
        self.reachable = {state.identity()[0] for state in self.all_states}
        for index, state in enumerate(self.all_states):
            local = state.identity()[0]
            remote = SimpleNamespace(state=state, local_id=local, grove_sync_requested=asyncio.Event())
            async def work(fn, *args, **kw):
                return fn(*args)
            async def call(node, method, params, _local=local, **kw):
                if node not in self.reachable or _local not in self.reachable:
                    raise PeerError('OFFLINE', 'Owned link disconnected')
                target = self.services[node]
                with target.state.connect(read_only=True) as db:
                    pair = configured(db, _local)
                return target.handle(pair, params)
            remote.work, remote.call = work, call
            self.services[local] = VoterService(state, remote, SimpleNamespace(mesh_advertise_ip=None, mesh_advertise_port=None))
        with self.states[0].connect(read_only=True) as db:
            self.identity = admin_revision(db, self.realm['id'], self.users[0]['id'])

    def service(self, index=0):
        return self.services[self.all_states[index].identity()[0]]

    def renew_all(self):
        for state in self.all_states:
            with state.connect(write=True) as db:
                db.execute('UPDATE grove_login_continuity SET lease_until=?', (int(time.time()) + 300,))


class GroveVoterTest(unittest.TestCase):
    def setUp(self):
        root = Path.cwd() / 'work/tmp/grove-voters/tests'
        root.mkdir(parents=True, exist_ok=True)
        self.temp = TemporaryDirectory(dir=root)
        self.f = VoterFixture(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_promote_and_demote_with_joint_majority_and_historical_admission(self):
        f = self.f
        target = f.new.identity()[0]
        self.assertTrue(asyncio.run(f.service().change(target, True, f.identity)))
        for state in f.all_states:
            result = grove_voters.status(state)
            self.assertEqual(result['version'], 1)
            self.assertIn(target, result['voters'])
            self.assertEqual(len(mesh_enrollment.load_policy(state).voters), 4)
            with state.connect(read_only=True) as db:
                current = grove_continuity.read_anchor(db)
                self.assertEqual(grove_admission.validate_certificate(f.admission, current[1], grove_continuity.anchor_digest(current[0]))[0], target)
        f.renew_all()
        removed = f.states[2].identity()[0]
        self.assertTrue(asyncio.run(f.service().change(removed, False, f.identity)))
        for state in f.all_states:
            self.assertNotIn(removed, grove_voters.status(state)['voters'])
            self.assertEqual(len(mesh_enrollment.load_policy(state).voters), 3)
        f.renew_all()
        with f.states[0].connect(read_only=True) as db:
            self.assertIsNotNone(grove_continuity.retirement_document(db, f.realm['id'], removed))

    def test_offline_member_catches_up_without_issuer(self):
        f = self.f
        offline = f.states[2].identity()[0]
        f.reachable.remove(offline)
        self.assertTrue(asyncio.run(f.service().change(f.new.identity()[0], True, f.identity)))
        self.assertEqual(grove_voters.status(f.states[2])['version'], 0)
        f.reachable.add(offline)
        asyncio.run(f.service(2).synchronize())
        self.assertEqual(grove_voters.status(f.states[2])['version'], 1)

    def test_missing_majority_keeps_original_roster(self):
        f = self.f
        f.reachable = {f.states[0].identity()[0], f.new.identity()[0]}
        with self.assertRaises(PeerError) as error:
            asyncio.run(f.service().change(f.new.identity()[0], True, f.identity))
        self.assertEqual(error.exception.code, 'GROVE_QUORUM_REQUIRED')
        self.assertEqual(grove_voters.status(f.states[0])['version'], 0)

    def test_another_member_completes_accepted_change_after_sponsor_leaves(self):
        f = self.f
        service = f.service()
        gather = service.gather
        async def interrupted(nodes, params):
            if params['action'] == 'apply':
                raise RuntimeError('Owned coordinator stopped after acceptance')
            return await gather(nodes, params)
        service.gather = interrupted
        with self.assertRaises(RuntimeError):
            asyncio.run(service.change(f.new.identity()[0], True, f.identity))
        f.reachable.remove(f.states[0].identity()[0])
        replacement = f.service(1)
        replacement.recover_request()
        self.assertTrue(asyncio.run(replacement.change(f.new.identity()[0], True, f.identity)))
        self.assertEqual(grove_voters.status(f.states[1])['version'], 1)
        f.reachable.add(f.states[0].identity()[0])
        service.gather = gather
        asyncio.run(service.synchronize())
        self.assertEqual(grove_voters.status(f.states[0])['version'], 1)

    def test_invitation_and_new_member_join_after_promotion(self):
        from spearmint import grove_quorum_join
        f = self.f
        self.assertTrue(asyncio.run(f.service().change(f.new.identity()[0], True, f.identity)))
        f.renew_all()
        code = grove_quorum_join.invitation(f.states[0], mesh_enrollment.load_policy(f.states[0]))
        _, _, anchor, policy = grove_quorum_join.read_invitation(code)
        self.assertEqual(len(anchor['voters']), 4)
        self.assertEqual(len(policy.voters), 4)
        incoming = State(Path(self.temp.name) / 'incoming')
        incoming.initialize(lambda: f.password_hash)
        origin = 'https://incoming.example:18443'
        certificate = []
        for state in f.states:
            with state.connect(write=True) as db:
                current = grove_continuity.read_anchor(db)
                certificate.append(grove_admission.record_ballot(db, state, incoming.identity()[0], origin,
                    *current, f.users[0]['id'], 'owned'))
        for state in f.all_states:
            with state.connect(write=True) as db:
                grove_admission.admit(db, certificate, anchor, f.envelope, 'owned')
        with f.new.connect(read_only=True) as db:
            snapshot = grove_continuity.snapshot(f.new, db, f.realm['id'], incoming.identity()[0])
        grove_admission.join(incoming, None, origin, {'realm': f.realm, 'snapshot': snapshot, 'certificate': certificate},
                             f.new.identity()[0], lambda db: None, seed_certificate=certificate)
        self.assertEqual(grove_voters.status(incoming)['version'], 1)
        with incoming.connect(read_only=True) as db:
            self.assertTrue(db.execute('SELECT enabled FROM grove_member WHERE node_id=?', (f.new.identity()[0],)).fetchone()[0])

    def test_demoted_new_member_keeps_membership_and_existing_certificates(self):
        f = self.f
        target = f.new.identity()[0]
        self.assertTrue(asyncio.run(f.service().change(target, True, f.identity)))
        f.renew_all()
        before = mesh_enrollment.load_policy(f.states[0]).roots_pem()
        self.assertTrue(asyncio.run(f.service().change(target, False, f.identity)))
        f.renew_all()
        self.assertNotIn(target, mesh_enrollment.load_policy(f.new).voters)
        with f.new.connect(read_only=True) as db:
            current = grove_continuity.read_anchor(db)
            self.assertTrue(grove_continuity.admitted(db, current[1], target))
            self.assertTrue(db.execute('SELECT enabled FROM grove_member WHERE node_id=?', (target,)).fetchone()[0])
        after = mesh_enrollment.load_policy(f.states[0]).roots_pem()
        from cryptography import x509
        self.assertEqual({fingerprint(c) for c in x509.load_pem_x509_certificates(before)},
                         {fingerprint(c) for c in x509.load_pem_x509_certificates(after)})

    def test_minimum_voter_count_does_not_change_membership(self):
        with self.assertRaises(PeerError) as error:
            asyncio.run(self.f.service().change(self.f.states[2].identity()[0], False, self.f.identity))
        self.assertEqual(error.exception.code, 'GROVE_VOTER_LIMIT')

    def test_promoted_voter_can_change_password_and_history_survives_its_demotion(self):
        from pyotp import TOTP
        from spearmint import auth
        f = self.f
        target = f.new.identity()[0]
        self.assertTrue(asyncio.run(f.service().change(target, True, f.identity)))
        f.renew_all()
        token, _ = grove_login.login(f.new, 'admin', f.password, TOTP(f.secret).now(), '127.0.0.1')
        actor = auth.actor_for(f.new, token, '127.0.0.1')
        document, _ = grove_password.issue(f.new, actor, f.password, 'new-voter-fixture-password')
        ballots = [grove_identity_changes.ballot(state, 'password', document, f.users[0]['id'], target)
                   for state in f.states]
        document = grove_identity_changes.certify(f.new, 'password', document, ballots)
        for state in f.all_states:
            grove_password.apply(state, [document], target)
        with f.new.connect(read_only=True) as db:
            identity = admin_revision(db, f.realm['id'], f.users[0]['id'])
        self.assertTrue(asyncio.run(f.service().change(target, False, identity)))
        f.renew_all()
        for state in f.all_states:
            self.assertFalse(grove_password.apply(state, [document], f.states[0].identity()[0]))

    def test_restore_keeps_committed_roster_promises_and_signer_backup(self):
        from spearmint.maintenance import backup, restore, verify_backup
        f = self.f
        state = f.states[0]
        directory = Path(self.temp.name)
        snapshot = directory / 'before-membership'
        backup(state, snapshot)
        self.assertEqual(verify_backup(snapshot)['node_id'], state.identity()[0])
        self.assertIn(mesh_enrollment.SIGNING_KEY, json.loads((snapshot / 'manifest.json').read_text())['extra_files'])
        self.assertTrue(asyncio.run(f.service().change(f.new.identity()[0], True, f.identity)))
        f.renew_all()
        service = f.service()
        gather = service.gather
        async def stop_before_apply(nodes, params):
            if params['action'] == 'apply':
                raise RuntimeError('Owned coordinator stopped before persistence')
            return await gather(nodes, params)
        service.gather = stop_before_apply
        with self.assertRaises(RuntimeError):
            asyncio.run(service.change(f.new.identity()[0], False, f.identity))
        restore(state, snapshot, directory / 'save-current')
        with state.connect(read_only=True) as db:
            self.assertEqual(db.execute('SELECT max(version) FROM grove_voter_configuration').fetchone()[0], 1)
            self.assertIsNotNone(db.execute('SELECT proposal FROM grove_voter_ballot WHERE version=2').fetchone()[0])
        self.assertEqual((state.directory / mesh_enrollment.SIGNING_KEY).read_bytes(),
                         (snapshot / mesh_enrollment.SIGNING_KEY).read_bytes())

    def test_existing_password_survives_configuration_change(self):
        f = self.f
        actor = f.login()
        change, _ = grove_password.issue(f.states[0], actor, f.password, 'replacement-fixture-password')
        approvals = [grove_identity_changes.ballot(state, 'password', change, f.users[0]['id'], f.states[0].identity()[0] if index else None)
                     for index, state in enumerate(f.states[:2])]
        change = grove_identity_changes.certify(f.states[0], 'password', change, approvals)
        for state in f.all_states:
            grove_password.apply(state, [change], f.states[0].identity()[0])
        with f.states[0].connect(read_only=True) as db:
            identity = admin_revision(db, f.realm['id'], f.users[0]['id'])
        self.assertTrue(asyncio.run(f.service().change(f.new.identity()[0], True, identity)))
        f.renew_all()
        for state in f.all_states:
            grove_password.apply(state, [change], f.states[0].identity()[0])
        f.renew_all()
        nonce = '1' * 32
        with f.new.connect(read_only=True) as db:
            current = grove_continuity.read_anchor(db)
        vote = grove_continuity.vote(f.new, f.states[0].identity()[0], nonce, grove_continuity.anchor_digest(current[0]),
                                    '', '', '', '')
        self.assertIn('configuration', json.loads(__import__('base64').urlsafe_b64decode(vote['ballot']['record'] + '==')))


if __name__ == '__main__':
    unittest.main()
