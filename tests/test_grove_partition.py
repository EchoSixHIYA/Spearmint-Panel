"""Functional partition, quorum-change and recovery checks; no live node probes."""
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from grove_fixture import GroveFixture
from spearmint import auth, grove, grove_availability, grove_continuity, grove_identity_changes, grove_login, grove_password, grove_revocation
from spearmint.peer.grove_endpoints import trusted_members
from spearmint.peer.grove_service_admin import source_identity
from spearmint.peer.protocol import PeerError
from spearmint.peer.services import PeerServices
from spearmint import grove_roles


class Coordinator:
    approve_identity_change = PeerServices.approve_identity_change
    revoke_grove_operator = PeerServices.revoke_grove_operator
    change_grove_password = PeerServices.change_grove_password
    approve_grove_role = PeerServices.approve_grove_role

    def __init__(self, fixture, reachable):
        self.state = fixture.states[0]
        self.local_id = self.state.identity()[0]
        self.nodes = {state.identity()[0]: state for state in fixture.states[1:reachable + 1]}
        self.calls = []

    async def work(self, method, *args):
        return method(*args)

    async def call(self, node, method, params, **_):
        self.calls.append(method)
        if node not in self.nodes:
            raise PeerError('OFFLINE', 'Owned fixture link is disconnected')
        state = self.nodes[node]
        if method == grove_identity_changes.METHOD:
            return grove_identity_changes.ballot(state, params['kind'], params['document'], params['actor'], self.local_id)
        if method == grove_revocation.APPLY:
            count = grove_revocation.apply(state, [params['revocation']], self.local_id)
        elif method == grove_password.APPLY:
            count = grove_password.apply(state, [params['change']], self.local_id)
        elif method == grove_roles.APPLY_METHOD:
            count = grove_roles.apply(state, [params['certificate']], self.local_id)
        else:
            raise AssertionError('Unexpected operation RPC: ' + method)
        return {'accepted': True, 'applied': count}

    async def request_grove_sync(self):
        pass


class GrovePartitionTest(unittest.TestCase):
    def setUp(self):
        root = Path.cwd() / 'work/tmp/grove-offline-policy/tests'
        root.mkdir(parents=True, exist_ok=True)
        self.temp = TemporaryDirectory(dir=root)
        self.fixture = GroveFixture(Path(self.temp.name))
        self.state = self.fixture.states[0]

    def tearDown(self):
        grove_availability.synchronize(self.state, 'functional-sync', False)
        self.temp.cleanup()

    def certificate(self, kind, document, actor):
        votes = [grove_identity_changes.ballot(state, kind, document, actor, self.state.identity()[0] if i else None)
                 for i, state in enumerate(self.fixture.states[:2])]
        return grove_identity_changes.certify(self.state, kind, document, votes)

    def test_partition_allows_existing_login_and_service_identity_with_hard_deadline(self):
        self.fixture.expire_freshness()
        actor = self.fixture.login()
        self.assertIsNotNone(actor)
        self.assertEqual(source_identity(self.state, self.state.identity()[0], None, actor)[1], self.fixture.users[0]['id'])
        with self.state.connect(read_only=True) as db:
            access = grove_availability.status(db)
            self.assertEqual(access['mode'], 'offline')
            self.assertFalse(access['identity_changes'])
            self.assertIsNone(trusted_members(db, self.state.identity()[0]))
            self.assertIsNotNone(trusted_members(db, self.state.identity()[0], operational=True))
            self.assertEqual(access['offline_until'], self.fixture.now - 600 - grove.DIRECTORY_TTL + 12 * 3600)
            self.assertIsNone(grove_login.usable_replica(db, int(time.time())))
            self.assertIsNotNone(grove_login.usable_replica(db, int(time.time()), operational=True))
            deadline = access['offline_until']
        with patch('time.time', return_value=deadline):
            with self.state.connect(read_only=True) as db:
                self.assertFalse(grove_availability.ordinary(db))
                self.assertIsNone(auth.active_session(db, actor.token_hash, deadline))

    def test_offline_identity_changes_wait_without_writing(self):
        self.fixture.expire_freshness()
        actor = self.fixture.login()
        with self.assertRaises(PeerError) as error:
            grove_revocation.issue(self.state, actor, self.fixture.users[1]['id'])
        self.assertEqual(error.exception.code, 'GROVE_QUORUM_REQUIRED')
        with self.assertRaises(PeerError):
            grove_password.issue(self.state, actor, self.fixture.password, 'replacement-password')
        with self.state.connect(read_only=True) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grove_login_password').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM grove_login_revocation').fetchone()[0], 0)

    def test_password_and_suspension_commit_only_after_majority(self):
        actor = self.fixture.login()
        operator = self.fixture.login(username='operator')
        document, voters = grove_revocation.issue(self.state, actor, self.fixture.users[1]['id'])
        with self.state.connect(read_only=True) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grove_login_revocation').fetchone()[0], 0)
        own = grove_identity_changes.ballot(self.state, 'revocation', document, self.fixture.users[0]['id'])
        with self.assertRaises(PeerError):
            grove_identity_changes.certify(self.state, 'revocation', document, [own])
        certified = self.certificate('revocation', document, self.fixture.users[0]['id'])
        self.assertEqual(grove_revocation.apply(self.state, [certified], self.state.identity()[0]), 1)
        with self.state.connect(read_only=True) as db:
            self.assertIsNone(auth.active_session(db, operator.token_hash, int(time.time())))
        password, _ = grove_password.issue(self.state, actor, self.fixture.password, 'replacement-password')
        with self.state.connect(read_only=True) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grove_login_password').fetchone()[0], 0)
        password = self.certificate('password', password, self.fixture.users[0]['id'])
        grove_password.apply(self.state, [password], self.state.identity()[0])
        with self.state.connect(read_only=True) as db:
            self.assertIsNone(auth.active_session(db, actor.token_hash, int(time.time())))

    def test_rejoin_applies_revocation_then_renews_without_extending_on_login(self):
        actor = self.fixture.login()
        document, _ = grove_revocation.issue(self.state, actor, self.fixture.users[1]['id'])
        certified = self.certificate('revocation', document, self.fixture.users[0]['id'])
        for state in self.fixture.states[:2]:
            grove_revocation.apply(state, [certified], self.state.identity()[0])
        isolated = self.fixture.states[2]
        with isolated.connect(write=True) as db:
            db.execute('UPDATE grove_login_continuity SET lease_until=?', (self.fixture.now - 600,))
        session = self.fixture.login(index=2, username='operator')
        with isolated.connect(read_only=True) as db:
            before = db.execute('SELECT lease_until FROM grove_login_continuity').fetchone()[0]
        grove_availability.synchronize(isolated, 'functional-sync', True)
        with isolated.connect(read_only=True) as db:
            self.assertEqual(grove_availability.status(db)['mode'], 'synchronizing')
            self.assertIsNotNone(auth.active_session(db, session.token_hash, int(time.time())))
        grove_revocation.apply(isolated, [certified], self.state.identity()[0])
        nonce = 'f' * 32
        digest = grove_continuity.anchor_digest(self.fixture.envelope)
        votes = {}
        for state in self.fixture.states[:2]:
            with isolated.connect(read_only=True) as db:
                revocations = grove_continuity.revocation_digest(db, digest)
                passwords = grove_continuity.password_digest(db, digest)
                roles = grove_continuity.role_digest(grove_continuity.role_versions(db))
                members = grove_continuity.admission_digest(grove_continuity.admission_versions(db))
            reply = grove_continuity.vote(state, isolated.identity()[0], nonce, digest, revocations, passwords, roles, members)
            votes[state.identity()[0]] = reply['ballot']
        self.assertTrue(grove_continuity.renew(isolated, self.fixture.envelope, nonce, votes))
        grove_availability.synchronize(isolated, 'functional-sync', False)
        with isolated.connect(read_only=True) as db:
            self.assertEqual(grove_availability.status(db)['mode'], 'online')
            self.assertIsNone(auth.active_session(db, session.token_hash, int(time.time())))
            self.assertGreater(db.execute('SELECT lease_until FROM grove_login_continuity').fetchone()[0], before)

    def test_coordinator_waits_for_majority_before_any_local_change(self):
        actor = self.fixture.login()
        coordinator = Coordinator(self.fixture, 0)
        with self.assertRaises(PeerError):
            asyncio.run(coordinator.revoke_grove_operator(actor, self.fixture.users[1]['id']))
        with self.state.connect(read_only=True) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grove_login_revocation').fetchone()[0], 0)
        coordinator = Coordinator(self.fixture, 1)
        result = asyncio.run(coordinator.revoke_grove_operator(actor, self.fixture.users[1]['id']))
        self.assertEqual(result, {'confirmed': 2, 'members': 3})
        self.assertTrue(all(method.startswith('grove.') for method in coordinator.calls))

    def test_role_change_collects_votes_automatically(self):
        actor = self.fixture.login()
        coordinator = Coordinator(self.fixture, 1)
        result = asyncio.run(coordinator.approve_grove_role(actor, self.fixture.users[1]['id'], 'node_admin'))
        self.assertTrue(result['applied'])
        with self.state.connect(read_only=True) as db:
            self.assertEqual(db.execute('SELECT role FROM grove_login_role WHERE user_id=?',
                                       (self.fixture.users[1]['id'],)).fetchone()[0], 'node_admin')

    def test_role_update_is_checked_by_each_approving_voter(self):
        actor = self.fixture.login()
        pending, _ = grove_revocation.issue(self.state, actor, self.fixture.users[1]['id'])
        coordinator = Coordinator(self.fixture, 1)
        asyncio.run(coordinator.approve_grove_role(actor, self.fixture.users[1]['id'], 'node_admin'))
        with self.assertRaises(PeerError) as error:
            grove_identity_changes.ballot(self.fixture.states[1], 'revocation', pending,
                self.fixture.users[0]['id'], self.state.identity()[0])
        self.assertEqual(error.exception.code, 'CONFLICT')


if __name__ == '__main__':
    unittest.main()
