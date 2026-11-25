"""Functional account lifecycle against an isolated, retired-issuer Grove."""
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from pyotp import TOTP

from spearmint import auth, factors, grove, grove_accounts, grove_continuity, grove_login
from spearmint.grove_account_service import GroveAccountService
from spearmint.peer.grove_service_admin import source_identity
from spearmint.peer.pairing import configured
from spearmint.peer.protocol import PeerError
from spearmint.peer.services import PeerServices
from test_grove_voters import VoterFixture


class AccountLink:
    renew_grove_snapshot = PeerServices.renew_grove_snapshot
    grove_continuity_vote = PeerServices.grove_continuity_vote

    def __init__(self, state, network):
        self.state = state
        self.local_id = state.identity()[0]
        self.network = network
        self.grove_accounts = GroveAccountService(state, self)

    async def work(self, method, *args, **kwargs):
        return method(*args)

    async def call(self, node, method, params, **kwargs):
        target = self.network.get(node)
        if not target:
            raise PeerError('OFFLINE', 'Owned fixture link is disconnected')
        with target.state.connect(read_only=True) as db:
            pair = configured(db, self.local_id)
        if method == grove_accounts.METHOD:
            return target.grove_accounts.dispatch(pair, params)
        if method == grove_continuity.ACCOUNTS_VOTE_METHOD:
            return target.grove_continuity_vote(pair, params, method)
        raise AssertionError('Unexpected account method ' + method)

    async def request_grove_sync(self):
        pass

    async def sync(self):
        with self.state.connect(read_only=True) as db:
            current = grove_continuity.read_anchor(db)
        return await self.renew_grove_snapshot(current, standby=False)


class GroveAccountTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        root = Path.cwd() / 'work/tmp/grove-accounts/tests'
        root.mkdir(parents=True, exist_ok=True)
        temp = TemporaryDirectory(dir=root)
        self.addCleanup(temp.cleanup)
        self.fixture = VoterFixture(Path(temp.name))
        self.network = {}
        self.links = [AccountLink(state, self.network) for state in self.fixture.all_states]
        self.network.update((link.local_id, link) for link in self.links)
        self.one, self.two, self.three, self.member = self.links
        self.admin = self.fixture.login()

    async def test_invite_register_and_sync_with_one_voter_offline(self):
        self.network.pop(self.three.local_id)
        invite = await self.one.grove_accounts.run('invite', 'invitee', 'fixture', role='remote_operator', actor=self.admin)
        users = grove.describe(self.two.state, private=True)['users']
        self.assertTrue(next(user for user in users if user['name'] == 'invitee')['pending'])
        secret, _ = factors.new_totp('invitee', 'Grove')
        code = TOTP(secret).now()
        password = 'invitee-chosen-password'
        registered = await self.two.grove_accounts.run('register', 'invitee', 'fixture', code=invite['code'],
                                                        password=password, totp=secret, otp=code)
        self.assertIn('recovery_code', registered)
        with self.assertRaises(PeerError) as error:
            await self.two.grove_accounts.run('register', 'invitee', 'fixture', code=invite['code'],
                                              password=password, totp=secret, otp=code)
        self.assertEqual(error.exception.code, 'DENIED')

        # A non-voter and a returning voter fetch the latest certified account
        # through the normal lease renewal rather than receiving the original invite.
        self.network[self.three.local_id] = self.three
        self.assertTrue(await self.three.sync())
        self.assertTrue(await self.member.sync())
        self.assertIsNotNone(grove_login.login(self.member.state, 'invitee', password, code, 'fixture'))
        with self.one.state.connect(read_only=True) as db:
            snapshot = grove_continuity.snapshot(self.one.state, db, self.fixture.realm['id'], self.member.local_id)
        self.assertEqual([entry['profile']['name'] for entry in snapshot['records']], ['admin', 'operator'])
        with self.one.state.connect(write=True) as db:
            db.execute('DELETE FROM grove_login_verifier')
            grove_login.import_snapshot(self.one.state, db, self.fixture.directory, snapshot['records'],
                                        self.fixture.anchor['verifiers_sha256'])
        self.assertIsNotNone(grove_login.login(self.one.state, 'invitee', password, code, 'fixture'))

    async def test_admin_creation_assisted_and_self_service_reset(self):
        result = await self.one.grove_accounts.run('create', 'second-admin', 'fixture', role='node_admin',
                                                    password='temporary-admin-password', actor=self.admin)
        secret = parse_qs(urlsplit(result['provisioning_uri']).query)['secret'][0]
        session = grove_login.login(self.two.state, 'second-admin', 'temporary-admin-password', TOTP(secret).now(), 'fixture')
        self.assertIsNotNone(session)
        second_admin = auth.actor_for(self.two.state, session[0], 'fixture')
        self.assertIsNotNone(source_identity(self.two.state, self.two.local_id, None, second_admin))
        assistance = await self.two.grove_accounts.run('assist', 'admin', 'fixture', actor=second_admin)
        reset = await self.two.grove_accounts.run('reset', 'admin', 'fixture', code=assistance['code'],
                                                   password='new-fixture-password')
        with self.one.state.connect(read_only=True) as db:
            self.assertIsNone(auth.active_session(db, self.admin.token_hash, int(time.time())))
        self.assertIsNone(grove_login.login(self.three.state, 'admin', self.fixture.password, TOTP(self.fixture.secret).now(), 'fixture'))
        own_reset = await self.three.grove_accounts.run('reset', 'admin', 'fixture', code=reset['recovery_code'],
                                                         password='second-new-fixture-password')
        self.assertNotEqual(reset['recovery_code'], own_reset['recovery_code'])
        self.assertIsNotNone(grove_login.login(self.three.state, 'admin', 'second-new-fixture-password',
                                              TOTP(self.fixture.secret).now(), 'fixture'))
        for code in (assistance['code'], reset['recovery_code']):
            with self.assertRaises(PeerError) as error:
                await self.one.grove_accounts.run('reset', 'admin', 'fixture', code=code, password='third-new-fixture-password')
            self.assertEqual(error.exception.code, 'DENIED')

    async def test_recovery_code_can_be_generated_for_existing_grove_account(self):
        code = await self.one.grove_accounts.run('recovery-code', 'admin', 'fixture',
                                                  actor=self.admin, current_password=self.fixture.password)
        self.assertIn('recovery_code', code)
        await self.two.grove_accounts.run('reset', 'admin', 'fixture', code=code['recovery_code'],
                                           password='existing-admin-new-password')
        self.assertIsNotNone(grove_login.login(self.three.state, 'admin', 'existing-admin-new-password',
                                              TOTP(self.fixture.secret).now(), 'fixture'))

    async def test_quorum_loss_leaves_account_unchanged(self):
        self.network.pop(self.two.local_id)
        self.network.pop(self.three.local_id)
        with self.assertRaises(PeerError) as error:
            await self.one.grove_accounts.run('invite', 'waiting', 'fixture', role='remote_operator', actor=self.admin)
        self.assertEqual(error.exception.code, 'GROVE_QUORUM_REQUIRED')
        with self.one.state.connect(read_only=True) as db:
            self.assertEqual(grove_accounts.versions(db), {})
