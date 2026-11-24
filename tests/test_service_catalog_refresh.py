"""Functional catalog refresh and unchanged identity-lease renewal regressions."""
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from grove_fixture import GroveFixture
from spearmint import grove_availability, grove_continuity, grove_identity_changes, grove_revocation
from spearmint.peer.protocol import PeerError
from spearmint.peer.services import PeerServices


class Renewal:
    renew_grove_snapshot = PeerServices.renew_grove_snapshot

    def __init__(self, fixture):
        self.state = fixture.states[0]
        self.local_id = self.state.identity()[0]
        self.remote = fixture.states[1]
        self.modes = []

    async def work(self, method, *args):
        with self.state.connect(read_only=True) as db:
            self.modes.append((getattr(method, '__name__', 'renew'), grove_availability.status(db)['mode']))
        return method(*args)

    async def call(self, node, method, params, **_):
        if node != self.remote.identity()[0]:
            raise PeerError('OFFLINE', 'Owned fixture is disconnected')
        if method != grove_continuity.MEMBERS_VOTE_METHOD:
            raise AssertionError('Unexpected fixture method: ' + method)
        return grove_continuity.vote(self.remote, self.local_id, params['nonce'], params['anchor'],
                                    params['revocations'], params['passwords'], params['roles'], params['members'])


class Catalog:
    grove_directory = PeerServices.grove_directory

    def __init__(self, result):
        self.result = result

    async def grove_service(self, *_args, **_kwargs):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class ServiceCatalogRefreshTest(unittest.TestCase):
    def test_unchanged_lease_renewal_keeps_ordinary_access_online(self):
        with TemporaryDirectory() as root:
            fixture = GroveFixture(Path(root))
            coordinator = Renewal(fixture)
            self.assertTrue(asyncio.run(coordinator.renew_grove_snapshot((fixture.envelope, fixture.anchor), standby=False)))
            self.assertTrue(coordinator.modes)
            self.assertEqual({mode for _, mode in coordinator.modes}, {'online'})

    def test_actual_identity_change_is_applied_while_synchronizing_then_resumes(self):
        with TemporaryDirectory() as root:
            fixture = GroveFixture(Path(root))
            actor = fixture.login()
            document, _ = grove_revocation.issue(fixture.states[0], actor, fixture.users[1]['id'])
            ballots = [grove_identity_changes.ballot(state, 'revocation', document, fixture.users[0]['id'],
                       fixture.states[0].identity()[0] if index else None) for index, state in enumerate(fixture.states[:2])]
            certified = grove_identity_changes.certify(fixture.states[0], 'revocation', document, ballots)
            grove_revocation.apply(fixture.states[1], [certified], fixture.states[0].identity()[0])
            coordinator = Renewal(fixture)
            self.assertTrue(asyncio.run(coordinator.renew_grove_snapshot((fixture.envelope, fixture.anchor), standby=False)))
            self.assertIn(('apply', 'synchronizing'), coordinator.modes)
            with fixture.states[0].connect(read_only=True) as db:
                self.assertEqual(grove_availability.status(db)['mode'], 'online')
                self.assertEqual(db.execute('SELECT count(*) FROM grove_login_revocation').fetchone()[0], 1)

    def test_failed_catalog_is_incomplete_and_cannot_remove_visible_rows(self):
        directory = {'node_id': 'owned', 'stale': False, 'services': [], 'connection_id': 'session', 'directory_generation': 1}
        result = asyncio.run(Catalog(PeerError('ROUTE_LOST', 'Owned route changed')).grove_directory(SimpleNamespace(grove=True), directory))
        self.assertTrue(result['stale'])
        self.assertFalse(result['catalog_complete'])
        empty = asyncio.run(Catalog({'services': []}).grove_directory(SimpleNamespace(grove=True), directory))
        self.assertFalse(empty['stale'])
        self.assertTrue(empty['catalog_complete'])

    def test_grove_identity_wait_does_not_publish_an_empty_complete_catalog(self):
        directory = {'node_id': 'owned', 'stale': False, 'services': [], 'connection_id': 'session', 'directory_generation': 1}
        grove = asyncio.run(Catalog(None).grove_directory(SimpleNamespace(grove=True), directory))
        self.assertTrue(grove['stale'])
        self.assertFalse(grove['catalog_complete'])
        legacy = asyncio.run(Catalog(None).grove_directory(SimpleNamespace(grove=False), directory))
        self.assertFalse(legacy['stale'])
        self.assertTrue(legacy['catalog_complete'])


if __name__ == '__main__':
    unittest.main()
