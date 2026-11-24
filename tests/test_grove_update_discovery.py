import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from spearmint import grove_updates, update_release
from spearmint.peer.protocol import PeerError, wire_b64


class UpdateDiscoveryTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        public_key = patch.object(update_release, 'RELEASE_PUBLIC_KEY', self.key.public_key().public_bytes_raw())
        public_key.start()
        self.addCleanup(public_key.stop)
        self.previous = self.release(1)
        self.latest = self.release(2)
        self.updates = grove_updates.UpdateCoordinator.__new__(grove_updates.UpdateCoordinator)
        self.updates.local_id = 'local'
        self.updates.github_checked = grove_updates.time.monotonic()
        self.updates.github_catalog = self.previous
        self.updates.check_task = None
        self.updates.catalog = None
        self.updates.cached_seed_release = Mock(return_value=None)
        self.updates.cached_group_release = Mock(return_value=None)
        self.updates.remote = SimpleNamespace(work=AsyncMock(return_value=['local', 'peer-a', 'peer-b']))

    def release(self, sequence):
        index = {
            'sequence': sequence, 'tag': f'v0.4.0-preview.{sequence}', 'version': '0.4.0',
            'commit': f'{sequence:040x}', 'schema': 30,
            'packages': {target: {'sha256': 'a' * 64, 'size': 123} for target in update_release.TARGETS},
        }
        signature = wire_b64(self.key.sign(update_release.signed_bytes(index)))
        packages = {target: {**asset, 'id': 1} for target, asset in index['packages'].items()}
        return update_release.Release.model_validate({**index, 'packages': packages, 'signature': signature})

    async def test_first_manual_check_refreshes_a_recent_catalog(self):
        with patch.object(update_release, 'latest_release', return_value=self.latest) as github:
            self.assertEqual(await self.updates.discover_release(), (self.previous, 'github'))
            result = await self.updates.find_release()
        github.assert_called_once_with()
        self.assertEqual(result, {'source': 'github', 'release': self.latest.model_dump()})
        self.assertEqual(self.updates.catalog, self.latest)

    async def test_concurrent_checks_share_a_github_refresh(self):
        with patch.object(update_release, 'latest_release', return_value=self.latest) as github:
            first, second = await asyncio.gather(self.updates.find_release(), self.updates.find_release())
        github.assert_called_once_with()
        self.assertEqual(first, second)
        self.assertEqual(first['release'], self.latest.model_dump())

    async def test_waits_for_new_catalog_when_github_is_unreachable(self):
        async def ask(node, params):
            if node == 'peer-a':
                return {'pending': False, 'release': self.previous.model_dump()}
            if params.get('refresh'):
                return {'pending': True, 'release': self.previous.model_dump()}
            return {'pending': False, 'release': self.latest.model_dump()}

        self.updates.ask = AsyncMock(side_effect=ask)
        with patch.object(update_release, 'latest_release', side_effect=OSError), \
                patch.object(grove_updates.asyncio, 'sleep', new_callable=AsyncMock):
            result = await self.updates.find_release()
        self.updates.ask.assert_any_await('peer-b', {'action': 'catalog', 'refresh': True})
        self.updates.ask.assert_any_await('peer-b', {'action': 'catalog'})
        self.assertEqual(result, {'source': 'peer-b', 'release': self.latest.model_dump()})

    async def test_preserves_newer_verified_catalog_when_github_returns_an_older_release(self):
        self.updates.cached_seed_release.return_value = self.latest
        with patch.object(update_release, 'latest_release', return_value=self.previous):
            result = await self.updates.find_release()
        self.assertEqual(result, {'source': 'cache', 'release': self.latest.model_dump()})

    async def test_does_not_install_older_offer_over_a_locally_installed_release(self):
        self.updates.verify_source = AsyncMock()
        self.updates.local_status = Mock(return_value=None)
        self.updates.local_path = None
        self.updates.target = 'windows-amd64'
        self.updates.schema = 30
        self.updates.build = {'commit': self.latest.commit, 'version': '0.4.0'}
        self.updates.cached_seed_release.return_value = self.latest
        self.updates.remote.work.return_value = True
        offer = SimpleNamespace(target='local', expires=int(grove_updates.time.time()) + 60, release=self.previous)
        with patch.object(grove_updates.worker, 'read_record', return_value=None):
            result = await self.updates.accept(offer)
        self.assertEqual(result, {'status': 'unsupported', 'reason': 'older_release'})

    async def test_older_peer_can_still_supply_a_signed_catalog(self):
        response = {'pending': False, 'release': self.latest.model_dump()}
        self.updates.remote.call = AsyncMock(side_effect=[PeerError('INVALID_REQUEST', 'Unknown request'), response])
        result = await self.updates.ask('peer-a', {'action': 'catalog', 'refresh': True})
        self.assertEqual(result, response)
        self.updates.remote.call.assert_awaited_with('peer-a', grove_updates.METHOD, {'action': 'catalog'}, diagnostic=True)


class GitHubReleaseListTest(unittest.TestCase):
    def test_release_list_revalidates_through_the_http_cache(self):
        with patch.object(update_release, 'build_opener') as opener, \
                patch.object(update_release.time, 'time_ns', side_effect=[101, 102]):
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'[]'
            self.assertIsNone(update_release.latest_release())
            self.assertIsNone(update_release.latest_release())
        requests = [call.args[0] for call in opener.return_value.open.call_args_list]
        self.assertEqual([request.full_url for request in requests],
                         [f'{update_release.API}/releases?per_page=10&_={timestamp}' for timestamp in (101, 102)])
        self.assertTrue(all(request.get_header('Cache-control') == 'no-cache' for request in requests))
