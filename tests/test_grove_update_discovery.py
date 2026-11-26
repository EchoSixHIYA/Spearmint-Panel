import asyncio
from pathlib import Path
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
        self.updates.root = Path('fixture')
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

    async def test_older_panel_can_confirm_current_version_during_rolling_upgrade(self):
        old = SimpleNamespace(node_id='existing-member')
        self.updates.local_path = 'local.json'
        self.updates.target = 'windows-amd64'
        self.updates.build = {'commit': self.latest.commit}
        self.updates.verify_source = AsyncMock(side_effect=PeerError('GROVE_USER_AUTHORIZATION_REQUIRED', 'sign first'))
        offer = SimpleNamespace(job='a' * 32, target='local', release=self.latest,
                                expires=int(grove_updates.time.time()) + 60, identity=['realm', 'user', 1, 0, 0])
        with patch.object(grove_updates.worker, 'read_record', return_value=None), \
                patch.object(grove_updates.worker, 'write_record') as saved:
            current = await self.updates.accept(offer, old)
            self.assertEqual(current, {'status': 'succeeded', 'reason': 'already_current'})
            self.updates.remote.work.assert_any_await(self.updates.authorize_member, old, rpc=True)
            self.updates.verify_source.assert_not_awaited()
            self.updates.build['commit'] = self.previous.commit
            with self.assertRaises(PeerError):
                await self.updates.accept(offer, old)
        saved.assert_not_called()

    async def test_outdated_recipient_is_reported_without_retrying_the_offer(self):
        self.updates.remote.call = AsyncMock(side_effect=[
            PeerError('INVALID_REQUEST', 'Legacy update protocol'),
            {'pending': False, 'release': self.latest.model_dump()},
        ])
        result = await self.updates.ask('peer-a', {'action': 'offer', 'intent': {'identity': {'grant': 'fixture'}}})
        self.assertEqual(result, {'status': 'unsupported', 'reason': 'upgrade_from_older_panel'})
        self.assertEqual([call.args[2]['action'] for call in self.updates.remote.call.await_args_list], ['offer', 'catalog'])

    async def test_reports_the_selected_supplier_and_clears_it_before_trying_another(self):
        asset = self.latest.packages['windows-amd64']
        self.updates.ask = AsyncMock(return_value={'ready': True})
        self.updates.transfer = AsyncMock(side_effect=[False, True])
        report = Mock()

        self.assertTrue(await self.updates.from_members(asset, wait_for_sources=False, on_transfer=report))
        suppliers = [entry.args[0] for entry in self.updates.transfer.await_args_list]
        self.assertEqual({*suppliers}, {'peer-a', 'peer-b'})
        self.assertEqual([entry.args[0] for entry in report.call_args_list], [suppliers[0], None, suppliers[1]])

    async def test_group_receipt_uses_the_actual_supplier_when_reported(self):
        origin = 'spm1-' + '0' * 64
        supplier = 'spm1-' + '1' * 64
        receiving = 'spm1-' + '2' * 64
        legacy = 'spm1-' + '3' * 64
        finished = 'spm1-' + '4' * 64
        self.updates.local_id = origin
        self.updates.group_path = 'group.json'
        self.updates.remote.work.return_value = [origin, supplier, receiving, legacy, finished]
        self.updates.prepare_group_archives = Mock()
        batch = {'job': 'a' * 32, 'release': self.latest.model_dump(), 'identity': [],
                 'expires': int(grove_updates.time.time()) + 60,
                 'nodes': {origin: {'status': 'succeeded'}, supplier: {'status': 'succeeded'},
                           receiving: {'status': 'queued'}, legacy: {'status': 'queued'}, finished: {'status': 'queued'}}}
        self.updates.ask = AsyncMock(side_effect=lambda node, _: {
            receiving: {'status': 'downloading', 'reason': 'fetching_from_grove',
                        'source_node': origin, 'package_source_node': supplier},
            legacy: {'status': 'downloading', 'reason': 'fetching_from_grove', 'source_node': origin},
            finished: {'status': 'installing', 'package_source_node': supplier},
        }[node])

        with patch.object(grove_updates.worker, 'read_record', return_value=batch), \
                patch.object(grove_updates.worker, 'write_record') as saved:
            await self.updates.tick_group()
            receipt = self.updates.group_status()['nodes']
        saved.assert_called_once()
        self.assertEqual(receipt[receiving]['package_source_node'], supplier)
        self.assertNotIn('package_source_node', receipt[legacy])
        self.assertNotIn('package_source_node', receipt[finished])

    async def test_local_receipt_clears_the_supplier_when_installation_starts(self):
        origin = 'spm1-' + '0' * 64
        supplier = 'spm1-' + '1' * 64
        self.updates.local_id = 'spm1-' + '2' * 64
        self.updates.local_path = 'local.json'
        self.updates.root = Path('fixture')
        self.updates.build = {'commit': self.previous.commit}
        self.updates.target = 'windows-amd64'
        self.updates.state = SimpleNamespace(directory='fixture')
        self.updates.verify_source = AsyncMock()
        offer = grove_updates.Offer(job='a' * 32, expires=int(grove_updates.time.time()) + 60,
                                   release=self.latest, target=self.updates.local_id, identity={'fixture': 'verified elsewhere'})
        job = {'job': offer.job, 'release': self.latest.model_dump(), 'source': offer.identity,
               'source_node': origin, 'accepted_at': int(grove_updates.time.time()), 'expires': offer.expires, 'status': 'queued'}

        async def acquire(asset, *, on_transfer):
            on_transfer(supplier)
            receipt = self.updates.local_status(offer, origin)
            self.assertEqual(receipt['package_source_node'], supplier)
            self.assertEqual(receipt['source_node'], origin)
            return True

        self.updates.acquire = acquire
        with patch.object(grove_updates.worker, 'read_record', return_value=job), \
                patch.object(grove_updates.worker, 'write_record'), patch.object(grove_updates.worker, 'launch'):
            await self.updates.run_node(job)
            self.assertEqual(self.updates.local_status(offer, origin), {'status': 'installing', 'source_node': origin})


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
