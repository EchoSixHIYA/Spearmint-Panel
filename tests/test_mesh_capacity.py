from pathlib import Path
from types import SimpleNamespace
import unittest

from spearmint.config import Config
from spearmint.peer.neighbors import LIMIT, Neighbors


class MeshCapacityTest(unittest.TestCase):
    def test_ninth_fixed_member_does_not_hit_the_previous_eight_link_ceiling(self):
        manager = SimpleNamespace(neighbors={str(index): object() for index in range(8)})
        scheduler = Neighbors(manager)
        fixed = SimpleNamespace(legacy=False, fixed_source_ip='192.168.20.10')
        self.assertEqual(LIMIT, 128)
        self.assertTrue(scheduler.allow_dial(fixed))
        self.assertTrue(scheduler.accept(fixed))

    def test_full_fixed_target_allows_bounded_authenticated_recovery(self):
        fixed = SimpleNamespace(legacy=False, fixed_source_ip='192.168.20.10')
        manager = SimpleNamespace(neighbors={
            str(index): SimpleNamespace(pair=fixed, address=f'192.168.21.{index + 1}') for index in range(7)
        }, admitted={})
        scheduler = Neighbors(manager)
        release = scheduler.incoming('192.168.20.12')
        self.assertIsNotNone(release)
        self.assertIsNone(scheduler.incoming('192.168.20.13'))
        release()
        self.assertEqual(scheduler.steady_target(), 9)
        for index in range(7, 11):
            pair = SimpleNamespace(node_id=str(index), legacy=False, fixed_source_ip=None)
            self.assertTrue(scheduler.accept(pair, inbound=True))
            manager.neighbors[pair.node_id] = SimpleNamespace(pair=pair)
        self.assertFalse(scheduler.accept(SimpleNamespace(node_id='excess', legacy=False, fixed_source_ip=None), inbound=True))

    def test_neighbor_configuration_supports_the_physical_capacity(self):
        config = Config(Path('state'), 'https://localhost:18443', Path('web'), Path('docker'), neighbor_target=64)
        self.assertEqual(config.neighbor_target, 64)
        with self.assertRaises(ValueError):
            Config(Path('state'), 'https://localhost:18443', Path('web'), Path('docker'), neighbor_target=128)


if __name__ == '__main__':
    unittest.main()
