from pathlib import Path
from types import SimpleNamespace
import unittest

from spearmint.config import Config
from spearmint.peer.neighbors import LIMIT, Neighbors


class MeshCapacityTest(unittest.TestCase):
    def test_ninth_fixed_member_does_not_hit_the_previous_eight_link_ceiling(self):
        manager = SimpleNamespace(neighbors={str(index): object() for index in range(8)})
        scheduler = Neighbors(manager)
        fixed = SimpleNamespace(legacy=False, source_ip='106.15.36.235')
        self.assertEqual(LIMIT, 128)
        self.assertTrue(scheduler.allow_dial(fixed))
        self.assertTrue(scheduler.accept(fixed))

    def test_neighbor_configuration_supports_the_physical_capacity(self):
        config = Config(Path('state'), 'https://localhost:18443', Path('web'), Path('docker'), neighbor_target=64)
        self.assertEqual(config.neighbor_target, 64)
        with self.assertRaises(ValueError):
            Config(Path('state'), 'https://localhost:18443', Path('web'), Path('docker'), neighbor_target=128)


if __name__ == '__main__':
    unittest.main()
