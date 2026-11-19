from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import unittest
from unittest.mock import patch

from spearmint.gpu_metrics import collect, drm_devices, nvidia_devices


class GpuMetricsTest(unittest.TestCase):
    def test_multiple_devices_and_unavailable_counters(self):
        devices = nvidia_devices('GPU-1, GPU A, 0, 128, 8192\nGPU-2, GPU B, [N/A], [N/A], 16384\n')
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]['utilization_percent'], 0)
        self.assertEqual(devices[0]['memory_used_bytes'], 128 * 1024**2)
        self.assertIsNone(devices[1]['utilization_percent'])
        self.assertIsNone(devices[1]['memory_used_bytes'])
        self.assertIsNone(nvidia_devices('GPU-3, GPU C, nan, 0, 8192')[0]['utilization_percent'])

    def test_readable_amd_counters_and_missing_devices(self):
        work = Path.cwd() / 'work/tmp/ui-polish/gpu-test'
        work.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            card = root / 'card0/device'
            card.mkdir(parents=True)
            (card / 'gpu_busy_percent').write_text('37')
            (card / 'mem_info_vram_used').write_text('1024')
            (card / 'mem_info_vram_total').write_text('4096')
            devices = drm_devices(root)
            self.assertEqual(devices[0]['utilization_percent'], 37)
            self.assertEqual(devices[0]['memory_used_bytes'], 1024)
            (card / 'gpu_busy_percent').unlink()
            self.assertEqual(drm_devices(root), [])

    def test_driver_timeout_is_unavailable_instead_of_zero(self):
        with patch('spearmint.gpu_metrics.shutil.which', return_value='nvidia-smi'), \
             patch('spearmint.gpu_metrics.subprocess.run', side_effect=subprocess.TimeoutExpired('nvidia-smi', 2)), \
             patch('spearmint.gpu_metrics.drm_devices', return_value=[]):
            sample = collect()
        self.assertEqual(sample['status'], 'unavailable')
        self.assertEqual(sample['devices'], [])
        self.assertGreater(sample['valid_until'], sample['sampled_at'])


if __name__ == '__main__':
    unittest.main()
