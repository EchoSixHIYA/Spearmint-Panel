from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import time
import unittest
from unittest.mock import patch

import psutil

from spearmint.catalog import Service
from spearmint.drivers import Observation
from spearmint.host import Capture
from spearmint.process_gpu import windows_counters
from spearmint.service_metrics import ServiceMetrics, cgroup, container_sample, group_pids, memory_bytes, process_sample


def service(driver='process'):
    return Service('a' * 32, 'fixture', 'fixture service', driver,
                   'b' * 64 if driver == 'docker' else 'fixture.service', {}, True, 1)


class FakeProcess:
    def __init__(self, pid, born, cpu, memory, children=()):
        self.pid, self.born, self.cpu, self.memory, self.descendants = pid, born, cpu, memory, children

    def create_time(self): return self.born
    def cpu_times(self): return SimpleNamespace(user=self.cpu, system=0)
    def memory_info(self): return SimpleNamespace(rss=self.memory)
    def children(self, recursive=False): return self.descendants
    def is_running(self): return True
    def oneshot(self): return nullcontext()


class ServiceMetricsTest(unittest.TestCase):
    def test_process_tree_cpu_memory_and_warmup(self):
        child = FakeProcess(12, 300, 3, 256)
        root = FakeProcess(11, 200, 5, 512, [child])
        processes = {11: root, 12: child}
        observation = Observation('running', pid=11, instance='generation-one')
        with patch('spearmint.service_metrics.psutil.Process', side_effect=processes.__getitem__), \
                patch('spearmint.service_metrics.cgroup', return_value=None), \
                patch('spearmint.service_metrics.psutil.cpu_count', return_value=4), \
                patch('spearmint.service_metrics.time.time', side_effect=[1000, 1002]), \
                patch('spearmint.service_metrics.time.monotonic', side_effect=[100, 102]):
            first = process_sample(service(), observation)
            root.cpu += 2
            child.cpu += 1
            second = process_sample(service(), observation, first)
        self.assertIsNone(first['cpu_percent'])
        self.assertEqual(second['cpu_percent'], 37.5)
        self.assertEqual(second['memory_bytes'], 768)
        self.assertEqual(second['uptime_seconds'], 802)
        self.assertEqual(set(second['_processes']), {(11, 200), (12, 300)})

    def test_pid_reuse_during_sample_is_rejected(self):
        root = FakeProcess(11, 200, 5, 512)
        replacement = FakeProcess(11, 900, 1, 100)
        with patch('spearmint.service_metrics.psutil.Process', side_effect=[root, replacement]), \
                patch('spearmint.service_metrics.cgroup', return_value=None):
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                process_sample(service(), Observation('running', pid=11, instance='generation-one'))

    def test_complete_cgroup_is_used_instead_of_only_main_pid(self):
        work = Path.cwd() / 'work/tmp/service-detail-tests'
        work.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=work) as directory:
            root_path = Path(directory)
            proc, groups = root_path / 'proc', root_path / 'groups'
            (proc / '11').mkdir(parents=True)
            group = groups / 'system.slice/fixture.service'
            (group / 'child').mkdir(parents=True)
            (proc / '11/cgroup').write_text('0::/system.slice/fixture.service\n')
            (group / 'cgroup.procs').write_text('11\n')
            (group / 'child/cgroup.procs').write_text('12\n')
            (group / 'memory.current').write_text('4096')
            (group / 'cpu.stat').write_text('usage_usec 1000000\nuser_usec 900000\nsystem_usec 100000\n')
            self.assertEqual(cgroup(11, 'fixture.service', proc, groups), group)
            self.assertIsNone(cgroup(11, 'other.service', proc, groups))
            self.assertEqual(group_pids(group), {11, 12})
            processes = {11: FakeProcess(11, 200, 10, 512), 12: FakeProcess(12, 300, 10, 512)}
            observation = Observation('running', pid=11, instance='one')
            with patch('spearmint.service_metrics.psutil.Process', side_effect=processes.__getitem__), \
                    patch('spearmint.service_metrics.os', SimpleNamespace(name='posix')), \
                    patch('spearmint.service_metrics.cgroup', return_value=group), \
                    patch('spearmint.service_metrics.psutil.cpu_count', return_value=2), \
                    patch('spearmint.service_metrics.time.monotonic', side_effect=[10, 12]):
                first = process_sample(service(), observation)
                (group / 'cpu.stat').write_text('usage_usec 3000000\n')
                second = process_sample(service(), observation, first)
            self.assertEqual(second['memory_bytes'], 4096)
            self.assertEqual(second['cpu_percent'], 50)
            self.assertEqual(second['scope'], 'cgroup')

    def test_snapshot_discards_old_generation_expired_and_stopped_samples(self):
        metrics = ServiceMetrics({})
        item = service()
        observation = Observation('running', instance='generation-one', pid=11)
        self.assertIsNone(metrics.snapshot(item, observation)['cpu_percent'])
        key = metrics.interests[item.id][0]
        metrics.latest[item.id] = {'_key': key, '_processes': [(11, 200)], 'pid': 11, 'scope': 'process-tree',
                                  'sampled_at': time.time(), 'valid_until': time.time() + 30,
                                  'cpu_percent': 0, 'memory_bytes': 512, 'uptime_seconds': 40}
        metrics.gpu_sample = windows_counters({'pid_22_gpu_eng_0_engtype_Compute': 99}, {})
        metrics.gpu_births, metrics.gpu_until = {11: 200}, time.time() + 20
        sample = metrics.snapshot(item, observation)
        self.assertEqual(sample['cpu_percent'], 0)
        self.assertEqual(sample['gpu']['utilization_percent'], 0)
        self.assertNotIn('_processes', sample)
        json.dumps(sample)
        metrics.gpu_births = {11: 900}
        self.assertIsNone(metrics.snapshot(item, observation)['gpu']['utilization_percent'])
        metrics.latest[item.id]['valid_until'] = time.time() - 1
        self.assertIsNone(metrics.snapshot(item, observation)['memory_bytes'])
        self.assertIsNone(metrics.snapshot(replace(item, version=2), observation)['cpu_percent'])
        metrics.snapshot(item, replace(observation, status='stopped', pid=0))
        self.assertNotIn(item.id, metrics.latest)
        self.assertNotIn(item.id, metrics.interests)

    def test_driver_identity_change_and_unreadable_process(self):
        item = service()
        original = Observation('running', instance='one', pid=11)
        driver = SimpleNamespace(inspect=lambda _: replace(original, instance='two'))
        metrics = ServiceMetrics({'process': driver})
        metrics.snapshot(item, original)
        self.assertIsNone(metrics.collect(metrics.interests[item.id], None))
        with patch('spearmint.service_metrics.psutil.Process', side_effect=psutil.AccessDenied(11)):
            with self.assertRaises(psutil.AccessDenied):
                process_sample(item, original)

    def test_container_native_stats_and_identity(self):
        item = service('docker')
        observation = Observation('running', pid=11, instance='2026-01-01T00:00:00Z')
        driver = SimpleNamespace(registered=lambda _: (['docker'], {}, {'pid': 11, 'started': observation.instance}))
        stats = {'ID': item.target, 'CPUPerc': '40.00%', 'MemUsage': '64MiB / 2GiB'}
        replies = [Capture(0, json.dumps(stats).encode(), b'', False), Capture(0, b'linux\n', b'', False)]
        with patch('spearmint.service_metrics.capture', side_effect=replies) as command, \
                patch('spearmint.service_metrics.psutil.cpu_count', return_value=4), \
                patch('spearmint.service_metrics.process_sample', return_value={'_processes': []}):
            result = container_sample(item, observation, driver)
        self.assertEqual(result['cpu_percent'], 10)
        self.assertEqual(result['memory_bytes'], 64 * 1024**2)
        self.assertGreater(result['uptime_seconds'], 0)
        self.assertEqual(command.call_args_list[0].args[0][-2:], ['--', item.target])
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            container_sample(item, replace(observation, pid=12), driver)
        self.assertEqual(memory_bytes('1.5GiB'), 1610612736)
        self.assertIsNone(memory_bytes('N/A'))


if __name__ == '__main__':
    unittest.main()
