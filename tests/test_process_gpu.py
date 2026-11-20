import unittest

from spearmint.process_gpu import aggregate, nvidia_pmon, windows_counters


class ProcessGPUTest(unittest.TestCase):
    def test_only_service_pids_and_busiest_engine_are_counted(self):
        sample = windows_counters({
            'pid_11_luid_a_phys_0_eng_0_engtype_Compute': 20,
            'pid_12_luid_a_phys_0_eng_0_engtype_Compute': 30,
            'pid_11_luid_a_phys_0_eng_1_engtype_Copy': 40,
            'pid_99_luid_a_phys_0_eng_0_engtype_Compute': 90,
        }, {'pid_11_luid_a_phys_0': 1024, 'pid_12_luid_a_phys_0': 2048, 'pid_99_luid_a_phys_0': 8192})
        self.assertEqual(aggregate(sample, {11, 12}), {'utilization_percent': 50, 'memory_used_bytes': 3072})
        self.assertEqual(aggregate(sample, {100}), {'utilization_percent': 0, 'memory_used_bytes': 0})
        self.assertIsNone(aggregate(None, {11})['utilization_percent'])
        missing = windows_counters({'pid_11_luid_a_phys_0_eng_0_engtype_Compute': float('nan')},
                                   {'pid_11_luid_a_phys_0': float('nan')})
        self.assertIsNone(aggregate(missing, {11})['utilization_percent'])
        self.assertIsNone(aggregate(missing, {11})['memory_used_bytes'])

    def test_linux_process_monitor_and_unavailable_counters(self):
        sample = nvidia_pmon('# gpu pid type sm mem enc dec fb bar1 command\n'
                             '# Idx # C/G % % % % MB MB name\n'
                             '0 11 C 25 10 0 0 128 0 python\n'
                             '0 12 C 15 10 0 0 256 0 python\n'
                             '0 99 C 95 10 0 0 900 0 other\n')
        self.assertEqual(aggregate(sample, {11, 12}), {'utilization_percent': 40, 'memory_used_bytes': 384 * 1024**2})
        missing = nvidia_pmon('# gpu pid type sm fb command\n0 11 C - - python\n')
        self.assertIsNone(aggregate(missing, {11})['utilization_percent'])
        self.assertIsNone(aggregate(missing, {11})['memory_used_bytes'])
        self.assertIsNone(nvidia_pmon('Not Supported'))


if __name__ == '__main__':
    unittest.main()
