"""Functional identity checks when Linux wall-clock boot estimates drift."""
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
import subprocess
import json
from unittest.mock import patch

from spearmint.catalog import Service
from spearmint.native_process import NativeProcessDriver, alive, linux_identity, starting_status, write_status
from spearmint.state import State


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux kernel process identity')
class NativeIdentityTest(unittest.TestCase):
    def test_parent_and_child_read_the_same_kernel_identity(self):
        script = 'import os,json,sys; from spearmint.native_process import linux_identity; print(json.dumps(linux_identity(os.getpid())), flush=True); sys.stdin.read(1)'
        with subprocess.Popen([sys.executable, '-c', script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as child:
            try:
                identity = json.loads(child.stdout.readline())
                self.assertEqual(list(linux_identity(child.pid)), identity)
            finally:
                child.stdin.close()
                child.wait(timeout=10)

    def test_kernel_ticks_keep_live_process_recognized_when_wall_clock_changes(self):
        boot, ticks = linux_identity(os.getpid())
        self.assertIsInstance(boot, str)
        self.assertTrue(ticks.isdigit())
        self.assertTrue(alive(os.getpid(), 'incorrect wall clock estimate', ticks=ticks, kernel_boot=boot))

    def test_workload_record_survives_different_boot_time_estimates(self):
        root = Path.cwd() / 'work/tmp/service-deployment-v2/identity'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as temporary:
            state = State(Path(temporary) / 'state')
            node = state.initialize(lambda: 'identity fixture')
            service = Service('a' * 32, node, 'fixture', 'process', 'fixture', {}, True, 1)
            driver = NativeProcessDriver(state)
            record = starting_status(service, 'b' * 32, os.getpid())
            path = driver.directory(service) / 'status.json'
            write_status(path, record)
            with patch('spearmint.native_process.boot_id', return_value='wall clock drifted'):
                self.assertEqual(driver.read_status(service, path), record)
                self.assertEqual(driver.inspect(service).status, 'starting')
