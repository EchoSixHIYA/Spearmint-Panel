"""Bounded, read-only GPU sampling. Missing driver counters remain unavailable."""
import csv
import math
import os
from pathlib import Path
import shutil
import subprocess
import time


def number(value, maximum=None):
    try:
        result = float(value)
        if math.isfinite(result) and result >= 0 and (maximum is None or result <= maximum):
            return result
    except (TypeError, ValueError):
        pass
    return None


def nvidia_devices(output):
    devices = []
    for row in csv.reader(output.splitlines(), skipinitialspace=True):
        if len(row) != 5:
            continue
        identity, name, load, used, total = (cell.strip() for cell in row)
        if not identity or not name:
            continue
        used, total = number(used), number(total)
        devices.append({'id': identity, 'name': name, 'utilization_percent': number(load, 100),
                        'memory_used_bytes': round(used * 1024**2) if used is not None else None,
                        'memory_total_bytes': round(total * 1024**2) if total is not None else None})
    return devices


def drm_devices(root=Path('/sys/class/drm')):
    devices = []
    try:
        cards = sorted(root.glob('card[0-9]*'))
    except OSError:
        return devices
    for card in cards:
        if not card.name[4:].isdigit():
            continue
        device = card / 'device'
        try:
            load = number((device / 'gpu_busy_percent').read_text().strip(), 100)
        except OSError:
            continue
        if load is None:
            continue
        def memory(name):
            try:
                value = number((device / name).read_text().strip())
                return int(value) if value is not None else None
            except OSError:
                return None
        devices.append({'id': card.name, 'name': card.name, 'utilization_percent': load,
                        'memory_used_bytes': memory('mem_info_vram_used'), 'memory_total_bytes': memory('mem_info_vram_total')})
    return devices


def collect():
    # nvidia-smi selective CSV queries: https://docs.nvidia.com/deploy/nvidia-smi/
    # AMD sysfs counters: https://docs.kernel.org/gpu/amdgpu/thermal.html
    devices = []
    executable = shutil.which('nvidia-smi')
    if executable:
        try:
            result = subprocess.run([executable, '--query-gpu=uuid,name,utilization.gpu,memory.used,memory.total',
                                     '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=2,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0, check=False)
            if result.returncode == 0:
                devices = nvidia_devices(result.stdout)
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            pass
    if os.name != 'nt':
        devices.extend(drm_devices())
    now = time.time()
    return {'sampled_at': now, 'valid_until': now + 15, 'status': 'available' if devices else 'unavailable', 'devices': devices}
