"""Read GPU counters attributed to processes, never substitute whole-device load."""
import math
import os
import re
import shutil
import subprocess


def number(value):
    try:
        value = float(value)
        return value if math.isfinite(value) and value >= 0 else None
    except (ValueError, TypeError):
        return None


def windows_counters(engines, memory):
    records = {}
    for instance, value in engines.items():
        match = re.fullmatch(r'pid_(\d+)_(.+)_eng_(\d+)_engtype_.+?(?:#\d+)?', instance)
        load = number(value)
        if not match:
            continue
        pid, device, engine = match.groups()
        record = records.setdefault((int(pid), device), {'engines': {}, 'memory_used_bytes': 0 if memory is not None else None})
        previous = record['engines'].get(engine)
        record['engines'][engine] = max(previous or 0, load) if load is not None else previous
    for instance, value in (memory or {}).items():
        match = re.fullmatch(r'pid_(\d+)_(.+?)(?:#\d+)?', instance)
        used = number(value)
        if match:
            pid, device = match.groups()
            record = records.setdefault((int(pid), device), {'engines': {}, 'memory_used_bytes': 0})
            record['memory_used_bytes'] = max(record['memory_used_bytes'] or 0, round(used)) if used is not None else None
    return {'records': records, 'utilization_available': True, 'memory_available': memory is not None}


def nvidia_pmon(text):
    columns = None
    records = {}
    for line in text.splitlines():
        cells = line.lstrip('# ').split()
        if line.lstrip().startswith('#'):
            if {'gpu', 'pid', 'sm'} <= set(cells):
                columns = cells
            continue
        if not columns or len(cells) < len(columns) or not cells[columns.index('pid')].isdigit():
            continue
        pid = int(cells[columns.index('pid')])
        if pid <= 0:
            continue
        device = cells[columns.index('gpu')]
        load = number(cells[columns.index('sm')])
        used = number(cells[columns.index('fb')]) if 'fb' in columns else None
        record = records.setdefault((pid, device), {'engines': {}, 'memory_used_bytes': None})
        record['engines']['sm'] = load
        record['memory_used_bytes'] = round(used * 1024**2) if used is not None else None
    if columns is None:
        return None
    return {'records': records, 'utilization_available': True, 'memory_available': 'fb' in columns}


def aggregate(sample, pids):
    if sample is None:
        return {'utilization_percent': None, 'memory_used_bytes': None}
    engines, memory = {}, 0 if sample['memory_available'] else None
    valid = sample['utilization_available']
    for (pid, device), record in sample['records'].items():
        if pid not in pids:
            continue
        for engine, value in record['engines'].items():
            if value is None:
                valid = False
            else:
                key = (device, engine)
                engines[key] = engines.get(key, 0) + value
        if record['memory_used_bytes'] is None:
            memory = None
        elif memory is not None:
            memory += record['memory_used_bytes']
    return {'utilization_percent': round(min(100, max(engines.values(), default=0)), 1) if valid else None,
            'memory_used_bytes': memory}


class ProcessGPU:
    def __init__(self):
        self.query = None
        self.counters = {}
        self.primed = False

    def close(self):
        if self.query is not None:
            import win32pdh
            win32pdh.CloseQuery(self.query)
        self.query, self.counters, self.primed = None, {}, False

    def collect(self):
        if os.name == 'nt':
            return self.windows()
        executable = shutil.which('nvidia-smi')
        if not executable:
            return None
        try:
            result = subprocess.run([executable, 'pmon', '-c', '1', '-s', 'um'], capture_output=True,
                                    text=True, timeout=3, check=False)
            return nvidia_pmon(result.stdout) if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            return None

    def windows(self):
        import win32pdh
        import pywintypes
        try:
            if self.query is None:
                self.query = win32pdh.OpenQuery()
                self.counters['engines'] = win32pdh.AddEnglishCounter(self.query, r'\GPU Engine(*)\Utilization Percentage')
                try:
                    self.counters['memory'] = win32pdh.AddEnglishCounter(self.query, r'\GPU Process Memory(*)\Dedicated Usage')
                except (OSError, pywintypes.error):
                    pass
            win32pdh.CollectQueryData(self.query)
            if not self.primed:
                self.primed = True
                return None
            engines = win32pdh.GetFormattedCounterArray(self.counters['engines'], win32pdh.PDH_FMT_DOUBLE)
            memory = None
            if 'memory' in self.counters:
                try:
                    memory = win32pdh.GetFormattedCounterArray(self.counters['memory'], win32pdh.PDH_FMT_LARGE)
                except (OSError, pywintypes.error):
                    pass
            return windows_counters(engines, memory)
        except (OSError, pywintypes.error):
            self.close()
            return None
