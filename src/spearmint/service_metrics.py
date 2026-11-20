"""Demand-driven service resource sampling, isolated from lifecycle dispatch."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
import json
import logging
import os
from pathlib import Path, PurePosixPath
import time
from threading import Event, Lock, Thread

import psutil

from .drivers import CONTAINER_ID
from .host import HostError, capture
from .process_gpu import ProcessGPU, aggregate, number


logger = logging.getLogger(__name__)
INTERVAL = 2
VALID_FOR = 10
INTEREST_FOR = 30


def identity(service, observation):
    return service.version, observation.pid, observation.instance, observation.status, observation.shared_process


def cgroup(pid, target, proc=Path('/proc'), root=Path('/sys/fs/cgroup')):
    try:
        for row in (proc / str(pid) / 'cgroup').read_text().splitlines():
            if not row.startswith('0::'):
                continue
            path = PurePosixPath(row[3:])
            if not path.is_absolute():
                continue
            if target not in path.parts and f'docker-{target}.scope' not in path.parts:
                continue
            group = root.joinpath(*path.parts[1:]).resolve()
            if group.is_relative_to(root.resolve()) and group.is_dir():
                return group
    except (OSError, ValueError):
        pass
    return None


def group_pids(group, limit=4096):
    pids = set()
    files = [group / 'cgroup.procs', *group.rglob('cgroup.procs')]
    if len(files) > 128:
        raise ValueError('Service cgroup hierarchy exceeds sample budget')
    for file in set(files):
        pids.update(int(pid) for pid in file.read_text().split() if pid.isdecimal() and int(pid) > 0)
        if len(pids) > limit:
            raise ValueError('Service process count exceeds sample budget')
    return pids


def cpu_rate(current, previous, elapsed, cpus, since=None):
    if previous is None or elapsed <= 0 or not cpus:
        return None
    delta = 0
    for key, value in current.items():
        old = previous.get(key)
        if old is None and since is not None and isinstance(key[0], int) and key[1] >= since:
            delta += value
        if old is not None:
            if value < old:
                return None
            delta += value - old
    return round(min(100, max(0, delta / elapsed / cpus * 100)), 1)


def process_sample(service, observation, previous=None):
    root = psutil.Process(observation.pid)
    birth = root.create_time()
    group = cgroup(root.pid, service.target) if os.name != 'nt' else None
    if group:
        pids = group_pids(group)
        pids.add(root.pid)
        scope = 'cgroup'
    elif observation.shared_process:
        pids, scope = {root.pid}, 'shared-process'
    else:
        pids, scope = {root.pid, *(process.pid for process in root.children(recursive=True))}, 'process-tree'
    if len(pids) > 4096:
        raise ValueError('Service process count exceeds sample budget')
    counters, members, memory, complete = {}, [], 0, True
    for pid in pids:
        try:
            process = root if pid == root.pid else psutil.Process(pid)
            with process.oneshot():
                created = process.create_time()
                cpu = process.cpu_times()
                used = process.memory_info().rss
            if not process.is_running():
                continue
            key = (pid, created)
            counters[key] = cpu.user + cpu.system
            members.append(key)
            memory += used
        except psutil.NoSuchProcess:
            continue
        except (OSError, psutil.Error):
            complete = False
    if not root.is_running() or psutil.Process(root.pid).create_time() != birth:
        raise ValueError('Service process identity changed while sampling')
    if group:
        try:
            usage = dict(row.split() for row in (group / 'cpu.stat').read_text().splitlines())
            counters = {('cgroup', str(group), birth): int(usage['usage_usec']) / 1_000_000}
        except (OSError, ValueError, KeyError):
            if not complete:
                counters = {}
        try:
            memory = int((group / 'memory.current').read_text())
        except (OSError, ValueError):
            if not complete:
                memory = None
    elif not complete:
        memory, counters = None, {}
    now, tick = time.time(), time.monotonic()
    old = previous.get('_cpu') if previous else None
    # Different PIDs or birth times are never compared as the same process.
    comparable = bool(old is not None and counters.keys() & old.keys())
    cpu = cpu_rate(counters, old, tick - previous['_tick'], psutil.cpu_count(), previous['sampled_at']) if comparable else None
    return {'pid': root.pid, 'scope': scope, 'cpu_percent': cpu, 'memory_bytes': memory,
            'uptime_seconds': max(0, int(now - birth)) if not observation.shared_process else None,
            'sampled_at': now, 'valid_until': now + VALID_FOR, '_tick': tick, '_cpu': counters,
            '_processes': members if complete else []}


def memory_bytes(text):
    import re
    match = re.fullmatch(r'\s*(\d+(?:\.\d+)?)\s*([KMGTPE]?i?B)\s*', text)
    if not match:
        return None
    unit = match[2]
    power = 'BKMGTPE'.index(unit[0]) if unit != 'B' else 0
    return round(float(match[1]) * (1024 if 'i' in unit else 1000) ** power)


def container_sample(service, observation, driver):
    if not CONTAINER_ID.fullmatch(service.target):
        raise ValueError('Invalid registered container identity')
    argv, env, details = driver.registered(service)
    if details is None or details['pid'] != observation.pid or details['started'] != observation.instance:
        raise ValueError('Container identity changed before sampling')
    result = capture([*argv, 'stats', '--no-stream', '--no-trunc', '--format', '{{json .}}', '--', service.target],
                     env=env, timeout=3, limit=16 * 1024)
    if result.code or result.truncated:
        raise HostError('Container resource sample unavailable')
    value = json.loads(result.stdout)
    if value.get('ID') not in (service.target, service.target[:12]):
        raise ValueError('Docker returned a different container')
    load = number(str(value.get('CPUPerc', '')).removesuffix('%'))
    platform = getattr(driver, '_resource_platform', None)
    if platform is None or platform[1] < time.monotonic():
        info = capture([*argv, 'info', '--format', '{{.OSType}}'], env=env, timeout=2, limit=1024)
        system = info.stdout.decode('ascii', 'replace').strip() if not info.code and not info.truncated else ''
        platform = (system, time.monotonic() + 60)
        driver._resource_platform = platform
    cpus = psutil.cpu_count()
    # Windows daemon percentages already use total CPU capacity.
    divisor = cpus if platform[0] == 'linux' else 1 if platform[0] == 'windows' else None
    cpu = round(min(100, load / divisor), 1) if load is not None and divisor else None
    used = memory_bytes(str(value.get('MemUsage', '')).split('/')[0])
    try:
        started = datetime.fromisoformat(details['started'].replace('Z', '+00:00')).timestamp()
        uptime = max(0, int(time.time() - started)) if started > 0 else None
    except (ValueError, TypeError, OverflowError):
        uptime = None
    members = []
    # A Linux container PID is not a Windows host PID.
    if os.name != 'nt':
        try:
            members = process_sample(service, observation)['_processes']
        except (OSError, psutil.Error, ValueError):
            pass
    now = time.time()
    return {'pid': observation.pid, 'scope': 'container', 'cpu_percent': cpu, 'memory_bytes': used,
            'uptime_seconds': uptime, 'sampled_at': now, 'valid_until': now + VALID_FOR, '_processes': members}


class ServiceMetrics:
    def __init__(self, drivers):
        self.drivers = drivers
        self.lock = Lock()
        self.stop = Event()
        self.interests, self.latest = {}, {}
        self.gpu_sample, self.gpu_births, self.gpu_until = None, {}, 0

    @contextmanager
    def running(self):
        self.stop.clear()
        workers = [Thread(target=self.sample, name='service-resources', daemon=True),
                   Thread(target=self.sample_gpu, name='service-gpu', daemon=True)]
        for worker in workers:
            worker.start()
        try:
            yield
        finally:
            self.stop.set()
            for worker in workers:
                worker.join(timeout=5)

    def snapshot(self, service, observation):
        key = identity(service, observation)
        empty = {'pid': observation.pid or None, 'sampled_at': None, 'valid_until': None, 'scope': None,
                 'cpu_percent': None, 'memory_bytes': None, 'uptime_seconds': None,
                 'gpu': {'utilization_percent': None, 'memory_used_bytes': None, 'valid_until': None}}
        with self.lock:
            if observation.status != 'running' or observation.pid <= 0:
                self.interests.pop(service.id, None)
                self.latest.pop(service.id, None)
                return empty
            self.interests[service.id] = (key, service, observation, time.monotonic() + INTEREST_FOR)
            sample = self.latest.get(service.id)
            if sample is None or sample['_key'] != key or sample['valid_until'] < time.time():
                return empty
            result = {name: value for name, value in sample.items() if not name.startswith('_')}
            gpu = self.gpu_sample if self.gpu_until >= time.time() else None
            members = sample['_processes']
            # Only use GPU counters from the same sampled process generations.
            if not members or any(self.gpu_births.get(pid) != birth for pid, birth in members):
                gpu = None
            result['gpu'] = {**aggregate(gpu, {pid for pid, _ in members}),
                             'valid_until': self.gpu_until if gpu is not None else None}
            return result

    def collect(self, item, previous):
        key, service, observation, _ = item
        driver = self.drivers[service.driver]
        fresh = driver.inspect(service)
        if identity(service, fresh) != key:
            return None
        sample = (container_sample(service, observation, driver) if service.driver == 'docker'
                  else process_sample(service, observation, previous if previous and previous['_key'] == key else None))
        sample['_key'] = key
        return sample

    def sample(self):
        pending = {}
        scheduled = {}
        pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='service-sample')
        try:
            while not self.stop.is_set():
                with self.lock:
                    active = {sid: item for sid, item in self.interests.items() if item[3] > time.monotonic()}
                    self.interests = active
                    self.latest = {sid: value for sid, value in self.latest.items() if sid in active}
                for sid, future in list(pending.items()):
                    if not future.done():
                        continue
                    del pending[sid]
                    try:
                        sample = future.result()
                    except Exception:
                        sample = None
                        logger.debug('Service resource sample unavailable', exc_info=True)
                    with self.lock:
                        item = self.interests.get(sid)
                        if item and sample and sample['_key'] == item[0]:
                            self.latest[sid] = sample
                        elif item:
                            self.latest.pop(sid, None)
                for sid in sorted(active, key=lambda value: scheduled.get(value, 0)):
                    if len(pending) >= 4:
                        break
                    if sid not in pending:
                        item = active[sid]
                        with self.lock:
                            previous = self.latest.get(sid)
                        pending[sid] = pool.submit(self.collect, item, previous)
                        scheduled[sid] = time.monotonic()
                scheduled = {sid: value for sid, value in scheduled.items() if sid in active}
                self.stop.wait(INTERVAL)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def sample_gpu(self):
        reader = ProcessGPU()
        try:
            while not self.stop.is_set():
                with self.lock:
                    members = {pair for value in self.latest.values() for pair in value['_processes']}
                if members:
                    try:
                        sample = reader.collect()
                        births = {}
                        for pid, birth in members:
                            try:
                                if psutil.Process(pid).create_time() == birth:
                                    births[pid] = birth
                            except (OSError, psutil.Error):
                                pass
                    except Exception:
                        sample, births = None, {}
                        logger.debug('Service GPU sample unavailable', exc_info=True)
                    with self.lock:
                        self.gpu_sample, self.gpu_births, self.gpu_until = sample, births, time.time() + 12
                else:
                    reader.close()
                    with self.lock:
                        self.gpu_sample, self.gpu_births, self.gpu_until = None, {}, 0
                self.stop.wait(5)
        finally:
            reader.close()
