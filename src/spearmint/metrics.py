from collections import deque
from collections.abc import Callable
from contextlib import contextmanager
import os
from pathlib import Path
from threading import Event, Lock, Thread
import time
from typing import TypeVar

import psutil

from .platforms import WINDOWS
from .gpu_metrics import collect as collect_gpu


T = TypeVar("T")
INTERVAL = 2
VALID_FOR = 8
HISTORY_SECONDS = 15 * 60


def read(call: Callable[[], T]) -> T | None:
    try:
        return call()
    except (OSError, psutil.Error):
        return None


def rates(previous: dict, current: dict, elapsed: float) -> dict | None:
    received, sent = 0, 0
    comparable = False
    for name in previous.keys() & current.keys():
        old, new = previous[name], current[name]
        if new.bytes_recv >= old.bytes_recv and new.bytes_sent >= old.bytes_sent:
            comparable = True
            received += new.bytes_recv - old.bytes_recv
            sent += new.bytes_sent - old.bytes_sent
    if not comparable or elapsed <= 0:
        return None
    return {"received_per_second": round(received / elapsed), "sent_per_second": round(sent / elapsed)}


def system_directory() -> Path | None:
    if not WINDOWS:
        return Path("/")
    system_root = os.environ.get("SystemRoot")
    return Path(system_root) if system_root else None


def disk_snapshot(system: Path | None, state: Path) -> dict:
    root_disk = read(lambda: psutil.disk_usage(str(system))) if system is not None else None
    state_disk = read(lambda: psutil.disk_usage(str(state)))
    same_disk = None
    if root_disk is not None and state_disk is not None and system is not None:
        root_device = read(lambda: system.stat().st_dev)
        state_device = read(lambda: state.stat().st_dev)
        if root_device and state_device:
            same_disk = root_device == state_device
    return {
        "root_disk": root_disk._asdict() if root_disk is not None else None,
        "state_disk": state_disk._asdict() if state_disk is not None else None,
        "state_disk_is_root": same_disk,
    }


class Metrics:
    def __init__(self, state_directory: Path) -> None:
        self.state_directory = state_directory
        self.system_directory = system_directory()
        self.stop = Event()
        self.latest: dict | None = None
        self.gpu_latest: dict | None = None
        self.history = deque(maxlen=HISTORY_SECONDS // INTERVAL + 1)
        self.history_lock = Lock()

    @contextmanager
    def running(self):
        self.stop.clear()
        with self.history_lock:
            self.latest = None
            self.gpu_latest = None
            self.history.clear()
        worker = Thread(target=self.sample, name="host-metrics", daemon=True)
        gpu_worker = Thread(target=self.sample_gpu, name="gpu-metrics", daemon=True)
        worker.start()
        gpu_worker.start()
        try:
            yield
        finally:
            self.stop.set()
            worker.join(timeout=3)
            gpu_worker.join(timeout=3)

    def sample_gpu(self) -> None:
        while not self.stop.is_set():
            self.gpu_latest = collect_gpu()
            self.stop.wait(5)

    def sample(self) -> None:
        previous: dict = {}
        previous_time = time.monotonic()
        primed_cpu = False
        while not self.stop.is_set():
            now, interval_start = time.time(), time.monotonic()
            cpu = read(psutil.cpu_percent)
            memory = read(psutil.virtual_memory)
            disks = disk_snapshot(self.system_directory, self.state_directory)
            current = read(lambda: psutil.net_io_counters(pernic=True, nowrap=False)) or {}
            uptime = read(lambda: max(0, time.time() - psutil.boot_time()))
            sample = {
                "sampled_at": now, "valid_until": now + VALID_FOR, "source": "local",
                "cpu_percent": cpu if primed_cpu else None,
                "memory": {"total": memory.total, "available": memory.available} if memory else None,
                **disks,
                "network": rates(previous, current, interval_start - previous_time),
                "uptime_seconds": int(uptime) if uptime is not None else None,
            }
            self.record(sample)
            primed_cpu = cpu is not None
            previous, previous_time = current, interval_start
            self.stop.wait(max(0, INTERVAL - (time.monotonic() - interval_start)))

    def record(self, sample: dict) -> None:
        memory = sample["memory"]
        point = {
            "sampled_at": sample["sampled_at"],
            "cpu_percent": sample["cpu_percent"],
            "memory_percent": (memory["total"] - memory["available"]) / memory["total"] * 100
            if memory and memory["total"] else None,
            "root_disk_percent": (sample["root_disk"] or {}).get("percent"),
            "state_disk_percent": (sample["state_disk"] or {}).get("percent") if sample["state_disk_is_root"] is not True else None,
        }
        with self.history_lock:
            if self.latest is not None and sample["sampled_at"] < self.latest["sampled_at"]:
                self.history.clear()
            self.latest = sample
            self.history.append(point)

    def trend(self) -> dict:
        with self.history_lock:
            now = time.time()
            points = [point for point in self.history if now - HISTORY_SECONDS <= point["sampled_at"] <= now]
            return {"sampled_at": now, "window_seconds": HISTORY_SECONDS, "points": points}

    def snapshot(self) -> dict:
        sample = self.latest
        gpu = self.gpu_latest
        gpu = {**gpu, 'stale': time.time() > gpu['valid_until']} if gpu else {
            'sampled_at': None, 'valid_until': None, 'status': 'unavailable', 'devices': [], 'stale': True}
        if sample is None:
            return {
                "sampled_at": None, "valid_until": None, "source": "local", "stale": True,
                "cpu_percent": None, "memory": None, "root_disk": None, "state_disk": None,
                "state_disk_is_root": None,
                "network": None, "uptime_seconds": None,
                "gpu": gpu,
            }
        return {**sample, "gpu": gpu, "stale": time.time() > sample["valid_until"]}
