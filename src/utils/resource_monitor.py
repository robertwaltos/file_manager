"""
Resource monitoring and throttling helpers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import psutil


@dataclass
class ResourceMonitor:
    """Throttle processing when resource limits are exceeded."""

    max_cpu_percent: float
    max_ram_percent: float
    sleep_seconds: float = 0.5
    max_throttle_seconds: float = 15.0

    def __post_init__(self) -> None:
        psutil.cpu_percent(interval=None)

    def throttle(self) -> None:
        """Sleep while CPU or RAM usage exceeds thresholds."""
        if self.max_cpu_percent <= 0 and self.max_ram_percent <= 0:
            return
        start_time = time.monotonic()
        while True:
            cpu = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory().percent
            cpu_over = self.max_cpu_percent > 0 and cpu > self.max_cpu_percent
            ram_over = self.max_ram_percent > 0 and ram > self.max_ram_percent
            if not (cpu_over or ram_over):
                return
            if (time.monotonic() - start_time) >= self.max_throttle_seconds:
                return
            time.sleep(self.sleep_seconds)
