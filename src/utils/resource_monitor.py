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

    def __post_init__(self) -> None:
        psutil.cpu_percent(interval=None)

    def throttle(self) -> None:
        """Sleep while CPU or RAM usage exceeds thresholds."""
        while True:
            cpu = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory().percent
            if cpu <= self.max_cpu_percent and ram <= self.max_ram_percent:
                return
            time.sleep(self.sleep_seconds)
