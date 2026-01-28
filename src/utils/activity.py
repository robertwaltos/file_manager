"""
Activity tracking and stall monitoring utilities.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ActivityTracker:
    """Track last activity time for long-running workflows."""

    min_interval_seconds: float = 2.0
    _last_touch: float = field(default_factory=time.monotonic, init=False, repr=False)
    _last_note: str = field(default="", init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def touch(self, note: str = "") -> None:
        now = time.monotonic()
        with self._lock:
            if (now - self._last_touch) < self.min_interval_seconds and not note:
                return
            self._last_touch = now
            if note:
                self._last_note = note

    def snapshot(self) -> tuple[float, str]:
        with self._lock:
            return self._last_touch, self._last_note


@dataclass
class StallMonitor:
    """Monitor for stalled activity and optionally terminate the process."""

    tracker: ActivityTracker
    logger: object
    warning_seconds: float = 600.0
    abort_seconds: float = 0.0
    check_interval_seconds: float = 30.0
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, init=False, repr=False)
    _last_warning_at: float = field(default=0.0, init=False, repr=False)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="stall-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=self.check_interval_seconds + 5)
        self._thread = None

    def _run(self) -> None:
        while not self._stop_event.wait(self.check_interval_seconds):
            last_touch, note = self.tracker.snapshot()
            idle_for = time.monotonic() - last_touch
            if self.warning_seconds > 0 and idle_for >= self.warning_seconds:
                now = time.monotonic()
                if (now - self._last_warning_at) >= self.warning_seconds:
                    self._last_warning_at = now
                    self.logger.warning(
                        "Activity stall detected (idle %.0fs). Last note: %s",
                        idle_for,
                        note or "n/a",
                    )
            if self.abort_seconds > 0 and idle_for >= self.abort_seconds:
                self.logger.error(
                    "Aborting due to stall (idle %.0fs).", idle_for
                )
                os._exit(2)
