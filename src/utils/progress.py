"""
Lightweight progress reporting for long-running workflows.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from database import DatabaseManager


@dataclass
class ProgressSnapshot:
    """Summary of current workflow progress."""

    timestamp: str
    inventory_count: int
    hash_count: int
    corruption_count: int
    duplicate_candidates: int
    permission_issues: int
    task_summary: dict[str, int]


class ProgressReporter:
    """Emit periodic progress summaries using a background thread."""

    def __init__(
        self,
        db_paths: dict,
        logger: Optional[logging.Logger] = None,
        interval_seconds: int = 30,
        enabled: bool = True,
    ) -> None:
        self.db_paths = db_paths
        self.logger = logger or logging.getLogger("file_manager.performance")
        self.interval_seconds = max(interval_seconds, 5)
        self.enabled = enabled
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start background reporting if enabled."""
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="progress-reporter", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background reporting."""
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=self.interval_seconds + 5)
        self._thread = None

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            snapshot = self._snapshot()
            self._log_snapshot(snapshot)

    def _snapshot(self) -> ProgressSnapshot:
        db_manager = DatabaseManager(self.db_paths)
        try:
            inventory_count = db_manager.count_inventory()
            hash_count = db_manager.count_hashes()
            corruption_count = db_manager.count_corruptions()
            duplicate_candidates = db_manager.count_duplicate_candidates()
            permission_issues = db_manager.count_permission_issues(resolved=False)
            task_summary = db_manager.task_status_summary()
        finally:
            db_manager.close()
        return ProgressSnapshot(
            timestamp=datetime.utcnow().isoformat(),
            inventory_count=inventory_count,
            hash_count=hash_count,
            corruption_count=corruption_count,
            duplicate_candidates=duplicate_candidates,
            permission_issues=permission_issues,
            task_summary=task_summary,
        )

    def _log_snapshot(self, snapshot: ProgressSnapshot) -> None:
        summary = ", ".join(
            f"{status}:{count}" for status, count in sorted(snapshot.task_summary.items())
        )
        self.logger.info(
            "Dashboard %s | inventory=%s hashes=%s corruptions=%s duplicates=%s permissions=%s tasks={%s}",
            snapshot.timestamp,
            snapshot.inventory_count,
            snapshot.hash_count,
            snapshot.corruption_count,
            snapshot.duplicate_candidates,
            snapshot.permission_issues,
            summary,
        )
