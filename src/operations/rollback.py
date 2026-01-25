"""
Rollback utilities for file operations.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from database import DatabaseManager
from utils import ResourceMonitor


@dataclass
class RollbackStats:
    """Summary of rollback execution."""

    operation_id: str
    rolled_back: int
    skipped: int
    errors: int


class RollbackManager:
    """Rollback completed file operations using stored metadata."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        logger: Optional[logging.Logger] = None,
        monitor: Optional[ResourceMonitor] = None,
    ) -> None:
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.monitor = monitor

    def rollback_operation(self, operation_id: str, limit: Optional[int] = None) -> RollbackStats:
        """Rollback operations for a given operation ID."""
        operations = self.db_manager.list_file_operations(operation_id=operation_id, limit=limit)
        rolled_back = skipped = errors = 0
        rollback_operation_id = f"rollback_{operation_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        for entry in operations:
            rollback = entry.get("rollback")
            if not rollback:
                skipped += 1
                continue
            source = Path(rollback.get("source", ""))
            destination = Path(rollback.get("destination", ""))
            action = rollback.get("action", "")

            if not source.exists():
                skipped += 1
                continue
            if self.monitor is not None:
                self.monitor.throttle()

            try:
                if action == "move":
                    destination = self._resolve_conflict(destination)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(source, destination)
                    rolled_back += 1
                elif action == "copy":
                    destination = self._resolve_conflict(destination)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
                    rolled_back += 1
                elif action == "delete":
                    source.unlink()
                    rolled_back += 1
                else:
                    skipped += 1
                    continue
                self.db_manager.record_file_operation(
                    rollback_operation_id,
                    action=f"rollback_{action}",
                    source_path=str(source),
                    destination_path=str(destination) if destination else None,
                    status="completed",
                    size=_safe_size(destination) if destination and destination.exists() else None,
                )
            except Exception as exc:
                errors += 1
                self.db_manager.record_file_operation(
                    rollback_operation_id,
                    action=f"rollback_{action}",
                    source_path=str(source),
                    destination_path=str(destination) if destination else None,
                    status="failed",
                    error_message=str(exc),
                )
                self.logger.error("Rollback failed: %s -> %s (%s)", source, destination, exc)

        self.logger.info(
            "Rollback completed for %s. Rolled_back=%s Skipped=%s Errors=%s",
            operation_id,
            rolled_back,
            skipped,
            errors,
        )
        return RollbackStats(
            operation_id=operation_id,
            rolled_back=rolled_back,
            skipped=skipped,
            errors=errors,
        )

    def _resolve_conflict(self, destination: Path) -> Path:
        if not destination.exists():
            return destination
        stem = destination.stem
        suffix = destination.suffix
        parent = destination.parent
        counter = 1
        while True:
            candidate = parent / f"{stem}__rollback{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1


def _safe_size(path: Path) -> Optional[int]:
    try:
        return path.stat().st_size
    except OSError:
        return None
