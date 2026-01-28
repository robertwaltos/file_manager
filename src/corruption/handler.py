"""
Corruption quarantine handling.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import AppConfig, ensure_directories
from database import DatabaseManager
from utils import ActivityTracker, ResourceMonitor


@dataclass
class CorruptionMoveStats:
    """Summary stats for corruption quarantine moves."""

    moved: int
    skipped: int
    errors: int
    report_path: Path


class CorruptionMover:
    """Move corrupted files into the quarantine directory."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
        logger: Optional[logging.Logger] = None,
        movement_logger: Optional[logging.Logger] = None,
        monitor: Optional[ResourceMonitor] = None,
        activity_tracker: Optional[ActivityTracker] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.movement_logger = movement_logger or logging.getLogger("file_manager.movement")
        self.monitor = monitor
        self.activity_tracker = activity_tracker
        self.progress_log_interval = int(
            self.config.get("corruption", "quarantine_progress_log_interval", default=1000)
        )
        self.corrupted_root = self.config.resolve_path("paths", "corrupted", default="data/corrupted_files")
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")

    def run(self, limit: Optional[int] = None, operation_id: Optional[str] = None) -> CorruptionMoveStats:
        """Move corrupted files and emit a JSON report."""
        ensure_directories([self.corrupted_root, self.logs_root])
        candidates = self.db_manager.list_corruptions(limit=limit)

        if operation_id is None:
            operation_id = f"corruption_quarantine_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        moved = skipped = errors = 0
        results = []

        for index, entry in enumerate(candidates, start=1):
            if not entry["accessible"]:
                skipped += 1
                results.append(self._result(entry, "skipped", "not_accessible"))
                continue
            source_path = Path(entry["file_path"])
            if not source_path.exists():
                skipped += 1
                results.append(self._result(entry, "skipped", "source_missing"))
                continue
            if self._is_in_corrupted_root(source_path):
                skipped += 1
                results.append(self._result(entry, "skipped", "already_quarantined"))
                continue

            if self.monitor is not None:
                self.monitor.throttle()
            self._touch("corruption_quarantine", index, interval=200)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "Corruption quarantine progress: %s moved=%s skipped=%s errors=%s",
                    index,
                    moved,
                    skipped,
                    errors,
                )

            destination = self._build_destination(source_path, entry["file_id"])
            destination = self._resolve_conflict(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)

            try:
                source_size = source_path.stat().st_size
                shutil.move(source_path, destination)
            except Exception as exc:
                errors += 1
                results.append(self._result(entry, "error", str(exc)))
                self.movement_logger.error("Corruption move failed: %s -> %s (%s)", source_path, destination, exc)
                self.db_manager.record_file_operation(
                    operation_id,
                    action="move",
                    source_path=str(source_path),
                    destination_path=str(destination),
                    status="failed",
                    size=None,
                    error_message=str(exc),
                )
                continue

            if not destination.exists() or destination.stat().st_size != source_size:
                errors += 1
                results.append(self._result(entry, "error", "size_mismatch"))
                self.movement_logger.error("Corruption move validation failed: %s", destination)
                self.db_manager.record_file_operation(
                    operation_id,
                    action="move",
                    source_path=str(source_path),
                    destination_path=str(destination),
                    status="failed",
                    size=source_size,
                    error_message="size_mismatch",
                )
                continue

            self.db_manager.update_file_path(entry["file_id"], str(destination))
            self.db_manager.update_file_access(entry["file_id"], False, "corruption_quarantined")
            moved += 1
            results.append(self._result(entry, "moved", "ok"))
            self.movement_logger.info("Corrupted file moved: %s -> %s", source_path, destination)
            self.db_manager.record_file_operation(
                operation_id,
                action="move",
                source_path=str(source_path),
                destination_path=str(destination),
                status="completed",
                size=source_size,
                rollback={"action": "move", "source": str(destination), "destination": str(source_path)},
            )

        report_path = self.logs_root / f"corruption_quarantine_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "corrupted_root": str(self.corrupted_root),
                    "moved": moved,
                    "skipped": skipped,
                    "errors": errors,
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return CorruptionMoveStats(
            moved=moved,
            skipped=skipped,
            errors=errors,
            report_path=report_path,
        )

    def _build_destination(self, source_path: Path, file_id: int) -> Path:
        encoded_parent = self._encode_path(str(source_path.parent))
        destination_dir = self.corrupted_root / encoded_parent
        stem = source_path.stem
        suffix = source_path.suffix
        return destination_dir / f"{stem}__id{file_id}{suffix}"

    def _resolve_conflict(self, destination: Path) -> Path:
        if not destination.exists():
            return destination
        stem = destination.stem
        suffix = destination.suffix
        parent = destination.parent
        counter = 1
        while True:
            candidate = parent / f"{stem}__dup{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    def _encode_path(self, value: str) -> str:
        encoded = []
        for char in value:
            if char.isalnum() or char in "-_.":
                encoded.append(char)
            elif char in {":", "\\", "/"}:
                encoded.append("__")
            elif ord(char) < 128:
                encoded.append("_")
            else:
                encoded.append(f"_u{ord(char):04X}")
        return "".join(encoded).strip("_") or "root"

    def _is_in_corrupted_root(self, path: Path) -> bool:
        root_norm = str(self.corrupted_root).replace("\\", "/").lower()
        path_norm = str(path).replace("\\", "/").lower()
        return path_norm.startswith(root_norm)

    def _result(self, entry: dict, status: str, message: str) -> dict:
        return {
            "file_id": entry["file_id"],
            "file_path": entry["file_path"],
            "error_type": entry["error_type"],
            "status": status,
            "message": message,
        }

    def _touch(self, note: str, count: int, interval: int = 200) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)
