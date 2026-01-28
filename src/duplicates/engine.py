"""
Duplicate detection and reporting engine.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from config import AppConfig, ensure_directories
from database import DatabaseManager, DuplicateCandidate, FileMetadata
from hashing.hasher import Hasher
from metadata import MetadataScorer
from utils import ActivityTracker, ResourceMonitor


@dataclass
class DuplicateStats:
    """Summary statistics for duplicate detection."""

    candidate_groups: int
    duplicate_groups: int
    duplicate_files: int
    skipped_candidates: int
    error_files: int
    report_path: Path


class DuplicateEngine:
    """Detect duplicates and generate a JSON report."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
        logger: Optional[logging.Logger],
        monitor: Optional[ResourceMonitor] = None,
        activity_tracker: Optional[ActivityTracker] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.monitor = monitor
        self.activity_tracker = activity_tracker
        self.checkpoint_interval = int(
            self.config.get("safety", "checkpoint_interval_seconds", default=300)
        )
        self.checkpoint_after_groups = int(self.config.get("safety", "checkpoint_after_files", default=500))
        self.progress_log_interval = int(
            self.config.get("duplicates", "progress_log_interval", default=1000)
        )
        self.hasher = Hasher(
            full_hash_max_bytes=int(
                self.config.get("hashing", "full_hash_max_bytes", default=100 * 1024 * 1024)
            ),
            hybrid_chunk_bytes=int(self.config.get("hashing", "hybrid_chunk_bytes", default=1024 * 1024)),
        )
        self.primary_locations = self.config.get(
            "duplicates", "primary_locations", default=["Documents", "Pictures", "Desktop"]
        )
        self.google_drive_marker = str(
            self.config.get("duplicates", "google_drive_marker", default="Google Drive")
        )
        self.metadata_scorer = MetadataScorer()

    def run(
        self,
        operation_id: str,
        candidates: Optional[Iterable[tuple[str, int]]] = None,
    ) -> DuplicateStats:
        """Run duplicate detection and emit a JSON report."""
        report_dir = self.config.resolve_path(
            "paths", "duplicates_backup", default="data/duplicates_backup"
        )
        ensure_directories([report_dir])

        candidate_groups = 0
        duplicate_groups = 0
        duplicate_files = 0
        skipped_candidates = 0
        error_files = 0
        last_checkpoint_time = time.monotonic()

        report_groups: list[dict] = []
        skipped: list[dict] = []

        total_groups: Optional[int] = None
        if candidates is None:
            candidate_iter = (
                (candidate.file_name, candidate.size)
                for candidate in self.db_manager.iter_duplicate_candidates()
            )
        else:
            candidate_iter = list({(name, size) for name, size in candidates})
            total_groups = len(candidate_iter)

        for index, (file_name, size) in enumerate(candidate_iter, start=1):
            candidate_groups += 1
            files = self.db_manager.fetch_files_by_name_size(file_name, size)
            if len(files) < 2:
                skipped_candidates += 1
                continue
            self._touch("duplicates", index, interval=200)
            candidate = DuplicateCandidate(file_name=file_name, size=size, count=len(files))
            groups, skipped_info, errors = self._evaluate_candidate(candidate, files)
            report_groups.extend(groups)
            skipped.extend(skipped_info)
            duplicate_groups += len(groups)
            for group in groups:
                duplicate_files += len(group["duplicates"])
            error_files += errors
            self._log_progress(
                candidate_groups,
                total_groups,
                duplicate_groups,
                duplicate_files,
                skipped_candidates,
                error_files,
            )

            if self._should_checkpoint(candidate_groups, last_checkpoint_time):
                self.db_manager.save_checkpoint(
                    operation_id=operation_id,
                    phase="duplicates",
                    processed_files=candidate_groups,
                    total_files=None,
                    last_file_path=file_name,
                )
                last_checkpoint_time = time.monotonic()

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "operation_id": operation_id,
            "candidate_groups": candidate_groups,
            "duplicate_groups": duplicate_groups,
            "duplicate_files": duplicate_files,
            "skipped_candidates": skipped_candidates,
            "error_files": error_files,
            "groups": report_groups,
            "skipped": skipped,
        }

        report_path = report_dir / f"{self._report_prefix()}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        self.db_manager.update_operation_details(operation_id, str(report_path))

        return DuplicateStats(
            candidate_groups=candidate_groups,
            duplicate_groups=duplicate_groups,
            duplicate_files=duplicate_files,
            skipped_candidates=skipped_candidates,
            error_files=error_files,
            report_path=report_path,
        )

    def _evaluate_candidate(
        self, candidate: DuplicateCandidate, files: list[FileMetadata]
    ) -> tuple[list[dict], list[dict], int]:
        error_files = 0
        expected_hash_type = self.hasher.hash_type_for_size(candidate.size)
        hashed: list[tuple[FileMetadata, str]] = []
        skipped: list[dict] = []

        for file_meta in files:
            hash_value = self.db_manager.get_hash(file_meta.file_id, expected_hash_type)
            if not hash_value:
                skipped.append(
                    {
                        "file_path": file_meta.file_path,
                        "file_id": file_meta.file_id,
                        "reason": "missing_hash",
                    }
                )
                continue
            hashed.append((file_meta, hash_value))

        groups, error_files = self._group_by_hash(expected_hash_type, hashed, error_files)
        return groups, skipped, error_files

    def _group_by_hash(
        self,
        hash_type: str,
        hashed: list[tuple[FileMetadata, str]],
        error_files: int,
    ) -> tuple[list[dict], int]:
        grouped: dict[str, list[FileMetadata]] = {}
        for file_meta, hash_value in hashed:
            grouped.setdefault(hash_value, []).append(file_meta)

        groups: list[dict] = []
        for hash_value, files in grouped.items():
            if len(files) < 2:
                continue
            if hash_type == "sha256_hybrid":
                confirmed_groups, errors = self._confirm_full_hash(files)
                error_files += errors
                groups.extend(confirmed_groups)
            else:
                groups.append(self._build_group(hash_type, hash_value, files))
        return groups, error_files

    def _confirm_full_hash(self, files: list[FileMetadata]) -> tuple[list[dict], int]:
        error_files = 0
        grouped: dict[str, list[FileMetadata]] = {}
        for index, file_meta in enumerate(files, start=1):
            full_hash = self.db_manager.get_hash(file_meta.file_id, "sha256_full")
            if not full_hash:
                full_hash = self._compute_full_hash(file_meta)
            if not full_hash:
                error_files += 1
                continue
            self._touch("duplicates_full_hash", index, interval=100)
            grouped.setdefault(full_hash, []).append(file_meta)

        groups: list[dict] = []
        for hash_value, group_files in grouped.items():
            if len(group_files) < 2:
                continue
            groups.append(self._build_group("sha256_full", hash_value, group_files))
        return groups, error_files

    def _compute_full_hash(self, file_meta: FileMetadata) -> Optional[str]:
        file_path = Path(file_meta.file_path)
        try:
            if self.monitor is not None:
                self.monitor.throttle()
            file_size = file_path.stat().st_size
            full_hash = self.hasher.compute(file_path, file_size, "sha256_full")
            self.db_manager.insert_hash(file_meta.file_id, "sha256_full", full_hash)
            return full_hash
        except PermissionError as exc:
            self.db_manager.record_permission_issue(file_meta.file_path, str(exc), "duplicates")
            self.db_manager.record_corruption(file_meta.file_id, "permission_error", str(exc))
            self.logger.warning("Permission denied verifying %s: %s", file_meta.file_path, exc)
        except (OSError, IOError) as exc:
            self.db_manager.record_corruption(file_meta.file_id, "read_error", str(exc))
            self.logger.warning("Read error verifying %s: %s", file_meta.file_path, exc)
        return None

    def _build_group(self, hash_type: str, hash_value: str, files: list[FileMetadata]) -> dict:
        primary, reason = self._choose_primary(files)
        duplicates = [
            {
                "file_id": file_meta.file_id,
                "file_path": file_meta.file_path,
                "modification_date": file_meta.modification_date,
            }
            for file_meta in files
            if file_meta.file_id != primary.file_id
        ]
        return {
            "hash_type": hash_type,
            "hash_value": hash_value,
            "size": primary.size,
            "file_name": primary.file_name,
            "primary": {
                "file_id": primary.file_id,
                "file_path": primary.file_path,
                "modification_date": primary.modification_date,
                "reason": reason,
            },
            "duplicates": duplicates,
        }

    def _choose_primary(self, files: list[FileMetadata]) -> tuple[FileMetadata, str]:
        def normalize(value: str) -> str:
            return value.replace("\\", "/").lower()

        def priority(file_meta: FileMetadata) -> tuple[int, float, int, int]:
            path_norm = normalize(file_meta.file_path)
            marker_norm = normalize(self.google_drive_marker)
            is_google_drive = int(marker_norm in path_norm)
            is_primary = int(
                any(location.lower() in path_norm for location in self.primary_locations)
            )
            mod_time = self._parse_modification_time(file_meta.modification_date)
            metadata_score = self.metadata_scorer.score(Path(file_meta.file_path))
            return (is_google_drive, mod_time, metadata_score, is_primary)

        primary = max(files, key=priority)
        reasons = []
        metadata_score = self.metadata_scorer.score(Path(primary.file_path))
        if normalize(self.google_drive_marker) in normalize(primary.file_path):
            reasons.append("google_drive_priority")
        if self._parse_modification_time(primary.modification_date) > 0:
            reasons.append("newest_modification_date")
        if metadata_score > 0:
            reasons.append("metadata_richness")
        if any(location.lower() in normalize(primary.file_path) for location in self.primary_locations):
            reasons.append("primary_location")
        return primary, ", ".join(reasons) if reasons else "default_priority"

    def _parse_modification_time(self, value: str) -> float:
        if not value:
            return 0.0
        try:
            cleaned = str(value).strip()
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1] + "+00:00"
            return datetime.fromisoformat(cleaned).timestamp()
        except Exception:
            return 0.0

    def _touch(self, note: str, count: int, interval: int = 200) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

    def _log_progress(
        self,
        candidate_groups: int,
        total_groups: Optional[int],
        duplicate_groups: int,
        duplicate_files: int,
        skipped_candidates: int,
        error_files: int,
    ) -> None:
        if self.progress_log_interval <= 0:
            return
        if candidate_groups % self.progress_log_interval != 0:
            return
        total_label = total_groups if total_groups is not None else "?"
        self.logger.info(
            "Duplicate detection progress: %s/%s groups=%s dup_files=%s skipped=%s errors=%s",
            candidate_groups,
            total_label,
            duplicate_groups,
            duplicate_files,
            skipped_candidates,
            error_files,
        )

    def _report_prefix(self) -> str:
        return str(self.config.get("duplicates", "report_prefix", default="duplicate_report"))

    def _should_checkpoint(self, processed_groups: int, last_checkpoint_time: float) -> bool:
        if processed_groups % self.checkpoint_after_groups == 0:
            return True
        return (time.monotonic() - last_checkpoint_time) >= self.checkpoint_interval
