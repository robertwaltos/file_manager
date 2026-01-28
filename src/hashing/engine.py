"""
Hashing and corruption detection pipeline.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from config import AppConfig
from corruption.checker import CorruptionResult, IntegrityChecker
from database import DatabaseManager, InventoryEntry
from hashing.hasher import Hasher
from utils import ResourceMonitor


@dataclass
class HashingStats:
    """Summary statistics for a hashing run."""

    total_files: int
    processed_files: int
    hashed_files: int
    skipped_files: int
    corrupted_files: int
    error_files: int


@dataclass(frozen=True)
class HashJobResult:
    """Outcome of a hashing worker task."""

    entry: InventoryEntry
    hash_type: Optional[str]
    hash_value: Optional[str]
    corruption: Optional[CorruptionResult]
    error_type: Optional[str]
    error_message: Optional[str]


class HashingEngine:
    """Compute hashes for files and record corruption findings."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
        logger: logging.Logger,
        monitor: Optional[ResourceMonitor] = None,
        activity_tracker: Optional[object] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.logger = logger
        self.monitor = monitor
        self.activity_tracker = activity_tracker
        self.checkpoint_interval = int(
            self.config.get("safety", "checkpoint_interval_seconds", default=300)
        )
        self.checkpoint_after_files = int(self.config.get("safety", "checkpoint_after_files", default=500))
        self.hash_threads = int(self.config.get("resource_limits", "threads", "hashing", default=4))
        self.hash_exists_batch_size = int(
            self.config.get("hashing", "hash_exists_batch_size", default=1000)
        )
        self.hasher = Hasher(
            full_hash_max_bytes=int(
                self.config.get("hashing", "full_hash_max_bytes", default=100 * 1024 * 1024)
            ),
            hybrid_chunk_bytes=int(self.config.get("hashing", "hybrid_chunk_bytes", default=1024 * 1024)),
        )
        self.integrity_checker = IntegrityChecker(logger=self.logger)

    def run(self, operation_id: str) -> HashingStats:
        """Run the hashing pipeline and persist checkpoints."""
        total_files = self.db_manager.count_inventory(accessible_only=True)
        entries = self.db_manager.iter_inventory(accessible_only=True)
        return self._run_entries(operation_id, entries, total_files)

    def run_for_entries(self, operation_id: str, entries: Iterable[InventoryEntry]) -> HashingStats:
        """Run hashing for a subset of inventory entries."""
        entry_list = [entry for entry in entries if entry.accessible]
        return self._run_entries(operation_id, entry_list, len(entry_list))

    def _run_entries(
        self,
        operation_id: str,
        entries: Iterable[InventoryEntry],
        total_files: int,
    ) -> HashingStats:
        processed_files = 0
        hashed_files = 0
        skipped_files = 0
        corrupted_files = 0
        error_files = 0
        last_checkpoint_time = time.monotonic()
        last_file_path: Optional[str] = None

        if self.hash_threads <= 1:
            for entry, expected_hash_type, has_hash in self._iter_entries_with_hash_cache(entries):
                if has_hash:
                    skipped_files += 1
                    processed_files += 1
                    if self._checkpoint_if_needed(
                        operation_id, processed_files, total_files, entry.file_path, last_checkpoint_time
                    ):
                        last_checkpoint_time = time.monotonic()
                    continue
                result = self._process_entry(entry)
                (
                    processed_files,
                    hashed_files,
                    skipped_files,
                    corrupted_files,
                    error_files,
                    last_file_path,
                    last_checkpoint_time,
                ) = self._handle_result(
                    result,
                    processed_files,
                    hashed_files,
                    skipped_files,
                    corrupted_files,
                    error_files,
                    operation_id,
                    total_files,
                    last_checkpoint_time,
                )
        else:
            pending = []
            max_pending = max(self.hash_threads * 2, 1)
            with ThreadPoolExecutor(max_workers=self.hash_threads) as executor:
                for entry, expected_hash_type, has_hash in self._iter_entries_with_hash_cache(entries):
                    if has_hash:
                        skipped_files += 1
                        processed_files += 1
                        if self._checkpoint_if_needed(
                            operation_id, processed_files, total_files, entry.file_path, last_checkpoint_time
                        ):
                            last_checkpoint_time = time.monotonic()
                        continue
                    if self.monitor is not None:
                        self.monitor.throttle()
                    pending.append(executor.submit(self._process_entry, entry))
                    if len(pending) >= max_pending:
                        for result in self._drain_futures(pending, self.hash_threads):
                            (
                                processed_files,
                                hashed_files,
                                skipped_files,
                                corrupted_files,
                                error_files,
                                last_file_path,
                                last_checkpoint_time,
                            ) = self._handle_result(
                                result,
                                processed_files,
                                hashed_files,
                                skipped_files,
                                corrupted_files,
                                error_files,
                                operation_id,
                                total_files,
                                last_checkpoint_time,
                            )
                        pending = pending[self.hash_threads :]
                for result in self._drain_futures(pending, len(pending)):
                    (
                        processed_files,
                        hashed_files,
                        skipped_files,
                        corrupted_files,
                        error_files,
                        last_file_path,
                        last_checkpoint_time,
                    ) = self._handle_result(
                        result,
                        processed_files,
                        hashed_files,
                        skipped_files,
                        corrupted_files,
                        error_files,
                        operation_id,
                        total_files,
                        last_checkpoint_time,
                    )

        self.db_manager.save_checkpoint(
            operation_id=operation_id,
            phase="hashing",
            processed_files=processed_files,
            total_files=total_files,
            last_file_path=last_file_path,
            extra={
                "hashed_files": hashed_files,
                "skipped_files": skipped_files,
                "corrupted_files": corrupted_files,
                "error_files": error_files,
            },
        )

        return HashingStats(
            total_files=total_files,
            processed_files=processed_files,
            hashed_files=hashed_files,
            skipped_files=skipped_files,
            corrupted_files=corrupted_files,
            error_files=error_files,
        )

    def _iter_entries_with_hash_cache(
        self, entries: Iterable[InventoryEntry]
    ) -> Iterable[tuple[InventoryEntry, str, bool]]:
        batch: list[InventoryEntry] = []
        batch_size = max(self.hash_exists_batch_size, 1)
        for entry in entries:
            batch.append(entry)
            if len(batch) >= batch_size:
                yield from self._yield_entries_with_hash_status(batch)
                batch = []
        if batch:
            yield from self._yield_entries_with_hash_status(batch)

    def _yield_entries_with_hash_status(
        self, batch: list[InventoryEntry]
    ) -> Iterable[tuple[InventoryEntry, str, bool]]:
        groups: dict[str, list[InventoryEntry]] = {}
        for entry in batch:
            hash_type = self.hasher.hash_type_for_size(entry.size)
            groups.setdefault(hash_type, []).append(entry)
        existing: dict[str, set[int]] = {}
        for hash_type, group_entries in groups.items():
            ids = [entry.file_id for entry in group_entries]
            existing[hash_type] = self.db_manager.fetch_hash_file_ids(ids, hash_type)
        for entry in batch:
            hash_type = self.hasher.hash_type_for_size(entry.size)
            has_hash = entry.file_id in existing.get(hash_type, set())
            yield entry, hash_type, has_hash

    def _process_entry(self, entry: InventoryEntry) -> HashJobResult:
        file_path = Path(entry.file_path)
        try:
            file_size = file_path.stat().st_size
        except FileNotFoundError as exc:
            return HashJobResult(entry, None, None, None, "missing_file", str(exc))
        except PermissionError as exc:
            return HashJobResult(entry, None, None, None, "permission_error", str(exc))
        except OSError as exc:
            return HashJobResult(entry, None, None, None, "read_error", str(exc))

        hash_type = self.hasher.hash_type_for_size(file_size)
        try:
            hash_value = self.hasher.compute(file_path, file_size, hash_type)
        except PermissionError as exc:
            return HashJobResult(entry, None, None, None, "permission_error", str(exc))
        except (OSError, IOError) as exc:
            return HashJobResult(entry, None, None, None, "read_error", str(exc))

        corruption = self.integrity_checker.check(file_path)
        return HashJobResult(entry, hash_type, hash_value, corruption, None, None)

    def _drain_futures(self, pending: list, limit: int) -> Iterable[HashJobResult]:
        for future in as_completed(pending[:limit]):
            yield future.result()

    def _handle_result(
        self,
        result: HashJobResult,
        processed_files: int,
        hashed_files: int,
        skipped_files: int,
        corrupted_files: int,
        error_files: int,
        operation_id: str,
        total_files: int,
        last_checkpoint_time: float,
    ) -> tuple[int, int, int, int, int, Optional[str], float]:
        last_file_path: Optional[str] = None
        entry = result.entry
        if result.error_type:
            error_files += 1
            last_file_path = entry.file_path
            if result.error_type == "permission_error":
                self.db_manager.update_file_access(entry.file_id, False, result.error_message)
                self.db_manager.record_permission_issue(entry.file_path, result.error_message or "", "hashing")
            self.db_manager.record_corruption(entry.file_id, result.error_type, result.error_message or "")
            self.logger.warning("Hashing error (%s) for %s: %s", result.error_type, entry.file_path, result.error_message)
            processed_files += 1
        else:
            if result.hash_type and result.hash_value:
                self.db_manager.insert_hash(entry.file_id, result.hash_type, result.hash_value)
                hashed_files += 1
                last_file_path = entry.file_path
            if result.corruption is not None:
                self.db_manager.record_corruption(
                    entry.file_id,
                    result.corruption.error_type,
                    result.corruption.error_message,
                )
                corrupted_files += 1
            processed_files += 1

        if self._checkpoint_if_needed(
            operation_id, processed_files, total_files, last_file_path, last_checkpoint_time
        ):
            last_checkpoint_time = time.monotonic()
        if self.activity_tracker is not None:
            self.activity_tracker.touch("hashing")
        return (
            processed_files,
            hashed_files,
            skipped_files,
            corrupted_files,
            error_files,
            last_file_path,
            last_checkpoint_time,
        )

    def _checkpoint_if_needed(
        self,
        operation_id: str,
        processed_files: int,
        total_files: int,
        last_file_path: Optional[str],
        last_checkpoint_time: float,
    ) -> bool:
        if not self._should_checkpoint(processed_files, last_checkpoint_time):
            return False
        self.db_manager.save_checkpoint(
            operation_id=operation_id,
            phase="hashing",
            processed_files=processed_files,
            total_files=total_files,
            last_file_path=last_file_path,
        )
        return True

    def _should_checkpoint(self, processed_files: int, last_checkpoint_time: float) -> bool:
        if processed_files % self.checkpoint_after_files == 0:
            return True
        return (time.monotonic() - last_checkpoint_time) >= self.checkpoint_interval
