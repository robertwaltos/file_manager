
"""
File discovery and metadata scanning utilities.
"""

from __future__ import annotations

import fnmatch
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional

from config import AppConfig
from database import DatabaseManager, FileRecord
from utils import ResourceMonitor


class Scanner:
    """Scan file trees and emit normalized metadata records."""

    def __init__(self, config: AppConfig, db_manager: DatabaseManager) -> None:
        self.config = config
        self.db_manager = db_manager
        self.skip_hidden = bool(self.config.get("scan", "skip_hidden", default=True))
        self.follow_symlinks = bool(self.config.get("scan", "follow_symlinks", default=False))
        self.incremental = bool(self.config.get("scan", "incremental", default=False))
        self.excluded_paths = [
            Path(path) for path in self.config.get("exclusions", "system_paths", default=[])
        ]
        self.excluded_patterns = self.config.get("exclusions", "file_patterns", default=[])
        self.scan_threads = int(self.config.get("resource_limits", "threads", "scanning", default=4))

    def scan(self, root: Path, monitor: Optional[ResourceMonitor] = None) -> Iterable[FileRecord]:
        """Scan a root path and yield file metadata records."""
        if not root.exists():
            return []
        if self.scan_threads <= 1:
            return self._scan_sequential(root)
        return self._scan_threaded(root, monitor)

    def _scan_sequential(self, root: Path) -> Iterable[FileRecord]:
        for entry in self._iter_files(root):
            file_path = str(entry)
            if not self.incremental and self.db_manager.file_exists(file_path):
                continue
            record = self._build_record(entry)
            self._handle_permission_issue(record, context="scan")
            yield record

    def _scan_threaded(self, root: Path, monitor: Optional[ResourceMonitor]) -> Iterable[FileRecord]:
        pending = []
        max_pending = max(self.scan_threads * 2, 1)
        with ThreadPoolExecutor(max_workers=self.scan_threads) as executor:
            for entry in self._iter_files(root):
                file_path = str(entry)
                if not self.incremental and self.db_manager.file_exists(file_path):
                    continue
                if monitor is not None:
                    monitor.throttle()
                pending.append(executor.submit(self._build_record, entry))
                if len(pending) >= max_pending:
                    yield from self._drain_futures(pending, self.scan_threads)
                    pending = pending[self.scan_threads :]
            if pending:
                yield from self._drain_futures(pending, len(pending))

    def _drain_futures(self, pending: list, limit: int) -> Iterable[FileRecord]:
        for future in as_completed(pending[:limit]):
            record = future.result()
            self._handle_permission_issue(record, context="scan")
            yield record

    def _iter_files(self, root: Path) -> Iterator[Path]:
        """Yield file paths under a root, handling permission errors."""
        def on_error(error: OSError) -> None:
            if isinstance(error, PermissionError):
                self.db_manager.record_permission_issue(str(error.filename), str(error), "scan")

        for dirpath, dirnames, filenames in os.walk(
            root, topdown=True, onerror=on_error, followlinks=self.follow_symlinks
        ):
            current = Path(dirpath)
            if self._is_hidden(current) or self._is_excluded(current):
                dirnames[:] = []
                continue
            dirnames[:] = [
                name
                for name in dirnames
                if not self._is_hidden(current / name) and not self._is_excluded(current / name)
            ]
            for filename in filenames:
                file_path = Path(dirpath) / filename
                if not self.follow_symlinks and file_path.is_symlink():
                    continue
                if self._is_hidden(file_path) or self._is_excluded(file_path):
                    continue
                yield file_path

    def _handle_permission_issue(self, record: FileRecord, context: str) -> None:
        if record.accessible or not record.permission_error:
            return
        self.db_manager.record_permission_issue(record.file_path, record.permission_error, context)

    def _is_hidden(self, path: Path) -> bool:
        """Return True if the path is hidden and hidden files should be skipped."""
        if not self.skip_hidden:
            return False
        return any(part.startswith(".") for part in path.parts)

    def _is_excluded(self, path: Path) -> bool:
        """Return True when a path matches excluded directories or patterns."""
        if self._matches_excluded_paths(path):
            return True
        return self._matches_patterns(path)

    def _matches_excluded_paths(self, path: Path) -> bool:
        """Check whether the path sits under an excluded path prefix."""
        path_value = os.path.normcase(os.path.normpath(str(path)))
        for excluded in self.excluded_paths:
            excluded_value = os.path.normcase(os.path.normpath(str(excluded)))
            if path_value == excluded_value:
                return True
            if path_value.startswith(excluded_value.rstrip(os.sep) + os.sep):
                return True
        return False

    def _matches_patterns(self, path: Path) -> bool:
        """Check for filename or path matches against excluded patterns."""
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if fnmatch.fnmatch(str(path), pattern):
                return True
        return False

    def _build_record(self, path: Path) -> FileRecord:
        """Create a FileRecord from a filesystem path."""
        scan_date = datetime.utcnow().isoformat()
        try:
            stat = path.stat()
            return FileRecord(
                file_path=str(path),
                file_name=path.name,
                size=stat.st_size,
                creation_date=datetime.fromtimestamp(stat.st_ctime).isoformat(),
                modification_date=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                scan_date=scan_date,
                accessible=True,
                permission_error=None,
            )
        except (OSError, PermissionError) as exc:
            return FileRecord(
                file_path=str(path),
                file_name=path.name,
                size=0,
                creation_date="",
                modification_date="",
                scan_date=scan_date,
                accessible=False,
                permission_error=str(exc),
            )

    def build_record(self, path: Path) -> FileRecord:
        """Public wrapper for building a FileRecord."""
        return self._build_record(path)
