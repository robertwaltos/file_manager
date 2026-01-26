"""
SQLite database access layer for file inventory, hashing, and state persistence.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional

from .schema import create_databases


@dataclass(frozen=True)
class FileRecord:
    """Normalized metadata for a scanned file."""

    file_path: str
    file_name: str
    size: int
    creation_date: str
    modification_date: str
    scan_date: str
    accessible: bool
    permission_error: Optional[str]


@dataclass(frozen=True)
class FileUpsertResult:
    """Result of inserting or updating a file record."""

    file_id: int
    changed: bool
    existed: bool


@dataclass(frozen=True)
class InventoryEntry:
    """Lightweight record used for iterating over inventory rows."""

    file_id: int
    file_path: str
    size: int
    accessible: bool


@dataclass(frozen=True)
class FileMetadata:
    """Metadata needed for duplicate detection."""

    file_id: int
    file_path: str
    size: int
    modification_date: str
    file_name: str


@dataclass(frozen=True)
class DuplicateCandidate:
    """Candidate grouping for duplicate detection."""

    file_name: str
    size: int
    count: int


class DatabaseManager:
    """Manage SQLite connections and common queries."""

    def __init__(self, db_paths: Dict[str, Path]) -> None:
        self.db_paths = db_paths
        self._inventory_conn: Optional[sqlite3.Connection] = None
        self._state_conn: Optional[sqlite3.Connection] = None
        self._hash_conn: Optional[sqlite3.Connection] = None
        self._ai_conn: Optional[sqlite3.Connection] = None

    def initialize(self) -> None:
        """Create database files and tables."""
        create_databases(self.db_paths)

    def connect(self) -> None:
        """Open database connections if they are not already open."""
        if self._inventory_conn is None:
            self._inventory_conn = sqlite3.connect(self.db_paths["file_inventory"], check_same_thread=False)
            self._inventory_conn.execute("PRAGMA journal_mode=WAL;")
        if self._state_conn is None:
            self._state_conn = sqlite3.connect(self.db_paths["state"], check_same_thread=False)
            self._state_conn.execute("PRAGMA journal_mode=WAL;")
        if self._hash_conn is None:
            self._hash_conn = sqlite3.connect(self.db_paths["hash_database"], check_same_thread=False)
            self._hash_conn.execute("PRAGMA journal_mode=WAL;")
        if self._ai_conn is None:
            self._ai_conn = sqlite3.connect(self.db_paths["ai_classifications"], check_same_thread=False)
            self._ai_conn.execute("PRAGMA journal_mode=WAL;")

    def close(self) -> None:
        """Close any open database connections."""
        if self._inventory_conn is not None:
            self._inventory_conn.close()
            self._inventory_conn = None
        if self._state_conn is not None:
            self._state_conn.close()
            self._state_conn = None
        if self._hash_conn is not None:
            self._hash_conn.close()
            self._hash_conn = None
        if self._ai_conn is not None:
            self._ai_conn.close()
            self._ai_conn = None

    def normalize_drive_key(self, root: Path) -> str:
        """Normalize a scan root into a drive key."""
        if root.drive:
            return root.drive.upper()
        try:
            return str(root.resolve()).lower()
        except OSError:
            return str(root).lower()

    def file_exists(self, file_path: str) -> bool:
        """Check whether a file already exists in the inventory."""
        self.connect()
        cursor = self._inventory_conn.execute(
            "SELECT 1 FROM files WHERE file_path = ? LIMIT 1",
            (file_path,),
        )
        return cursor.fetchone() is not None

    def upsert_file(self, record: FileRecord) -> int:
        """Insert or update file metadata and return the record ID."""
        result = self.upsert_file_with_status(record)
        return result.file_id

    def upsert_file_with_status(self, record: FileRecord) -> FileUpsertResult:
        """Insert or update file metadata and return status details."""
        self.connect()
        existing = self._inventory_conn.execute(
            "SELECT id, size, modification_date FROM files WHERE file_path = ?",
            (record.file_path,),
        ).fetchone()

        if existing:
            file_id = int(existing[0])
            old_size = int(existing[1]) if existing[1] is not None else 0
            old_mod = str(existing[2]) if existing[2] else ""
            changed = old_size != record.size or old_mod != record.modification_date
            self._inventory_conn.execute(
                """
                UPDATE files
                SET file_name = ?,
                    size = ?,
                    creation_date = ?,
                    modification_date = ?,
                    scan_date = ?,
                    accessible = ?,
                    permission_error = ?
                WHERE id = ?
                """,
                (
                    record.file_name,
                    record.size,
                    record.creation_date,
                    record.modification_date,
                    record.scan_date,
                    1 if record.accessible else 0,
                    record.permission_error,
                    file_id,
                ),
            )
            self._inventory_conn.commit()
            return FileUpsertResult(file_id=file_id, changed=changed, existed=True)

        cursor = self._inventory_conn.execute(
            """
            INSERT INTO files (
                file_path,
                file_name,
                size,
                creation_date,
                modification_date,
                scan_date,
                accessible,
                permission_error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.file_path,
                record.file_name,
                record.size,
                record.creation_date,
                record.modification_date,
                record.scan_date,
                1 if record.accessible else 0,
                record.permission_error,
            ),
        )
        self._inventory_conn.commit()
        file_id = int(cursor.lastrowid)
        return FileUpsertResult(file_id=file_id, changed=True, existed=False)

    def update_file_access(self, file_id: int, accessible: bool, permission_error: Optional[str]) -> None:
        """Update access flags for a file record."""
        self.connect()
        self._inventory_conn.execute(
            """
            UPDATE files
            SET accessible = ?, permission_error = ?
            WHERE id = ?
            """,
            (1 if accessible else 0, permission_error, file_id),
        )
        self._inventory_conn.commit()

    def invalidate_hashes(self, file_id: int) -> None:
        """Remove hashes and corruption records for a file."""
        self.connect()
        self._hash_conn.execute("DELETE FROM hashes WHERE file_id = ?", (file_id,))
        self._hash_conn.execute("DELETE FROM corruptions WHERE file_id = ?", (file_id,))
        self._hash_conn.commit()
        if self._ai_conn is not None:
            self._ai_conn.execute("DELETE FROM classifications WHERE file_id = ?", (file_id,))
            self._ai_conn.commit()

    def iter_inventory(self, accessible_only: bool = True) -> Iterable[InventoryEntry]:
        """Yield inventory entries for processing."""
        self.connect()
        query = "SELECT id, file_path, size, accessible FROM files"
        params: tuple = ()
        if accessible_only:
            query += " WHERE accessible = 1"
        cursor = self._inventory_conn.execute(query, params)
        for file_id, file_path, size, accessible in cursor:
            yield InventoryEntry(
                file_id=int(file_id),
                file_path=str(file_path),
                size=int(size) if size is not None else 0,
                accessible=bool(accessible),
            )

    def iter_duplicate_candidates(self) -> Iterable[DuplicateCandidate]:
        """Yield duplicate candidate groupings based on file name and size."""
        self.connect()
        cursor = self._inventory_conn.execute(
            """
            SELECT file_name, size, COUNT(*) as cnt
            FROM files
            WHERE accessible = 1 AND file_name IS NOT NULL
            GROUP BY file_name, size
            HAVING cnt > 1
            """
        )
        for file_name, size, count in cursor:
            yield DuplicateCandidate(
                file_name=str(file_name),
                size=int(size) if size is not None else 0,
                count=int(count),
            )

    def fetch_files_by_name_size(self, file_name: str, size: int) -> list[FileMetadata]:
        """Fetch files matching a given name and size."""
        self.connect()
        cursor = self._inventory_conn.execute(
            """
            SELECT id, file_path, size, modification_date, file_name
            FROM files
            WHERE accessible = 1 AND file_name = ? AND size = ?
            """,
            (file_name, size),
        )
        return [
            FileMetadata(
                file_id=int(row[0]),
                file_path=str(row[1]),
                size=int(row[2]) if row[2] is not None else 0,
                modification_date=str(row[3]) if row[3] else "",
                file_name=str(row[4]) if row[4] else "",
            )
            for row in cursor.fetchall()
        ]

    def count_inventory(self, accessible_only: bool = True) -> int:
        """Count inventory entries."""
        self.connect()
        query = "SELECT COUNT(*) FROM files"
        if accessible_only:
            query += " WHERE accessible = 1"
        cursor = self._inventory_conn.execute(query)
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def hash_exists(self, file_id: int, hash_type: str) -> bool:
        """Check whether a hash record exists for a file."""
        self.connect()
        cursor = self._hash_conn.execute(
            "SELECT 1 FROM hashes WHERE file_id = ? AND hash_type = ? LIMIT 1",
            (file_id, hash_type),
        )
        return cursor.fetchone() is not None

    def get_hash(self, file_id: int, hash_type: str) -> Optional[str]:
        """Retrieve a hash value for a file."""
        self.connect()
        cursor = self._hash_conn.execute(
            "SELECT hash_value FROM hashes WHERE file_id = ? AND hash_type = ? LIMIT 1",
            (file_id, hash_type),
        )
        row = cursor.fetchone()
        return str(row[0]) if row else None

    def insert_hash(self, file_id: int, hash_type: str, hash_value: str) -> None:
        """Insert or update a hash record."""
        self.connect()
        cursor = self._hash_conn.execute(
            "SELECT id FROM hashes WHERE file_id = ? AND hash_type = ? LIMIT 1",
            (file_id, hash_type),
        )
        row = cursor.fetchone()
        if row:
            self._hash_conn.execute(
                "UPDATE hashes SET hash_value = ? WHERE file_id = ? AND hash_type = ?",
                (hash_value, file_id, hash_type),
            )
        else:
            self._hash_conn.execute(
                "INSERT INTO hashes (file_id, hash_type, hash_value) VALUES (?, ?, ?)",
                (file_id, hash_type, hash_value),
            )
        self._hash_conn.commit()

    def record_corruption(self, file_id: int, error_type: str, error_message: str) -> None:
        """Record a corruption finding for a file."""
        self.connect()
        self._hash_conn.execute(
            """
            INSERT INTO corruptions (file_id, error_type, error_message, detected_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
                error_type = excluded.error_type,
                error_message = excluded.error_message,
                detected_at = excluded.detected_at
            """,
            (file_id, error_type, error_message, datetime.utcnow().isoformat()),
        )
        self._hash_conn.commit()

    def corruption_exists(self, file_id: int) -> bool:
        """Return True if a corruption record exists for a file."""
        self.connect()
        cursor = self._hash_conn.execute(
            "SELECT 1 FROM corruptions WHERE file_id = ? LIMIT 1",
            (file_id,),
        )
        return cursor.fetchone() is not None

    def record_permission_issue(self, file_path: str, error_message: str, context: str) -> None:
        """Insert or update a permission issue record."""
        self.connect()
        self._state_conn.execute(
            """
            INSERT INTO permission_issues (
                file_path, error_message, context, attempts, last_attempt, resolved
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                error_message = excluded.error_message,
                context = excluded.context,
                attempts = permission_issues.attempts + 1,
                last_attempt = excluded.last_attempt,
                resolved = 0
            """,
            (file_path, error_message, context, 1, datetime.utcnow().isoformat(), 0),
        )
        self._state_conn.commit()

    def resolve_permission_issue(self, file_path: str) -> None:
        """Mark a permission issue as resolved."""
        self.connect()
        self._state_conn.execute(
            """
            UPDATE permission_issues
            SET resolved = 1
            WHERE file_path = ?
            """,
            (file_path,),
        )
        self._state_conn.commit()

    def count_permission_issues(self, resolved: bool = False) -> int:
        """Count permission issues filtered by resolved status."""
        self.connect()
        cursor = self._state_conn.execute(
            "SELECT COUNT(*) FROM permission_issues WHERE resolved = ?",
            (1 if resolved else 0,),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def list_permission_issues(self, resolved: bool = False, limit: Optional[int] = None) -> list[dict]:
        """List permission issues for retry handling."""
        self.connect()
        query = """
            SELECT file_path, error_message, context, attempts, last_attempt
            FROM permission_issues
            WHERE resolved = ?
            ORDER BY last_attempt DESC
        """
        params: list = [1 if resolved else 0]
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        cursor = self._state_conn.execute(query, tuple(params))
        return [
            {
                "file_path": str(row[0]),
                "error_message": str(row[1]) if row[1] else "",
                "context": str(row[2]) if row[2] else "",
                "attempts": int(row[3]) if row[3] is not None else 0,
                "last_attempt": str(row[4]) if row[4] else "",
            }
            for row in cursor.fetchall()
        ]

    def is_drive_completed(self, drive_key: str) -> bool:
        """Return True if a drive is marked completed."""
        self.connect()
        cursor = self._state_conn.execute(
            "SELECT status FROM drive_runs WHERE drive_key = ?",
            (drive_key,),
        )
        row = cursor.fetchone()
        return bool(row and row[0] == "completed")

    def mark_drive_completed(self, drive_key: str, notes: Optional[str] = None) -> None:
        """Mark a drive as completed."""
        self.connect()
        timestamp = datetime.utcnow().isoformat()
        self._state_conn.execute(
            """
            INSERT INTO drive_runs (drive_key, status, completed_at, last_scan, notes)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(drive_key) DO UPDATE SET
                status = excluded.status,
                completed_at = excluded.completed_at,
                last_scan = excluded.last_scan,
                notes = excluded.notes
            """,
            (drive_key, "completed", timestamp, timestamp, notes),
        )
        self._state_conn.commit()

    def list_completed_drives(self) -> list[str]:
        """List drive keys marked as completed."""
        self.connect()
        cursor = self._state_conn.execute(
            "SELECT drive_key FROM drive_runs WHERE status = 'completed'"
        )
        return [str(row[0]) for row in cursor.fetchall()]

    def ensure_task(self, task_id: str, name: str, depends_on: Optional[list[str]] = None) -> None:
        """Ensure a task exists in the queue."""
        self.connect()
        depends_json = json.dumps(depends_on or [])
        existing = self._state_conn.execute(
            "SELECT status FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        now = datetime.utcnow().isoformat()
        if existing:
            self._state_conn.execute(
                """
                UPDATE task_queue
                SET name = ?, depends_on = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (name, depends_json, now, task_id),
            )
        else:
            self._state_conn.execute(
                """
                INSERT INTO task_queue (
                    task_id, name, status, depends_on, created_at, updated_at, attempts, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (task_id, name, "pending", depends_json, now, now, 0, None),
            )
        self._state_conn.commit()

    def update_task_status(self, task_id: str, status: str, last_error: Optional[str] = None) -> None:
        """Update status for a queued task."""
        self.connect()
        now = datetime.utcnow().isoformat()
        if status == "in_progress":
            self._state_conn.execute(
                """
                UPDATE task_queue
                SET status = ?, updated_at = ?, attempts = attempts + 1, last_error = NULL
                WHERE task_id = ?
                """,
                (status, now, task_id),
            )
        else:
            self._state_conn.execute(
                """
                UPDATE task_queue
                SET status = ?, updated_at = ?, last_error = ?
                WHERE task_id = ?
                """,
                (status, now, last_error, task_id),
            )
        self._state_conn.commit()

    def get_task_status(self, task_id: str) -> Optional[str]:
        """Fetch the current status for a task."""
        self.connect()
        row = self._state_conn.execute(
            "SELECT status FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return str(row[0]) if row else None

    def list_tasks(self) -> list[dict]:
        """Return all queued tasks."""
        self.connect()
        cursor = self._state_conn.execute(
            """
            SELECT task_id, name, status, depends_on, attempts, last_error, updated_at
            FROM task_queue
            ORDER BY created_at ASC
            """
        )
        tasks = []
        for task_id, name, status, depends_on, attempts, last_error, updated_at in cursor.fetchall():
            tasks.append(
                {
                    "task_id": str(task_id),
                    "name": str(name) if name else "",
                    "status": str(status) if status else "",
                    "depends_on": json.loads(depends_on) if depends_on else [],
                    "attempts": int(attempts) if attempts is not None else 0,
                    "last_error": str(last_error) if last_error else "",
                    "updated_at": str(updated_at) if updated_at else "",
                }
            )
        return tasks

    def task_status_summary(self) -> dict[str, int]:
        """Return counts of tasks grouped by status."""
        self.connect()
        cursor = self._state_conn.execute(
            "SELECT status, COUNT(*) FROM task_queue GROUP BY status"
        )
        return {str(row[0]): int(row[1]) for row in cursor.fetchall()}

    def reset_in_progress_tasks(self) -> None:
        """Reset in-progress tasks back to pending for resume."""
        self.connect()
        self._state_conn.execute(
            "UPDATE task_queue SET status = 'pending' WHERE status = 'in_progress'"
        )
        self._state_conn.commit()

    def reset_task_statuses(self) -> None:
        """Reset all task statuses to pending."""
        self.connect()
        self._state_conn.execute(
            "UPDATE task_queue SET status = 'pending'"
        )
        self._state_conn.commit()

    def record_file_operation(
        self,
        operation_id: str,
        action: str,
        source_path: str,
        destination_path: Optional[str],
        status: str,
        size: Optional[int] = None,
        rollback: Optional[dict] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Record a file operation for audit and rollback."""
        self.connect()
        rollback_json = json.dumps(rollback) if rollback else None
        self._state_conn.execute(
            """
            INSERT INTO file_operations (
                operation_id,
                action,
                source_path,
                destination_path,
                status,
                size,
                created_at,
                error_message,
                rollback_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                operation_id,
                action,
                source_path,
                destination_path,
                status,
                size,
                datetime.utcnow().isoformat(),
                error_message,
                rollback_json,
            ),
        )
        self._state_conn.commit()

    def list_file_operations(
        self, operation_id: Optional[str] = None, status: Optional[str] = None, limit: Optional[int] = None
    ) -> list[dict]:
        """List file operations, optionally filtered by operation ID or status."""
        self.connect()
        query = """
            SELECT id, operation_id, action, source_path, destination_path, status, size, created_at,
                   error_message, rollback_json
            FROM file_operations
        """
        params: list = []
        clauses: list[str] = []
        if operation_id:
            clauses.append("operation_id = ?")
            params.append(operation_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC"
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        cursor = self._state_conn.execute(query, tuple(params))
        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "id": int(row[0]),
                    "operation_id": str(row[1]) if row[1] else "",
                    "action": str(row[2]) if row[2] else "",
                    "source_path": str(row[3]) if row[3] else "",
                    "destination_path": str(row[4]) if row[4] else "",
                    "status": str(row[5]) if row[5] else "",
                    "size": int(row[6]) if row[6] is not None else None,
                    "created_at": str(row[7]) if row[7] else "",
                    "error_message": str(row[8]) if row[8] else "",
                    "rollback": json.loads(row[9]) if row[9] else None,
                }
            )
        return results

    def list_incomplete_file_operations(self) -> list[dict]:
        """Return file operations that are not completed."""
        return self.list_file_operations(status="in_progress")

    def count_hashes(self) -> int:
        """Count hash records."""
        self.connect()
        cursor = self._hash_conn.execute("SELECT COUNT(*) FROM hashes")
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def count_corruptions(self) -> int:
        """Count corruption records."""
        self.connect()
        cursor = self._hash_conn.execute("SELECT COUNT(*) FROM corruptions")
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def count_duplicate_candidates(self) -> int:
        """Count potential duplicate groups."""
        self.connect()
        cursor = self._inventory_conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT file_name, size, COUNT(*) AS cnt
                FROM files
                WHERE accessible = 1 AND file_name IS NOT NULL
                GROUP BY file_name, size
                HAVING cnt > 1
            )
            """
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def get_latest_operation_details(self, operation_type: str, status: str = "completed") -> Optional[str]:
        """Return the latest operation details payload for a given operation type."""
        self.connect()
        row = self._state_conn.execute(
            """
            SELECT details FROM operations
            WHERE operation_type = ? AND status = ?
            ORDER BY finished_at DESC
            LIMIT 1
            """,
            (operation_type, status),
        ).fetchone()
        return str(row[0]) if row and row[0] else None

    def list_recent_operations(self, limit: int = 20) -> list[dict]:
        """List recent operations sorted by start time."""
        self.connect()
        cursor = self._state_conn.execute(
            """
            SELECT operation_id, operation_type, status, started_at, finished_at, details
            FROM operations
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [
            {
                "operation_id": str(row[0]) if row[0] else "",
                "operation_type": str(row[1]) if row[1] else "",
                "status": str(row[2]) if row[2] else "",
                "started_at": str(row[3]) if row[3] else "",
                "finished_at": str(row[4]) if row[4] else "",
                "details": str(row[5]) if row[5] else "",
            }
            for row in cursor.fetchall()
        ]

    def classification_exists(self, file_id: int) -> bool:
        """Return True if a classification record exists for a file."""
        self.connect()
        cursor = self._ai_conn.execute(
            "SELECT 1 FROM classifications WHERE file_id = ? LIMIT 1",
            (file_id,),
        )
        return cursor.fetchone() is not None

    def upsert_classification(
        self,
        file_id: int,
        category: str,
        subcategory: str,
        tags: str,
        nsfw_score: Optional[float],
        model: str,
        confidence: Optional[float],
        details_json: Optional[str] = None,
    ) -> None:
        """Insert or update a classification entry."""
        self.connect()
        self._ai_conn.execute(
            """
            INSERT INTO classifications (
                file_id, category, subcategory, tags, nsfw_score, model, confidence, updated_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
                category = excluded.category,
                subcategory = excluded.subcategory,
                tags = excluded.tags,
                nsfw_score = excluded.nsfw_score,
                model = excluded.model,
                confidence = excluded.confidence,
                updated_at = excluded.updated_at,
                details_json = excluded.details_json
            """,
            (
                file_id,
                category,
                subcategory,
                tags,
                nsfw_score,
                model,
                confidence,
                datetime.utcnow().isoformat(),
                details_json,
            ),
        )
        self._ai_conn.commit()

    def list_nsfw_classifications(self, threshold: float) -> list[dict]:
        """List files with NSFW scores above the given threshold."""
        self.connect()
        cursor = self._ai_conn.execute(
            """
            SELECT file_id, nsfw_score
            FROM classifications
            WHERE nsfw_score IS NOT NULL AND nsfw_score >= ?
            """,
            (threshold,),
        )
        results = []
        for file_id, nsfw_score in cursor.fetchall():
            row = self._inventory_conn.execute(
                "SELECT file_path FROM files WHERE id = ?",
                (file_id,),
            ).fetchone()
            if not row:
                continue
            results.append(
                {
                    "file_id": int(file_id),
                    "file_path": str(row[0]),
                    "nsfw_score": float(nsfw_score) if nsfw_score is not None else None,
                }
            )
        return results

    def list_classifications(self) -> list[dict]:
        """Return classification records joined with file paths."""
        self.connect()
        cursor = self._ai_conn.execute(
            """
            SELECT file_id, category, subcategory, tags, nsfw_score, model, confidence, updated_at, details_json
            FROM classifications
            """
        )
        results = []
        for row in cursor.fetchall():
            file_id = int(row[0])
            path_row = self._inventory_conn.execute(
                "SELECT file_path, modification_date FROM files WHERE id = ?",
                (file_id,),
            ).fetchone()
            if not path_row:
                continue
            results.append(
                {
                    "file_id": file_id,
                    "file_path": str(path_row[0]),
                    "modification_date": str(path_row[1]) if path_row[1] else "",
                    "category": str(row[1]) if row[1] else "",
                    "subcategory": str(row[2]) if row[2] else "",
                    "tags": str(row[3]) if row[3] else "",
                    "nsfw_score": float(row[4]) if row[4] is not None else None,
                    "model": str(row[5]) if row[5] else "",
                    "confidence": float(row[6]) if row[6] is not None else None,
                    "updated_at": str(row[7]) if row[7] else "",
                    "details_json": str(row[8]) if row[8] else "",
                }
            )
        return results

    def fetch_inventory_entries_by_paths(self, file_paths: Iterable[str]) -> list[InventoryEntry]:
        """Fetch inventory entries for a list of file paths."""
        self.connect()
        entries: list[InventoryEntry] = []
        paths = list(dict.fromkeys(file_paths))
        for chunk in _chunked(paths, 900):
            placeholders = ",".join("?" for _ in chunk)
            cursor = self._inventory_conn.execute(
                f"""
                SELECT id, file_path, size, accessible
                FROM files
                WHERE file_path IN ({placeholders})
                """,
                chunk,
            )
            for file_id, file_path, size, accessible in cursor:
                entries.append(
                    InventoryEntry(
                        file_id=int(file_id),
                        file_path=str(file_path),
                        size=int(size) if size is not None else 0,
                        accessible=bool(accessible),
                    )
                )
        return entries

    def fetch_name_size_by_paths(self, file_paths: Iterable[str]) -> list[tuple[str, int]]:
        """Fetch file name and size for a list of file paths."""
        self.connect()
        results: list[tuple[str, int]] = []
        paths = list(dict.fromkeys(file_paths))
        for chunk in _chunked(paths, 900):
            placeholders = ",".join("?" for _ in chunk)
            cursor = self._inventory_conn.execute(
                f"""
                SELECT file_name, size
                FROM files
                WHERE file_path IN ({placeholders}) AND file_name IS NOT NULL
                """,
                chunk,
            )
            for file_name, size in cursor:
                if not file_name:
                    continue
                results.append((str(file_name), int(size) if size is not None else 0))
        return results

    def update_file_path(self, file_id: int, new_path: str) -> None:
        """Update a file path and name for an inventory entry."""
        self.connect()
        self._inventory_conn.execute(
            "UPDATE files SET file_path = ?, file_name = ? WHERE id = ?",
            (new_path, Path(new_path).name, file_id),
        )
        self._inventory_conn.commit()

    def get_file_id_by_path(self, file_path: str) -> Optional[int]:
        """Return the inventory file ID for a path."""
        self.connect()
        row = self._inventory_conn.execute(
            "SELECT id FROM files WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        return int(row[0]) if row else None

    def delete_file_by_path(self, file_path: str) -> None:
        """Remove a file and related records from the databases."""
        self.connect()
        cursor = self._inventory_conn.execute(
            "SELECT id FROM files WHERE file_path = ?",
            (file_path,),
        )
        row = cursor.fetchone()
        if not row:
            return
        file_id = int(row[0])
        self._inventory_conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        self._inventory_conn.commit()
        self._hash_conn.execute("DELETE FROM hashes WHERE file_id = ?", (file_id,))
        self._hash_conn.execute("DELETE FROM corruptions WHERE file_id = ?", (file_id,))
        self._hash_conn.commit()

    def list_corruptions(self, limit: Optional[int] = None) -> list[dict]:
        """List corrupted files and associated metadata."""
        self.connect()
        query = """
            SELECT file_id, error_type, error_message, detected_at
            FROM corruptions
            ORDER BY detected_at DESC
        """
        params: tuple = ()
        if limit:
            query += " LIMIT ?"
            params = (limit,)
        cursor = self._hash_conn.execute(query, params)
        results: list[dict] = []
        for file_id, error_type, error_message, detected_at in cursor.fetchall():
            inv = self._inventory_conn.execute(
                "SELECT file_path, accessible FROM files WHERE id = ?",
                (file_id,),
            ).fetchone()
            if not inv:
                continue
            file_path, accessible = inv
            results.append(
                {
                    "file_id": int(file_id),
                    "file_path": str(file_path),
                    "accessible": bool(accessible),
                    "error_type": str(error_type),
                    "error_message": str(error_message) if error_message else "",
                    "detected_at": str(detected_at) if detected_at else "",
                }
            )
        return results

    def mark_missing_files(self, scan_start: str) -> int:
        """Mark files as inaccessible if they were not seen during the scan."""
        self.connect()
        cursor = self._inventory_conn.execute(
            "SELECT id, file_path FROM files WHERE scan_date < ?",
            (scan_start,),
        )
        missing = 0
        for file_id, file_path in cursor.fetchall():
            path = Path(str(file_path))
            if path.exists():
                continue
            self._inventory_conn.execute(
                "UPDATE files SET accessible = 0, permission_error = ? WHERE id = ?",
                ("missing", int(file_id)),
            )
            missing += 1
        self._inventory_conn.commit()
        return missing

    def update_operation_details(self, operation_id: str, details: str) -> None:
        """Update the details field for an operation."""
        self.connect()
        self._state_conn.execute(
            "UPDATE operations SET details = ? WHERE operation_id = ?",
            (details, operation_id),
        )
        self._state_conn.commit()

    def start_operation(self, operation_type: str, details: Optional[str] = None) -> str:
        """Insert an operation record and return the generated operation ID."""
        self.connect()
        operation_id = f"{operation_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self._state_conn.execute(
            """
            INSERT INTO operations (
                operation_id, operation_type, status, started_at, details
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (operation_id, operation_type, "in_progress", datetime.utcnow().isoformat(), details),
        )
        self._state_conn.commit()
        return operation_id

    def complete_operation(self, operation_id: str, status: str = "completed") -> None:
        """Mark an operation as completed or failed."""
        self.connect()
        self._state_conn.execute(
            """
            UPDATE operations
            SET status = ?, finished_at = ?
            WHERE operation_id = ?
            """,
            (status, datetime.utcnow().isoformat(), operation_id),
        )
        self._state_conn.commit()

    def list_incomplete_operations(self) -> list[tuple[str, str, str]]:
        """Return operation records that are still in progress."""
        self.connect()
        cursor = self._state_conn.execute(
            """
            SELECT operation_id, operation_type, started_at
            FROM operations
            WHERE status = 'in_progress'
            ORDER BY started_at DESC
            """
        )
        return list(cursor.fetchall())

    def get_latest_incomplete_operation(self, operation_type: str) -> Optional[dict]:
        """Return the most recent in-progress operation for a given type."""
        self.connect()
        cursor = self._state_conn.execute(
            """
            SELECT operation_id, started_at, details
            FROM operations
            WHERE status = 'in_progress' AND operation_type = ?
            ORDER BY started_at DESC
            LIMIT 1
            """,
            (operation_type,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {"operation_id": row[0], "started_at": row[1], "details": row[2]}

    def save_checkpoint(
        self,
        operation_id: str,
        phase: str,
        processed_files: int,
        total_files: Optional[int],
        last_file_path: Optional[str],
        extra: Optional[dict] = None,
    ) -> None:
        """Persist a checkpoint for the current operation phase."""
        self.connect()
        extra_json = json.dumps(extra) if extra is not None else None
        self._state_conn.execute(
            """
            INSERT INTO checkpoints (
                operation_id,
                phase,
                processed_files,
                total_files,
                last_file_path,
                updated_at,
                extra_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(operation_id, phase) DO UPDATE SET
                processed_files = excluded.processed_files,
                total_files = excluded.total_files,
                last_file_path = excluded.last_file_path,
                updated_at = excluded.updated_at,
                extra_json = excluded.extra_json
            """,
            (
                operation_id,
                phase,
                processed_files,
                total_files,
                last_file_path,
                datetime.utcnow().isoformat(),
                extra_json,
            ),
        )
        self._state_conn.commit()

    def get_checkpoint(self, operation_id: str, phase: str) -> Optional[dict]:
        """Fetch the last checkpoint for a given operation phase."""
        self.connect()
        cursor = self._state_conn.execute(
            """
            SELECT processed_files, total_files, last_file_path, updated_at, extra_json
            FROM checkpoints
            WHERE operation_id = ? AND phase = ?
            """,
            (operation_id, phase),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        extra = json.loads(row[4]) if row[4] else None
        return {
            "processed_files": row[0],
            "total_files": row[1],
            "last_file_path": row[2],
            "updated_at": row[3],
            "extra": extra,
        }


def _chunked(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]
