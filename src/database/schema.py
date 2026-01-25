
"""
Database schema definitions for the file management system.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict


def create_databases(db_paths: Dict[str, Path]) -> None:
    """Create all SQLite databases and their tables."""
    create_file_inventory_db(db_paths["file_inventory"])
    create_hash_database_db(db_paths["hash_database"])
    create_ai_classifications_db(db_paths["ai_classifications"])
    create_state_db(db_paths["state"])


def create_file_inventory_db(db_path: Path) -> None:
    """Create the file inventory database and its tables."""
    conn = _connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            file_path TEXT UNIQUE,
            file_name TEXT,
            size INTEGER,
            creation_date TIMESTAMP,
            modification_date TIMESTAMP,
            scan_date TIMESTAMP,
            accessible BOOLEAN,
            permission_error TEXT
        )
        """
    )
    _ensure_column(conn, "files", "file_name", "TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_size ON files(size)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_name_size ON files(file_name, size)")
    conn.commit()
    conn.close()


def create_hash_database_db(db_path: Path) -> None:
    """Create the hash database and its tables."""
    conn = _connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY,
            file_id INTEGER,
            hash_type TEXT,
            hash_value TEXT,
            FOREIGN KEY (file_id) REFERENCES files (id),
            UNIQUE (file_id, hash_type)
        )
        """
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_hashes_file_type ON hashes(file_id, hash_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hashes_value ON hashes(hash_value)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS corruptions (
            id INTEGER PRIMARY KEY,
            file_id INTEGER UNIQUE,
            error_type TEXT,
            error_message TEXT,
            detected_at TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_corruptions_file_id ON corruptions(file_id)")
    conn.commit()
    conn.close()


def create_ai_classifications_db(db_path: Path) -> None:
    """Create the AI classifications database and its tables."""
    conn = _connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS classifications (
            id INTEGER PRIMARY KEY,
            file_id INTEGER,
            category TEXT,
            subcategory TEXT,
            tags TEXT,
            nsfw_score REAL,
            model TEXT,
            confidence REAL,
            updated_at TIMESTAMP,
            details_json TEXT,
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
        """
    )
    _ensure_column(conn, "classifications", "model", "TEXT")
    _ensure_column(conn, "classifications", "confidence", "REAL")
    _ensure_column(conn, "classifications", "updated_at", "TIMESTAMP")
    _ensure_column(conn, "classifications", "details_json", "TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_classifications_file_id ON classifications(file_id)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_classifications_file_unique ON classifications(file_id)")
    conn.commit()
    conn.close()


def create_state_db(db_path: Path) -> None:
    """Create the state database for operations and checkpoints."""
    conn = _connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS operations (
            id INTEGER PRIMARY KEY,
            operation_id TEXT UNIQUE,
            operation_type TEXT,
            status TEXT,
            started_at TIMESTAMP,
            finished_at TIMESTAMP,
            details TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS checkpoints (
            id INTEGER PRIMARY KEY,
            operation_id TEXT,
            phase TEXT,
            processed_files INTEGER,
            total_files INTEGER,
            last_file_path TEXT,
            updated_at TIMESTAMP,
            extra_json TEXT,
            UNIQUE (operation_id, phase)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS permission_issues (
            id INTEGER PRIMARY KEY,
            file_path TEXT UNIQUE,
            error_message TEXT,
            context TEXT,
            attempts INTEGER,
            last_attempt TIMESTAMP,
            resolved BOOLEAN
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS drive_runs (
            drive_key TEXT PRIMARY KEY,
            status TEXT,
            completed_at TIMESTAMP,
            last_scan TIMESTAMP,
            notes TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_queue (
            task_id TEXT PRIMARY KEY,
            name TEXT,
            status TEXT,
            depends_on TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            attempts INTEGER,
            last_error TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS file_operations (
            id INTEGER PRIMARY KEY,
            operation_id TEXT,
            action TEXT,
            source_path TEXT,
            destination_path TEXT,
            status TEXT,
            size INTEGER,
            created_at TIMESTAMP,
            error_message TEXT,
            rollback_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_checkpoints_operation ON checkpoints(operation_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_permission_issues_resolved ON permission_issues(resolved)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_drive_runs_status ON drive_runs(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_task_queue_status ON task_queue(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_file_operations_operation ON file_operations(operation_id)")
    conn.commit()
    conn.close()


def _connect(db_path: Path) -> sqlite3.Connection:
    """Create a SQLite connection with WAL enabled."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    """Ensure a column exists on a SQLite table."""
    cursor = conn.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column in existing:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
