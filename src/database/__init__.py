"""
Database package for schema creation and persistence helpers.
"""

from .manager import (
    DatabaseManager,
    DuplicateCandidate,
    FileMetadata,
    FileRecord,
    FileUpsertResult,
    InventoryEntry,
)
from .schema import create_databases

__all__ = [
    "DatabaseManager",
    "DuplicateCandidate",
    "FileMetadata",
    "FileRecord",
    "FileUpsertResult",
    "InventoryEntry",
    "create_databases",
]
