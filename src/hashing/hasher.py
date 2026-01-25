"""
Hashing utilities for file content.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path


class Hasher:
    """Compute full or hybrid SHA-256 hashes for files."""

    def __init__(self, full_hash_max_bytes: int, hybrid_chunk_bytes: int) -> None:
        self.full_hash_max_bytes = full_hash_max_bytes
        self.hybrid_chunk_bytes = hybrid_chunk_bytes

    def hash_type_for_size(self, size: int) -> str:
        """Return the hash type based on file size."""
        return "sha256_full" if size <= self.full_hash_max_bytes else "sha256_hybrid"

    def compute(self, path: Path, size: int, hash_type: str) -> str:
        """Compute the requested hash type for a file."""
        if hash_type == "sha256_full":
            return self._sha256_full(path)
        if hash_type == "sha256_hybrid":
            return self._sha256_hybrid(path, size)
        raise ValueError(f"Unsupported hash type: {hash_type}")

    def _sha256_full(self, path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
        """Compute a full SHA-256 hash in streaming mode."""
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                data = handle.read(chunk_size)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    def _sha256_hybrid(self, path: Path, size: int) -> str:
        """Compute a hybrid SHA-256 hash using key file segments."""
        chunk = self.hybrid_chunk_bytes
        if size <= chunk * 3:
            return self._sha256_full(path)

        with path.open("rb") as handle:
            head = handle.read(chunk)
            middle_offset = max((size // 2) - (chunk // 2), 0)
            handle.seek(middle_offset)
            middle = handle.read(chunk)
            tail_offset = max(size - chunk, 0)
            handle.seek(tail_offset)
            tail = handle.read(chunk)

        hasher = hashlib.sha256()
        hasher.update(struct.pack("<Q", size))
        hasher.update(head)
        hasher.update(middle)
        hasher.update(tail)
        return hasher.hexdigest()
