import hashlib
from pathlib import Path

from hashing.hasher import Hasher


def test_full_hash_matches_sha256(tmp_path: Path) -> None:
    path = tmp_path / "small.txt"
    content = b"hash me"
    path.write_bytes(content)

    hasher = Hasher(full_hash_max_bytes=1024, hybrid_chunk_bytes=4)
    hash_type = hasher.hash_type_for_size(len(content))

    assert hash_type == "sha256_full"
    assert hasher.compute(path, len(content), hash_type) == hashlib.sha256(content).hexdigest()


def test_hybrid_hash_changes_with_content(tmp_path: Path) -> None:
    path = tmp_path / "large.bin"
    content = bytearray(b"0123456789" * 5)
    path.write_bytes(content)

    hasher = Hasher(full_hash_max_bytes=10, hybrid_chunk_bytes=4)
    hash_type = hasher.hash_type_for_size(len(content))

    assert hash_type == "sha256_hybrid"
    original = hasher.compute(path, len(content), hash_type)

    content[25] ^= 0xFF
    path.write_bytes(content)
    modified = hasher.compute(path, len(content), hash_type)

    assert original != modified
