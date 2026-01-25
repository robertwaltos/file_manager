from datetime import datetime
from pathlib import Path

from database import DatabaseManager, FileRecord


def build_db_paths(root: Path) -> dict[str, Path]:
    return {
        "file_inventory": root / "file_inventory.sqlite",
        "hash_database": root / "hash_database.sqlite",
        "ai_classifications": root / "ai_classifications.sqlite",
        "state": root / "state.sqlite",
    }


def test_database_inserts_and_checkpoints(tmp_path: Path) -> None:
    db_paths = build_db_paths(tmp_path)
    manager = DatabaseManager(db_paths)
    manager.initialize()

    record = FileRecord(
        file_path=str(tmp_path / "example.txt"),
        file_name="example.txt",
        size=123,
        creation_date=datetime.utcnow().isoformat(),
        modification_date=datetime.utcnow().isoformat(),
        scan_date=datetime.utcnow().isoformat(),
        accessible=True,
        permission_error=None,
    )

    file_id = manager.upsert_file(record)
    assert file_id > 0

    operation_id = manager.start_operation("scan")
    manager.save_checkpoint(operation_id, "discovery", 5, None, record.file_path)
    checkpoint = manager.get_checkpoint(operation_id, "discovery")

    assert checkpoint is not None
    assert checkpoint["processed_files"] == 5

    manager.insert_hash(file_id, "sha256_full", "abc123")
    assert manager.hash_exists(file_id, "sha256_full") is True

    manager.record_corruption(file_id, "read_error", "simulated")

    manager.complete_operation(operation_id)
    manager.close()
