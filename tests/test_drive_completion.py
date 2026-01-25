from pathlib import Path

from database import DatabaseManager


def test_drive_completion_tracking(tmp_path: Path) -> None:
    db_paths = {
        "file_inventory": tmp_path / "file_inventory.sqlite",
        "hash_database": tmp_path / "hash_database.sqlite",
        "ai_classifications": tmp_path / "ai_classifications.sqlite",
        "state": tmp_path / "state.sqlite",
    }
    manager = DatabaseManager(db_paths)
    manager.initialize()

    drive_key = manager.normalize_drive_key(Path("T:/"))
    assert manager.is_drive_completed(drive_key) is False

    manager.mark_drive_completed(drive_key, notes="test")
    assert manager.is_drive_completed(drive_key) is True
    assert drive_key in manager.list_completed_drives()

    manager.close()
