import json
from datetime import datetime
from pathlib import Path

from config import AppConfig
from database import DatabaseManager, FileRecord
from duplicates.engine import DuplicateEngine
from hashing.hasher import Hasher


def build_db_paths(root: Path) -> dict[str, Path]:
    return {
        "file_inventory": root / "file_inventory.sqlite",
        "hash_database": root / "hash_database.sqlite",
        "ai_classifications": root / "ai_classifications.sqlite",
        "state": root / "state.sqlite",
    }


def make_record(path: Path) -> FileRecord:
    stat = path.stat()
    timestamp = datetime.utcnow().isoformat()
    return FileRecord(
        file_path=str(path),
        file_name=path.name,
        size=stat.st_size,
        creation_date=timestamp,
        modification_date=timestamp,
        scan_date=timestamp,
        accessible=True,
        permission_error=None,
    )


def test_duplicate_report_detects_matching_hashes(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  duplicates_backup: \"{(tmp_path / 'dup').as_posix()}\"",
                "databases:",
                f"  file_inventory: \"{(tmp_path / 'file_inventory.sqlite').as_posix()}\"",
                f"  hash_database: \"{(tmp_path / 'hash_database.sqlite').as_posix()}\"",
                f"  ai_classifications: \"{(tmp_path / 'ai_classifications.sqlite').as_posix()}\"",
                f"  state: \"{(tmp_path / 'state.sqlite').as_posix()}\"",
                "hashing:",
                "  full_hash_max_bytes: 1024",
                "  hybrid_chunk_bytes: 4",
            ]
        ),
        encoding="utf-8",
    )
    config = AppConfig.load(config_path)

    db_manager = DatabaseManager(build_db_paths(tmp_path))
    db_manager.initialize()

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_c = tmp_path / "c"
    dir_a.mkdir()
    dir_b.mkdir()
    dir_c.mkdir()

    file_one = dir_a / "report.txt"
    file_two = dir_b / "report.txt"
    file_three = dir_c / "report.txt"

    file_one.write_text("same", encoding="utf-8")
    file_two.write_text("same", encoding="utf-8")
    file_three.write_text("different", encoding="utf-8")

    for file_path in (file_one, file_two, file_three):
        record = make_record(file_path)
        file_id = db_manager.upsert_file(record)
        hasher = Hasher(full_hash_max_bytes=1024, hybrid_chunk_bytes=4)
        hash_type = hasher.hash_type_for_size(record.size)
        hash_value = hasher.compute(file_path, record.size, hash_type)
        db_manager.insert_hash(file_id, hash_type, hash_value)

    engine = DuplicateEngine(config, db_manager, logger=None)
    candidates = {(file_one.name, file_one.stat().st_size)}
    stats = engine.run("duplicates_test", candidates=candidates)

    assert stats.duplicate_groups == 1
    report_data = json.loads(stats.report_path.read_text(encoding="utf-8"))
    assert report_data["duplicate_groups"] == 1
    assert len(report_data["groups"][0]["duplicates"]) == 1

    db_manager.close()
