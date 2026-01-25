import json
from datetime import datetime
from pathlib import Path

from config import AppConfig
from database import DatabaseManager, FileRecord
from thumbnails.engine import ThumbnailCleanupEngine


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


def write_config(tmp_path: Path) -> AppConfig:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  logs: \"{(tmp_path / 'logs').as_posix()}\"",
                "databases:",
                f"  file_inventory: \"{(tmp_path / 'file_inventory.sqlite').as_posix()}\"",
                f"  hash_database: \"{(tmp_path / 'hash_database.sqlite').as_posix()}\"",
                f"  ai_classifications: \"{(tmp_path / 'ai_classifications.sqlite').as_posix()}\"",
                f"  state: \"{(tmp_path / 'state.sqlite').as_posix()}\"",
                "thumbnails:",
                "  action: \"move\"",
                f"  quarantine_path: \"{(tmp_path / 'quarantine').as_posix()}\"",
                "  max_size_bytes: 1024",
                "  max_dimension_px: 256",
                "  name_markers:",
                "    - \"thumb\"",
                "  directory_markers:",
                "    - \"thumbs\"",
                "  cover_name_markers:",
                "    - \"cover\"",
                "  cover_audio_extensions:",
                "    - \".mp3\"",
            ]
        ),
        encoding="utf-8",
    )
    return AppConfig.load(config_path)


def test_thumbnail_report_skips_cover_images(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    db_manager = DatabaseManager(build_db_paths(tmp_path))
    db_manager.initialize()

    music_dir = tmp_path / "music"
    music_dir.mkdir()
    (music_dir / "song.mp3").write_bytes(b"data")
    cover = music_dir / "cover_thumb.jpg"
    cover.write_bytes(b"small")

    thumbs_dir = tmp_path / "thumbs"
    thumbs_dir.mkdir()
    thumbnail = thumbs_dir / "photo_thumb.jpg"
    thumbnail.write_bytes(b"small")

    for file_path in (cover, thumbnail):
        record = make_record(file_path)
        db_manager.upsert_file(record)

    engine = ThumbnailCleanupEngine(config, db_manager, logger=None)
    stats = engine.build_report()
    report_data = json.loads(stats.report_path.read_text(encoding="utf-8"))
    candidates = {entry["file_path"] for entry in report_data["candidates"]}

    assert str(cover) not in candidates
    assert str(thumbnail) in candidates

    db_manager.close()


def test_thumbnail_cleanup_moves_candidates(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    db_manager = DatabaseManager(build_db_paths(tmp_path))
    db_manager.initialize()

    thumbs_dir = tmp_path / "thumbs"
    thumbs_dir.mkdir()
    thumbnail = thumbs_dir / "photo_thumb.jpg"
    thumbnail.write_bytes(b"small")

    record = make_record(thumbnail)
    db_manager.upsert_file(record)

    engine = ThumbnailCleanupEngine(config, db_manager, logger=None)
    stats = engine.build_report()
    engine.apply_report(stats.report_path)

    quarantine = tmp_path / "quarantine"
    moved_files = list(quarantine.rglob("photo_thumb*"))
    assert not thumbnail.exists()
    assert len(moved_files) == 1
    assert not db_manager.file_exists(str(thumbnail))

    db_manager.close()
