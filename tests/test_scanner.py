from pathlib import Path

from config import AppConfig
from database import DatabaseManager
from discovery.scanner import Scanner


def test_scanner_skips_hidden_and_patterns(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "keep.txt").write_text("ok", encoding="utf-8")
    (root / ".hidden.txt").write_text("hidden", encoding="utf-8")
    (root / "skipme.skip").write_text("skip", encoding="utf-8")

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "scan:",
                "  skip_hidden: true",
                "  follow_symlinks: false",
                "exclusions:",
                "  system_paths: []",
                "  file_patterns:",
                "    - \"*.skip\"",
            ]
        ),
        encoding="utf-8",
    )

    config = AppConfig.load(config_path)
    db_paths = {
        "file_inventory": tmp_path / "file_inventory.sqlite",
        "hash_database": tmp_path / "hash_database.sqlite",
        "ai_classifications": tmp_path / "ai_classifications.sqlite",
        "state": tmp_path / "state.sqlite",
    }
    manager = DatabaseManager(db_paths)
    manager.initialize()

    scanner = Scanner(config, manager)
    records = list(scanner.scan(root))

    assert len(records) == 1
    assert records[0].file_path.endswith("keep.txt")

    manager.close()
