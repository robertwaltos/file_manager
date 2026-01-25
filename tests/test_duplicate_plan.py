import json
from pathlib import Path

from config import AppConfig
from duplicates.plan import DuplicatePlanEngine


def test_duplicate_plan_generates_plan_and_review(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    backup_root = tmp_path / "backup"
    logs_root = tmp_path / "logs"

    report = {
        "generated_at": "2024-01-01T00:00:00",
        "groups": [
            {
                "hash_type": "sha256_full",
                "hash_value": "abc",
                "file_name": "dup.txt",
                "size": 4,
                "primary": {"file_id": 1, "file_path": "C:/primary/dup.txt"},
                "duplicates": [{"file_id": 2, "file_path": "D:/dup/dup.txt"}],
            }
        ],
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  duplicates_backup: \"{backup_root.as_posix()}\"",
                f"  logs: \"{logs_root.as_posix()}\"",
                "duplicates:",
                "  backup_action: \"move\"",
            ]
        ),
        encoding="utf-8",
    )
    config = AppConfig.load(config_path)

    engine = DuplicatePlanEngine(config, db_manager=None, logger=None)
    stats = engine.build_plan(report_path)

    assert stats.plan_path.exists()
    assert stats.review_path.exists()
    assert stats.move_count == 1

    plan_data = json.loads(stats.plan_path.read_text(encoding="utf-8"))
    assert plan_data["moves"][0]["destination"].startswith(str(backup_root))
