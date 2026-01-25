from pathlib import Path

from config import AppConfig


def test_config_resolves_paths(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("paths:\n  logs: \"logs\"\n", encoding="utf-8")

    config = AppConfig.load(config_path)
    logs_path = config.resolve_path("paths", "logs")

    assert logs_path == config_path.parent / "logs"
    assert config.get("missing", default=123) == 123
