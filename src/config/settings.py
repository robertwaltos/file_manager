"""
Configuration loader and helpers for the file management system.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable

import yaml

DEFAULT_CONFIG_PATH = Path("config.yaml")
ENV_CONFIG_PATH = "FILE_MANAGER_CONFIG"


@dataclass(frozen=True)
class AppConfig:
    """Container for raw configuration data and path helpers."""

    root_dir: Path
    raw: Dict[str, Any]

    @classmethod
    def load(cls, path: Path | None = None) -> "AppConfig":
        """Load configuration from YAML and normalize the root directory."""
        config_value = os.environ.get(ENV_CONFIG_PATH)
        config_path = path
        if config_path is None:
            config_path = Path(config_value) if config_value else DEFAULT_CONFIG_PATH
        config_path = config_path.expanduser()
        if not config_path.is_absolute():
            config_path = (Path.cwd() / config_path).resolve()
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        root_dir = config_path.parent
        return cls(root_dir=root_dir, raw=data)

    def get(self, *keys: str, default: Any = None) -> Any:
        """Retrieve nested configuration values with an optional default."""
        node: Any = self.raw
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def resolve_path(self, *keys: str, default: str | None = None) -> Path:
        """Resolve a path from configuration keys to an absolute Path."""
        value = self.get(*keys, default=default)
        if value is None:
            raise KeyError(f"Missing config path for {'.'.join(keys)}")
        path = Path(value)
        if not path.is_absolute():
            path = (self.root_dir / path).resolve()
        return path


def ensure_directories(paths: Iterable[Path]) -> None:
    """Create directories if they do not already exist."""
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
