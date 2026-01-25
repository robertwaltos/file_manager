"""
Standalone launcher for the web dashboard.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from config import AppConfig
from dashboard import DashboardServer
from utils import setup_logging


def _build_db_paths(config: AppConfig) -> dict[str, Path]:
    return {
        "file_inventory": config.resolve_path(
            "databases", "file_inventory", default="data/file_inventory.sqlite"
        ),
        "hash_database": config.resolve_path(
            "databases", "hash_database", default="data/hash_database.sqlite"
        ),
        "ai_classifications": config.resolve_path(
            "databases", "ai_classifications", default="data/ai_classifications.sqlite"
        ),
        "state": config.resolve_path("databases", "state", default="data/state.sqlite"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the file manager web dashboard.")
    parser.add_argument("--config", default=None, help="Optional config path override")
    parser.add_argument("--host", default=None, help="Override dashboard host")
    parser.add_argument("--port", type=int, default=None, help="Override dashboard port")
    args = parser.parse_args()

    config_path = Path(args.config) if args.config else None
    config = AppConfig.load(config_path)
    loggers = setup_logging(config.resolve_path("paths", "logs", default="logs"))
    logger = loggers["main"]

    host = args.host or str(config.get("dashboard", "web_host", default="127.0.0.1"))
    port = args.port or int(config.get("dashboard", "web_port", default=8765))
    server = DashboardServer(_build_db_paths(config), host=host, port=port, logger=logger)
    server.start()
    logger.info("Dashboard running at http://%s:%s (Ctrl+C to stop)", host, port)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping dashboard server.")
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
