"""
Logging configuration for the file management system.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict


def setup_logging(log_dir: Path) -> Dict[str, logging.Logger]:
    """Initialize loggers and return a mapping of named loggers."""
    log_dir.mkdir(parents=True, exist_ok=True)
    date_stamp = datetime.utcnow().strftime("%Y%m%d")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    master_log = log_dir / f"master_log_{date_stamp}.log"
    error_log = log_dir / f"error_log_{date_stamp}.log"
    performance_log = log_dir / f"performance_log_{date_stamp}.log"
    movement_log = log_dir / f"movement_log_{date_stamp}.log"

    base_logger = logging.getLogger("file_manager")
    if not base_logger.handlers:
        base_logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        base_logger.addHandler(stream_handler)

        file_handler = logging.FileHandler(master_log, encoding="utf-8")
        file_handler.setFormatter(formatter)
        base_logger.addHandler(file_handler)

        error_handler = logging.FileHandler(error_log, encoding="utf-8")
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        base_logger.addHandler(error_handler)

    performance_logger = logging.getLogger("file_manager.performance")
    if not performance_logger.handlers:
        performance_logger.setLevel(logging.INFO)
        perf_handler = logging.FileHandler(performance_log, encoding="utf-8")
        perf_handler.setFormatter(formatter)
        performance_logger.addHandler(perf_handler)
        performance_logger.propagate = False

    movement_logger = logging.getLogger("file_manager.movement")
    if not movement_logger.handlers:
        movement_logger.setLevel(logging.INFO)
        move_handler = logging.FileHandler(movement_log, encoding="utf-8")
        move_handler.setFormatter(formatter)
        movement_logger.addHandler(move_handler)
        movement_logger.propagate = False

    return {"main": base_logger, "performance": performance_logger, "movement": movement_logger}
